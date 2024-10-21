// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use libc::{mlockall, madvise, MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT, MADV_WILLNEED};


use std::env;
use std::process::exit;
use std::process::Command;
use std::collections::HashMap;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

use precis_profiles::precis_core::profile::Profile;
use precis_profiles::UsernameCasePreserved;

use ratchet::RTAuthenSess;
use ratchet::RTHeader;
use ratchet::RTTACType;
use ratchet::RTAuthenPacket;
use ratchet::md5_xor;
use ratchet::RTDecodedPacket;
use ratchet::RTAuthenReplyPacket;
use ratchet::RTAuthenContinuePacket;

const SECRET_KEY: &str = "testing123"; // TODO: When building a red-black tree of clients, 
                                    //ensure that they are required to have a secret, or not clients.

struct RTServerSettings<'a> {
    rt_server_max_length : u32, // = 65535, // https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-18
    rt_server_i18n : bool,
    rt_server_read_clients : &'a str,
    rt_server_read_creds : &'a str,
}

impl<'a> RTServerSettings<'a> {
    fn new(rt_server_max_length: u32, rt_server_i18n: bool, rt_server_read_clients: &'a str, rt_server_read_creds: &'a str) -> Self {
        Self { rt_server_max_length, rt_server_i18n, rt_server_read_clients, rt_server_read_creds }
    }
}

struct RTKnownClient {

}

fn prefetch_memory_region(start_addr: *const u8, length: usize) {
    let result = unsafe { madvise(start_addr as *mut _, length, MADV_WILLNEED) };

    if result != 0 {
        eprintln!("madvise failed");
    } else {
        println!("Memory region prefetched successfully");
    }
}

static mut RUNS: f64 = 0.0;
static mut RUNNING_AVG: f64 = 0.0;
static mut FIRST_RUN: Option<Instant> = None;

/// # Panics
/// 
/// Panics if the server cannot open on the specified hostaddr
/// 
pub fn main() {

    let mut server_settings = RTServerSettings::new(65535, 
                                                                    true,
                                                                    "cat /dev/null",
                                                                    "cat /dev/null");

    
    println!("Ratchet Info: starting...");

    // Create a new HashMap
    let mut credentials: HashMap<String, String> = HashMap::new();


    let mut custom_creds_cmd = String::new(); // Use String instead of &str
    for (key, value) in env::vars() {
        if key == "RATCHET_READ_CLIENTS" {
            custom_creds_cmd = value; // Directly assign the value
        }
    }
    
    if !custom_creds_cmd.is_empty() { 
        server_settings.rt_server_read_creds = custom_creds_cmd.as_str(); // Use the String here
        
        // Use the configured command to obtain creds.
        rt_obtain_creds(server_settings.rt_server_read_creds, &mut credentials, server_settings.rt_server_i18n);
    }
    

    // Check if the specific argument is present
    if env::args().any(|x| x == *"--add-insecure-test-credential-do-not-use".to_string()) {
        credentials.insert("username".to_string(), "123456".to_string());
    }

    // Check if the specific argument is present
    if env::args().any(|x| x == *"--add-basic-db-test-do-not-use".to_string()) {
        rt_obtain_creds("echo 'user1,extremely_secure_pass\nuser2,unbelievable_password\nuser3,awesome_password'", &mut credentials, server_settings.rt_server_i18n);
    }

    if env::args().any(|x| x == *"--ignore-i18n".to_string()) {
        server_settings.rt_server_i18n = false;
    }


    let username_case_preserved : UsernameCasePreserved = UsernameCasePreserved::new();

    let listener = match TcpListener::bind("0.0.0.0:44449") {
        Ok(l) => l,
        #[allow(clippy::panic)] // this is definitely fatal for a server.
        Err(e) => panic!("Ratchet Error: {} check permissions for user: {:#?}.", e, rt_get_user_name()),
    };

    // polish applied: https://github.com/rust-lang/rust/issues/67027
    match listener.set_nonblocking(false) {
        Ok(_) => (),
        Err(_) => {
            println!("Ratchet Debug: Couldn't set listener non-blocking, proceeding anyway.")
        }
    }


    println!("Ratchet Info: NOWLISTENING bound to some port 49");


    unsafe {
        ctrlc::set_handler(move || {
            println!("Ratchet Debug: Average processing time over {} RUNS: {:#?}", rt_get_runs(), Duration::from_secs_f64(rt_get_avg() / rt_get_runs()));
            println!("Ratchet Debug: total rate: {} RUNS / sec", RUNS / (Instant::now() - FIRST_RUN.unwrap()).as_secs_f64());
            exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    }

    let result = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) };
    if result != 0 {
        eprintln!("mlockall failed with error code: {}", result);
    } else {
        println!("mlockall succeeded");
    }

    for stream in listener.incoming() {
        let start_time = Instant::now();
        unsafe { RUNS = RUNS + 1.0;
            match FIRST_RUN {
                Some(_) => (),
                None => {
                    FIRST_RUN = Some(start_time.clone())
                },
            }
        }

        // Stage 0: Check that this is a valid stream, produce some logs about the event.
        let mut stream = match stream {
            Ok(s) => { // TODO: Collect this into session info so that the following diagnostic logs can be associated
                println!("Ratchet Info: Received connection request from {}", s.peer_addr()
                                                                               .map_or("Unknown Address".to_string(),
                                                                               |addr| addr.to_string())); 
                                                                                // it *doesn't* take two to tango?
                println!("Ratchet Debug: Other connection info: Read Timeout: {:#?}, Write Timeout: {:#?}", s.read_timeout(),s.write_timeout());

                // This shouldn't be bandwidth-intensive enough, prefer latency optimization and disable Nagle's
                match s.set_nodelay(true) {
                    Ok(_) => (),
                    Err(_) => {
                        println!("Ratchet Debug: Couldn't disable Nagles for this Socket, proceeding anyway.");
                    },
                };

                // polish applied: https://github.com/rust-lang/rust/issues/67027
                match s.set_nonblocking(false) {
                    Ok(_) => (),
                    Err(_) => {
                        println!("Ratchet Debug: Couldn't set stream non-blocking, proceeding anyway.")
                    }
                }
                s // hand over the TcpStream
            },
            Err(e) => { 
                println!("Ratchet Error: TCP Error, {}", e);
                continue;
            },
        };

        // Stage 1: Parse header, establish session
        let hdr: RTHeader = match RTHeader::parse_init_header(&mut stream, 0) { 
            Ok(h) => {
                println!("Ratchet Debug: Processed {:#?}", h); 
                h
            },
            Err(e) => {
                println!("Ratchet Error: {}", e);
                //authen_sess.send_error_packet( &mut stream);
                continue;
            },
        };

        let mut authen_sess = RTAuthenSess::from_header(&hdr, SECRET_KEY);

        // Stage 2: Parse packet, perform appropriate treatment
        let contents = match hdr.tacp_hdr_type {
            RTTACType::TAC_PLUS_AUTHEN => hdr.parse_authen_packet(&mut stream, SECRET_KEY),
            RTTACType::TAC_PLUS_AUTHOR => {
                println!("Ratchet Debug: Not Implemented");
                authen_sess.send_error_packet( &mut stream);
                continue;
            },
            RTTACType::TAC_PLUS_ACCT => {
                println!("Ratchet Debug: Not Implemented");
                authen_sess.send_error_packet( &mut stream);
                continue;
            },
        };

        let decoded: RTDecodedPacket = match contents {
            Err(e) => { 
                println!("Ratchet Error: {}", e); 
                authen_sess.send_error_packet( &mut stream);
                continue; 
            }
            Ok(d) => {
                println!("Ratchet Debug: Processed {:#?}", d); 
                d
            },
        };
        
        // Stage 3: Decide what stuff to do depending on the type of packet.
        match decoded {
            RTDecodedPacket::RTAuthenPacket(ap) => match ap {
                RTAuthenPacket::RTAuthenStartPacket(asp) => {
                    match asp.authen_type {
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_ASCII => {
                            // TODO: This can hang forever with a misbehaving client,
                            //      ... the server must be multithreaded or implement read/write timeout.
                            //      ... better to go multithreaded.
                            let mut cur_seq = 1; // We received one.
                            println!("Ratchet Info: Decoded: {}", asp);
                            // (sort of) Authenticate the server before putting a cred on the line
                            let mut retries = 0;

                            // Stage 1: Fetch the Username
                            let obtained_username;
                            if asp.user.len() == 0 { // have to fetch username
                                let get_user_packet = RTAuthenReplyPacket::get_getuser_packet();

                                // TODO: Refactor this mantra into a neatly architected thingamajig
                                //   ... maybe the 'outermost' detail needed is the session info (i.e., expected pack number, expected sesid), so
                                //   ... it should be a part of a session implementation for the full transaction.
                                let user_resp_hdr = RTHeader::get_v0_header(hdr.tacp_hdr_sesid, &get_user_packet, cur_seq);
                                cur_seq += 1;
                                println!("Ratchet Debug: {:#?}", user_resp_hdr);
                                println!("Ratchet Debug: {:#?}", get_user_packet);
                                let pad = user_resp_hdr.compute_md5_pad( SECRET_KEY );
                                let mut payload = md5_xor(&get_user_packet.serialize(), &pad);
                                let mut msg = user_resp_hdr.serialize();
                                msg.append(&mut payload);
        
                                println!("{:?}", msg);
                                // TODO: This blocks
                                match stream.write(&msg) {
                                    Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
                                    Err(e) => 
                                        println!("Ratchet Error: TCP Error, {}", e),
                                    //},
                                }
    
                                // TODO: Ok... session loop is starting over...? Not really it's a sequence .... hmmmmmmmmm...
                                let user_hdr: RTHeader = match RTHeader::parse_init_header(&mut stream, cur_seq) { 
                                    Ok(h) => {
                                        //println!("Ratchet Debug: Processed {:#?}", h); 
                                        cur_seq += 1;
                                        h
                                    },
                                    Err(e) => {
                                        println!("Ratchet Error: {}", e);
                                        authen_sess.send_error_packet( &mut stream);
                                        continue;
                                    },
                                };
    
                                let user_contents = match user_hdr.tacp_hdr_type {
                                    RTTACType::TAC_PLUS_AUTHEN => user_hdr.parse_authen_packet(&mut stream, SECRET_KEY),
                                    RTTACType::TAC_PLUS_AUTHOR => {
                                        println!("Ratchet Debug: Not Implemented");
                                        authen_sess.send_error_packet( &mut stream);
                                        continue;
                                    },
                                    RTTACType::TAC_PLUS_ACCT => {
                                        println!("Ratchet Debug: Not Implemented");
                                        authen_sess.send_error_packet( &mut stream);
                                        continue;
                                    },
                                };
    
                                let decoded_user: RTDecodedPacket = match user_contents {
                                    Err(e) => { 
                                        println!("Ratchet Error: {}", e); 
                                        authen_sess.send_error_packet( &mut stream);
                                        continue; 
                                    }
                                    Ok(d) => {
                                        //println!("Ratchet Debug: Processed {:#?}", d); 
                                        d
                                    },
                                };

                                println!("Ratchet Debug: Deciding on decoded user packet");
                                match decoded_user {
                                    RTDecodedPacket::RTAuthenPacket(rtauthen_user_packet) => {
                                        println!("Ratchet Debug: Was authen packet, checking for Continue");
                                        match rtauthen_user_packet {
                                            RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => {
                                                obtained_username = rtauthen_continue_packet.user_msg;
                                            },
                                            _ => {
                                                println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence"); 
                                                authen_sess.send_error_packet( &mut stream);
                                                continue; 
                                            },
                                        }
                                    },
                                    _ => { 
                                        println!("Ratchet Error: Non authen packet in Authen sequence");
                                        println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence"); 
                                        authen_sess.send_error_packet( &mut stream);
                                        continue; 
                                    },
                                }
                            } else {
                                obtained_username = asp.user;
                            }
                            
                            // Stage 2: Fetch the Password
                            // TODO: Everybody gets one
                            
                            let get_password_packet = RTAuthenReplyPacket::get_getpass_packet();

                            // TODO: Refactor this mantra into a neatly architected thingamajig
                            //   ... maybe the 'outermost' detail needed is the session info (i.e., expected pack number, expected sesid), so
                            //   ... it should be a part of a session implementation for the full transaction.
                            println!("Ratchet Debug: {:#?}", get_password_packet);
                            let getpass_resp_hdr = RTHeader::get_v0_header(hdr.tacp_hdr_sesid, &get_password_packet, cur_seq);
                            println!("Ratchet Debug: {:#?}", getpass_resp_hdr);
                            let pad = getpass_resp_hdr.compute_md5_pad( SECRET_KEY );
                            let mut payload = md5_xor(&get_password_packet.serialize(), &pad);
                            let mut msg = getpass_resp_hdr.serialize();
                            msg.append(&mut payload);
    
                            println!("{:?}", msg);
                            // TODO: This blocks
                            match stream.write(&msg) {
                                Ok(v) => { 
                                    cur_seq += 1;
                                    println!("Ratchet Debug: Sent {} bytes", v)
                            },
                                Err(e) => 
                                    println!("Ratchet Error: TCP Error, {}", e),
                                //},
                            }

                            // TODO: Ok... session loop is starting over...? Not really it's a sequence .... hmmmmmmmmm...
                            let pass_hdr: RTHeader = match RTHeader::parse_init_header(&mut stream, cur_seq) { 
                                Ok(h) => {
                                    //println!("Ratchet Debug: Processed {:#?}", h); 
                                    cur_seq += 1;
                                    h
                                },
                                Err(e) => {
                                    println!("Ratchet Error: {}", e);
                                    authen_sess.send_error_packet( &mut stream);
                                    continue;
                                },
                            };

                            let pass_contents = match pass_hdr.tacp_hdr_type {
                                RTTACType::TAC_PLUS_AUTHEN => pass_hdr.parse_authen_packet(&mut stream, SECRET_KEY),
                                RTTACType::TAC_PLUS_AUTHOR => {
                                    println!("Ratchet Debug: Not Implemented");
                                    authen_sess.send_error_packet( &mut stream);
                                    continue;
                                },
                                RTTACType::TAC_PLUS_ACCT => {
                                    println!("Ratchet Debug: Not Implemented");
                                    authen_sess.send_error_packet( &mut stream);
                                    continue;
                                },
                            };

                            let decoded_pass: RTDecodedPacket = match pass_contents {
                                Err(e) => { 
                                    println!("Ratchet Error: {}", e); 
                                    authen_sess.send_error_packet( &mut stream);
                                    continue; 
                                }
                                Ok(d) => {
                                    //println!("Ratchet Debug: Processed {:#?}", d); 
                                    d
                                },
                            };

                            let obtained_password;
                            match decoded_pass {
                                RTDecodedPacket::RTAuthenPacket(rtauthen_pass_packet) => {
                                    match rtauthen_pass_packet {
                                        RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => {
                                            obtained_password = rtauthen_continue_packet.user_msg;
                                        },
                                        _ => {
                                            println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence"); 
                                            authen_sess.send_error_packet( &mut stream);
                                            continue; 
                                        },
                                    }
                                },
                                _ => { 
                                    println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence"); 
                                    authen_sess.send_error_packet( &mut stream);
                                    continue; 
                                },
                            }
                            
                            
                            // TODO: BIG CODE DUPLICATION
                            // TODO: BIG CODE DUPLICATION
                            // TODO: BIG CODE DUPLICATION
                            // TODO: BIG CODE DUPLICATION
                            // TODO: BIG CODE DUPLICATION
                            // TODO: BIG CODE DUPLICATION
                            let raw_username = String::from_utf8_lossy(&obtained_username);
                            let auth_request_password = String::from_utf8_lossy(&obtained_password);
                            let mut user_authenticated = false;
        
                            println!("Ratchet Debug: Looking up {}", raw_username);
        
                            let username = if server_settings.rt_server_i18n {
                                match username_case_preserved.prepare(raw_username) {
                                    Ok(fixed_username) => { 
                                        println!("Ratchet Debug: Looking up {}", fixed_username);
                                        fixed_username
                                    },
                                    Err(e) => {
                                        println!("Ratchet Error: Invalid username passed, {}", e);
                                        authen_sess.send_error_packet( &mut stream);
                                        continue;
                                    },
                                }
                            } else {
                                raw_username
                            };
                            
                            if let Some(p) = credentials.get(&username.to_string()) {
                                // User known, check authentication success.
                                println!("Ratchet Debug: Found user with password: {}", p);
                                println!("Attempting to compare {} to {}", p, auth_request_password);
                                user_authenticated = p == &auth_request_password;
                            } else {
                                println!("Ratchet Debug: Couldn't find {:#?}, check username", username);
                                // user who? user not authenticated!
                            }
        
                            if user_authenticated {
                                let r = RTAuthenReplyPacket::get_success_packet();
                                println!("Ratchet Debug: {username} Authenticated successfully, signalling client.");
                                println!("Ratchet Debug: {:#?}", r);
                                let resp_hdr = RTHeader::get_v0_header(hdr.tacp_hdr_sesid, &r, cur_seq);
                                println!("Ratchet Debug: {:#?}", resp_hdr);
                                let pad = resp_hdr.compute_md5_pad( SECRET_KEY );
                                let mut payload = md5_xor(&r.serialize(), &pad);
                                let mut msg = resp_hdr.serialize();
                                msg.append(&mut payload);
        
                                println!("{:?}", msg);
                                // TODO: This blocks
                                match stream.write(&msg) {
                                    Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
                                    Err(e) => {
                                        println!("Ratchet Error: TCP Error, {}", e);
                                    },
                                }
                            } else {
                                let r = RTAuthenReplyPacket::get_fail_packet();
                                println!("Ratchet Debug: {username} Authentication failed, signalling client.");
                                println!("Ratchet Debug: {:#?}", r);
                                let resp_hdr = RTHeader::get_v0_header(hdr.tacp_hdr_sesid, &r, cur_seq);
                                println!("Ratchet Debug: {:#?}", resp_hdr);
                                let pad = resp_hdr.compute_md5_pad( SECRET_KEY );
                                let mut payload = md5_xor(&r.serialize(), &pad);
                                let mut msg = resp_hdr.serialize();
                                msg.append(&mut payload);
        
                                println!("{:?}", msg);
                                // TODO: This blocks
                                match stream.write(&msg) {
                                    Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
                                    Err(e) => 
                                        println!("Ratchet Error: TCP Error, {}", e),
                                    //},
                                }
                            }
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_PAP => {
                            println!("Ratchet Info: Decoded: {}", asp);
                            let raw_username = String::from_utf8_lossy(&asp.user);
                            let auth_request_password = String::from_utf8_lossy(&asp.data);
                            let mut user_authenticated = false;
        
                            println!("Ratchet Debug: Looking up {}", raw_username);
        
                            let username = if server_settings.rt_server_i18n {
                                match username_case_preserved.prepare(raw_username) {
                                    Ok(fixed_username) => { 
                                        println!("Ratchet Debug: Looking up {}", fixed_username);
                                        fixed_username
                                    },
                                    Err(e) => {
                                        println!("Ratchet Error: Invalid username passed, {}", e);
                                        authen_sess.send_error_packet( &mut stream);
                                        continue;
                                    },
                                }
                            } else {
                                raw_username
                            };
                            
                            if let Some(p) = credentials.get(&username.to_string()) {
                                // User known, check authentication success.
                                println!("Ratchet Debug: Found user with password: {}", p);
                                println!("Attempting to compare {} to {}", p, auth_request_password);
                                user_authenticated = p == &auth_request_password;
                            } else {
                                println!("Ratchet Debug: Couldn't find {:#?}, check username", username);
                                // user who? user not authenticated!
                            }
        
                            if user_authenticated {
                                let r = RTAuthenReplyPacket::get_success_packet();
                                println!("Ratchet Debug: {username} Authenticated successfully, signalling client.");
                                println!("Ratchet Debug: {:#?}", r);
                                let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, &r, 1);
                                println!("Ratchet Debug: {:#?}", resp_hdr);
                                let pad = resp_hdr.compute_md5_pad( SECRET_KEY );
                                let mut payload = md5_xor(&r.serialize(), &pad);
                                let mut msg = resp_hdr.serialize();
                                msg.append(&mut payload);
        
                                println!("{:?}", msg);
                                // TODO: This blocks
                                match stream.write(&msg) {
                                    Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
                                    Err(e) => {
                                        println!("Ratchet Error: TCP Error, {}", e);
                                    },
                                }
                            } else {
                                let r = RTAuthenReplyPacket::get_fail_packet();
                                println!("Ratchet Debug: {username} Authentication failed, signalling client.");
                                println!("Ratchet Debug: {:#?}", r);
                                let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, &r, 1);
                                println!("Ratchet Debug: {:#?}", resp_hdr);
                                let pad = resp_hdr.compute_md5_pad( SECRET_KEY );
                                let mut payload = md5_xor(&r.serialize(), &pad);
                                let mut msg = resp_hdr.serialize();
                                msg.append(&mut payload);
        
                                println!("{:?}", msg);
                                // TODO: This blocks
                                match stream.write(&msg) {
                                    Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
                                    Err(e) => 
                                        println!("Ratchet Error: TCP Error, {}", e),
                                    //},
                                }
                            }
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_CHAP => todo!(),
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAP => todo!(),
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 => todo!(),
                    }
                },
                RTAuthenPacket::RTAuthenReplyPacket(rtauthen_reply_packet) => { 
                    println!("Ratchet Error: umm... no, I'M the server.");
                    authen_sess.send_error_packet( &mut stream);
                    continue; 
                },
                RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => {
                    println!("Ratchet Error: Unexpected continue packet!!");
                    authen_sess.send_error_packet( &mut stream);
                    continue;
                },
                // _ => println!("Unknown Authen Packet Format"),
            }
            _ => {
                println!("Unknown Packet Format");
                authen_sess.send_error_packet( &mut stream);
                continue;
            },
        }
        let end_time = Instant::now();
        unsafe {RUNNING_AVG = RUNNING_AVG + ((end_time - start_time)).as_secs_f64();}
    }
}

/// For a user-specified shell command string,
/// expect a CSV list of clients.
/// 
/// Install the CSV list of clients as the users database.
/// 
fn rt_obtain_creds(cmd: &str, creds_out: &mut HashMap<String, String>, server_i18n: bool) {
    // Otherwise use rt_server_read_creds to obtain credentials
    let output = Command::new("sh")
    .arg("-c")
    .arg(cmd)
    .output()
    .expect("Failed to execute configured command.");

    let data_str = String::from_utf8_lossy(&output.stdout);

    // Split by newline
    for line in data_str.lines() {
        // Split each line by comma
        let parts: Vec<&str> = line.split(',').collect();
        let username_case_preserved : UsernameCasePreserved = UsernameCasePreserved::new();

        // Ensure there are exactly two parts to form a key-value pair
        if parts.len() == 2 {
            let key = parts[0].trim().to_string();

            let username = if server_i18n {
                match username_case_preserved.prepare(key) {
                    Ok(fixed_username) => { 
                        println!("Ratchet Debug: Looking up {}", fixed_username);
                        fixed_username.to_string()
                    },
                    Err(e) => {
                        println!("Ratchet Error: Invalid username passed, {}", e);
                        continue;
                    },
                }
            } else {
                key
            };
            
            println!("Ratchet Debug: Installed user {}", username);
            let value = parts[1].to_string();
            creds_out.insert(username, value);
        }
    }
}

unsafe fn rt_get_avg() -> f64{
    return RUNNING_AVG;
}

unsafe fn rt_get_runs() -> f64 {
    return RUNS;
}

fn rt_get_user_name() -> String {
    return match if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "whoami"])
            .output()
    } else {
        Command::new("sh")
            .args(["-c", "whoami"])
            .output()
    } { 
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            return "Couldn't get username".to_string();
        }
    };
} 