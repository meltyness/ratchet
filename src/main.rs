// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use libc::{mlockall, MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT};


use std::array;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::exit;
use std::process::Command;
use std::collections::HashMap;
use std::net::TcpListener;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use std::thread;
use std::sync::Arc;

use precis_profiles::precis_core::profile::Profile;
use precis_profiles::UsernameCasePreserved;

use ratchet::RTAuthenSess;
use ratchet::RTHeader;
use ratchet::RTTACType;
use ratchet::RTAuthenPacket;
use ratchet::RTDecodedPacket;
use ratchet::RTAuthenReplyPacket;

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
    let mut clients_v4: [HashMap<u32, String>; 33] = array::from_fn(|_| HashMap::new());
    let mut clients_v6: [HashMap<u128, String>; 129] = array::from_fn(|_| HashMap::new());

    let mut custom_clients_cmd = String::new();
    let mut custom_creds_cmd = String::new(); // Use String instead of &str
    let mut custom_hostport = String::from("[::]:44449");
    for (key, value) in env::vars() {
        if key == "RATCHET_READ_CLIENTS" {
            custom_clients_cmd = value; // Directly assign the value
        } else if key == "RATCHET_READ_CREDS" {
            custom_creds_cmd = value; // Directly assign the value
        } else if key == "RATCHET_CUST_HOSTPORT" {
            custom_hostport = value; // Directly assign the value
        }
    }
    
    if !custom_clients_cmd.is_empty() {
        server_settings.rt_server_read_creds = custom_clients_cmd.as_str(); // Use the String here
        
        // Use the configured command to obtain creds.
        rt_obtain_clients(server_settings.rt_server_read_creds, &mut clients_v4, &mut clients_v6);
    }

    if !custom_creds_cmd.is_empty() { 
        server_settings.rt_server_read_creds = custom_creds_cmd.as_str(); // Use the String here
        
        // Use the configured command to obtain creds.
        rt_obtain_creds(server_settings.rt_server_read_creds, &mut credentials, server_settings.rt_server_i18n);
    }    

    // Check if the specific argument is present
    if env::args().any(|x| x == *"--add-insecure-test-credential-do-not-use".to_string()) {
        credentials.insert("username".to_string(), "123456".to_string());
        rt_obtain_clients("echo '127.0.0.1,testing123'", &mut clients_v4, &mut clients_v6);
    }

    // Check if the specific argument is present
    if env::args().any(|x| x == *"--add-basic-db-test-do-not-use".to_string()) {
        rt_obtain_creds("echo 'user1,extremely_secure_pass\nuser2,unbelievable_password\nuser3,awesome_password'", &mut credentials, server_settings.rt_server_i18n);
        rt_obtain_clients("echo '127.0.0.1,testing123'", &mut clients_v4, &mut clients_v6);
    }

        // Check if the specific argument is present
        if env::args().any(|x| x == *"--add-huge-wildcard-test-do-not-use".to_string()) {
            credentials.insert("username".to_string(), "123456".to_string());
            rt_obtain_clients("echo '0.0.0.0/0,testing123'", &mut clients_v4, &mut clients_v6);
        }

    if env::args().any(|x| x == *"--ignore-i18n".to_string()) {
        server_settings.rt_server_i18n = false;
    }



    let listener = match TcpListener::bind(custom_hostport.as_str()) {
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

    // unsafe {
    //     ctrlc::set_handler(move || {
    //         println!("Ratchet Debug: Average processing time over {} RUNS: {:#?}", rt_get_runs(), Duration::from_secs_f64(rt_get_avg() / rt_get_runs()));
    //         println!("Ratchet Debug: total rate: {} RUNS / sec", RUNS / (Instant::now() - FIRST_RUN.unwrap()).as_secs_f64());
    //         exit(0);
    //     })
    //     .expect("Error setting Ctrl-C handler");
    // }

    let result = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) };
    if result != 0 {
        eprintln!("mlockall failed with error code: {}", result);
    } else {
        println!("mlockall succeeded");
    }

    
    let credentials_container = Arc::new(credentials);
    let clients_v4_container = Arc::new(clients_v4);
    let clients_v6_container = Arc::new(clients_v6);

    for stream in listener.incoming() {
        // let start_time = Instant::now();
        // unsafe { RUNS = RUNS + 1.0;
        //     match FIRST_RUN {
        //         Some(_) => (),
        //         None => {
        //             FIRST_RUN = Some(start_time.clone())
        //         },
        //     }
        // }
        let clients_v4_container = clients_v4_container.clone();
        let clients_v6_container = clients_v6_container.clone();
        let credentials_container = credentials_container.clone();
        thread::spawn( move || {
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
                return;
            },
        };

        stream.set_read_timeout(Some(Duration::from_secs(10))); // for interactive sessions, the user has to type this fast
                                                                     // for DoS prevention, the server has to tolerate 2*10*(line rate) sessions
        stream.set_write_timeout(Some(Duration::from_secs(3)));
        // Stage 0.5: Determine if this is a client
        // TODO: completely encapsulate this into the session eventually...
        let v4_binding = clients_v4_container.clone();
        let v6_binding = clients_v6_container.clone();
        let SECRET_KEY = match rt_fetch_secret(&stream.peer_addr().unwrap().ip(), &v4_binding, &v6_binding) {
            Ok(s) => s,
            Err(e) => {
                println!("Ratchet Warning: Unknown client, {:#?}", stream.peer_addr());
                return;
            },
        };
        

        if SECRET_KEY == "" {
            println!("Ratchet Warning: Unknown client, {:#?}", stream.peer_addr());
            return;
        }

        // Stage 1: Parse header, establish session
        let hdr: RTHeader = match RTHeader::parse_init_header(&mut stream, 0) { 
            Ok(h) => {
                println!("Ratchet Debug: Processed {:#?}", h); 
                h
            },
            Err(e) => {
                println!("Ratchet Error: {}", e);
                //authen_sess.send_error_packet( &mut stream);
                return;
            },
        };

        let mut authen_sess = RTAuthenSess::from_header(&hdr, SECRET_KEY);

        // Stage 2: Parse packet, perform appropriate treatment
        let contents = match hdr.tacp_hdr_type {
            RTTACType::TAC_PLUS_AUTHEN => hdr.parse_authen_packet(&mut stream, SECRET_KEY),
            RTTACType::TAC_PLUS_AUTHOR => {
                println!("Ratchet Debug: Not Implemented");
                authen_sess.send_error_packet( &mut stream);
                return;
            },
            RTTACType::TAC_PLUS_ACCT => {
                println!("Ratchet Debug: Not Implemented");
                authen_sess.send_error_packet( &mut stream);
                return;
            },
        };

        let decoded: RTDecodedPacket = match contents {
            Err(e) => { 
                println!("Ratchet Error: {}", e); 
                authen_sess.send_error_packet( &mut stream);
                return; 
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
                            println!("Ratchet Info: Decoded: {}", asp);
                            
                            // (sort of) Authenticate the server before putting a cred on the line
                            //let mut retries = 0;

                            // Stage 1: Fetch the Username
                            let obtained_username= if asp.user.len() == 0 { // have to fetch username
                                    match authen_sess.do_get(&mut stream, RTAuthenReplyPacket::get_getuser_packet()) {
                                        Ok(u) => u,
                                        Err(_) => {
                                            authen_sess.send_error_packet(&mut stream);
                                            return;
                                        },
                                    }
                                } else {
                                    String::from_utf8_lossy(&asp.user).to_string()
                                };

                            // no retries.
                            if obtained_username.len() == 0 {
                                // buzz off
                                match authen_sess.send_final_packet(&mut stream,  RTAuthenReplyPacket::get_fail_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent failure packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }
                                return;
                            }
                            
                            // Stage 2: Fetch the Password
                            // TODO: Everybody gets one
                            let obtained_password=
                                match authen_sess.do_get(&mut stream, RTAuthenReplyPacket::get_getpass_packet()) {
                                    Ok(u) => u,
                                    Err(_) => {
                                        authen_sess.send_error_packet(&mut stream);
                                        return;
                                    },
                                };
                            
                            if obtained_password.len() == 0 || obtained_username.len() == 0 {
                                // buzz off
                                match authen_sess.send_final_packet(&mut stream,  RTAuthenReplyPacket::get_fail_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent failure packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }
                                return;
                            }
                            let username_case_preserved : UsernameCasePreserved = UsernameCasePreserved::new();
                            let raw_username = obtained_username;
                            let auth_request_password = obtained_password;
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
                                        return;
                                    },
                                }
                            } else {
                                raw_username.try_into().unwrap()
                            };
                            
                            if let Some(p) = credentials_container.get(&username.to_string()) {
                                // User known, check authentication success.
                                println!("Ratchet Debug: Found user with password: {}", p);
                                println!("Attempting to compare {} to {}", p, auth_request_password);
                                user_authenticated = p == &auth_request_password;
                            } else {
                                println!("Ratchet Debug: Couldn't find {:#?}, check username", username);
                                // user who? user not authenticated!
                            }
        
                            if user_authenticated {
                                match authen_sess.send_final_packet(&mut stream, RTAuthenReplyPacket::get_success_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent success packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }

                            } else {
                                match authen_sess.send_final_packet(&mut stream,  RTAuthenReplyPacket::get_fail_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent failure packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }
                            }
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_PAP => {
                            println!("Ratchet Info: Decoded: {}", asp);
                            let raw_username = String::from_utf8_lossy(&asp.user);
                            let auth_request_password = String::from_utf8_lossy(&asp.data);
                            let mut user_authenticated = false;
        
                            println!("Ratchet Debug: Looking up {}", raw_username);
                            let username_case_preserved : UsernameCasePreserved = UsernameCasePreserved::new();
                            let username = if server_settings.rt_server_i18n {
                                match username_case_preserved.prepare(raw_username) {
                                    Ok(fixed_username) => { 
                                        println!("Ratchet Debug: Looking up {}", fixed_username);
                                        fixed_username
                                    },
                                    Err(e) => {
                                        println!("Ratchet Error: Invalid username passed, {}", e);
                                        authen_sess.send_error_packet( &mut stream);
                                        return;
                                    },
                                }
                            } else {
                                raw_username
                            };
                            
                            if let Some(p) = credentials_container.get(&username.to_string()) {
                                // User known, check authentication success.
                                println!("Ratchet Debug: Found user with password: {}", p);
                                println!("Attempting to compare {} to {}", p, auth_request_password);
                                user_authenticated = p == &auth_request_password;
                            } else {
                                println!("Ratchet Debug: Couldn't find {:#?}, check username", username);
                                // user who? user not authenticated!
                            }
        
                            if user_authenticated {
                                match authen_sess.send_final_packet(&mut stream, RTAuthenReplyPacket::get_success_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent success packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }

                            } else {
                                match authen_sess.send_final_packet(&mut stream,  RTAuthenReplyPacket::get_fail_packet()) {
                                    Ok(_) => println!("Ratchet Debug: Sent failure packet"),
                                    Err(e) => println!("Ratchet Error: TCP Error, {}", e),
                                }
                            }
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_CHAP => {
                            println!("Unknown Packet Format");
                            authen_sess.send_error_packet( &mut stream);
                            return;
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAP => {
                            println!("Unknown Packet Format");
                            authen_sess.send_error_packet( &mut stream);
                            return;
                        },
                        ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 => {
                            println!("Unknown Packet Format");
                            authen_sess.send_error_packet( &mut stream);
                            return;
                        },
                    }
                },
                RTAuthenPacket::RTAuthenReplyPacket(rtauthen_reply_packet) => { 
                    println!("Ratchet Error: umm... no, I'M the server.");
                    authen_sess.send_error_packet( &mut stream);
                    return; 
                },
                RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => {
                    println!("Ratchet Error: Unexpected continue packet!!");
                    authen_sess.send_error_packet( &mut stream);
                    return;
                },
                // _ => println!("Unknown Authen Packet Format"),
            }
            _ => {
                println!("Unknown Packet Format");
                authen_sess.send_error_packet( &mut stream);
                return;
            },
        }
        });
        // let end_time = Instant::now();
        // unsafe {RUNNING_AVG = RUNNING_AVG + ((end_time - start_time)).as_secs_f64();}
    }
}

fn rt_fetch_secret<'a>(ip: &IpAddr, clients_v4: &'a [HashMap<u32, String>; 33] , clients_v6: &'a [HashMap<u128, String>; 129]) -> Result<&'a String, &'a str> {
    println!("Ratchet Debug: Thumbing through {:#?} and {:#?}", clients_v4, clients_v6);
    match ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            println!("Ratchet Debug: Seeking out {}", ipv4_addr.to_bits());
            let addr = ipv4_addr.to_bits();
            let mut mask = 0xFFFFFFFFu32;
            let mut i = 0;
            while i <= 32 {
                println!("Ratchet Debug: Masking result: {}", (addr & mask));
                match clients_v4[32 - i].get(&(addr & mask)) {
                    Some(str) => {
                        return Ok(str);
                    },
                    None => (),
                }
                i += 1;
               mask <<= 1;
            }
            Err("Unknown client")
        },
        std::net::IpAddr::V6(ipv6_addr) => {
            match ipv6_addr.to_ipv4_mapped() {
                Some(ipv4_addr) => {
                    println!("Ratchet Debug: Seeking out {}", ipv4_addr.to_bits());
                    let addr = ipv4_addr.to_bits();
                    let mut mask = 0xFFFFFFFFu32;
                    let mut i = 0;
                    while i <= 32 {
                        println!("Ratchet Debug: Masking result: {}", (addr & mask));
                        match clients_v4[32 - i].get(&(addr & mask)) {
                            Some(str) => {
                                return Ok(str);
                            },
                            None => (),
                        }
                        i += 1;
                        mask <<= 1;
                    }
                    Err("Unknown client")
                },
                None => {
                    println!("Ratchet Debug: Seeking out {}", ipv6_addr.to_bits());
                    let addr = ipv6_addr.to_bits();
                    let mut mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
                    let mut i = 0;
                    while i <= 128 {
                        match clients_v6[128 - i].get(&(addr & mask)) {
                            Some(str) => {
                                return Ok(str);
                            },
                            None => (),
                        }
                        i += 1;
                        mask <<= 1;
                    }
                    Err("Unknown client")    
                },
            }
            
        },
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

/// For a user-specified shell command string,
/// expect a CSV list of clients.
/// 
/// Install the CSV list of clients as the users database.
/// 
fn rt_obtain_clients(cmd: &str, v4_clients_out: &mut [HashMap<u32, String>; 33], v6_clients_out: &mut [HashMap<u128, String>; 129]) {
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
            let value = parts[1].to_string(); // keys can contain spaces in some implementations

            if value.len() == 0 || key.len() == 0 {
                println!("Ratchet Error: Must have valid network and secret, skipping {}", key);
            }

            let key_parts: Vec<&str> = key.split('/').collect();

            let net_mask_def = key_parts.len() == 2;

            match Ipv4Addr::from_str(key_parts[0]) {
                Ok(s) => {
                    let int_address = s.to_bits();
                    if !net_mask_def {
                        v4_clients_out[32].insert(int_address, value);
                        continue;
                    } else {
                        let netmask = match u32::from_str(key_parts[1]) {
                            Ok(n) => n as usize,
                            Err(_) => continue,
                        };

                        if netmask <= 32 && (int_address == (int_address & (IPV4_MASKS[netmask]))) {
                            v4_clients_out[netmask].insert(int_address, value);
                        } else {
                            println!("Ratchet Debug: Bad netmask, or bad network address, skipping {}", key);
                        }
                    }
                },
                Err(_) => {
                    match Ipv6Addr::from_str(key_parts[0]) {
                        Ok(s) =>  {
                            let int_address = s.to_bits();
                            if !net_mask_def {
                                v6_clients_out[128].insert(int_address, value);
                                continue;
                            } else {
                                let netmask = match u32::from_str(key_parts[1]) {
                                    Ok(n) => n as usize,
                                    Err(_) => continue,
                                };
        
                                if netmask <= 128 && (int_address == (int_address & (IPV6_MASKS[netmask]))) {
                                    v6_clients_out[netmask].insert(int_address, value);
                                } else {
                                    println!("Ratchet Debug: Bad netmask, or bad network address, skipping {}", key);
                                }
                            }
                        },
                        Err(_) => {
                            // Not IPv4 or IPv6 ... discarding.
                            println!("Ratchet Debug: Bad input, or bad network address, skipping {}", key);
                        },
                    }
                }
            };
            
            println!("Ratchet Debug: Installed client {}", key);
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

macro_rules! generate_v6netmasks {
    // Macro for generating netmasks for IPv4 and IPv6
    ($name:ident, $bits:expr, $size:expr) => {
        const $name: [u128; $bits + 1] = {
            let mut masks = [0; $bits + 1];
            let mut i = 0;
            while i <= $bits {
                masks[i] = if i == 0 {
                    0
                } else {
                    (!0u128) << ($size - i)
                };
                i += 1;
            }
            masks
        };
    };
}

macro_rules! generate_v4netmasks {
    // Macro for generating netmasks for IPv4 and IPv6
    ($name:ident, $bits:expr, $size:expr) => {
        const $name: [u32; $bits + 1] = {
            let mut masks = [0; $bits + 1];
            let mut i = 0;
            while i <= $bits {
                masks[i] = if i == 0 {
                    0
                } else {
                    (!0u32) << ($size - i)
                };
                i += 1;
            }
            masks
        };
    };
}

// Generate IPv4 and IPv6 masks
generate_v4netmasks!(IPV4_MASKS, 32, 32);
generate_v6netmasks!(IPV6_MASKS, 128, 128);