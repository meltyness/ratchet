// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use std::env;
use std::process::Command;
use std::collections::HashMap;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Write;

use precis_profiles::precis_core::profile::Profile;
use precis_profiles::UsernameCasePreserved;

use ratchet::RTHeader;
use ratchet::RTTACType;
use ratchet::RTAuthenPacket;
use ratchet::md5_xor;
use ratchet::RTDecodedPacket;
use ratchet::RTAuthenReplyPacket;

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


    let username_case_preserved : UsernameCasePreserved = UsernameCasePreserved::new();

    let listener = match TcpListener::bind("0.0.0.0:44449") {
        Ok(l) => l,
        #[allow(clippy::panic)] // this is definitely fatal for a server.
        Err(e) => panic!("Ratchet Error: {} check permissions for user: {:#?}.", e, rt_get_user_name()),
    };

    let generic_error = RTAuthenReplyPacket::get_error_packet().serialize();

    println!("Ratchet Info: NOWLISTENING bound to some port 49");

    for stream in listener.incoming() {        
        // Stage 0: Check that this is a valid stream, produce some logs about the event.
        let mut stream = match stream {
            Ok(s) => { // TODO: Collect this into session info so that the following diagnostic logs can be associated
                println!("Ratchet Info: Received connection request from {}", s.peer_addr()
                                                                               .map_or("Unknown Address"
                                                                               .to_string(), |addr| addr.to_string())); 
                                                                                // it *doesn't* take two to tango?
                println!("Ratchet Debug: Other connection info: Read Timeout: {:#?}, Write Timeout: {:#?}", s.read_timeout(),s.write_timeout());
                match s.set_nodelay(true) {
                    Ok(_) => (),
                    Err(_) => {
                        println!("Ratchet Debug: Couldn't disable Nagles for this Socket, proceeding anyway.");
                    },
                };
                s // hand over the TcpStream
            },
            Err(e) => { 
                println!("Ratchet Error: TCP Error, {}", e);
                continue;
            },
        };

        // Stage 1: Parse header, establish session
        let hdr: RTHeader = match RTHeader::parse_init_header(&mut stream) { 
            Ok(h) => {
                //println!("Ratchet Debug: Processed {:#?}", h); 
                h
            },
            Err(e) => {
                println!("Ratchet Error: {}", e);
                rt_send_error_packet(&generic_error, &mut stream);
                continue;
            },
        };

        // Stage 2: Parse packet, perform appropriate treatment
        let contents = match hdr.tacp_hdr_type {
            RTTACType::TAC_PLUS_AUTHEN => hdr.parse_authen_packet(&mut stream, SECRET_KEY),
            RTTACType::TAC_PLUS_AUTHOR => {
                println!("Ratchet Debug: Not Implemented");
                rt_send_error_packet(&generic_error, &mut stream);
                continue;
            },
            RTTACType::TAC_PLUS_ACCT => {
                println!("Ratchet Debug: Not Implemented");
                rt_send_error_packet(&generic_error, &mut stream);
                continue;
            },
        };

        let decoded: RTDecodedPacket = match contents {
            Err(e) => { 
                println!("Ratchet Error: {}", e); 
                rt_send_error_packet(&generic_error, &mut stream);
                continue; 
            }
            Ok(d) => {
                //println!("Ratchet Debug: Processed {:#?}", d); 
                d
            },
        };
        
        // Stage 3: Decide what stuff to do depending on the type of packet.
        match decoded {
            RTDecodedPacket::RTAuthenPacket(ap) => match ap {
                RTAuthenPacket::RTAuthenStartPacket(asp) => {
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
                                rt_send_error_packet(&generic_error, &mut stream);
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
                        let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, &r);
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
                        let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, &r);
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
                    }
                },
                RTAuthenPacket::RTAuthenReplyPacket(rtauthen_reply_packet) => { 
                    println!("Ratchet Error: umm... no, I'M the server.");
                    rt_send_error_packet(&generic_error, &mut stream);
                    continue; 
                },
                // _ => println!("Unknown Authen Packet Format"),
            }
            _ => {
                println!("Unknown Packet Format");
                rt_send_error_packet(&generic_error, &mut stream);
                continue;
            },
        }
        
        println!("Ratchet Info: Finished Processing!");
    }
}

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
            let key = parts[0].trim().to_string(); // key takes ownership

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
            let value = parts[1].trim().to_string(); // value takes ownership
            creds_out.insert(username, value); // Insert key-value pair
        }
    }
}

fn rt_send_error_packet(msg: &[u8], stream: &mut TcpStream) {
    // It's just a header, it shouldn't reveal anything interesting.
    match stream.write(msg) {
        Ok(v) => println!("Ratchet Debug: Sent {} bytes", v),
        Err(e) => {
            println!("Ratchet Error: TCP Error, {}", e);
        },
    }
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