// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use std::time::Duration;
use std::{env, thread};
use std::io::Write;
use std::{collections::HashMap, net::TcpListener};
use std::process::Command;

use ratchet::{md5_xor, RTAuthenPacket, RTAuthenReplyPacket, RTDecodedPacket, RTHeader, RTTACType};

const SECRET_KEY: &str = "testing123"; // TODO: When building a red-black tree of clients, ensure that they are required to have a secret, or not clients.

struct RTServerSettings {
    rt_server_max_length : u32 // = 65535, // https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-18
}

impl RTServerSettings {
    fn new(rt_server_max_length: u32) -> Self {
        Self { rt_server_max_length }
    }
}

struct RTKnownClient {

}

// https://www.rfc-editor.org/rfc/rfc8265.html#section-3.4
//impl USNCasePres {

//}

pub fn main() {
    let server_settings = RTServerSettings::new(65535);
    println!("Ratchet Info: starting...");

    // Create a new HashMap
    let mut credentials = HashMap::new();

    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check if the specific argument is present
    if args.contains(&"--add-insecure-test-credential-do-not-use".to_string()) {
        credentials.insert("username", "123456");
    }

    let listener = TcpListener::bind("0.0.0.0:44449");

    match listener {
        Ok(_) => println!("Ratchet Info: bound to some port 49"),
        Err(e) => panic!("Ratchet Error: {} check permissions for user: {:#?}.", e, get_user_name()),
    }

    let listener=listener.unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        // Stage 1: Parse header, establish session
        let my_hdr = RTHeader::parse_init_header(&mut stream);
        let hdr: RTHeader = match my_hdr { 
            Err(e) => {
                println!("Ratchet Error: {}", e);
                continue;
            },
            Ok(h) => {
                //println!("Ratchet Debug: Processed {:#?}", h); 
                h
            },
        };

        // Stage 2: Parse packet, perform appropriate treatment
        let contents = match hdr.tacp_hdr_type {
            RTTACType::TAC_PLUS_AUTHEN => hdr.parse_authen_packet(&mut stream, SECRET_KEY),
            RTTACType::TAC_PLUS_AUTHOR => todo!(),
            RTTACType::TAC_PLUS_ACCT => todo!(),
        };

        let decoded: RTDecodedPacket = match contents {
            Err(e) => { println!("Ratchet Error: {}", e); continue }
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
                    let username = String::from_utf8_lossy(&asp.user);
                    let auth_request_password = String::from_utf8_lossy(&asp.data);
                    let mut user_authenticated = false;

                    println!("Ratchet Debug: Looking up {}", username);
                    
                    if let Some(&p) = credentials.get(username.as_ref()) {
                        // User known, check authentication success.
                        println!("Ratchet Debug: Found user with password: {}", p);
                        println!("Attempting to compare {} to {}", p, auth_request_password);
                        user_authenticated = p == auth_request_password;
                    }

                    if user_authenticated {
                        let r = RTAuthenReplyPacket::get_success_packet();
                        println!("Ratchet Debug: {username} Authenticated successfully, signalling client.");
                        println!("Ratchet Debug: {:#?}", r);
                        let length = r.serialize().len() as u32;
                        println!("Ratchet Debug: Preparing packet with {length}");
                        let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, length);
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
                        let length = r.serialize().len() as u32;
                        println!("Ratchet Debug: Preparing packet with {length}");
                        let resp_hdr = RTHeader::get_resp_header(hdr.tacp_hdr_sesid, length);
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
                RTAuthenPacket::RTAuthenReplyPacket(rtauthen_reply_packet) => { println!("Ratchet Error: umm... no, I'M the server."); continue },
                // _ => println!("Unknown Authen Packet Format"),
            }
            _ => println!("Unknown Packet Format"),
        }
        thread::sleep(Duration::from_secs(2));
        println!("Connection established!");
    }
}

// "Treatment of Enumerated Protocol Values" 
fn drop_error() {

}

fn get_user_name() -> String {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "whoami"])
            .output()
            .expect("failed to determine username")
    } else {
        Command::new("sh")
            .args(["-c", "whoami"])
            .output()
            .expect("failed to determine unix username")
    };
    return String::from_utf8(output.stdout).expect("Failed to determine username").trim_end().to_string();
} 