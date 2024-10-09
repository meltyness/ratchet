// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use std::net::TcpListener;
use std::process::Command;

use ratchet::{RTAuthenPacket, RTDecodedPacket, RTHeader, RTTACType};

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

fn main() {
    let server_settings = RTServerSettings::new(65535);
    println!("Ratchet Info: starting...");
    // let test_pak = RTHeader {    
    //     tacp_hdr_version : RTTACVersion::from_byte(0xc1).expect("huh?"),
    //     tacp_hdr_type : RTTACType::from_byte(0x1).expect("huh?"),
    //     tacp_hdr_seqno : 0, // 1-255, always rx odd tx even, session ends if a wrap occurs
    //     tacp_hdr_flags : 0,
    //     tacp_hdr_sesid : 0, // must be CSPRNG
    //     tacp_hdr_length : 0,};
    // Read Configuration

    //println!("Ratchet Debug: Test packet: {:#?}", test_pak);

    let listener = TcpListener::bind("0.0.0.0:44449");

    match listener {
        Ok(_) => println!("Ratchet Info: bound to some port 49"),
        Err(E) => panic!("Ratchet Error: {} check permissions for user: {:#?}.", E, get_user_name()),
    }

    let listener=listener.unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let hdr: RTHeader;
        let decoded: RTDecodedPacket;

        // Stage 1: Parse header, establish session
        let my_hdr = RTHeader::parse_init_header(&mut stream);
        hdr = match my_hdr { 
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

        decoded = match contents {
            Err(e) => { println!("Ratchet Error: {}", e); continue }
            Ok(d) => {
                //println!("Ratchet Debug: Processed {:#?}", d); 
                d
            },
        };
        
        // Stage 3: Decide what stuff to do depending on the type of packet.
        match decoded {
            RTDecodedPacket::RTAuthenPacket(ap) => match ap {
                RTAuthenPacket::RTAuthenStartPacket(asp) => println!("Ratchet Info: Decoded: {}", asp),
                _=> println!("Unknown Authen Packet Format"),
            }
            _ => println!("Unknown Packet Format"),
        }

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