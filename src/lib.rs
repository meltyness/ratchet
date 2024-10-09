// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use std::{fmt, io::Read, net::TcpStream};
const TACP_HEADER_MAX_LENGTH: usize = 12; // 12 bytes.
 
// This macro generates a fn, from_byte for 
//  - a given u8-enum type, and
//  - list of applicable variants.
macro_rules! impl_from_byte {
    ($enum_name:ident $(,$variant:ident)+) => {
        impl $enum_name {
            pub fn from_byte(value: u8) -> Result<Self, &'static str> {
                match value {
                    $( 
                        x if x == $enum_name::$variant as u8 => Ok($enum_name::$variant),
                    )+
                    _ => Err(concat!("Invalid byte value processing for: ", stringify!($enum_name))),
                }
            }
        }
    };
}

#[derive(Debug)]
pub struct RTHeader {
    pub tacp_hdr_version : RTTACVersion,
    pub tacp_hdr_type : RTTACType,
    pub tacp_hdr_seqno : u8, // 1-255, always rx odd tx even, session ends if a wrap occurs
    pub tacp_hdr_flags : u8,
    pub tacp_hdr_sesid : u32, // must be CSPRNG
    pub tacp_hdr_length : u32,
}

impl RTHeader {
    pub fn get_expected_packet_length(&self) -> usize {
        match self.tacp_hdr_length.try_into() { Ok(l) => l, _ => return 0}
    }

    pub fn parse_init_header(stream: &mut TcpStream) -> Result<Self, &str> {
        let mut hdr_buf: [u8; TACP_HEADER_MAX_LENGTH] = [0u8; TACP_HEADER_MAX_LENGTH];
        stream.read_exact(&mut hdr_buf);
        
        // TODO: Check overrun
        //println!("Ratchet Debug : Full packet contents: {:#x?}", hdr_buf);
        
        let ret = RTHeader {
            tacp_hdr_version: RTTACVersion::from_byte(hdr_buf[0])?,
            tacp_hdr_type:    RTTACType::from_byte(hdr_buf[1])?,
            tacp_hdr_seqno:   match hdr_buf[2] { 1 => Ok(1), _ => Err("Invalid initial sequence number")}?,
            tacp_hdr_flags:   match hdr_buf[3] { 0 => Ok(0), _ => Err("Single-session Mode Not Implemented, must be encrypted.")}?,
            tacp_hdr_sesid:   u32::from_be_bytes(hdr_buf[4..8].try_into().unwrap()),  // Note: order doesn't matter as long as we're consistent
            tacp_hdr_length:  u32::from_be_bytes(hdr_buf[8..12].try_into().unwrap()), // TODO: Limits
                                                                                      // TODO: This panics
        };

        println!("Ratchet Debug: Parsed header: {:#?}", ret);
        return Ok(ret);
    }

    pub fn parse_authen_packet(&self, stream: &mut TcpStream, key: &str) -> Result<RTDecodedPacket, &str> {
        let mut md5pad = self.compute_md5_pad(key).expect("");

        let mut pck_buf = vec![0u8; self.get_expected_packet_length()];
        stream.read_exact(&mut pck_buf);
        let pck_buf = md5_xor(&pck_buf, &md5pad);

        // println!("Ratchet Debug: Decoded packet contents: {:#x?}", pck_buf);
        
        let ret = RTAuthenStartPacket::from_raw_packet(&pck_buf).unwrap();
        
        // println!("Ratchet Debug: Processed Start Packet: {:#?}", ret);
        let usn_end = RT_AUTHENTICATION_START_PACKET_INDEXES.data_len + (ret.user_len as usize);
        println!("Ratchet Debug: Remaining packet data: {:?}", String::from_utf8(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.data_len+1..usn_end].to_vec()));
        
        return Ok(RTDecodedPacket::RTAuthenPacket(RTAuthenPacket::RTAuthenStartPacket(ret)));
    }

    pub fn compute_md5_pad(&self, key: &str) -> Result<Vec<u8>, &str> {
        // Determine MD5 pad-key thing
        let mut md5ctx = md5::Context::new();
        md5ctx.consume(self.tacp_hdr_sesid.to_be_bytes());
        md5ctx.consume(key);
        md5ctx.consume(&[self.tacp_hdr_version.clone() as u8]);
        md5ctx.consume(self.tacp_hdr_seqno.to_be_bytes());

        let mut md5pad = md5ctx.compute().to_vec();
        let mut md5last: Vec<u8> = vec![];
        md5pad.clone_into(&mut md5last);

        while md5pad.len() < self.get_expected_packet_length() {
            let mut md5ctx = md5::Context::new();
            md5ctx.consume(self.tacp_hdr_sesid.to_be_bytes());
            md5ctx.consume(key);
            md5ctx.consume(&[self.tacp_hdr_version.clone() as u8]);
            md5ctx.consume(self.tacp_hdr_seqno.to_be_bytes());
            md5ctx.consume(md5last.clone());

            md5last = md5ctx.compute().to_vec();
            md5pad.append(&mut md5last);
        }

        //println!("Ratchet Debug: Computed key {:#x?}", md5pad);
        md5pad.truncate(self.get_expected_packet_length());
        return Ok(md5pad);
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RTTACVersion {
    // Always prefix with TAC_PLUS_MAJOR_VER := 0xc
    TAC_PLUS_MINOR_VER_DEFAULT = 0xc0,
    TAC_PLUS_MINOR_VER_ONE = 0xc1,
}

impl_from_byte!(RTTACVersion, 
    TAC_PLUS_MINOR_VER_DEFAULT,
    TAC_PLUS_MINOR_VER_ONE);

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RTTACType {
    TAC_PLUS_AUTHEN = 0x01, //(Authentication)
    TAC_PLUS_AUTHOR = 0x02, //(Authorization)
    TAC_PLUS_ACCT = 0x03,   //(Accounting)
}
impl_from_byte!(RTTACType, 
    TAC_PLUS_AUTHEN);

#[repr(u8)]
enum RTTACFlag {
    TAC_PLUS_UNENCRYPTED_FLAG = 0x01,    // Generate a warnings,
    TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04, // different set of behaviors, TODO: Later. https://www.rfc-editor.org/rfc/rfc8907.html#name-single-connection-mode
}

#[derive(Debug)]
pub enum RTDecodedPacket {
    RTAuthenPacket(RTAuthenPacket),
    RTAuthorPacket(RTAuthorPacket),
    RTAcctPacket(RTAcctPacket),
}

#[derive(Debug)]
pub enum RTAuthenPacket {
    RTAuthenStartPacket(RTAuthenStartPacket),
}

pub struct RTAuthenStartPacketIndexes {
    action : usize,
    priv_level : usize,
    authen_type : usize,
    authen_svc : usize,
    user_len : usize,
    port_len : usize,
    rem_addr_len : usize,
    data_len : usize,
}

const RT_AUTHENTICATION_START_PACKET_INDEXES: RTAuthenStartPacketIndexes = RTAuthenStartPacketIndexes {
    action: 0,
    priv_level: 1,
    authen_type: 2,
    authen_svc: 3,
    user_len: 4,
    port_len: 5,
    rem_addr_len: 6,
    data_len: 7,
};

#[derive(Debug)]
pub struct RTAuthenStartPacket {
    action : RTAuthenPacketAction,
    priv_lvl : u8,
    authen_type : RTAuthenPacketType,
    authen_service : RTAuthenPacketService,
    user_len : u8,
    port_len : u8,
    rem_addr_len : u8,
    data_len : u8,
    user : Vec<u8>,
    port : Vec<u8>,
    rem_addr : Vec<u8>,
    data : Vec<u8>,
}

impl std::fmt::Display for RTAuthenStartPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTAuthenStartPacket {{\n")?;
        write!(f, "    action: {:?},\n", self.action)?;
        write!(f, "    priv_lvl: {},\n", self.priv_lvl)?;
        write!(f, "    authen_type: {:?},\n", self.authen_type)?;
        write!(f, "    authen_service: {:?},\n", self.authen_service)?;
        write!(f, "    user_len: {},\n", self.user_len)?;
        write!(f, "    port_len: {},\n", self.port_len)?;
        write!(f, "    rem_addr_len: {},\n", self.rem_addr_len)?;
        write!(f, "    data_len: {},\n", self.data_len)?;
        write!(f, "    user: \"{:?}\",\n", String::from_utf8(self.user.clone()))?;
        write!(f, "    port: \"{:?}\",\n", String::from_utf8(self.port.clone()))?;
        write!(f, "    rem_addr: \"{:?}\",\n", String::from_utf8(self.rem_addr.clone()))?;
        write!(f, "    data: \"{:?}\",\n", String::from_utf8(self.data.clone()))?;
        write!(f, "}}")
    }
}

const RT_AUTH_TEXT_START: usize = RT_AUTHENTICATION_START_PACKET_INDEXES.data_len + 1;
impl RTAuthenStartPacket {
    pub fn from_raw_packet(pck_buf : &Vec<u8>) -> Result<RTAuthenStartPacket, &str> {
        let ret = RTAuthenStartPacket {
            action: RTAuthenPacketAction::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.action])?,
            priv_lvl: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.priv_level],
            authen_type: RTAuthenPacketType::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.authen_type])?,
            authen_service: RTAuthenPacketService::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.authen_svc])?,
            user_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len],
            port_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len],
            rem_addr_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.rem_addr_len],
            data_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.data_len],
            user: pck_buf[RT_AUTH_TEXT_START..   // TODO: This doesn't seem right...
                        RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize)].to_vec(),
            port: pck_buf[RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize)..
                        RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize) +
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize)].to_vec(),
            rem_addr: pck_buf[RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize) +
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize)..
                        RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize) + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize) + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.rem_addr_len] as usize)].to_vec(),     
            data: pck_buf[RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize) + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize) + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.rem_addr_len] as usize)..].to_vec(),
        };

        return Ok(ret);
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketAction {
    TAC_PLUS_AUTHEN_LOGIN = 0x01,
    TAC_PLUS_AUTHEN_CHPASS = 0x02,
    TAC_PLUS_AUTHEN_SENDAUTH = 0x04,
}
impl_from_byte!(RTAuthenPacketAction, 
    TAC_PLUS_AUTHEN_LOGIN);

#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketPriv {
    BYTE_IDX = 1,
}

#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketType {
    TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01,
    TAC_PLUS_AUTHEN_TYPE_PAP = 0x02,
    TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03,
    TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05,
    TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06,
}

impl_from_byte!(RTAuthenPacketType,
                TAC_PLUS_AUTHEN_TYPE_PAP);

#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketService {
    TAC_PLUS_AUTHEN_SVC_NONE = 0x00,
    TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01,
    TAC_PLUS_AUTHEN_SVC_ENABLE = 0x02,
    TAC_PLUS_AUTHEN_SVC_PPP = 0x03,
    TAC_PLUS_AUTHEN_SVC_PT = 0x05,
    TAC_PLUS_AUTHEN_SVC_RCMD = 0x06,
    TAC_PLUS_AUTHEN_SVC_X25 = 0x07,
    TAC_PLUS_AUTHEN_SVC_NASI = 0x08,
    TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x09,
}

impl_from_byte!(RTAuthenPacketService, 
    TAC_PLUS_AUTHEN_SVC_LOGIN);

#[derive(Debug)]
pub struct RTAuthorPacket {

}

#[derive(Debug)]
pub struct RTAcctPacket {

}

struct RTAuthenSess {
    rt_curr_seqno : u8, // 1-255, always rx odd tx even, session ends if a wrap occurs
    rt_my_sessid : u32,
}

pub fn md5_xor(msg: &Vec<u8> , pad: &Vec<u8>) -> Vec<u8> {
    // Determine the length of the shorter of the two vectors
    let len = msg.len().min(pad.len());
    
    // Create a new vector to hold the result
    let mut result = Vec::with_capacity(len);
    
    // Perform the XOR operation byte by byte
    for i in 0..len {
        result.push(msg[i] ^ pad[i]);
    }
    
    result
}