// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

//use std::{fmt, io::Read, io::Write, net::TcpStream};

use flex_alloc_secure::{ExposeProtected, alloc::SecureAlloc, boxed::ProtectedBox, flex_alloc};
use std::collections::HashMap;
use std::fmt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const TACP_HEADER_MAX_LENGTH: usize = 12; // 12 bytes.

/// This macro generates a fn, from_byte for
///  - a given u8-enum type, and
///  - list of applicable variants.
macro_rules! impl_from_byte {
    ($enum_name:ident $(,$variant:ident)+) => {
        impl $enum_name {
            pub const fn from_byte(value: u8) -> Result<Self, &'static str> {
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

/// This macro generates a fn, from_byte for
///  - a given u8-enum type, and
///  - list of applicable variants.
macro_rules! impl_global_consts {
    ($enum_name:ident $(,$variant:ident)+) => {
        $(
            const $variant: u8 = ($enum_name::$variant as u8);
        )+
    };
}

/// This represents the TACACS+ Header
#[derive(Debug)]
pub struct RTHeader {
    pub tacp_hdr_version: RTTACVersion,
    pub tacp_hdr_type: RTTACType,
    pub tacp_hdr_seqno: u8, // 1-255, always rx odd tx even, session ends if a wrap occurs
    pub tacp_hdr_flags: u8,
    pub tacp_hdr_sesid: u32, // must be CSPRNG
    pub tacp_hdr_length: u32,
}

impl RTHeader {
    /// This prepares to stream a header
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![
            self.tacp_hdr_version.clone() as u8,
            self.tacp_hdr_type.clone() as u8,
            self.tacp_hdr_seqno,
            self.tacp_hdr_flags,
        ];

        result.extend(&self.tacp_hdr_sesid.to_be_bytes());
        result.extend(&self.tacp_hdr_length.to_be_bytes());

        //println!("Ratchet Debug: Serialized header to {:#?}", result);

        result
    }

    /// For a given session number, and pre-prepared reply packet, this
    /// generates a header with appropriate metadata.
    ///
    /// TOOD: Do we want to abstract the session beyond the behaviors specified
    /// in the main loop? why?
    ///
    pub fn get_resp_header<T>(r: &T, seqno: u8, sesid: u32, version: RTTACVersion) -> Self
    where
        T: RTSerializablePacket,
    {
        #[allow(clippy::cast_possible_truncation)]
        let lt = r.pred_length();
        Self {
            tacp_hdr_version: version,
            tacp_hdr_type: r.tx_type(),
            tacp_hdr_seqno: seqno + 1,
            tacp_hdr_flags: 0, // Optionally, "NOECHO"
            tacp_hdr_sesid: sesid,
            tacp_hdr_length: lt,
        }
    }

    pub fn get_v0_header(ses: u32, r: &RTAuthenReplyPacket, cur_seq: u8) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let lt = r.serialize().len() as u32;
        let seq_no = cur_seq + 1;
        Self {
            tacp_hdr_version: RTTACVersion::TAC_PLUS_MINOR_VER_DEFAULT,
            tacp_hdr_type: RTTACType::TAC_PLUS_AUTHEN,
            tacp_hdr_seqno: seq_no,
            tacp_hdr_flags: 0,
            tacp_hdr_sesid: ses,
            tacp_hdr_length: lt,
        }
    }

    /// Implements infallible cast, commonly needed
    pub fn get_expected_packet_length(&self) -> usize {
        self.tacp_hdr_length.try_into().unwrap_or_default()
    }

    /// This pulls the header off the TCP stream
    ///
    /// This prevents ratchet from proecssing very large
    /// messages, as required by RFC8907
    ///
    pub async fn parse_init_header(stream: &mut TcpStream, cur_seq: u8) -> Result<Self, &str> {
        let mut hdr_buf: [u8; TACP_HEADER_MAX_LENGTH] = [0u8; TACP_HEADER_MAX_LENGTH];
        //println!("Ratchet Debug: Reading {} off the line", cur_seq);
        let exp_seq = cur_seq + 1;
        // TODO: this blocks.

        match stream.read_exact(&mut hdr_buf).await {
            Ok(_) => (),
            Err(e) => {
                //println!("Ratchet Error: TCP Error from subsystem: {}", e);
                return Err("Segment too short, check client implementation.");
            }
        }

        let ret = Self {
            tacp_hdr_version: RTTACVersion::from_byte(hdr_buf[0])?,
            tacp_hdr_type: RTTACType::from_byte(hdr_buf[1])?,
            tacp_hdr_seqno: (if hdr_buf[2] == exp_seq {
                Ok(exp_seq)
            } else {
                Err("Invalid initial sequence number")
            })?,
            tacp_hdr_flags: match hdr_buf[3] {
                TAC_PLUS_NULL_FLAG => Ok(0),
                _ => Err("Single-session Mode Not Implemented, must be encrypted."),
            }?,
            tacp_hdr_sesid: read_be_u32(&mut &hdr_buf[4..8])
                .map_or(Err("read_be_u32 can only process 4-slices"), Ok)?,
            tacp_hdr_length: read_be_u32(&mut &hdr_buf[8..12])
                .map_or(Err("read_be_u32 can only process 4-slices"), Ok)?,
        };

        if ret.tacp_hdr_length > 65535 {
            return Err("Client wants to send unreasonably large password or something");
        }

        //println!("Ratchet Debug: Parsed header: {:#?}", ret);
        Ok(ret)
    }

    /// This pulls the packet off the TCP stream
    ///
    /// It performs the decryption specified in the RFC.
    /// TODO: Why does peeking close the TCP socket?
    ///
    pub async fn parse_authen_packet(
        &self,
        stream: &mut TcpStream,
        key: &ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
    ) -> Result<RTDecodedPacket, &str> {
        let md5pad = self.compute_md5_pad(key);
        let mut pck_buf = vec![0u8; self.get_expected_packet_length()];
        // TODO: this blocks
        match stream.read_exact(&mut pck_buf).await {
            Ok(_) => (),
            Err(e) => {
                //println!("Ratchet Error: TCP Error from subsystem: {}", e);
                return Err("Segment too short, check client implementation.");
            }
        }

        //println!("Ratchet Debug: Comparing buf: {} and pad: {}", pck_buf.len(), md5pad.len());

        let pck_buf = md5_xor(&pck_buf, &md5pad);

        match RTAuthenStartPacket::from_raw_packet(&pck_buf) {
            Ok(r) => Ok(RTDecodedPacket::RTAuthenPacket(
                RTAuthenPacket::RTAuthenStartPacket(r),
            )),
            Err(e) => {
                // TODO: Result<Option...? hm.
                //println!("Ratchet Debug: Packet was not Start packet, trying Continue packet");
                match RTAuthenContinuePacket::from_raw_packet(&pck_buf) {
                    Ok(r) => Ok(RTDecodedPacket::RTAuthenPacket(
                        RTAuthenPacket::RTAuthenContinuePacket(r),
                    )),
                    Err(e) => {
                        //println!("Ratchet Error: Invalid packet field processed {}", e);
                        return Err("Packet field error in authentication.");
                    }
                }
            }
        }
    }

    pub async fn parse_autz_packet(
        &self,
        stream: &mut TcpStream,
        key: &ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
    ) -> Result<RTDecodedPacket, &str> {
        let md5pad = self.compute_md5_pad(key);
        let mut pck_buf = vec![0u8; self.get_expected_packet_length()];
        // TODO: this blocks
        match stream.read_exact(&mut pck_buf).await {
            Ok(_) => (),
            Err(e) => {
                //println!("Ratchet Error: TCP Error from subsystem: {}", e);
                return Err("Segment too short, check client implementation.");
            }
        }

        //println!("Ratchet Debug: Comparing buf: {} and pad: {}", pck_buf.len(), md5pad.len());

        let pck_buf = md5_xor(&pck_buf, &md5pad);

        match RTAuthorRequestPacket::from_raw_packet(&pck_buf) {
            Ok(r) => Ok(RTDecodedPacket::RTAuthorPacket(
                RTAuthorPacket::RTAuthorRequestPacket(r),
            )),
            Err(e) => {
                println!("Parse error {}", e);
                return Err("Packet field error in authentication.");
            }
        }
    }

    /// Generate the pad and truncate it to length
    ///
    /// This seems to work for the implementations checked.
    ///
    pub fn compute_md5_pad(
        &self,
        key: &ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
    ) -> Vec<u8> {
        let payload_length = self.get_expected_packet_length();
        let mut md5ctx = md5::Context::new();
        let mut md5pad = vec![];
        let mut md5last = vec![];
        key.expose_read(|inner_key| {
            md5ctx.consume(self.tacp_hdr_sesid.to_be_bytes());
            md5ctx.consume(inner_key.iter().map(|z| *z).collect::<Vec<u8>>());
            md5ctx.consume([self.tacp_hdr_version.clone() as u8]);
            md5ctx.consume(self.tacp_hdr_seqno.to_be_bytes());

            md5pad = md5ctx.compute().to_vec();
            md5last = vec![];
            md5pad.clone_into(&mut md5last);

            while md5pad.len() < payload_length {
                let mut md5ctx = md5::Context::new();
                md5ctx.consume(self.tacp_hdr_sesid.to_be_bytes());
                md5ctx.consume(inner_key.iter().map(|z| *z).collect::<Vec<u8>>());
                md5ctx.consume([self.tacp_hdr_version.clone() as u8]);
                md5ctx.consume(self.tacp_hdr_seqno.to_be_bytes());
                md5ctx.consume(md5last.clone());

                md5last = md5ctx.compute().to_vec();
                md5pad.extend(&md5last);
            }

            md5pad.truncate(payload_length);
        });

        md5pad
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RTTACVersion {
    // Always prefix with TAC_PLUS_MAJOR_VER = 0xc
    TAC_PLUS_MINOR_VER_DEFAULT = 0xc0,
    TAC_PLUS_MINOR_VER_ONE = 0xc1,
}

impl_from_byte!(
    RTTACVersion,
    TAC_PLUS_MINOR_VER_DEFAULT,
    TAC_PLUS_MINOR_VER_ONE
);

impl_global_consts!(
    RTTACVersion,
    TAC_PLUS_MINOR_VER_DEFAULT,
    TAC_PLUS_MINOR_VER_ONE
);

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RTTACType {
    TAC_PLUS_AUTHEN = 0x01, //(Authentication)
    TAC_PLUS_AUTHOR = 0x02, //(Authorization)
    TAC_PLUS_ACCT = 0x03,   //(Accounting)
}
impl_from_byte!(RTTACType, TAC_PLUS_AUTHEN, TAC_PLUS_AUTHOR);

#[allow(non_camel_case_types)]
#[repr(u8)]
enum RTTACFlag {
    TAC_PLUS_NULL_FLAG = 0x00,        // This is actually a mask flag, define 0.
    TAC_PLUS_UNENCRYPTED_FLAG = 0x01, // Generate a warnings,
    TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04, // different set of behaviors, TODO: Later. https://www.rfc-editor.org/rfc/rfc8907.html#name-single-connection-mode
}

impl_global_consts!(RTTACFlag, TAC_PLUS_NULL_FLAG);

#[derive(Debug)]
pub enum RTDecodedPacket {
    RTAuthenPacket(RTAuthenPacket),
    RTAuthorPacket(RTAuthorPacket),
    RTAcctPacket(RTAcctPacket),
}

pub trait RTSerializablePacket {
    fn serialize(&self) -> Vec<u8>;
    fn pred_length(&self) -> u32; // TODO: For performance, it would be better if we could just guess.
    fn tx_type(&self) -> RTTACType;
}

#[derive(Debug)]
pub enum RTAuthenPacket {
    RTAuthenStartPacket(RTAuthenStartPacket),
    RTAuthenReplyPacket(RTAuthenReplyPacket),
    RTAuthenContinuePacket(RTAuthenContinuePacket),
}

pub struct RTAuthenStartPacketIndexes {
    action: usize,
    priv_level: usize,
    authen_type: usize,
    authen_svc: usize,
    user_len: usize,
    port_len: usize,
    rem_addr_len: usize,
    data_len: usize,
}

const RT_AUTHENTICATION_START_PACKET_INDEXES: RTAuthenStartPacketIndexes =
    RTAuthenStartPacketIndexes {
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
    action: RTAuthenPacketAction,
    priv_lvl: u8,
    pub authen_type: RTAuthenPacketType,
    authen_service: RTAuthenPacketService,
    user_len: u8,
    port_len: u8,
    rem_addr_len: u8,
    data_len: u8,
    pub user: Vec<u8>,
    port: Vec<u8>,
    rem_addr: Vec<u8>,
    pub data: Vec<u8>,
}

impl std::fmt::Display for RTAuthenStartPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RTAuthenStartPacket {{")?;
        writeln!(f, "    action: {:?},", self.action)?;
        writeln!(f, "    priv_lvl: {},", self.priv_lvl)?;
        writeln!(f, "    authen_type: {:?},", self.authen_type)?;
        writeln!(f, "    authen_service: {:?},", self.authen_service)?;
        writeln!(f, "    user_len: {},", self.user_len)?;
        writeln!(f, "    port_len: {},", self.port_len)?;
        writeln!(f, "    rem_addr_len: {},", self.rem_addr_len)?;
        writeln!(f, "    data_len: {},", self.data_len)?;
        writeln!(
            f,
            "    user: \"{:?}\",",
            String::from_utf8(self.user.clone())
        )?;
        writeln!(
            f,
            "    port: \"{:?}\",",
            String::from_utf8(self.port.clone())
        )?;
        writeln!(
            f,
            "    rem_addr: \"{:?}\",",
            String::from_utf8_lossy(&self.rem_addr.clone())
        )?;
        writeln!(
            f,
            "    data: \"MASKED USER PASSWORD\"," /* , String::from_utf8_lossy(&self.data.clone()) */
        )?;
        writeln!(f, "}}")
    }
}

const RT_AUTH_TEXT_START: usize = RT_AUTHENTICATION_START_PACKET_INDEXES.data_len + 1;
/// This processes the decrypted Start packet
/// and implements the following checks:
///
/// - That the headers are presumably present
/// - That the headers suggest valid fields
/// - That the port and rem_addr fields are ASCII,
///    as required by the protocol spec
///
///
impl RTAuthenStartPacket {
    #[allow(clippy::indexing_slicing)]
    pub fn from_raw_packet(pck_buf: &[u8]) -> Result<Self, &str> {
        //println!("Ratchet Debug: Hey, check out this: {:#?}", String::from_utf8_lossy(pck_buf));

        // it seems risky to have the protocol do this unchecked.
        if pck_buf.len() < 8 {
            return Err("Malformed authentication packet (too short)");
        }

        let purported_size = (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize)
            + (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize)
            + (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.rem_addr_len] as usize)
            + (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.data_len] as usize)
            + 8;
        let expected_size = pck_buf.len();
        if purported_size != expected_size {
            //println!("Malformed packet size! {} {}", purported_size, expected_size);
            return Err("Malformed packet size (doesn't add up)");
        }

        // assert!(false, "The code needs to verify that the text portions (user, port, rem_addr, and pck_buf) are printables");

        let ret = Self {
            action: RTAuthenPacketAction::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.action])?,
            priv_lvl: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.priv_level],
            authen_type: RTAuthenPacketType::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.authen_type])?,
            authen_service: RTAuthenPacketService::from_byte(pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.authen_svc])?,
            user_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len],
            port_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len],
            rem_addr_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.rem_addr_len],
            data_len: pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.data_len],
            user: pck_buf[RT_AUTH_TEXT_START..

                        RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize)].to_vec(),

            port: pck_buf[RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize)..

                        RT_AUTH_TEXT_START + 
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.user_len] as usize) +
                        (pck_buf[RT_AUTHENTICATION_START_PACKET_INDEXES.port_len] as usize)].to_vec(),

            rem_addr: pck_buf[RT_AUTH_TEXT_START + //  "The rem_addr_len indicates the length of the user field, in bytes." wat
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

        // Not sure how I feel about doing this after instantiating but, it's a nitpick I think.
        if ret
            .port
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authen Start port");
        }

        if ret
            .rem_addr
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authen Start rem_addr");
        }

        Ok(ret)
    }

    /// This prepares to stream a header
    ///
    /// ⚡ Library cannot yet support a client.
    ///
    fn serialize() {
        unimplemented!();
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketAction {
    TAC_PLUS_AUTHEN_LOGIN = 0x01,
    TAC_PLUS_AUTHEN_CHPASS = 0x02,
    TAC_PLUS_AUTHEN_SENDAUTH = 0x04,
}
impl_from_byte!(RTAuthenPacketAction, TAC_PLUS_AUTHEN_LOGIN);

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketPriv {
    BYTE_IDX = 1,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenPacketType {
    TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01,
    TAC_PLUS_AUTHEN_TYPE_PAP = 0x02,
    TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03,
    TAC_PLUS_AUTHEN_TYPE_MSCHAP = 0x05,
    TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06,
}
impl_from_byte!(
    RTAuthenPacketType,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN_TYPE_ASCII
);

#[allow(non_camel_case_types)]
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
impl_from_byte!(
    RTAuthenPacketService,
    TAC_PLUS_AUTHEN_SVC_NONE,
    TAC_PLUS_AUTHEN_SVC_LOGIN
);

// RTAuthenReplyPacket
pub struct RTAuthenReplyPacketIndexes {
    status: usize,
    flags: usize,
    server_msg_len: usize,
    data_len: usize,
}

const RT_AUTHENTICATION_REPLY_PACKET_INDEXES: RTAuthenReplyPacketIndexes =
    RTAuthenReplyPacketIndexes {
        status: 0,
        flags: 1,
        server_msg_len: 2,
        data_len: 3,
    };

#[derive(Debug)]
pub struct RTAuthenReplyPacket {
    status: u8,
    flags: u8,
    server_msg_len: u16,
    data_len: u16,
    server_msg: Vec<u8>,
    data: Vec<u8>,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthenReplyStatus {
    TAC_PLUS_AUTHEN_STATUS_PASS = 0x01,
    TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02,
    TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03,
    TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04,
    TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05,
    TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06,
    TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07,
    TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21,
}

impl_global_consts!(
    RTAuthenReplyStatus,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_GETDATA,
    TAC_PLUS_AUTHEN_STATUS_GETUSER,
    TAC_PLUS_AUTHEN_STATUS_GETPASS,
    TAC_PLUS_AUTHEN_STATUS_RESTART,
    TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_FOLLOW
);

const TAC_PLUS_REPLY_FLAG_NOECHO: u8 = 0x01;

impl RTAuthenReplyPacket {
    pub fn get_getuser_packet() -> Self {
        Self {
            status: TAC_PLUS_AUTHEN_STATUS_GETUSER,
            flags: 0,
            server_msg_len: 9,
            data_len: 0,
            server_msg: "Username:".into(),
            data: vec![],
        }
    }

    pub fn get_getpass_packet() -> Self {
        Self {
            status: TAC_PLUS_AUTHEN_STATUS_GETPASS,
            flags: TAC_PLUS_REPLY_FLAG_NOECHO,
            server_msg_len: 9,
            data_len: 0,
            server_msg: "Password:".into(),
            data: vec![],
        }
    }

    pub fn get_success_packet() -> Self {
        Self {
            status: TAC_PLUS_AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg_len: 0,
            data_len: 0,
            server_msg: vec![],
            data: vec![],
        }
    }

    pub fn get_fail_packet() -> Self {
        Self {
            status: TAC_PLUS_AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg_len: 0,
            data_len: 0,
            server_msg: vec![],
            data: vec![],
        }
    }

    pub fn get_error_packet() -> Self {
        Self {
            status: TAC_PLUS_AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg_len: 66,
            data_len: 0,
            server_msg: "Unsupported Feature or Malformed Request; please see ratchet docs."
                .bytes()
                .collect(),
            data: vec![],
        }
    }
}

impl RTSerializablePacket for RTAuthenReplyPacket {
    /// This prepares to stream a response
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Serialize the fixed-size fields
        result.push(self.status);
        result.push(self.flags);
        result.extend(&self.server_msg_len.to_be_bytes());
        result.extend(&self.data_len.to_be_bytes());

        // Serialize the variable-size fields
        result.extend(&self.server_msg);
        result.extend(&self.data);

        result
    }

    fn pred_length(&self) -> u32 {
        6u32 + (self.server_msg.len() + self.data.len()) as u32
    }

    fn tx_type(&self) -> RTTACType {
        RTTACType::TAC_PLUS_AUTHEN // An RTAuthenReplyPacket is always a TAC_PLUS_AUTHEN
    }
}

// Ok so this one's easy:

// This is a standard ASCII authentication. The START packet MAY contain the username. If the user does not include the username, then the server MUST obtain it from the client with a CONTINUE TAC_PLUS_AUTHEN_STATUS_GETUSER. If the user does not provide a username, then the server can send another TAC_PLUS_AUTHEN_STATUS_GETUSER request, but the server MUST limit the number of retries that are permitted; the recommended limit is three attempts. When the server has the username, it will obtain the password using a continue with TAC_PLUS_AUTHEN_STATUS_GETPASS. ASCII login uses the user_msg field for both the username and password. The data fields in both the START and CONTINUE packets are not used for ASCII logins; any content MUST be ignored. The session is composed of a single START followed by zero or more pairs of REPLYs and CONTINUEs, followed by a final REPLY indicating PASS, FAIL, or ERROR.

#[derive(Debug)]
pub struct RTAuthenContinuePacket {
    user_msg_len: u16,
    data_len: u16,
    flags: u8,
    pub user_msg: Vec<u8>,
    data: Vec<u8>,
}

pub struct RTAuthenContPacketIndexes {
    user_msg_len: usize,
    data_len: usize,
    flags: usize,
}

const RT_AUTHENTICATION_CONT_PACKET_INDEXES: RTAuthenContPacketIndexes =
    RTAuthenContPacketIndexes {
        user_msg_len: 0,
        data_len: 2,
        flags: 4,
    };

const RT_CONT_TEXT_START: usize = RT_AUTHENTICATION_CONT_PACKET_INDEXES.flags + 1;

impl RTAuthenContinuePacket {
    pub fn from_raw_packet(pck_buf: &[u8]) -> Result<Self, &str> {
        //println!("Ratchet Debug: Hey, check out this: {:#?}", String::from_utf8_lossy(pck_buf));

        // it seems risky to have the protocol do this unchecked.
        if pck_buf.len() < 5 {
            return Err("Malformed authentication packet (too short)");
        }
        let purported_user_msg_len = read_be_u16(
            &mut &pck_buf[RT_AUTHENTICATION_CONT_PACKET_INDEXES.user_msg_len
                ..RT_AUTHENTICATION_CONT_PACKET_INDEXES.user_msg_len + 2],
        )
        .map_or(Err("read_be_u16 can only process 2-slices"), Ok)?;
        let purported_data_len = read_be_u16(
            &mut &pck_buf[RT_AUTHENTICATION_CONT_PACKET_INDEXES.data_len
                ..RT_AUTHENTICATION_CONT_PACKET_INDEXES.data_len + 2],
        )
        .map_or(Err("read_be_u16 can only process 2-slices"), Ok)?;

        let purported_size = (purported_user_msg_len as usize) + (purported_data_len as usize) + 5;
        let expected_size = pck_buf.len();

        if purported_size != expected_size {
            //println!("Malformed packet size! {} {}", purported_size, expected_size);
            return Err("Malformed packet size (doesn't add up)");
        }

        // assert!(false, "The code needs to verify that the text portions (user, port, rem_addr, and pck_buf) are printables");

        let ret = Self {
            user_msg_len: purported_user_msg_len,
            data_len: purported_data_len,
            flags: pck_buf[RT_AUTHENTICATION_CONT_PACKET_INDEXES.flags],
            user_msg: pck_buf
                [RT_CONT_TEXT_START..RT_CONT_TEXT_START + (purported_user_msg_len as usize)]
                .to_vec(),

            data: pck_buf[RT_CONT_TEXT_START + (purported_user_msg_len as usize)..].to_vec(),
        };

        // Not sure how I feel about doing this after instantiating but, it's a nitpick I think.
        if ret
            .user_msg
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authen Continue user_msg");
        }

        if ret
            .data
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authen Continue data");
        }

        Ok(ret)
    }
}

#[derive(Debug)]
pub enum RTAuthorPacket {
    RTAuthorRequestPacket(RTAuthorRequestPacket),
    RTAuthorRespPacket(RTAuthorRespPacket),
}

pub struct RTAuthorRequestPacketIndexes {
    authen_method: usize,
    priv_level: usize,
    authen_type: usize,
    authen_svc: usize,
    user_len: usize,
    port_len: usize,
    rem_addr_len: usize,
    arg_cnt: usize,
}

const RT_AUTHORIZATION_REQUEST_PACKET_INDEXES: RTAuthorRequestPacketIndexes =
    RTAuthorRequestPacketIndexes {
        authen_method: 0,
        priv_level: 1,
        authen_type: 2,
        authen_svc: 3,
        user_len: 4,
        port_len: 5,
        rem_addr_len: 6,
        arg_cnt: 7,
    };

#[derive(Debug)]
pub struct RTAuthorRequestPacket {
    authen_method: RTAuthorPacketMethod,
    priv_lvl: u8,
    pub authen_type: RTAuthenPacketType,
    authen_service: RTAuthenPacketService,
    user_len: u8,
    port_len: u8,
    rem_addr_len: u8,
    pub user: Vec<u8>,
    port: Vec<u8>,
    rem_addr: Vec<u8>,
    pub args: HashMap<String, (bool, Vec<String>)>, // "Multiple cmd-arg arguments may be specified..."
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum RTAuthorPacketMethod {
    TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00,
    TAC_PLUS_AUTHEN_METH_NONE = 0x01,
    TAC_PLUS_AUTHEN_METH_KRB5 = 0x02,
    TAC_PLUS_AUTHEN_METH_LINE = 0x03,
    TAC_PLUS_AUTHEN_METH_ENABLE = 0x04,
    TAC_PLUS_AUTHEN_METH_LOCAL = 0x05,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06,
    TAC_PLUS_AUTHEN_METH_GUEST = 0x08,
    TAC_PLUS_AUTHEN_METH_RADIUS = 0x10,
    TAC_PLUS_AUTHEN_METH_KRB4 = 0x11,
    TAC_PLUS_AUTHEN_METH_RCMD = 0x20,
}
impl_from_byte!(
    RTAuthorPacketMethod,
    TAC_PLUS_AUTHEN_METH_NOT_SET,
    TAC_PLUS_AUTHEN_METH_NONE,
    TAC_PLUS_AUTHEN_METH_KRB5,
    TAC_PLUS_AUTHEN_METH_LINE,
    TAC_PLUS_AUTHEN_METH_ENABLE,
    TAC_PLUS_AUTHEN_METH_LOCAL,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_AUTHEN_METH_GUEST,
    TAC_PLUS_AUTHEN_METH_RADIUS,
    TAC_PLUS_AUTHEN_METH_KRB4,
    TAC_PLUS_AUTHEN_METH_RCMD
);

impl RTAuthorRequestPacket {
    #[allow(clippy::indexing_slicing)]
    #[allow(non_snake_case)]
    pub fn from_raw_packet(buf: &[u8]) -> Result<Self, &str> {
        if buf.len() < 8 {
            return Err("Malformed authorization request (too short)");
        }

        let arg_cnt = buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.arg_cnt] as usize;
        if arg_cnt > 24 {
            // avoid abuse and excessive allocations
            return Err("Too many authz args");
        }

        // Tee off args_total and arg_tuples, for later use.
        // Note: since this uses the fallible version we don't need to do a forward check of buffer size
        let (args_total, arg_tuples) =
            match (0..arg_cnt).try_fold((0usize, vec![]), |(sum, mut arg_tuples), i| {
                match buf.get(8 + i) {
                    Some(&arg_len) => {
                        arg_tuples.push((sum, sum + arg_len as usize));
                        Some((sum + arg_len as usize, arg_tuples))
                    }
                    None => None,
                }
            }) {
                Some(tot) => tot,
                None => {
                    return Err("Missing args");
                }
            };

        let purported_size = 8 + 
            (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize) +
            (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len] as usize) +
            (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.rem_addr_len] as usize) +
            arg_cnt + //one for each delicious byte
            args_total;
        let expected_size = buf.len(); // buf.len() will have been selected from the header, should be guaranteed by
        if purported_size != expected_size {
            // TcpStream::read_exact, and client behavior to be the next protocol packet
            // This check guarantees that all reads directed by arg_tuples are in-bounds
            // since arg_tuples.last() == args_total
            // highest read inside of the struct below is (expected_size - 1), comparing purported_size and RT_AUTHOR_TEXT_START, RT_ARGS_TEXT_START, and args_total
            return Err("Malformed authz packet size (doesn't add up)");
        }
        let RT_AUTHOR_TEXT_START = 8 + arg_cnt;

        let RT_ARGS_TEXT_START = RT_AUTHOR_TEXT_START
            + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)
            + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len] as usize)
            + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.rem_addr_len] as usize);

        // construct argument hashmap
        let arg_hash = match arg_tuples.iter().try_fold(
            HashMap::with_capacity(arg_cnt),
            |mut h: HashMap<String, (bool, Vec<String>)>, (arg_start, arg_end)| {
                let arg_start = arg_start + RT_ARGS_TEXT_START;
                let arg_end = arg_end + RT_ARGS_TEXT_START;
                if let Some((arg_sep, arg_t, arg_v)) = // try and fetch an AVP from buffer
                    buf[arg_start..arg_end].iter().try_fold(
                        (b'\0', String::new(), String::new()),
                        |(arg_sep, mut arg_t, mut arg_v), &n| {
                            if arg_sep == b'\0' {
                                if n == b'*' || n == b'=' {
                                    Some((n, arg_t, arg_v))
                                } else {
                                    if n.is_ascii_graphic() {
                                        arg_t.push(n as char);
                                        Some((arg_sep, arg_t, arg_v))
                                    } else {
                                        None // with 3.7, A's must be ASCII printable
                                    }
                                }
                            } else {
                                if n.is_ascii_graphic() {
                                    // it is acceptable to put arg_sep into value
                                    arg_v.push(n as char);
                                    Some((arg_sep, arg_t, arg_v))
                                } else {
                                    None // with 3.7, V's must be ASCII printable
                                }
                            }
                        },
                    )
                {
                    let mandatory = arg_sep == b'=';
                    match h.get_mut(&arg_t) {
                        Some((_, vals)) => {
                            vals.push(arg_v);
                        }
                        None => {
                            h.insert(arg_t, (mandatory, vec![arg_v]));
                        }
                    }
                    Some(h)
                } else {
                    None // Any error producing an AVP propagates
                }
            },
        ) {
            Some(h) => h,
            None => {
                return Err("Args error");
            }
        };

        let re = Self {
            authen_method: RTAuthorPacketMethod::from_byte(
                buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.authen_method],
            )?,
            priv_lvl: buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.priv_level],
            authen_type: RTAuthenPacketType::from_byte(
                buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.authen_type],
            )?,
            authen_service: RTAuthenPacketService::from_byte(
                buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.authen_svc],
            )?,

            user_len: buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len],
            port_len: buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len],
            rem_addr_len: buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.rem_addr_len],
            user: buf[RT_AUTHOR_TEXT_START
                ..RT_AUTHOR_TEXT_START
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)]
                .to_vec(),

            port: buf[RT_AUTHOR_TEXT_START
                + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)
                ..RT_AUTHOR_TEXT_START
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len] as usize)]
                .to_vec(),

            rem_addr: buf[RT_AUTHOR_TEXT_START
                + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)
                + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len] as usize)
                ..RT_AUTHOR_TEXT_START
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.user_len] as usize)
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.port_len] as usize)
                    + (buf[RT_AUTHORIZATION_REQUEST_PACKET_INDEXES.rem_addr_len] as usize)]
                .to_vec(),

            args: arg_hash,
        };

        // Not sure how I feel about doing this after instantiating but, it's a nitpick I think.
        if re
            .port
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authz Req port");
        }

        if re
            .rem_addr
            .iter()
            .map(|c| c.is_ascii_control())
            .reduce(|c_1, cs| c_1 || cs)
            .unwrap_or(false)
        {
            return Err("Non-printable characters in TACACS Authz Req rem_addr");
        }

        Ok(re)
    }

    pub fn reconstruct_command(&self) -> Option<String> {
        match self.args.get("cmd") {
            Some((_, cmd_string)) => {
                let basic = cmd_string.join(" ");
                match self.args.get("cmd-arg") {
                    Some((_, arg_list)) => Some(arg_list.iter().fold(basic, |mut total, s| {
                        total.push(' ');
                        total.push_str(&s);
                        total
                    })),
                    None => Some(basic),
                }
            }
            None => None,
        }
    }
}

pub struct RTAuthorRespPacketIndexes {
    status: usize,
    arg_cnt: usize,
    srv_msg_len: usize,
    data_len: usize,
}

const RT_AUTHORIZATION_RESPONSE_PACKET_INDEXES: RTAuthorRespPacketIndexes =
    RTAuthorRespPacketIndexes {
        status: 0,
        arg_cnt: 1,
        srv_msg_len: 2,
        data_len: 4,
    };

#[derive(Debug)]
pub struct RTAuthorRespPacket {
    status: RTAuthorStatus,
    arg_cnt: u8,
    server_msg_len: u16,
    data_len: u16,
    server_msg: Vec<u8>,
    data: Vec<u8>,
    args: HashMap<String, Vec<u8>>,
}

impl RTSerializablePacket for RTAuthorRespPacket {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Serialize the fixed-size fields
        result.push(self.status.clone() as u8);
        result.push(self.arg_cnt);
        result.extend(&self.server_msg_len.to_be_bytes());
        result.extend(&self.data_len.to_be_bytes());

        // Serialize the variable-size fields
        result.extend(&self.server_msg);
        result.extend(&self.data);

        // TODO: special considerations for PASS_REPL, ERROR, FOLLOW

        result
    }

    fn pred_length(&self) -> u32 {
        6u32 + (self.server_msg.len() + self.data.len()) as u32
    }

    fn tx_type(&self) -> RTTACType {
        RTTACType::TAC_PLUS_AUTHOR
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum RTAuthorStatus {
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01,
    TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02,
    TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10,
    TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11,
    TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21,
}
impl_from_byte!(
    RTAuthorStatus,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_ERROR,
    TAC_PLUS_AUTHOR_STATUS_FOLLOW
);

impl RTAuthorRespPacket {
    pub fn get_error_packet() -> Self {
        Self {
            status: RTAuthorStatus::TAC_PLUS_AUTHOR_STATUS_ERROR,
            arg_cnt: 0,
            server_msg_len: 66,
            data_len: 0,
            server_msg: "Unsupported Feature or Malformed Request; please see ratchet docs."
                .bytes()
                .collect(),
            data: vec![],
            args: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct RTAcctPacket {}

pub struct RTAuthenSess<'a> {
    rt_curr_seqno: u8, // 1-255, always rx odd tx even, session ends if a wrap occurs
    rt_my_sessid: u32,
    rt_my_version: RTTACVersion,
    rt_key: &'a ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
}

impl<'a> RTAuthenSess<'a> {
    pub fn from_header(
        r: &RTHeader,
        key: &'a ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
    ) -> Self {
        Self {
            rt_curr_seqno: r.tacp_hdr_seqno,
            rt_my_sessid: r.tacp_hdr_sesid,
            rt_my_version: r.tacp_hdr_version.clone(),
            rt_key: key,
        }
    }

    pub fn next_header<T>(&mut self, reply: &T) -> RTHeader
    where
        T: RTSerializablePacket,
    {
        return RTHeader::get_resp_header(
            reply,
            self.rt_curr_seqno,
            self.rt_my_sessid,
            self.rt_my_version.clone(),
        );
    }

    /// This serves multiple purposes
    /// When processing ASCII authentication typical behavior only optionally includes
    /// the username in the first packet.
    ///
    /// So at the protocol level, first we request the username,
    /// then we request the password.
    ///
    pub async fn do_get(
        &mut self,
        mut stream: &mut TcpStream,
        get_user_packet: RTAuthenReplyPacket,
    ) -> Result<String, &str> {
        // TODO: Refactor this mantra into a neatly architected thingamajig
        //   ... maybe the 'outermost' detail needed is the session info (i.e., expected pack number, expected sesid), so
        //   ... it should be a part of a session implementation for the full transaction.
        let user_resp_hdr = self.next_header(&get_user_packet);
        //println!("Ratchet Debug: {:#?}", user_resp_hdr);
        //println!("Ratchet Debug: {:#?}", get_user_packet);
        let pad = user_resp_hdr.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&get_user_packet.serialize(), &pad);
        let mut msg = user_resp_hdr.serialize();
        msg.append(&mut payload);

        //println!("{:?}", msg);
        // TODO: This blocks
        match stream.write(&msg).await {
            Ok(v) => {
                if self.inc_seqno().is_err() {
                    return Err("Wrapped sequence number, restart single-session");
                }
                //println!("Ratchet Debug: Sent {} bytes", v)
            }
            Err(e) => {
                return Err("Broken pipe");
                //println!("Ratchet Error: TCP Error, {}", e),
            }
        }

        // TODO: Ok... session loop is starting over...? Not really it's a sequence .... hmmmmmmmmm...
        let user_hdr: RTHeader =
            match RTHeader::parse_init_header(&mut stream, self.rt_curr_seqno).await {
                Ok(h) => {
                    //println!("Ratchet Debug: Processed {:#?}", h);
                    if self.inc_seqno().is_err() {
                        return Err("Wrapped sequence number, restart single-session");
                    }
                    h
                }
                Err(e) => {
                    //println!("Ratchet Error: {}", e);
                    self.send_error_packet(&mut stream).await;
                    return Err("Bad header from client");
                }
            };

        let user_contents = match user_hdr.tacp_hdr_type {
            RTTACType::TAC_PLUS_AUTHEN => {
                user_hdr.parse_authen_packet(&mut stream, self.rt_key).await
            }
            RTTACType::TAC_PLUS_AUTHOR => {
                //println!("Ratchet Debug: Not Implemented");
                self.send_error_packet(&mut stream).await;
                return Err("Unexpected Authorization reply from client");
            }
            RTTACType::TAC_PLUS_ACCT => {
                //println!("Ratchet Debug: Not Implemented");
                self.send_error_packet(&mut stream).await;
                return Err("Unexpected Accounting reply from client");
            }
        };

        let decoded_user: RTDecodedPacket = match user_contents {
            Err(e) => {
                //println!("Ratchet Error: {}", e);
                self.send_error_packet(&mut stream).await;
                return Err("Invalid data passed in GetUser body");
            }
            Ok(d) => {
                //println!("Ratchet Debug: Processed {:#?}", d);
                d
            }
        };

        //println!("Ratchet Debug: Deciding on decoded user packet");
        match decoded_user {
            RTDecodedPacket::RTAuthenPacket(rtauthen_user_packet) => {
                //println!("Ratchet Debug: Was authen packet, checking for Continue");
                match rtauthen_user_packet {
                    RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => Ok(
                        String::from_utf8_lossy(&rtauthen_continue_packet.user_msg.clone())
                            .to_string(),
                    ),
                    _ => {
                        //println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence");
                        self.send_error_packet(&mut stream).await;
                        return Err("Invalid data passed in GetUser body");
                    }
                }
            }
            _ => {
                //println!("Ratchet Error: Non authen packet in Authen sequence");
                //println!("Ratchet Error: Unexpected packet type in ASCII Authentication sequence");
                self.send_error_packet(&mut stream).await;
                return Err("Invalid data passed in GetUser body");
            }
        }
    }

    pub async fn send_final_packet(
        &mut self,
        stream: &mut TcpStream,
        generic_error: RTAuthenReplyPacket,
    ) -> Result<bool, &str> {
        let generic_error_header: RTHeader = self.next_header(&generic_error);

        let pad = generic_error_header.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&generic_error.serialize(), &pad);
        let mut msg = generic_error_header.serialize();
        msg.append(&mut payload);
        // It's just a header, it shouldn't reveal anything interesting.
        match stream.write(&msg).await {
            Ok(v) => {
                //println!("Ratchet Debug: Sent {} bytes", v);
                if self.inc_seqno().is_err() {
                    return Err("Wrapped sequence number, restart single-session");
                }
                Ok(true)
            }
            Err(e) => {
                //println!("Ratchet Error: TCP Error, {}", e);
                Err("Bad TCP Session")
            }
        }
    }

    pub async fn send_error_packet(&mut self, stream: &mut TcpStream) -> bool {
        let generic_error = RTAuthenReplyPacket::get_error_packet();
        let generic_error_header: RTHeader = self.next_header(&generic_error);

        let pad = generic_error_header.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&generic_error.serialize(), &pad);
        let mut msg = generic_error_header.serialize();
        msg.append(&mut payload);
        // It's just a header, it shouldn't reveal anything interesting.
        match stream.write(&msg).await {
            Ok(v) => {
                //println!("Ratchet Debug: Sent {} bytes", v);
                if self.inc_seqno().is_err() {
                    return false;
                }
                true
            }
            Err(e) => {
                //println!("Ratchet Error: TCP Error, {}", e);
                false
            }
        }
    }

    fn inc_seqno(&mut self) -> Result<bool, &str> {
        if self.rt_curr_seqno == 255 {
            return Err("Session restart");
        } else {
            self.rt_curr_seqno += 1;
            return Ok(true);
        }
    }
}

pub struct RTAutzSess<'a> {
    rt_curr_seqno: u8, // 1-255, always rx odd tx even, session ends if a wrap occurs
    rt_my_sessid: u32,
    rt_my_version: RTTACVersion,
    rt_key: &'a ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
}

impl<'a> RTAutzSess<'a> {
    pub fn from_header(
        r: &RTHeader,
        key: &'a ProtectedBox<flex_alloc::vec::Vec<u8, SecureAlloc>>,
    ) -> Self {
        Self {
            rt_curr_seqno: r.tacp_hdr_seqno,
            rt_my_sessid: r.tacp_hdr_sesid,
            rt_my_version: r.tacp_hdr_version.clone(),
            rt_key: key,
        }
    }

    pub fn next_header<T>(&mut self, reply: &T) -> RTHeader
    where
        T: RTSerializablePacket,
    {
        return RTHeader::get_resp_header(
            reply,
            self.rt_curr_seqno,
            self.rt_my_sessid,
            self.rt_my_version.clone(),
        );
    }

    pub async fn send_success_packet(&mut self, stream: &mut TcpStream) -> Result<bool, &str> {
        let generic_authz_success = RTAuthorRespPacket {
            status: RTAuthorStatus::TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            arg_cnt: 0,
            server_msg_len: 0,
            data_len: 0,
            server_msg: vec![],
            data: vec![],
            args: HashMap::new(),
        };
        let generic_succ_header: RTHeader = self.next_header(&generic_authz_success);

        let pad = generic_succ_header.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&generic_authz_success.serialize(), &pad);
        let mut msg = generic_succ_header.serialize();
        msg.append(&mut payload);
        // It's just a header, it shouldn't reveal anything interesting.
        match stream.write(&msg).await {
            Ok(v) => {
                //println!("Ratchet Debug: Sent {} bytes", v);
                if self.inc_seqno().is_err() {
                    return Err("Wrapped sequence number, restart single-session");
                }
                Ok(true)
            }
            Err(e) => {
                //println!("Ratchet Error: TCP Error, {}", e);
                Err("Bad TCP Session")
            }
        }
    }

    pub async fn send_failure_packet(&mut self, stream: &mut TcpStream) -> Result<bool, &str> {
        let generic_authz_fail = RTAuthorRespPacket {
            status: RTAuthorStatus::TAC_PLUS_AUTHOR_STATUS_FAIL,
            arg_cnt: 0,
            server_msg_len: 0,
            data_len: 0,
            server_msg: vec![],
            data: vec![],
            args: HashMap::new(),
        };
        let generic_fail_header: RTHeader = self.next_header(&generic_authz_fail);

        let pad = generic_fail_header.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&generic_authz_fail.serialize(), &pad);
        let mut msg = generic_fail_header.serialize();
        msg.append(&mut payload);
        // It's just a header, it shouldn't reveal anything interesting.
        match stream.write(&msg).await {
            Ok(v) => {
                //println!("Ratchet Debug: Sent {} bytes", v);
                if self.inc_seqno().is_err() {
                    return Err("Wrapped sequence number, restart single-session");
                }
                Ok(true)
            }
            Err(e) => {
                //println!("Ratchet Error: TCP Error, {}", e);
                Err("Bad TCP Session")
            }
        }
    }

    pub async fn send_error_packet(&mut self, stream: &mut TcpStream) -> bool {
        let generic_error = RTAuthorRespPacket::get_error_packet();
        let generic_error_header: RTHeader = self.next_header(&generic_error);

        let pad = generic_error_header.compute_md5_pad(self.rt_key);
        let mut payload = md5_xor(&generic_error.serialize(), &pad);
        let mut msg = generic_error_header.serialize();
        msg.append(&mut payload);
        // It's just a header, it shouldn't reveal anything interesting.
        match stream.write(&msg).await {
            Ok(v) => {
                //println!("Ratchet Debug: Sent {} bytes", v);
                if self.inc_seqno().is_err() {
                    return false;
                }
                true
            }
            Err(e) => {
                //println!("Ratchet Error: TCP Error, {}", e);
                false
            }
        }
    }

    fn inc_seqno(&mut self) -> Result<bool, &str> {
        if self.rt_curr_seqno == 255 {
            return Err("Session restart");
        } else {
            self.rt_curr_seqno += 1;
            return Ok(true);
        }
    }
}

#[allow(clippy::indexing_slicing)]
/// Uses a TACACS+ MD5 pad to obfuscate or deobfuscate a message
///
/// ⚡ This won't work if you call it without a proper pad.
///
pub fn md5_xor(msg: &[u8], pad: &[u8]) -> Vec<u8> {
    // Create a new vector to hold the result
    let mut result = Vec::with_capacity(msg.len());

    // Perform the XOR operation byte by byte
    for i in 0..msg.len() {
        result.push(msg[i] ^ pad[i % pad.len()]);
    }

    result
}

/// This is from an example provided in the Rust std docs.
///
/// ⚡ The length of any slice passed must be 4.
///
/// ```
/// assert_eq!(4, std::mem::size_of::<u32>());
/// ```
///
fn read_be_u32<'a>(input: &'a mut &'a [u8]) -> Result<u32, &'a str> {
    if input.len() < 4 {
        return Err("read_be_u32 can only process 4-slices");
    }
    let (int_bytes, rest) = input.split_at(4);
    *input = rest;
    #[allow(clippy::unwrap_used)]
    Ok(u32::from_be_bytes(int_bytes.try_into().unwrap()))
}

/// This is from an example provided in the Rust std docs.
///
/// ⚡ The length of any slice passed must be 2.
///
/// ```
/// assert_eq!(2, std::mem::size_of::<u16>());
/// ```
///
fn read_be_u16<'a>(input: &'a mut &'a [u8]) -> Result<u16, &'a str> {
    if input.len() < 2 {
        return Err("read_be_u32 can only process 4-slices");
    }
    let (int_bytes, rest) = input.split_at(2);
    *input = rest;
    #[allow(clippy::unwrap_used)]
    Ok(u16::from_be_bytes(int_bytes.try_into().unwrap()))
}
