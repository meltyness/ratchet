// RATCHET
//
// A rust implementation of a TACACS+ Protocol "server"
// as defined by RFC8907 and related.
//
// (C) 2024 - T.J. Hampton
//

use core::str;

use std::iter;
// benchmarking
use std::process::exit;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use flex_alloc_secure::ExposeProtected;
use flex_alloc_secure::alloc::SecureAlloc;
use flex_alloc_secure::boxed::ProtectedBox;
use flex_alloc_secure::vec::SecureVec;

use precis_profiles::UsernameCasePreserved;
use precis_profiles::precis_core::profile::Profile;

use pwhash::bcrypt;

use ratchet::RTAuthenPacket;
use ratchet::RTAuthenReplyPacket;
use ratchet::RTAuthenSess;
use ratchet::RTAutzSess;
use ratchet::RTDecodedPacket;
use ratchet::RTHeader;
use ratchet::RTTACType;

use std::array;
use std::collections::HashMap;
use std::env;
use std::io::Read;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::timeout;

struct RTServerSettings<'a> {
    rt_server_max_length: u32, // = 65535, // https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-18
    rt_server_i18n: bool,
    rt_perf_bench: bool,
    rt_server_read_clients: &'a str,
    rt_server_read_creds: &'a str,
    rt_server_long_poll: &'a str,
    rt_server_user_cmd_policy: &'a str,
}

impl<'a> RTServerSettings<'a> {
    fn new(
        rt_server_max_length: u32,
        rt_server_i18n: bool,
        rt_perf_bench: bool,
        rt_server_read_clients: &'a str,
        rt_server_read_creds: &'a str,
        rt_server_long_poll: &'a str,
        rt_server_user_cmd_policy: &'a str,
    ) -> Self {
        Self {
            rt_server_max_length,
            rt_server_i18n,
            rt_perf_bench,
            rt_server_read_clients,
            rt_server_read_creds,
            rt_server_long_poll,
            rt_server_user_cmd_policy,
        }
    }
}

struct RTKnownClient {}
/// validated to only contain execution-permissible outcomes
#[derive(Debug)]
struct RTPolicy(Vec<RTPolicyEntry>);
/// validated to only contain logging-permissible outcomes
#[derive(Debug)]
struct RTLoggingPolicy(Vec<RTPolicyEntry>);
#[derive(Clone, Debug)]
struct RTPolicyEntry {
    precedence: usize,
    outcome: RTPolicyOutcome,
    criteria: RTPolicyCriteria,
}

#[derive(Clone, Copy, Debug)]
enum RTPolicyOutcome {
    Permit,
    Reject,
    Silence,
}
#[derive(Clone, Debug)]
enum RTPolicyCriteria {
    BeginsWith(String),
    EndsWith(String),
    Contains(String),
}

impl RTPolicy {
    pub fn do_match(&self, cmd: &str) -> Option<(usize, RTPolicyOutcome)> {
        match self.0.iter().zip(iter::repeat(cmd)).find(process_criteria) {
            Some((entry, _)) => Some((entry.precedence, entry.outcome)),
            None => None,
        }
    }
}

fn process_criteria<'a>((crit, cmd): &'a (&RTPolicyEntry, &str)) -> bool {
    match &crit.criteria {
        RTPolicyCriteria::BeginsWith(pfx) => cmd.starts_with(pfx),
        RTPolicyCriteria::EndsWith(sfx) => cmd.ends_with(sfx),
        RTPolicyCriteria::Contains(ifx) => cmd.contains(ifx),
    }
}

// benchmarking
static RUNS: AtomicU64 = AtomicU64::new(0);
//static mut RUNNING_AVG: f64 = 0.0;
static mut FIRST_RUN: Option<Instant> = None;
static GUTTER: std::sync::LazyLock<Arc<RwLock<String>>> = std::sync::LazyLock::new(|| Arc::new(RwLock::new(String::new())));

/// Entry point for ratchet:
///
/// Broadly:
/// Obtain User Creds list, TACACS+ Clients list from pre-specified commands,
/// or flags from tests.
///
/// Currently only configurable is `--ignore-i18n` which may improve performance
/// a tad. See README for details about environment variables to obtains creds/clients.
///  
pub fn main() {
    println!("Ratchet Info: starting...");

    let mut server_settings = RTServerSettings::new(
        65535,
        true,
        false,
        "cat /dev/null",
        "cat /dev/null",
        "sleep inf",
        "echo",
    );

    // These form the primary config data of the server
    // Authorization policy, Authentication credentials
    let mut credentials: HashMap<String, String> = HashMap::new();
    let mut clients_v4: [HashMap<u32, ProtectedBox<SecureVec<u8>>>; 33] =
        array::from_fn(|_| HashMap::new());
    let mut clients_v6: [HashMap<u128, ProtectedBox<SecureVec<u8>>>; 129] =
        array::from_fn(|_| HashMap::new());
    let mut user_cmd_policy: HashMap<String, RTPolicy> = HashMap::new();

    let mut custom_clients_cmd = String::new();
    let mut custom_creds_cmd = String::new(); // Use String instead of &str
    let mut custom_long_poll_cmd = String::new();
    let mut custom_hostport = String::from("[::]:44449");
    let mut custom_user_cmd_policy_cmd = String::new();
    for (key, value) in env::vars() {
        if key == "RATCHET_READ_CLIENTS" {
            custom_clients_cmd = value; // Directly assign the value
        } else if key == "RATCHET_READ_CREDS" {
            custom_creds_cmd = value; // Directly assign the value
        } else if key == "RATCHET_CUST_HOSTPORT" {
            custom_hostport = value; // Directly assign the value
        } else if key == "RATCHET_LONG_POLL" {
            custom_long_poll_cmd = value;
        } else if key == "RATCHET_USER_CMD_POLICY" {
            custom_user_cmd_policy_cmd = value;
        }
    }

    if !custom_clients_cmd.is_empty() {
        server_settings.rt_server_read_clients = custom_clients_cmd.as_str(); // Use the String here

        // Use the configured command to obtain creds.
        rt_obtain_clients(
            server_settings.rt_server_read_clients,
            &mut clients_v4,
            &mut clients_v6,
        );
    }

    if !custom_creds_cmd.is_empty() {
        server_settings.rt_server_read_creds = custom_creds_cmd.as_str(); // Use the String here

        // Use the configured command to obtain creds.
        rt_obtain_creds(
            server_settings.rt_server_read_creds,
            &mut credentials,
            server_settings.rt_server_i18n,
        );
    }

    if !custom_long_poll_cmd.is_empty() {
        server_settings.rt_server_long_poll = custom_long_poll_cmd.as_str();
    }

    if !custom_user_cmd_policy_cmd.is_empty() {
        server_settings.rt_server_user_cmd_policy = custom_user_cmd_policy_cmd.as_str();

        rt_obtain_user_policy_terms(
            server_settings.rt_server_user_cmd_policy,
            &mut user_cmd_policy,
            server_settings.rt_server_i18n,
        );
    }

    if env::args().any(|x| x == *"--add-insecure-test-credential-do-not-use".to_string()) {
        credentials.insert(
            "username".to_string(),
            "$2b$05$iE0X0t4n0Ag8pGR0o6zqn.qBZt9reoIOHAajI1NQNZOun0Mc57uuG".to_string(),
        );
        rt_obtain_clients(
            "echo 127.0.0.1,testing123",
            &mut clients_v4,
            &mut clients_v6,
        );
    }

    if env::args().any(|x| x == *"--add-basic-db-test-do-not-use".to_string()) {
        rt_obtain_creds(
            "echo 'user1,extremely_secure_pass\nuser2,$2b$05$OIBXZUqfOWT2SHyShytLD.Qwk/XsBJTxFypqvKdfjE2sj5N7SDapC\nuser3,awesome_password'",
            &mut credentials,
            server_settings.rt_server_i18n,
        );
        rt_obtain_clients(
            "echo 127.0.0.1,testing123",
            &mut clients_v4,
            &mut clients_v6,
        );
    }

    if env::args().any(|x| x == *"--add-huge-wildcard-test-do-not-use".to_string()) {
        credentials.insert(
            "username".to_string(),
            "$2b$05$iE0X0t4n0Ag8pGR0o6zqn.qBZt9reoIOHAajI1NQNZOun0Mc57uuG".to_string(),
        );
        rt_obtain_clients(
            "echo 0.0.0.0/0,testing123",
            &mut clients_v4,
            &mut clients_v6,
        );
    }

    if env::args().any(|x| x == *"--ignore-i18n".to_string()) {
        server_settings.rt_server_i18n = false;
    }

    // XXX: Using --perf-bench-test-do-not-use disables authentication, effectively.
    if env::args().any(|x| x == *"--perf-bench-test-do-not-use".to_string()) {
        server_settings.rt_perf_bench = true;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio_main(
                custom_hostport,
                credentials,
                clients_v4,
                clients_v6,
                user_cmd_policy,
                server_settings,
            )
            .await;
        })
}

/// Main server loop,
/// - Listens on specified hostport
/// - Dispatches threads on new connections, killed after 30s
/// - Mediates shared access to clients, users, creds
///
///  # Panics
///
/// Panics if the server cannot open on the specified hostaddr
///
async fn tokio_main(
    custom_hostport: String,
    credentials: HashMap<String, String>,
    clients_v4: [HashMap<u32, ProtectedBox<SecureVec<u8>>>; 33],
    clients_v6: [HashMap<u128, ProtectedBox<SecureVec<u8>>>; 129],
    user_cmd_policy: HashMap<String, RTPolicy>,
    server_settings: RTServerSettings<'_>,
) {
    rt_generate_gutter().await;

    let listener = match TcpListener::bind(custom_hostport.as_str()).await {
        Ok(l) => l,
        #[allow(clippy::panic)] // this is definitely fatal for a server.
        Err(e) => panic!(
            "Ratchet Error: {} check permissions for user: {:#?}.",
            e,
            rt_get_system_user_name()
        ),
    };
    // CONTRACT: cargo tests use 'NOWLISTENING' in order to validate server readiness
    println!("Ratchet Info: NOWLISTENING bound to some port 49");

    // benchmarking
    if server_settings.rt_perf_bench {
        println!("Ratchet Warning: Benchmarking enabled, bypassing credential authentication");
        unsafe {
            ctrlc::set_handler(move || {
                //println!("Ratchet Debug: Average dispatch time over {} RUNS: {:#?}", rt_get_runs(), Duration::from_secs_f64(rt_get_avg() / rt_get_runs()));
                println!("Ratchet Debug: total rate: {} RUNS / sec", RUNS.load(atomic::Ordering::Relaxed) as f64 / (Instant::now() - FIRST_RUN.unwrap()).as_secs_f64());
                exit(0);
            })
            .expect("Ratchet Fatal: Error setting Ctrl-C handler");
        }
    }

    // Long-polling needs to update these on user/API-initiated changes
    // TODO: Migrate to something like dashmap to optimize
    let credentials_container = Arc::new(RwLock::new(credentials));
    let clients_v4_container = Arc::new(RwLock::new(clients_v4));
    let clients_v6_container = Arc::new(RwLock::new(clients_v6));
    let user_policy_container = Arc::new(RwLock::new(user_cmd_policy));

    let pollv4_clients = clients_v4_container.clone();
    let pollv6_clients = clients_v6_container.clone();
    let poll_creds = credentials_container.clone();
    let poll_user_policy = user_policy_container.clone();

    rt_launch_long_polling_process(
        server_settings.rt_server_i18n,
        server_settings.rt_server_read_clients.to_string(),
        server_settings.rt_server_read_creds.to_string(),
        server_settings.rt_server_user_cmd_policy.to_string(),
        server_settings.rt_server_long_poll.to_string(),
        poll_creds,
        pollv4_clients,
        pollv6_clients,
        poll_user_policy,
    );

    loop {
        let stream = listener.accept().await;

        // benchmarking
        if server_settings.rt_perf_bench {
            let start_time = Instant::now();
            unsafe {
                let _ = RUNS.fetch_update(atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |a| Some(a+1));
                match FIRST_RUN {
                    Some(_) => (),
                    None => FIRST_RUN = Some(start_time.clone()),
                }
            }
        }

        let clients_v4_container = clients_v4_container.clone();
        let clients_v6_container = clients_v6_container.clone();
        let credentials_container = credentials_container.clone();
        let user_policy_container = user_policy_container.clone();
        //
        tokio::spawn(timeout(Duration::from_millis(60100), async move {
            // Stage 0: Check that this is a valid stream, produce some logs about the event.
            let mut stream = match stream {
                Ok((s, peer_addr)) => {
                    // TODO: Collect this into session info so that the following diagnostic logs can be associated
                    //println!("Ratchet Debug: Received connection request from {}",peer_addr);

                    // This shouldn't be bandwidth-intensive enough, prefer latency optimization and disable Nagle's
                    match s.set_nodelay(true) {
                        Ok(_) => (),
                        Err(_) => {
                            //println!("Ratchet Debug: Couldn't disable Nagles for this Socket, proceeding anyway.");
                        }
                    };

                    s // hand over the TcpStream
                }
                Err(e) => {
                    println!("Ratchet Error: TCP Error, {}", e);
                    return;
                }
            };

            // Stage 0.5: Determine if this is a client
            // TODO: completely encapsulate this into the session eventually...
            let v4_binding = clients_v4_container.read().await;
            let v6_binding = clients_v6_container.read().await;
            let session_key = match rt_fetch_secret(
                &stream.peer_addr().unwrap().ip(),
                &v4_binding,
                &v6_binding,
            ) {
                Ok(s) => {
                    //println!("Ratchet Debug: Again found client, OK {:?}", s);
                    s
                }
                Err(e) => {
                    println!("Ratchet Warning: Unknown client, {:#?}", stream.peer_addr());
                    return;
                }
            };

            let mut secret_is_blank = true;

            session_key.expose_read(|thing| secret_is_blank = thing.len() == 0);

            if secret_is_blank {
                println!("Ratchet Warning: Unknown client, {:#?}", stream.peer_addr());
                return;
            }

            // Stage 1: Parse header, establish session
            let hdr: RTHeader = match RTHeader::parse_init_header(&mut stream, 0).await {
                Ok(h) => {
                    //println!("Ratchet Debug: Processed {:#?}", h);
                    h
                }
                Err(e) => {
                    println!("Ratchet Error: {}", e);
                    //authen_sess.send_error_packet( &mut stream);
                    return;
                }
            };

            // Stage 2: Parse packet, perform appropriate treatment
            let contents = match hdr.tacp_hdr_type {
                RTTACType::TAC_PLUS_AUTHEN => {
                    hdr.parse_authen_packet(&mut stream, session_key).await
                }
                RTTACType::TAC_PLUS_AUTHOR => {
                    //println!("Ratchet Debug: Processing authz request");
                    hdr.parse_autz_packet(&mut stream, session_key).await
                }
                RTTACType::TAC_PLUS_ACCT => {
                    //println!("Ratchet Debug: Not Implemented");
                    let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                    temp_sess.send_error_packet(&mut stream).await;
                    return;
                }
            };

            let decoded: RTDecodedPacket = match contents {
                Err(e) => {
                    println!("Ratchet Error: {}", e);
                    let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                    temp_sess.send_error_packet(&mut stream).await;
                    return;
                }
                Ok(d) => {
                    //println!("Ratchet Debug: Processed {:#?}", d);
                    d
                }
            };

            // Stage 3: Decide what stuff to do depending on the type of packet.
            match decoded {
                RTDecodedPacket::RTAuthenPacket(ap) => match ap {
                    RTAuthenPacket::RTAuthenStartPacket(asp) => {
                        match asp.authen_type {
                            ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_ASCII => {
                                //println!("Ratchet Debug: Decoded: {}", asp);
                                let mut authen_sess = RTAuthenSess::from_header(&hdr, session_key);
                                // (sort of) Authenticate the server before putting a cred on the line
                                //let mut retries = 0;

                                // Stage 1: Fetch the Username
                                let obtained_username = if asp.user.len() == 0 {
                                    // have to fetch username
                                    match authen_sess
                                        .do_get(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_getuser_packet(),
                                        )
                                        .await
                                    {
                                        Ok(u) => u,
                                        Err(_) => {
                                            authen_sess.send_error_packet(&mut stream).await;
                                            return;
                                        }
                                    }
                                } else {
                                    String::from_utf8_lossy(&asp.user).to_string()
                                };

                                // no retries.
                                if obtained_username.len() == 0 {
                                    // buzz off
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_fail_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent failure packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                    return;
                                }

                                // Stage 2: Fetch the Password
                                // TODO: Everybody gets one
                                let obtained_password = match authen_sess
                                    .do_get(&mut stream, RTAuthenReplyPacket::get_getpass_packet())
                                    .await
                                {
                                    Ok(u) => u,
                                    Err(_) => {
                                        authen_sess.send_error_packet(&mut stream).await;
                                        return;
                                    }
                                };

                                if obtained_password.len() == 0 || obtained_username.len() == 0 {
                                    // buzz off
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_fail_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent failure packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                    return;
                                }
                                let username_case_preserved: UsernameCasePreserved =
                                    UsernameCasePreserved::new();
                                let raw_username = obtained_username;
                                let auth_request_password = obtained_password;
                                let mut user_authenticated = false;

                                //println!("Ratchet Debug: Looking up {}", raw_username);

                                let username = match rt_fetch_precis_username(
                                    &raw_username.into_bytes(),
                                    server_settings.rt_server_i18n,
                                ) {
                                    Ok(u) => u,
                                    Err(e) => {
                                        println!("Ratchet Error: Invalid username passed.");
                                        authen_sess.send_error_packet(&mut stream).await;
                                        return;
                                    }
                                };

                                let creds = credentials_container.read().await;
                                if let Some(p) = creds.get(&username.to_string()) {
                                    // User known, check authentication success.
                                    //println!("Ratchet Debug: Found user with credential, for {:#?}!",username);
                                    user_authenticated = bcrypt::verify(auth_request_password, p);
                                } else {
                                    //println!("Ratchet Debug: Couldn't find {:#?}, check username",username);
                                    // user who? user not authenticated!
                                    bcrypt::verify(auth_request_password, &GUTTER.read().await);
                                }

                                if user_authenticated {
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_success_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent success packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                } else {
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_fail_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent failure packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                }
                            }
                            ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_PAP => {
                                println!("Ratchet Info: Decoded: {}", asp);
                                let mut authen_sess = RTAuthenSess::from_header(&hdr, session_key);
                                let auth_request_password = String::from_utf8_lossy(&asp.data);
                                let mut user_authenticated = false;

                                let username = match rt_fetch_precis_username(
                                    &asp.user,
                                    server_settings.rt_server_i18n,
                                ) {
                                    Ok(u) => u,
                                    Err(e) => {
                                        println!("Ratchet Error: Invalid username passed.");
                                        authen_sess.send_error_packet(&mut stream).await;
                                        return;
                                    }
                                };

                                let creds = credentials_container.read().await;
                                if let Some(p) = creds.get(&username.to_string()) {
                                    // User known, check authentication success.
                                    //println!("Ratchet Debug: Found user with credential, for {:#?}!",username);
                                    user_authenticated = bcrypt::verify(&*auth_request_password, p);
                                } else {
                                    //println!("Ratchet Debug: Couldn't find {:#?}, check username",username);
                                    // user who? user not authenticated!
                                    bcrypt::verify(&*auth_request_password, &GUTTER.read().await);
                                }

                                if user_authenticated {
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_success_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent success packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                } else {
                                    match authen_sess
                                        .send_final_packet(
                                            &mut stream,
                                            RTAuthenReplyPacket::get_fail_packet(),
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            //println!("Ratchet Debug: Sent failure packet");
                                        }
                                        Err(e) => {
                                            println!("Ratchet Error: TCP Error, {}", e);
                                        }
                                    }
                                }
                            }
                            ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_CHAP => {
                                println!("Unknown Packet Format");
                                let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                                temp_sess.send_error_packet(&mut stream).await;
                                return;
                            }
                            ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAP => {
                                println!("Unknown Packet Format");
                                let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                                temp_sess.send_error_packet(&mut stream).await;
                                return;
                            }
                            ratchet::RTAuthenPacketType::TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 => {
                                println!("Unknown Packet Format");
                                let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                                temp_sess.send_error_packet(&mut stream).await;
                                return;
                            }
                        }
                    }
                    RTAuthenPacket::RTAuthenReplyPacket(rtauthen_reply_packet) => {
                        println!("Ratchet Error: umm... no, I'M the server.");
                        let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                        temp_sess.send_error_packet(&mut stream).await;
                        return;
                    }
                    RTAuthenPacket::RTAuthenContinuePacket(rtauthen_continue_packet) => {
                        println!("Ratchet Error: Unexpected continue packet!!");
                        let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                        temp_sess.send_error_packet(&mut stream).await;
                        return;
                    }
                },
                RTDecodedPacket::RTAuthorPacket(ap) => match ap {
                    ratchet::RTAuthorPacket::RTAuthorRequestPacket(rtauthor_request_packet) => {
                        let mut authz_sess = RTAutzSess::from_header(&hdr, session_key);
                        let policy = user_policy_container.read().await;
                        // default authorize
                        let mut authorization_outcome = true;

                        //println!("Ratchet Debug: Looking up Authz info for {}", name);

                        let username = match rt_fetch_precis_username(
                            &rtauthor_request_packet.user,
                            server_settings.rt_server_i18n,
                        ) {
                            Ok(u) => u,
                            Err(e) => {
                                println!("Ratchet Error: Invalid username passed.");
                                match authz_sess.send_failure_packet(&mut stream).await {
                                    Ok(_) => {
                                        //println!("Ratchet Debug: Unauthorized successfully");
                                    }
                                    Err(_) => {
                                        //println!("Ratchet Debug: Error unauthorizing");
                                    }
                                }
                                return;
                            }
                        };

                        if let (Some(policy_list), Some(cmd)) = (
                            policy.get(&username.to_string()),
                            rtauthor_request_packet.reconstruct_command(),
                        ) {
                            //println!("Ratchet Debug: Found applicable policy for {username}");
                            // First match policy against the command
                            match policy_list.0.iter().find(|&policy_item| {
                                match &policy_item.criteria {
                                    RTPolicyCriteria::BeginsWith(pfx) => cmd.starts_with(pfx),
                                    RTPolicyCriteria::EndsWith(sfx) => cmd.ends_with(sfx),
                                    RTPolicyCriteria::Contains(ifx) => cmd.contains(ifx), //TODO: slowness
                                }
                            }) {
                                Some(matching_policy_item) => {
                                    // TODO: this should be prioritized against other policy applicable
                                    //println!("Ratchet Debug: Found match via {matching_policy_item:?}");
                                    match matching_policy_item.outcome {
                                        RTPolicyOutcome::Permit => {
                                            authorization_outcome = true;
                                        }
                                        RTPolicyOutcome::Reject => {
                                            authorization_outcome = false;
                                        }
                                        _ => todo!(),
                                    }
                                }
                                None => (),
                            }
                        }

                        if authorization_outcome {
                            match authz_sess.send_success_packet(&mut stream).await {
                                Ok(_) => {
                                    //println!("Ratchet Debug: Authorized successfully");
                                }
                                Err(_) => {
                                    //println!("Ratchet Debug: Error authorizing");
                                }
                            };
                        } else {
                            match authz_sess.send_failure_packet(&mut stream).await {
                                Ok(_) => {
                                    //println!("Ratchet Debug: Unauthorized successfully");
                                }
                                Err(_) => {
                                    //println!("Ratchet Debug: Error unauthorizing");
                                }
                            };
                        }
                        return;
                    }
                    ratchet::RTAuthorPacket::RTAuthorRespPacket(rtauthor_resp_packet) => {
                        // TODO: this should be a temp author sess.
                        let mut temp_sess = RTAutzSess::from_header(&hdr, session_key);
                        match temp_sess.send_failure_packet(&mut stream).await {
                            Ok(_) => {
                                //println!("Ratchet Debug: Unauthorized successfully");
                            }
                            Err(_) => {
                                //println!("Ratchet Debug: Error unauthorizing");
                            }
                        }
                        return;
                    }
                },
                _ => {
                    println!("Unknown Packet Format");
                    let mut temp_sess = RTAuthenSess::from_header(&hdr, session_key);
                    temp_sess.send_error_packet(&mut stream).await;
                    return;
                }
            }
        }));
        // benchmarking
        // if server_settings.rt_perf_bench {
        //     let end_time = Instant::now();
        //     unsafe {RUNNING_AVG = RUNNING_AVG + ((end_time - start_time)).as_secs_f64();}
        // }
    }
}

/// The long polling process consumes an API
/// which signals to ratchet when any update is
/// available to the clients or creds.
fn rt_launch_long_polling_process(
    server_i18n: bool,
    clients_cmd: String,
    cred_cmd: String,
    user_policy_cmd: String,
    long_poll_cmd: String,
    poll_creds: Arc<RwLock<HashMap<String, String>>>,
    pollv4_clients: Arc<RwLock<[HashMap<u32, ProtectedBox<SecureVec<u8>>>; 33]>>,
    pollv6_clients: Arc<RwLock<[HashMap<u128, ProtectedBox<SecureVec<u8>>>; 129]>>,
    poll_user_cmd_policy: Arc<RwLock<HashMap<String, RTPolicy>>>,
) {
    tokio::spawn(async move {
        let v4_container = pollv4_clients.clone();
        let v6_container = pollv6_clients.clone();
        let creds_ctr = poll_creds.clone();
        let mut update_serial = 0u64;
        let mut send_serial = false;
        loop {
            println!("Ratchet Info: Waiting async for poll update signal.");
            let (prog, arg1) = match cfg!(target_os = "windows") {
                true => ("cmd", "/C"),
                false => ("sh", "-c"),
            };
            let output = if send_serial {
                Command::new(prog)
                    .arg(arg1)
                    .arg(format!("{} {update_serial}", long_poll_cmd))
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("Failed to execute configured command")
            } else {
                Command::new(prog)
                    .arg(arg1)
                    .arg(long_poll_cmd.clone())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("Failed to execute configured command")
            };

            let text_response = output.wait_with_output().expect("Failed to open STDOUT");
            //println!("Ratchet Debug: Saw {:?} from Long Poll command.", text_response.stdout);
            if text_response.stdout.len() > 7 {
                // "U p d a t e _ \d+ \n"
                // if we detect that we're on an updated server, send serial updates in the future
                send_serial = true;
                let s_num_text_b10 = text_response
                    .stdout
                    .iter()
                    .skip(7)
                    .take(20) // clamp this in-case something weird happens.
                    .fold(vec![], |mut v, &c| {
                        if c >= b'0' && c <= b'9' {
                            v.push(c);
                        }
                        v
                    });
                // TODO: using base10 is like 40x worse, but this isn't a hot path
                // PANIC: Enforcing that s_num_text_b10 contains only "0-9" should ensure that it's always radix: 10.
                match u64::from_str_radix(&String::from_utf8_lossy(&s_num_text_b10), 10) {
                    Ok(n) => {
                        update_serial = n;
                        //println!("Ratchet Debug: Computed {n} planning to send serial: {send_serial}");
                    }
                    Err(_) => {
                        update_serial = 0;
                        send_serial = false;
                        println!("Ratchet Info: Issue parsing serial, reverting to old behavior.")
                    }
                }
            }

            println!("Ratchet Info: Poll update signal detected.");
            let mut clients_v4 = v4_container.write().await;
            let mut clients_v6 = v6_container.write().await;
            let mut credentials = creds_ctr.write().await;
            let mut user_policy = poll_user_cmd_policy.write().await;
            clients_v4.iter_mut().for_each(|h| h.clear());
            clients_v6.iter_mut().for_each(|h| h.clear());
            credentials.clear();
            rt_obtain_clients(&clients_cmd, &mut clients_v4, &mut clients_v6);
            rt_obtain_creds(&cred_cmd, &mut credentials, server_i18n);
            rt_obtain_user_policy_terms(&user_policy_cmd, &mut user_policy, server_i18n);
            println!("Ratchet Info: Poll-directed update applied.");
        }
    });
}

fn rt_fetch_precis_username(packet_text: &Vec<u8>, i18n: bool) -> Result<String, &str> {
    let raw_username = String::from_utf8_lossy(&packet_text);
    if i18n {
        //println!("Ratchet Debug: Looking up {}", raw_username);
        let username_case_preserved: UsernameCasePreserved = UsernameCasePreserved::new();
        match username_case_preserved.prepare(raw_username) {
            Ok(fixed_username) => {
                //println!("Ratchet Debug: Looking up {}",fixed_username);
                Ok(fixed_username.to_string())
            }
            Err(e) => Err("Ratchet Error: Bad username passed"),
        }
    } else {
        Ok(raw_username.to_string())
    }
}

/// rt_fetch_secret performs the routing lookup to
/// a secret belonging to a specified device
fn rt_fetch_secret<'a>(
    ip: &IpAddr,
    clients_v4: &'a [HashMap<u32, ProtectedBox<SecureVec<u8>>>; 33],
    clients_v6: &'a [HashMap<u128, ProtectedBox<SecureVec<u8>>>; 129],
) -> Result<&'a ProtectedBox<SecureVec<u8>>, &'a str> {
    //println!("Ratchet Debug: Thumbing through {:#?} and {:#?}",clients_v4, clients_v6);
    match ip {
        std::net::IpAddr::V4(ipv4_addr) => {
            //println!("Ratchet Debug: Seeking out {}", ipv4_addr.to_bits());
            let addr = ipv4_addr.to_bits();
            let mut mask = 0xFFFFFFFFu32;
            let mut i = 0;
            while i <= 32 {
                //println!("Ratchet Debug: Masking result: {}", (addr & mask));
                match clients_v4[32 - i].get(&(addr & mask)) {
                    Some(str) => {
                        //println!("Ratchet Debug: Found with {:?}", str);
                        return Ok(str);
                    }
                    None => (),
                }
                i += 1;
                mask <<= 1;
            }
            Err("Unknown client")
        }
        std::net::IpAddr::V6(ipv6_addr) => match ipv6_addr.to_ipv4_mapped() {
            Some(ipv4_addr) => {
                //println!("Ratchet Debug: Seeking out {}", ipv4_addr.to_bits());
                let addr = ipv4_addr.to_bits();
                let mut mask = 0xFFFFFFFFu32;
                let mut i = 0;
                while i <= 32 {
                    //println!("Ratchet Debug: Masking result: {}", (addr & mask));
                    match clients_v4[32 - i].get(&(addr & mask)) {
                        Some(str) => {
                            //println!("Ratchet Debug: Found with {:?}", str);
                            return Ok(str);
                        }
                        None => (),
                    }
                    i += 1;
                    mask <<= 1;
                }
                Err("Unknown client")
            }
            None => {
                //println!("Ratchet Debug: Seeking out {}", ipv6_addr.to_bits());
                let addr = ipv6_addr.to_bits();
                let mut mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
                let mut i = 0;
                while i <= 128 {
                    match clients_v6[128 - i].get(&(addr & mask)) {
                        Some(str) => {
                            return Ok(str);
                        }
                        None => (),
                    }
                    i += 1;
                    mask <<= 1;
                }
                Err("Unknown client")
            }
        },
    }
}

/// rt_obtain_policy_terms updates the policy terms for users and devices
///
/// no, saying 'policy' does not mean the kernel contains policy.
fn rt_obtain_user_policy_terms(
    policy_cmd: &str,
    user_group_policies: &mut HashMap<String, RTPolicy>,
    i18n: bool,
) {
    let (prog, arg1) = match cfg!(target_os = "windows") {
        true => ("cmd", "/C"),
        false => ("sh", "-c"),
    };
    let output = Command::new(prog)
        .arg(arg1)
        .arg(policy_cmd)
        .output()
        .expect("Ratchet Fatal: Failed to execute configured command.");

    let data_str = String::from_utf8_lossy(&output.stdout);

    // Format is as follows
    // A policy is a line-oriented collection list of blocks with
    // ^\$$
    // ^\($
    // ^\)$
    // as control
    enum PolicyParserState {
        Free,                       // before the first subject is encountered
        Subject(Vec<String>),       // collecting subjects
        Policy(Vec<RTPolicyEntry>), // applicable subject-policy mappings to append into
    }

    let mut parser_state = PolicyParserState::Free;
    let mut new_policy = HashMap::new();
    let mut collected_users = vec![];
    for line in data_str.lines() {
        //println!("Ratchet Debug: Parsing policy line: {line}");
        match parser_state {
            PolicyParserState::Free => {
                //println!("Ratchet Debug: In state free");
                if line == "$" {
                    parser_state = PolicyParserState::Subject(vec![]);
                }
            }
            PolicyParserState::Subject(ref mut users) => {
                //println!("Ratchet Debug: In state subject");
                if line == "(" {
                    collected_users = users.clone();
                    parser_state = PolicyParserState::Policy(vec![]);
                } else {
                    // do precis rewriting on subjects
                    match rt_fetch_precis_username(&line.as_bytes().to_vec(), i18n) {
                        Ok(u) => {
                            users.push(u);
                        }
                        Err(e) => {
                            println!("Ratchet Error: Invalid username passed.");
                        }
                    };
                }
            }
            PolicyParserState::Policy(ref mut items) => {
                //println!("Ratchet Debug: In state close");
                if line == ")" {
                    collected_users.drain(..).for_each(|name| {
                        new_policy.insert(name, RTPolicy(items.to_owned()));
                    });
                    parser_state = PolicyParserState::Free;
                } else {
                    match rt_parse_policy_text(line, false) {
                        Some(entry) => {
                            items.push(entry);
                        }
                        None => {
                            return;
                        }
                    }
                }
            }
        }
    }
    // Formatted policy must terminate all policy definitions
    match parser_state {
        PolicyParserState::Free => {
            //println!("Ratchet Debug: File format incorrect, terminating policy parsing");
        }
        _ => {
            return;
        }
    }
    // only replace policy atomically if it is flawless
    user_group_policies.clear();
    new_policy.drain().for_each(|z| {
        user_group_policies.insert(z.0, z.1);
    });
    //println!("Ratchet Debug: Processed into {user_group_policies:#?}");
}

fn rt_parse_policy_text(text: &str, logging: bool) -> Option<RTPolicyEntry> {
    let entries = text
        .split(|z| z as u8 == b',')
        .take(5)
        .collect::<Vec<&str>>();
    //println!("Ratchet Debug: Parsing policy text got {} with {}", text, entries.len());
    if entries.len() >= 5 {
        let prec = match usize::from_str(entries[0]) {
            Ok(v) => v,
            Err(_) => {
                return None;
            }
        };
        let outcome = match entries[1] {
            e if e == "rej" => RTPolicyOutcome::Reject,
            e if e == "acc" => RTPolicyOutcome::Permit,
            e if e == "sil" => {
                if logging {
                    RTPolicyOutcome::Silence
                }
                // this outcome is only applicable for logging policies
                else {
                    return None;
                }
            }
            _ => {
                return None;
            }
        };
        let cmd_text = entries[4].to_string();
        let matcher_type = match entries[2] {
            e if e == "<" => RTPolicyCriteria::BeginsWith(cmd_text),
            e if e == ">" => RTPolicyCriteria::EndsWith(cmd_text),
            e if e == "=" => RTPolicyCriteria::Contains(cmd_text),
            _ => {
                return None;
            }
        };
        Some(RTPolicyEntry {
            precedence: prec,
            outcome: outcome,
            criteria: matcher_type,
        })
    } else {
        None
    }
}

fn rt_obtain_devi_policy_terms(
    policy_cmd: String,
    user_group_policies: Arc<RwLock<HashMap<String, RTPolicy>>>,
    dev_v4_policies_out: &mut [HashMap<u32, RTPolicy>; 33],
    dev_v6_policies_out: &mut [HashMap<u128, RTPolicy>; 129],
) {
    todo!()
}

/// For a user-specified shell command string,
/// expect a CSV list of clients.
///
/// Install the CSV list of clients as the users database.
///
/// Explicitly reject users configured with plaintext passwords;
/// the password has to look like a '2b' formatted bcrypt password hash.
/// see crypt(5) for more flavor text.
///
fn rt_obtain_creds(cmd: &str, creds_out: &mut HashMap<String, String>, server_i18n: bool) {
    // Otherwise use rt_server_read_creds to obtain credentials
    let (prog, arg1) = match cfg!(target_os = "windows") {
        true => ("cmd", "/C"),
        false => ("sh", "-c"),
    };
    let output = Command::new(prog)
        .arg(arg1)
        .arg(cmd)
        .output()
        .expect("Failed to execute configured command.");

    let data_str = String::from_utf8_lossy(&output.stdout);

    // Split by newline
    let mut line_ct = 0;
    for line in data_str.lines() {
        line_ct += 1;
        // Split each line by comma
        let parts: Vec<&str> = line.split(',').collect();

        let username_case_preserved: UsernameCasePreserved = UsernameCasePreserved::new();

        // Ensure there are exactly two parts to form a key-value pair
        if parts.len() == 2 {
            let key = parts[0].trim().to_string();

            let username = if server_i18n {
                match username_case_preserved.prepare(key) {
                    Ok(fixed_username) => {
                        //println!("Ratchet Debug: Looking up {}", fixed_username);
                        fixed_username.to_string()
                    }
                    Err(e) => {
                        println!(
                            "Ratchet Error: Invalid username passed around line, {}",
                            line_ct
                        );
                        continue;
                    }
                }
            } else {
                key
            };

            //println!("Ratchet Debug: Installed user {}", username);
            let value = parts[1].to_string();

            if rt_validate_hash(&value) {
                creds_out.insert(username, value);
            } else {
                println!(
                    "Ratchet Warning: Passwords must be valid '2b' Bcrypt hashes, around line {}",
                    line_ct
                );
                continue;
            }
        } else {
            println!(
                "Ratchet Warning: Invalid username passed around line {}",
                line_ct
            );
            continue;
        }
    }
}

/// Validates that a hash appears to be a valid '2b'-style bcrypt hash
fn rt_validate_hash(hash_tested: &String) -> bool {
    // splitting implies a single blank substring, first
    hash_tested
        .split_terminator('$')
        .skip(1)
        .enumerate()
        .all(|(idx, next)| {
            //println!("Ratchet Debug: Validating hash with {idx} predicate and {next}");
            match idx {
                // Bcrypt variant identity
                0 => next == "2b",
                // cost / rounds
                1 => {
                    next.len() == 2
                        && match next.parse::<u8>() {
                            Ok(val) => val >= 4 && val <= 31,
                            Err(_) => false,
                        }
                }
                // Base64 salt / checksum -- see man 5 crypt for format spec...; not the base64 rfc
                2 => {
                    next.len() == 53
                        && match next.find(|c| {
                            !(c >= 'A' && c <= 'Z'
                                || c >= 'a' && c <= 'z'
                                || c >= '0' && c <= '9'
                                || c == '.'
                                || c == '/')
                        }) {
                            Some(weird_char) => {
                                //println!("Ratchet Debug: I have an issue with: {:?}", weird_char);
                                false
                            }
                            None => true,
                        }
                }
                _ => false,
            }
        })
}

/// For a user-specified shell command string,
/// expect a CSV list of clients.
///
/// Install the CSV list of clients as the users database.
///
/// TODO: Consider adjusting the representation to instead be a
///        sorted array of the final IP which can associate to
///        the start IP. Matching progresses as follow:
///        
///       To match a against R_f:
///         - if a < R_{fi}
///           - Check if a >= R_{si} => shortest match!
///           - a matches, or a is unreachable
///         - else proceed to i++
///
///       ? - is this always correct?
///       ? - does this make worst-case behavior externally reachable; i.e., repeatedly spoofing in 224.0.0.x?
///
fn rt_obtain_clients(
    cmd: &str,
    v4_clients_out: &mut [HashMap<u32, ProtectedBox<SecureVec<u8>>>; 33],
    v6_clients_out: &mut [HashMap<u128, ProtectedBox<SecureVec<u8>>>; 129],
) {
    // Otherwise use rt_server_read_creds to obtain credentials
    let (prog, arg1) = match cfg!(target_os = "windows") {
        true => ("cmd", "/C"),
        false => ("sh", "-c"),
    };
    let mut output = Command::new(prog)
        .arg(arg1)
        .arg(cmd)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Ratchet Fatal: Failed to execute configured command.");

    output
        .wait()
        .expect("Ratchet Fatal: Client creds command failed");

    let data_str = SecureVec::from_iter_in(
        output
            .stdout
            .take()
            .unwrap()
            .bytes()
            .map(|garbage| match garbage {
                Ok(bytes) => bytes,
                _ => 0,
            }),
        SecureAlloc,
    );

    // Split by newline
    let mut line_ct = 0;
    for line in data_str.split(|c| *c == b'\n') {
        line_ct += 1;
        // Split each line by comma
        let parts = SecureVec::from_iter_in(
            line.split(|c| *c == b',')
                .map(|u| str::from_utf8(u).unwrap_or(&"")),
            SecureAlloc,
        );

        // Ensure there are exactly two parts to form a key-value pair
        if parts.len() == 2 {
            let key = parts[0].trim().to_string();
            if parts[1].len() == 0 || key.len() == 0 {
                println!(
                    "Ratchet Error: Must have valid network and secret, skipping {}",
                    key
                );
                continue;
            }

            let key_parts: Vec<&str> = key.split('/').collect();

            let net_mask_def = key_parts.len() == 2;

            match Ipv4Addr::from_str(key_parts[0]) {
                Ok(s) => {
                    let int_address = s.to_bits();
                    if !net_mask_def {
                        let value = ProtectedBox::from(SecureVec::from(parts[1])); // keys can contain spaces in some implementations
                        v4_clients_out[32].insert(int_address, value);
                        continue;
                    } else {
                        let netmask = match u32::from_str(key_parts[1]) {
                            Ok(n) => n as usize,
                            Err(_) => continue,
                        };
                        // TODO: A (probably) faster solution would be to use an immediate / left-shift
                        //       to fetch the ith mask.
                        if netmask <= 32 && (int_address == (int_address & (IPV4_MASKS[netmask]))) {
                            let value = ProtectedBox::from(SecureVec::from(parts[1])); // keys can contain spaces in some implementations
                            v4_clients_out[netmask].insert(int_address, value);
                        } else {
                            //println!("Ratchet Debug: Bad netmask, or bad network address, skipping {}",key);
                        }
                    }
                }
                Err(_) => {
                    match Ipv6Addr::from_str(key_parts[0]) {
                        Ok(s) => {
                            let int_address = s.to_bits();
                            if !net_mask_def {
                                let value = ProtectedBox::from(SecureVec::from(parts[1])); // keys can contain spaces in some implementations
                                v6_clients_out[128].insert(int_address, value);
                                continue;
                            } else {
                                let netmask = match u32::from_str(key_parts[1]) {
                                    Ok(n) => n as usize,
                                    Err(_) => continue,
                                };

                                if netmask <= 128
                                    && (int_address == (int_address & (IPV6_MASKS[netmask])))
                                {
                                    let value = ProtectedBox::from(SecureVec::from(parts[1])); // keys can contain spaces in some implementations
                                    v6_clients_out[netmask].insert(int_address, value);
                                } else {
                                    //println!("Ratchet Debug: Bad netmask, or bad network address, skipping {}", key);
                                }
                            }
                        }
                        Err(_) => {
                            // Not IPv4 or IPv6 ... discarding.
                            //println!("Ratchet Debug: Bad input, or bad network address, skipping {}",key);
                        }
                    }
                }
            };

            //println!("Ratchet Debug: Installed client {}", key);
        } else {
            println!(
                "Ratchet Warning: Invalid network/client passed around {}. Expected 2 parts, found {}",
                line_ct,
                parts.len()
            );
            continue;
        }
    }
}

// benchmarking
// unsafe fn rt_get_avg() -> f64{
//     return RUNNING_AVG;
// }

/// benchmarking related
unsafe fn rt_get_runs() -> f64 {
    return RUNS.load(atomic::Ordering::Relaxed) as f64;
}

/// In case of failure to open a socket, get some environment
/// info from the system we're running on.
fn rt_get_system_user_name() -> String {
    return match if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "whoami"]).output()
    } else {
        Command::new("sh").args(["-c", "whoami"]).output()
    } {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            return "Couldn't get username".to_string();
        }
    };
}

async fn rt_generate_gutter() {
    let mut g= GUTTER.write().await;
    g.push_str(&pwhash::bcrypt::hash(rt_generate_gutter_string()).expect("Ratchet Fatal: Unable to generate gutter"));
}

fn rt_generate_gutter_string() -> String { 
    (0..72).fold(
        String::with_capacity(72),
        |mut s, _| {
            loop {
                let c = rand::random::<u8>();
                if c.is_ascii_alphanumeric() || c.is_ascii_graphic() || c.is_ascii_punctuation() {
                    s.push(c as char);
                    break;
                }
            }
            s
        }
    )
}

/// This precomputes an array of hashes.
/// TODO: Probably would be best to transition users to use CPU intrinsics that
/// generate these instead.
macro_rules! generate_v6netmasks {
    // Macro for generating netmasks for IPv4 and IPv6
    ($name:ident, $bits:expr, $size:expr) => {
        const $name: [u128; $bits + 1] = {
            let mut masks = [0; $bits + 1];
            let mut i = 0;
            while i <= $bits {
                masks[i] = if i == 0 { 0 } else { (!0u128) << ($size - i) };
                i += 1;
            }
            masks
        };
    };
}

/// This precomputes an array of hashes.
/// TODO: Probably would be best to transition users to use CPU intrinsics that
/// generate these instead.
macro_rules! generate_v4netmasks {
    // Macro for generating netmasks for IPv4 and IPv6
    ($name:ident, $bits:expr, $size:expr) => {
        const $name: [u32; $bits + 1] = {
            let mut masks = [0; $bits + 1];
            let mut i = 0;
            while i <= $bits {
                masks[i] = if i == 0 { 0 } else { (!0u32) << ($size - i) };
                i += 1;
            }
            masks
        };
    };
}

// Generate IPv4 and IPv6 masks
// TODO: Transition these to appropriate CPU intrinsics
generate_v4netmasks!(IPV4_MASKS, 32, 32);
generate_v6netmasks!(IPV6_MASKS, 128, 128);
