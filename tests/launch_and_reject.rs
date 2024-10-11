use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn end_to_end_test_auth_rejection() {
    // Start the server
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--bin", "ratchet", "--", "--add-insecure-test-credential-do-not-use"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start ratchet application");

        
        let stdout = child.stdout.as_mut().expect("Failed to open stdout");
        let reader = BufReader::new(stdout);
        
        // Loop to read output until "NOWLISTENING" appears
        let mut now_listening = false;
        
        for line in reader.lines() {
            match line {
                Ok(output) => {
                    println!("{}", output);
                    if output.contains("NOWLISTENING") {
                        now_listening = true;
                        break; // Exit loop once we find "NOWLISTENING"
                    }
                },
                Err(e) => {
                    eprintln!("Error reading line: {}", e);
                    break; // Exit loop on read error
                },
            }
        }

    match child.try_wait() {
        Ok(Some(status)) => {
            println!("Exited with {status}");
            assert!(false, "Server closed unexpectedly! {status}");
        },
        Err(e) => {
            println!("Exited with {e}");
            assert!(false, "Server closed unexpectedly! {e}");
        },
        Ok(None) => {if now_listening {
            println!("Server is now listening.");
            } // this is fine
        },
    }

    // Infer location of testing script
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/resources");

    // Run the Perl script and capture its output
    let output = Command::new("perl")
        .args([&format!("{}/test.pl", d.display()), "negative"])
        .output()
        .expect("Failed to execute perl script");

    // Convert the output to a String
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Check if "Success!" is in the output
    if !stdout.contains("Authentication failed") {
        // If not, assert false to indicate the test has failed
        let _ = child.kill().expect("Failed to kill the ratchet application");
        
        let mut server_msg= String::new();
        match child.stdout.take().unwrap().read_to_string(&mut server_msg){
            Ok(_) => (),
            Err(e) => assert!(false, "Nah, that ain't it, chief. {} \n Testing Framework Errors: {} \n Server output: none available\n", stdout, stderr),
        }
        assert!(false, "Nah, that ain't it, chief. {} \n Testing Framework Errors: {} \n Server output {}\n", stdout, stderr, server_msg);
    }

    // Kill the server
    let _ = child.kill().expect("Failed to kill the ratchet application");

    // Optionally, you could check if the process was killed successfully
    // and/or check its output here.

    // If the test reaches this point, we consider it a success
    println!("Test completed successfully!");

    assert!(true);
}