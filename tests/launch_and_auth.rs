use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn end_to_end_test_authentication() {
    // Start the server
    let mut child = Command::new("cargo")
        .args(&["run", "--release", "--bin", "ratchet"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start ratchet application");

    thread::sleep(Duration::from_secs(1));

    match child.try_wait() {
        Ok(Some(status)) => {
            println!("Exited with {status}");
            assert!(false, "Server closed unexpectedly! {status}");
        },
        Err(e) => {
            println!("Exited with {e}");
            assert!(false, "Server closed unexpectedly! {e}");
        },
        Ok(None) => (), // this is fine
    }

    // Infer location of testing script
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/resources");

    // Run the Perl script and capture its output
    let output = Command::new("perl")
        .arg(format!("{}/test.pl", d.display()))
        .output()
        .expect("Failed to execute perl script");

    // Convert the output to a String
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Check if "Success!" is in the output
    if !stdout.contains("Success!") {
        // If not, assert false to indicate the test has failed
        let _ = child.kill().expect("Failed to kill the ratchet application");
        assert!(false, "Nah, that ain't it, chief. {} \n Testing Framework Errors: {}", stdout, stderr);
    }
    // Pause for 30 seconds
    thread::sleep(Duration::from_secs(1));

    // Kill the server
    let _ = child.kill().expect("Failed to kill the ratchet application");

    // Optionally, you could check if the process was killed successfully
    // and/or check its output here.

    // If the test reaches this point, we consider it a success
    println!("Test completed successfully!");

    assert!(true);
}