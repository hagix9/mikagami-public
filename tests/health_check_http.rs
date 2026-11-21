//! `contrib/health/check-http` (the HTTP health check for `[health] command`) against a
//! loopback HTTP server: exit 0 only for the expected status and body, 1 otherwise, 2 for a
//! usage error. Needs `curl` (present on the supported hosts); its absence is a failure.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contrib/health/check-http")
}

/// Serves `responses` (one per connection) and returns the URL.
fn serve(responses: Vec<Option<&'static str>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            match response {
                Some(text) => {
                    let _ = stream.write_all(text.as_bytes());
                }
                // Never answer (the client's timeout must end the check).
                None => std::thread::sleep(Duration::from_secs(4)),
            }
        }
    });
    format!("http://127.0.0.1:{port}/healthz")
}

fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn leak(text: String) -> Option<&'static str> {
    Some(Box::leak(text.into_boxed_str()))
}

fn run(args: &[&str]) -> i32 {
    Command::new("sh")
        .arg(script())
        .args(args)
        .output()
        .unwrap()
        .status
        .code()
        .unwrap_or(-1)
}

#[test]
fn curl_is_available() {
    assert!(
        Command::new("curl").arg("--version").output().is_ok(),
        "curl is required by check-http"
    );
}

#[test]
fn healthy_only_with_the_expected_status_and_body() {
    let url = serve(vec![
        leak(http("200 OK", "status: ok")),
        leak(http("200 OK", "status: ok")),
        leak(http("200 OK", "status: degraded")),
        leak(http("503 Service Unavailable", "status: ok")),
        leak(http("204 No Content", "")),
    ]);
    assert_eq!(run(&[&url]), 0);
    assert_eq!(run(&[&url, "--contains", "ok"]), 0);
    assert_eq!(run(&[&url, "--contains", "status: ok"]), 1);
    assert_eq!(run(&[&url]), 1, "503 is unhealthy");
    assert_eq!(run(&[&url, "--status", "204"]), 0);
}

#[test]
fn a_pattern_is_matched_literally() {
    let url = serve(vec![leak(http("200 OK", "abc"))]);
    assert_eq!(run(&[&url, "--contains", "a*c"]), 1);
}

#[test]
fn no_answer_within_the_timeout_and_no_server_are_unhealthy() {
    let url = serve(vec![None]);
    let started = std::time::Instant::now();
    assert_eq!(run(&[&url, "--timeout", "1"]), 1);
    assert!(started.elapsed() < Duration::from_secs(3));
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}/")
    };
    assert_eq!(run(&[&closed]), 1);
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run(&[]), 2);
    assert_eq!(run(&["ftp://127.0.0.1/"]), 2);
    assert_eq!(run(&["http://127.0.0.1/", "--status", "abc"]), 2);
    assert_eq!(run(&["http://127.0.0.1/", "--timeout", "0"]), 2);
    assert_eq!(run(&["http://127.0.0.1/", "--bogus"]), 2);
    assert_eq!(run(&["http://127.0.0.1/", "--status", "0200"]), 2);
    assert_eq!(run(&["http://127.0.0.1/", "--status", "99"]), 2);
}
