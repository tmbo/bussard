//! Integration test for the vendor-download path against a tiny in-test HTTP
//! server (std `TcpListener`). No real network: the server serves fabricated
//! bytes so we can exercise happy, checksum-mismatch and oversize paths.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use bussard_prod::fetch::{DownloadConsent, fetch_entry, sha256_hex};
use bussard_prod::index::IndexEntry;

/// Spawns a one-shot HTTP/1.1 server that answers the first request with
/// `status` and `body`. Returns the bound `http://127.0.0.1:PORT/` base URL.
fn serve_once(status: &'static str, body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain the request headers (we don't care about them).
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://{addr}/file.knxprod")
}

fn entry(url: String, sha256: String, size: u64) -> IndexEntry {
    IndexEntry {
        manufacturer: "Test".into(),
        manufacturer_id: "M-0000".into(),
        order_numbers: vec!["X-1".into()],
        name: "Test product".into(),
        url,
        sha256,
        size,
        filename: "file.knxprod".into(),
        application_ref: None,
        redistributable: false,
        notes: None,
    }
}

#[test]
fn fetch_happy_path() {
    let body = b"a valid little knxprod payload".to_vec();
    let url = serve_once("200 OK", body.clone());
    let e = entry(url, sha256_hex(&body), body.len() as u64);

    let got = fetch_entry(&e, DownloadConsent::granted()).unwrap();
    assert_eq!(got, body);
}

#[test]
fn fetch_rejects_sha_mismatch() {
    let body = b"tampered payload".to_vec();
    let url = serve_once("200 OK", body.clone());
    // Correct size, wrong checksum: simulates the vendor re-publishing.
    let e = entry(url, "0".repeat(64), body.len() as u64);

    let err = fetch_entry(&e, DownloadConsent::granted())
        .unwrap_err()
        .to_string();
    assert!(err.contains("SHA-256 mismatch"), "{err}");
    assert!(
        err.contains("report"),
        "error should guide reporting: {err}"
    );
}

#[test]
fn fetch_rejects_size_mismatch() {
    let body = b"short body".to_vec();
    let url = serve_once("200 OK", body.clone());
    // Claim a larger size than served.
    let e = entry(url, sha256_hex(&body), body.len() as u64 + 100);

    let err = fetch_entry(&e, DownloadConsent::granted())
        .unwrap_err()
        .to_string();
    assert!(err.contains("size mismatch"), "{err}");
}

#[test]
fn fetch_rejects_oversize() {
    // Server sends far more than the tiny declared size; the capped reader must
    // abort rather than buffer the whole thing.
    let body = vec![9u8; 4096];
    let url = serve_once("200 OK", body);
    // Declare a tiny size so the download blows the cap.
    let e = entry(url, "0".repeat(64), 8);

    let err = fetch_entry(&e, DownloadConsent::granted())
        .unwrap_err()
        .to_string();
    assert!(err.contains("exceeds"), "{err}");
}
