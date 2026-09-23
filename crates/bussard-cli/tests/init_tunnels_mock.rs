//! `bussard init --gateway` against a mock KNXnet/IP interface (issue #105).
//!
//! The mock answers DESCRIPTION_REQUEST with a tunnelling-info DIB (four slots,
//! three occupied) and refuses every CONNECT with `E_NO_MORE_CONNECTIONS`. The
//! test proves `init` prints the tunnel budget and names the full-interface
//! condition instead of a generic timeout.

use std::process::Command;

use bussard_transport::knxnet::{self, ServiceType};
use tokio::net::UdpSocket;

/// Wraps a body in a KNXnet/IP header.
fn frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = vec![0x06, 0x10];
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A device-info DIB plus a tunnelling-info DIB with `slots` slots, the first
/// `in_use` of them occupied.
fn description_body(slots: usize, in_use: usize) -> Vec<u8> {
    let mut dev = vec![0u8; 54];
    dev[0] = 54;
    dev[1] = 0x01;
    dev[2] = 0x02;
    dev[4..6].copy_from_slice(&0x1000u16.to_be_bytes());
    let name = b"Mock Interface";
    dev[24..24 + name.len()].copy_from_slice(name);

    let mut tun = vec![(4 + 4 * slots) as u8, 0x07];
    tun.extend_from_slice(&248u16.to_be_bytes());
    for slot in 0..slots {
        tun.extend_from_slice(&(0x10F1u16 + slot as u16).to_be_bytes());
        let status: u16 = if slot < in_use { 0x0006 } else { 0x0007 };
        tun.extend_from_slice(&status.to_be_bytes());
    }
    dev.extend_from_slice(&tun);
    dev
}

/// Serves the mock until the socket is dropped: describe with 4/3, refuse connects.
async fn serve(gw: UdpSocket) {
    let mut buf = [0u8; 1024];
    loop {
        let Ok((n, peer)) = gw.recv_from(&mut buf).await else {
            return;
        };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        let reply = match parsed.service {
            ServiceType::DescriptionRequest => {
                frame(ServiceType::DescriptionResponse, &description_body(4, 3))
            }
            ServiceType::ConnectRequest => frame(ServiceType::ConnectResponse, &[0x00, 0x24]),
            _ => continue,
        };
        let _ = gw.send_to(&reply, peer).await;
    }
}

#[tokio::test]
async fn test_init_reports_tunnels_and_full_interface() -> Result<(), Box<dyn std::error::Error>> {
    let gw = UdpSocket::bind("127.0.0.1:0").await?;
    let port = gw.local_addr()?.port();
    let server = tokio::spawn(serve(gw));

    let dir = std::env::temp_dir().join(format!("bussard-init-tunnels-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(["init", "--gateway", &format!("127.0.0.1:{port}"), "--dir"])
            .arg(&dir)
            .output()
    })
    .await??;
    server.abort();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "init still writes the skeleton: {stderr}"
    );
    assert!(
        stdout.contains("Tunnelling: 4 tunnels, 3 in use."),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Mock Interface"), "stdout: {stdout}");
    assert!(
        stderr.contains("no free tunnelling connection (E_NO_MORE_CONNECTIONS)"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("Home Assistant"), "stderr: {stderr}");
    assert!(
        !stderr.contains("did not respond"),
        "a full interface is not a timeout: {stderr}"
    );
    Ok(())
}
