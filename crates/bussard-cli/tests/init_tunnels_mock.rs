//! `bussard init --gateway` against a mock KNXnet/IP interface (issue #105).
//!
//! The mock answers DESCRIPTION_REQUEST with a tunnelling-info DIB (four slots,
//! three occupied) and refuses every CONNECT with `E_NO_MORE_CONNECTIONS`. The
//! test proves `init` prints the tunnel budget and names the full-interface
//! condition instead of a generic timeout.

use std::process::Command;
use std::time::Duration;

use bussard_testkit::MockGateway;
use bussard_testkit::wire::description_response_body;

#[tokio::test]
async fn test_init_reports_tunnels_and_full_interface() -> Result<(), Box<dyn std::error::Error>> {
    // Describe with 4 slots / 3 in use, refuse every CONNECT with 0x24.
    let gw = MockGateway::builder()
        .description(description_response_body("Mock Interface", 4, 3))
        .refuse_connect(0x24)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .start()
        .await?;
    let port = gw.port();

    let dir = std::env::temp_dir().join(format!("bussard-init-tunnels-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(["init", "--gateway", &format!("127.0.0.1:{port}"), "--dir"])
            .arg(&dir)
            .output()
    })
    .await??;
    drop(gw);

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
