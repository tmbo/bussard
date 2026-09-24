//! `--keyring` serves the tunnel alone when it has no entry for the target
//! (issue #189), against a loopback secure-only interface
//! ([`MockSecureGateway`]) with plain [`MockDevice`]s behind it.
//!
//! - a device the keyring does not list: the keyring's tunnelling user opens
//!   the secure tunnel and the device is read in the clear;
//! - a device the keyring lists: management still rides `A_SecureData`;
//! - a device the model marks `security.activated: true` but the keyring
//!   lacks: refused with the "no tool key" hint, nothing sent to it;
//! - `connection.keyring` in `bussard.toml` is the default, `--keyring`
//!   overrides it.
//!
//! The keyring is the SYNTHETIC fixture of `keyring_cli.rs` (made-up
//! passwords, never a real export).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use bussard_model::IndividualAddress;
use bussard_secure::{Password, salt};
use bussard_testkit::{MockDevice, MockSecureGateway, TestResult};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination};

/// The synthetic keyring: tunnelling user 2 (password `tunnel-user-pw`,
/// tunnel 1.1.200) on interface 1.1.0 (device authentication code
/// `device-auth-pw`), and one device entry, 1.1.10.
const KEYRING: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-02-03T04:05:06" Signature="BwFnB3x3sq9qwzQsIIYDHQ==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="1000" Key="XXLSoIYX1PClHpjLLr06xw==" />
  <Interface Type="Tunneling" Host="1.1.0" IndividualAddress="1.1.200" UserID="2" Password="CEuTO5HdZ/da1DOMrSJhAQZ94w6kq3rM2I2EFv/3fWw=" Authentication="fj0EBnFwaOJuRN85Aovn5Z8UU1ndm0p0F5tkraeg72Y=">
    <Group Address="2563" Senders="1.1.10" />
  </Interface>
  <GroupAddresses>
    <Group Address="2563" Key="9gsADI4+cx1p65cAhr5GDA==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="1.1.10" ToolKey="4KejWFAOVLtfuK2uo4tiyA==" ManagementPassword="v66sERBaqXzGcl6zuAsdsA==" Authentication="Qoy1wZsb3MhAe+PdJd6p4uHl3mt02IukjeAPcy2BWrE=" SequenceNumber="42" />
  </Devices>
</Keyring>"#;

/// The synthetic keyring's made-up password.
const KEYRING_PASSWORD: &str = "synthetic-keyring-pw";

/// `A_SecureData`, the Data Secure wrapper APCI.
const A_SECURE_DATA: u16 = 0x03F1;

/// The plain device the keyring does not list.
const PLAIN: &str = "1.1.52";
/// The device the keyring lists.
const LISTED: &str = "1.1.10";

fn ia(s: &str) -> TestResult<IndividualAddress> {
    Ok(s.parse()?)
}

/// A secure-only interface at 1.1.0 accepting the keyring's user 2, with a
/// plain device at 1.1.52 and one at 1.1.10 behind it.
async fn gateway() -> TestResult<MockSecureGateway> {
    Ok(MockSecureGateway::builder()
        .individual_address(0x1100)
        .device_auth(Password::new("device-auth-pw").derive(salt::DEVICE_AUTHENTICATION_CODE))
        .user(
            2,
            Password::new("tunnel-user-pw").derive(salt::USER_PASSWORD),
            0x11C8,
        )
        .device(MockDevice::new(ia(PLAIN)?))
        .device(MockDevice::new(ia(LISTED)?))
        .start()
        .await?)
}

/// A scratch model directory with the keyring next to it, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    /// `<tmp>/bussard-kr-tunnel-<tag>-<pid>/` with `knx/` (links, optional
    /// `bussard.toml` extra lines, optional device file) and `keys.knxkeys`.
    fn new(tag: &str, config_extra: &str, device_file: Option<&str>) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("bussard-kr-tunnel-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("knx");
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
        std::fs::write(
            dir.join("bussard.toml"),
            format!("connection:\n  transport: tunnel\n{config_extra}"),
        )?;
        if let Some(body) = device_file {
            std::fs::write(dir.join("devices").join("device.yaml"), body)?;
        }
        std::fs::write(root.join("keys.knxkeys"), KEYRING)?;
        Ok(Scratch(root))
    }

    fn dir(&self) -> PathBuf {
        self.0.join("knx")
    }

    fn keyring(&self) -> PathBuf {
        self.0.join("keys.knxkeys")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `bussard describe <target> --json --dir <dir> --gateway <gw> [extra]`
/// with the keyring password set.
async fn describe(target: &str, dir: &Path, gateway: String, extra: &[&str]) -> TestResult<Output> {
    let mut args: Vec<String> = vec![
        "describe".into(),
        target.into(),
        "--json".into(),
        "--dir".into(),
        dir.to_string_lossy().into_owned(),
        "--gateway".into(),
        gateway,
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(&args)
            .env("BUSSARD_KEYRING_PASSWORD", KEYRING_PASSWORD)
            .env("BUSSARD_TUNNEL_RECONNECT_SECS", "0")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .stdin(Stdio::null())
            .output()
    })
    .await??;
    Ok(out)
}

/// The frames the client tunnelled to `target`.
fn frames_to(requests: &[CemiFrame], target: IndividualAddress) -> Vec<&CemiFrame> {
    requests
        .iter()
        .filter(|f| f.destination == Destination::Individual(target))
        .collect()
}

fn is_secure_data(frame: &CemiFrame) -> bool {
    matches!(&frame.apdu, Apdu::Other { apci, .. } if *apci == A_SECURE_DATA)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_describe_keyring_without_entry_reads_in_the_clear_through_the_secure_tunnel()
-> TestResult {
    let gw = gateway().await?;
    let scratch = Scratch::new("plain", "", None)?;
    let keyring = scratch.keyring();
    let out = describe(
        PLAIN,
        &scratch.dir(),
        gw.addr().to_string(),
        &["--keyring", &keyring.to_string_lossy()],
    )
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![2], "the keyring's user opened the tunnel");
    assert_eq!(stats.plain_refusals, 0);
    let to_device = frames_to(&stats.requests, ia(PLAIN)?);
    assert!(!to_device.is_empty(), "nothing reached {PLAIN}");
    assert!(
        !to_device.iter().any(|f| is_secure_data(f)),
        "a device the keyring does not list is read in the clear"
    );
    assert!(!stderr.contains("has no tool key"), "{stderr}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_describe_keyring_listed_device_still_uses_secure_data() -> TestResult {
    let gw = gateway().await?;
    let scratch = Scratch::new("listed", "", None)?;
    let keyring = scratch.keyring();
    // The plain mock ignores A_SecureData, so the command fails; what matters
    // is that it asked secured.
    let _ = describe(
        LISTED,
        &scratch.dir(),
        gw.addr().to_string(),
        &["--keyring", &keyring.to_string_lossy()],
    )
    .await?;
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![2]);
    let to_device = frames_to(&stats.requests, ia(LISTED)?);
    assert!(
        to_device.iter().any(|f| is_secure_data(f)),
        "a keyring-listed device is managed with A_SecureData"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_describe_activated_device_missing_from_keyring_is_refused() -> TestResult {
    let gw = gateway().await?;
    let device = format!("address: {PLAIN}\nname: Secure module\nsecurity:\n  activated: true\n");
    let scratch = Scratch::new("activated", "", Some(&device))?;
    let keyring = scratch.keyring();
    let out = describe(
        PLAIN,
        &scratch.dir(),
        gw.addr().to_string(),
        &["--keyring", &keyring.to_string_lossy()],
    )
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("has no tool key for {PLAIN}")),
        "{stderr}"
    );
    let stats = gw.stats()?;
    assert!(
        frames_to(&stats.requests, ia(PLAIN)?).is_empty(),
        "nothing is sent to the refused device"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_describe_uses_the_config_keyring_by_default() -> TestResult {
    let gw = gateway().await?;
    // Relative to the model directory.
    let scratch = Scratch::new("config", "  keyring: ../keys.knxkeys\n", None)?;
    let out = describe(PLAIN, &scratch.dir(), gw.addr().to_string(), &[]).await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![2], "connection.keyring opened the tunnel");
    assert!(!frames_to(&stats.requests, ia(PLAIN)?).is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_describe_keyring_flag_overrides_the_config_keyring() -> TestResult {
    let gw = gateway().await?;
    let scratch = Scratch::new("override", "  keyring: missing.knxkeys\n", None)?;
    // The configured file does not exist: without the flag that is the error.
    let out = describe(PLAIN, &scratch.dir(), gw.addr().to_string(), &[]).await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("missing.knxkeys"), "{stderr}");
    // The flag wins over it.
    let keyring = scratch.keyring();
    let out = describe(
        PLAIN,
        &scratch.dir(),
        gw.addr().to_string(),
        &["--keyring", &keyring.to_string_lossy()],
    )
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(gw.stats()?.users, vec![2]);
    Ok(())
}
