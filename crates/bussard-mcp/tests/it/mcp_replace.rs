//! Mock-gateway tests of `knx_replace_device` (issue #751): the replace flow
//! from chat, backup, press the button, identify, the one yes, then the
//! address, the flash, the apply and the record.
//!
//! The dead device is 1.1.4 of `mcp_flash`'s model (the synthetic
//! application, pinned in `bussard.lock`). The replacement is a factory-fresh
//! `bussard-testkit` [`MockDevice`] in programming mode at 15.15.255 running
//! no application, on a loopback [`MockGateway`] tunnel.
//!
//! The `download: true` path (issue #779) moves the pinned archive out of
//! `products/` into a mirror that a fixture vendor index serves over
//! `file://`: the download puts it back and the flash runs, or, when the
//! index's SHA-256 does not match, the job refuses before the address write.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`.

use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::consts::{LE_LOAD_COMPLETED, LE_UNLOAD, LS_UNLOADED};
use bussard_testkit::{MockDevice, MockGateway};
use serde_json::{Value, json};

use super::mcp_flash::{
    ALLOC_BASE, CHANNEL, Client, app_load_events, call, device_at, serve, write_model,
};

const SERIAL: [u8; 6] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];

fn ia(s: &str) -> anyhow::Result<IndividualAddress> {
    Ok(s.parse()?)
}

/// A factory-fresh replacement in programming mode at 15.15.255.
fn spare() -> anyhow::Result<MockDevice> {
    Ok(device_at(ia("15.15.255")?, None, LS_UNLOADED)?
        .with_programming(true)
        .with_serial(SERIAL)
        .with_order_info(b"M-00FA-TEST"))
}

/// A line with `devices`, a programming-tier server on `mcp_flash`'s model,
/// and the programming-mode wait shortened for the mock.
async fn start(
    devices: Vec<MockDevice>,
) -> anyhow::Result<(
    MockGateway,
    tempfile::TempDir,
    Client,
    tokio::task::JoinHandle<()>,
)> {
    // SAFETY: nextest runs each test in its own process; the variable is read
    // when the programming-mode wait starts.
    unsafe {
        std::env::set_var(bussard_service::assign::WAIT_MS_ENV, "400");
    }
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(120))
        .devices(devices)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let (client, task) = serve(dir.path(), &gateway).await?;
    Ok((gateway, dir, client, task))
}

/// Polls `knx_job_status` until `until` holds for the status.
async fn poll(client: &Client, job: &str, until: impl Fn(&Value) -> bool) -> anyhow::Result<Value> {
    for _ in 0..600 {
        let status = call(client, "knx_job_status", json!({"job": job})).await?;
        if until(&status) {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("job {job} never reached the expected state")
}

/// Starts the replacement of 1.1.4 and polls until the job is identified
/// or done.
async fn identified(client: &Client) -> anyhow::Result<(String, Value)> {
    let first = call(client, "knx_replace_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(first["step"], "press_button", "{first}");
    assert!(
        first["question"]
            .as_str()
            .unwrap_or_default()
            .contains("programming button"),
        "{first}"
    );
    let job = first["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {first}"))?
        .to_string();
    let status = poll(client, &job, |s| {
        s["step"] == "identified" || s["done"] == true
    })
    .await?;
    Ok((job, status))
}

#[tokio::test]
async fn test_knx_replace_device_assigns_flashes_applies_and_records() -> anyhow::Result<()> {
    let (gateway, dir, client, task) = start(vec![spare()?]).await?;

    let first = call(&client, "knx_replace_device", json!({"address": "1.1.4"})).await?;
    assert_eq!(first["step"], "press_button", "{first}");
    assert!(first["backup"]["snapshot"].is_string(), "{first}");
    assert_eq!(first["backup"]["lock"]["application"], "M-00FA_A-0002");
    let job = first["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {first}"))?
        .to_string();
    let status = poll(&client, &job, |s| {
        s["step"] == "identified" || s["done"] == true
    })
    .await?;
    assert_eq!(status["step"], "identified", "{status}");
    assert_eq!(status["kind"], "replace", "{status}");
    assert_eq!(status["current_address"], "15.15.255", "{status}");
    assert_eq!(status["address"], "1.1.4", "{status}");
    assert_eq!(status["serial"], "00fa01020304", "{status}");
    assert_eq!(status["mask"], "07B0", "{status}");
    assert_eq!(status["application"], "M-00FA_A-0002", "{status}");
    assert_eq!(status["download_needed"], false, "{status}");
    assert!(
        status["question"]
            .as_str()
            .unwrap_or_default()
            .starts_with("Replace Weather station (1.1.4)"),
        "{status}"
    );
    let digest = status["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {status}"))?
        .to_string();
    // Identification wrote nothing: the spare still answers at 15.15.255.
    assert_eq!(gateway.with_device(ia("15.15.255")?, |d| d.writes)?, 0);

    // Neither a yes without this job's digest nor a digest without a yes.
    let wrong = call(
        &client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": "sha256:00", "yes": true}),
    )
    .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");
    let no_yes = call(
        &client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": digest}),
    )
    .await?;
    assert_eq!(no_yes["refused"], true, "{no_yes}");
    assert!(gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());

    let started = call(
        &client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": digest, "yes": true}),
    )
    .await?;
    let result = if started["done"] == true {
        started
    } else {
        poll(&client, &job, |s| s["done"] == true).await?["result"].clone()
    };
    assert_eq!(result["step"], "done", "{result}");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["verified"], true, "{result}");
    assert_eq!(result["assigned"], true, "{result}");
    assert_eq!(result["flashed"], true, "{result}");
    assert_eq!(result["from"], "15.15.255", "{result}");
    assert_eq!(
        result["write"]["load_application"]["loaded"], true,
        "{result}"
    );
    assert_eq!(result["write"]["readback"]["verified"], true, "{result}");
    assert!(result["recorded"]["replaced"].is_string(), "{result}");
    let summary = result["summary"].as_str().unwrap_or_default();
    assert!(
        summary.starts_with("Weather station (1.1.4) is replaced"),
        "{summary}"
    );

    // The spare took the address, got the application with the model's
    // parameters (threshold 9, object 2 on), and the model records it.
    let (events, params) = gateway.with_device(ia("1.1.4")?, |dev| {
        (app_load_events(dev), dev.read_mem(ALLOC_BASE + 0x100, 2))
    })?;
    assert_eq!(events.first(), Some(&LE_UNLOAD), "load events {events:?}");
    assert_eq!(
        events.last(),
        Some(&LE_LOAD_COMPLETED),
        "load events {events:?}"
    );
    assert_eq!(params, [9, 0x80], "threshold 9, object 2 on");
    let file = std::fs::read_to_string(dir.path().join("devices").join("1.1.4.toml"))?;
    assert!(
        file.lines().any(|l| l.starts_with("replaced = \"20")),
        "{file}"
    );
    let lock = std::fs::read_to_string(dir.path().join("bussard.lock"))?;
    assert!(lock.contains("00FA01020304"), "{lock}");

    // The job is done; a second yes is refused.
    let again = call(
        &client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": digest, "yes": true}),
    )
    .await?;
    assert_eq!(again["refused"], true, "{again}");
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_replace_device_refuses_while_the_old_device_answers() -> anyhow::Result<()> {
    let old = device_at(ia("1.1.4")?, None, LS_UNLOADED)?;
    let (gateway, _dir, client, task) = start(vec![old, spare()?]).await?;
    let (_, status) = identified(&client).await?;
    assert_eq!(status["done"], true, "{status}");
    let reason = status["result"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("1.1.4 still answers"), "{reason}");
    assert!(reason.contains("Nothing was written"), "{reason}");
    assert!(gateway.with_device(ia("15.15.255")?, |_| ()).is_ok());
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_replace_device_refuses_another_product() -> anyhow::Result<()> {
    let (gateway, dir, client, task) = start(vec![spare()?]).await?;
    let path = dir.path().join("devices").join("1.1.4.toml");
    let file = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        file.replacen(
            "name = \"Weather station\"\n",
            "name = \"Weather station\"\nproduct = \"MDT-JAL0410\"\n",
            1,
        ),
    )?;
    let (_, status) = identified(&client).await?;
    assert_eq!(status["done"], true, "{status}");
    let reason = status["result"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("refusing to replace 1.1.4"), "{reason}");
    assert!(reason.contains("M-00FA-TEST"), "{reason}");
    assert_eq!(gateway.with_device(ia("15.15.255")?, |d| d.writes)?, 0);
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_replace_device_refuses_a_device_the_model_does_not_have() -> anyhow::Result<()> {
    let (_gateway, _dir, client, task) = start(vec![spare()?]).await?;
    let refused = call(&client, "knx_replace_device", json!({"address": "1.1.9"})).await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no device file for 1.1.9"),
        "{refused}"
    );
    client.cancel().await?;
    task.abort();
    Ok(())
}

/// The download case (issue #779): the device file names the replacement's
/// order number, the archive `bussard.lock` pins is not in `products/`, and
/// a fixture vendor index serves it from a `file://` mirror outside the
/// model directory. `intact: false` lists a SHA-256 the mirror's bytes do
/// not have, so the download never yields the pinned archive. Returns the
/// job and its identified status.
async fn identified_with_download(
    dir: &std::path::Path,
    mirror: &std::path::Path,
    client: &Client,
    intact: bool,
) -> anyhow::Result<(String, Value)> {
    use sha2::Digest as _;
    let path = dir.join("devices").join("1.1.4.toml");
    let file = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        file.replacen(
            "name = \"Weather station\"\n",
            "name = \"Weather station\"\nproduct = \"M-00FA-TEST\"\n",
            1,
        ),
    )?;
    let served = mirror.join("flash-test.knxprod");
    std::fs::rename(dir.join("products").join("flash-test.knxprod"), &served)?;
    let bytes = std::fs::read(&served)?;
    let sha: String = if intact {
        sha2::Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    } else {
        "0".repeat(64)
    };
    let index = mirror.join("index.json");
    std::fs::write(
        &index,
        serde_json::to_vec(&json!({"entries": [{
            "manufacturer": "Test",
            "manufacturer_id": "M-00FA",
            "order_numbers": ["M-00FA-TEST"],
            "name": "Flash test",
            "url": format!("file://{}", served.display()),
            "sha256": sha,
            "size": bytes.len(),
            "filename": "flash-test.knxprod",
        }]}))?,
    )?;
    // SAFETY: nextest runs each test in its own process; the index is read
    // when the tool plans the product data and when it downloads.
    unsafe {
        std::env::set_var(bussard_service::setup::products::PRODUCT_INDEX_ENV, &index);
    }
    let (job, status) = identified(client).await?;
    assert_eq!(status["step"], "identified", "{status}");
    assert_eq!(status["download_needed"], true, "{status}");
    Ok((job, status))
}

/// The yes for `job`: without `download: true` it is refused with nothing
/// written; with it, the job runs to its end, whose result is returned.
async fn yes_with_download(client: &Client, job: &str, status: &Value) -> anyhow::Result<Value> {
    let digest = status["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {status}"))?;
    let without = call(
        client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": digest, "yes": true}),
    )
    .await?;
    assert_eq!(without["refused"], true, "{without}");
    assert!(
        without["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("download: true"),
        "{without}"
    );
    let started = call(
        client,
        "knx_replace_device",
        json!({"job": job, "plan_digest": digest, "yes": true, "download": true}),
    )
    .await?;
    if started["done"] == true {
        return Ok(started);
    }
    Ok(poll(client, job, |s| s["done"] == true).await?["result"].clone())
}

#[tokio::test]
async fn test_knx_replace_device_downloads_the_pinned_archive_then_flashes() -> anyhow::Result<()> {
    let (gateway, dir, client, task) = start(vec![spare()?]).await?;
    let mirror = tempfile::tempdir()?;
    let (job, status) = identified_with_download(dir.path(), mirror.path(), &client, true).await?;
    let result = yes_with_download(&client, &job, &status).await?;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["verified"], true, "{result}");
    assert_eq!(result["flashed"], true, "{result}");
    assert_eq!(
        result["write"]["load_application"]["loaded"], true,
        "{result}"
    );
    // The download put the pinned archive back into the store.
    assert_eq!(
        std::fs::read(dir.path().join("products").join("flash-test.knxprod"))?,
        std::fs::read(mirror.path().join("flash-test.knxprod"))?
    );
    let events = gateway.with_device(ia("1.1.4")?, |dev| app_load_events(dev))?;
    assert_eq!(
        events.last(),
        Some(&LE_LOAD_COMPLETED),
        "load events {events:?}"
    );
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_knx_replace_device_refuses_when_the_download_leaves_the_archive_unusable()
-> anyhow::Result<()> {
    let (gateway, dir, client, task) = start(vec![spare()?]).await?;
    let mirror = tempfile::tempdir()?;
    let (job, status) = identified_with_download(dir.path(), mirror.path(), &client, false).await?;
    let result = yes_with_download(&client, &job, &status).await?;
    assert_ne!(result["ok"], true, "{result}");
    let reason = result["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("the download did not give bussard the archive"),
        "{result}"
    );
    assert!(reason.contains("Nothing was written"), "{reason}");
    // Refused before the address write: the spare is untouched.
    assert_eq!(gateway.with_device(ia("15.15.255")?, |d| d.writes)?, 0);
    assert!(gateway.with_device(ia("1.1.4")?, |_| ()).is_err());
    assert!(
        !dir.path()
            .join("products")
            .join("flash-test.knxprod")
            .exists()
    );
    client.cancel().await?;
    task.abort();
    Ok(())
}
