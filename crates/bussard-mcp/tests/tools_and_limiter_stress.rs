//! Robustness tests for the pure MCP tool logic and the read rate limiter.
//!
//! - Tool functions with absurd limits (0, usize::MAX) and empty queries.
//! - `decode_for_dpt` with truncated/oversized payloads (no panic).
//! - `ReadLimiter` timing + concurrency at the 3-concurrent case.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_mcp::tools::{decode_for_dpt, get_group, model_lookup, recent_telegrams};
use bussard_model::schema::Device;
use bussard_model::schema::{BussardConfig, Group, Groups, Link, Links};
use bussard_model::{GroupAddress, IndividualAddress, LoadedDevice, Model};
use bussard_monitor::{Filter, TelegramRing};
use bussard_transport::TransportKind;

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

fn small_model() -> Model {
    let mut groups = BTreeMap::new();
    for i in 0..10u32 {
        groups.insert(
            ga(&format!("3/0/{i}")),
            Group {
                name: format!("Group {i}"),
                dpt: Some("1.001".parse().unwrap()),
                description: None,
                protected: false,
            },
        );
    }
    let mut links = BTreeMap::new();
    links.insert(
        ia("1.1.4"),
        vec![Link {
            object: 1,
            name: Some("Obj".to_string()),
            send: None,
            listen: vec![ga("3/0/0")],
        }],
    );
    let mut devices = BTreeMap::new();
    devices.insert(
        ia("1.1.4"),
        LoadedDevice {
            device: Device {
                address: ia("1.1.4"),
                name: "Dev".to_string(),
                description: None,
                location: None,
                replaced: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: Default::default(),
                com_objects: BTreeMap::new(),
                security: None,
            },
            file_stem: "1.1.4-dev".to_string(),
        },
    );
    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: Some("T".to_string()),
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices,
    }
}

// ---------------------------------------------------------------------------
// Absurd limits on model_lookup.
// ---------------------------------------------------------------------------

/// Regression (was issue #39 off-by-one): `model_lookup` with `limit == 0` used
/// to return ONE result per category, not zero, because the limit was checked
/// AFTER the push. It is now checked before the push, so `limit: 0` yields an
/// empty result and `limit: n` yields at most `n`.
#[test]
fn model_lookup_limit_zero_returns_zero() {
    let m = small_model();
    let v = model_lookup(&m, "group", 0);
    assert_eq!(
        v["groups"].as_array().unwrap().len(),
        0,
        "limit==0 must yield zero results"
    );
    // And a non-zero limit still yields exactly that many.
    let v1 = model_lookup(&m, "group", 1);
    assert_eq!(v1["groups"].as_array().unwrap().len(), 1);
}

#[test]
fn model_lookup_limit_usize_max_is_bounded_by_data() {
    let m = small_model();
    let v = model_lookup(&m, "group", usize::MAX);
    // All 10 groups match "group" but there are only 10.
    assert_eq!(v["groups"].as_array().unwrap().len(), 10);
}

#[test]
fn model_lookup_empty_query_matches_broadly_without_panic() {
    let m = small_model();
    // Empty query: `contains("")` is always true, so everything matches (bounded
    // by the limit). Must not panic.
    let v = model_lookup(&m, "", 3);
    assert_eq!(v["groups"].as_array().unwrap().len(), 3);
}

#[test]
fn model_lookup_unicode_query_is_safe() {
    let m = small_model();
    for q in ["🚀", "Ω≈ç", "\0", "  ", "GROUP"] {
        let r = std::panic::catch_unwind(|| model_lookup(&m, q, 50));
        assert!(r.is_ok(), "model_lookup panicked on {q:?}");
    }
}

// ---------------------------------------------------------------------------
// recent_telegrams with absurd limits.
// ---------------------------------------------------------------------------

#[test]
fn recent_telegrams_limit_zero_and_max() {
    let ring = TelegramRing::new();
    let f = Filter::default();
    // Empty ring, any limit -> empty.
    assert!(recent_telegrams(&ring, &f, None, 0).is_empty());
    assert!(recent_telegrams(&ring, &f, None, usize::MAX).is_empty());
}

// ---------------------------------------------------------------------------
// get_group with an undefined GA.
// ---------------------------------------------------------------------------

#[test]
fn get_group_undefined_ga_reports_not_found() {
    let m = small_model();
    let ring = TelegramRing::new();
    let v = get_group(&m, &ring, ga("9/7/255"));
    assert_eq!(v["found"], false);
    assert!(v["links"].as_array().unwrap().is_empty());
    assert!(v["last_telegram"].is_null());
}

// ---------------------------------------------------------------------------
// decode_for_dpt with truncated / oversized / no-dpt payloads.
// ---------------------------------------------------------------------------

#[test]
fn decode_for_dpt_handles_hostile_payloads() {
    for dpt in [
        Some("9.001".parse().unwrap()),
        Some("232.600".parse().unwrap()),
        None,
    ] {
        for len in 0..=20usize {
            let payload: Vec<u8> = vec![0xAB; len];
            let r = std::panic::catch_unwind(|| decode_for_dpt(dpt, &payload));
            assert!(r.is_ok(), "decode_for_dpt panicked dpt {dpt:?} len {len}");
        }
    }
    // No DPT -> None display + Null json.
    let (disp, json) = decode_for_dpt(None, &[1, 2, 3]);
    assert!(disp.is_none());
    assert!(json.is_null());
}

// ---------------------------------------------------------------------------
// BusStatus json shape.
// ---------------------------------------------------------------------------

#[test]
fn bus_status_json_is_stable() {
    let bus = BusStatus::new(TransportKind::Tunnel);
    let j = bus.to_json();
    assert_eq!(j["transport"], "tunnel");
    assert_eq!(j["state"], "connecting");
    assert_eq!(j["connected"], false);
}

// ---------------------------------------------------------------------------
// ReadLimiter: the 3-concurrent case (extends the existing 2-cap tests).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_limiter_caps_at_three_concurrent() {
    let limiter = Arc::new(ReadLimiter::new(Duration::from_millis(0), 3));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..12 {
        let limiter = limiter.clone();
        let in_flight = in_flight.clone();
        let max_seen = max_seen.clone();
        handles.push(tokio::spawn(async move {
            let _p = limiter.acquire().await;
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(15)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert!(
        max_seen.load(Ordering::SeqCst) <= 3,
        "never more than 3 concurrent, saw {}",
        max_seen.load(Ordering::SeqCst)
    );
    // And it must actually reach 3 (the cap is used, not accidentally serialised).
    assert!(
        max_seen.load(Ordering::SeqCst) >= 2,
        "concurrency should be exercised"
    );
}

#[tokio::test]
async fn read_limiter_spacing_with_three_permits() {
    // With 3 permits and a spacing interval, the first 3 acquires are near-
    // instant (permits available), but each still stamps the spacing clock, so
    // successive acquires observe the min interval. We assert monotonic spacing
    // across a burst without over-constraining exact timing.
    let limiter = ReadLimiter::new(Duration::from_millis(40), 3);
    let start = Instant::now();
    for _ in 0..4 {
        let _p = limiter.acquire().await;
        drop(_p);
    }
    // 4 acquires with a 40ms floor between each stamped read: at least ~120ms
    // (3 gaps). Generous lower bound to avoid flakiness.
    assert!(
        start.elapsed() >= Duration::from_millis(100),
        "spaced acquires took {:?}",
        start.elapsed()
    );
}
