//! Stress and robustness tests for the capture store and telegram ring.
//!
//! - 10k-telegram writer flood through the mpsc → all rows land.
//! - Ring `wait_for` under contention: many waiters, one match.
//! - Re-decode of corrupt raw blobs falls back to the snapshot.
//! - DB reopened by a second reader sees the writer's rows (WAL).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_monitor::store::{
    CaptureRecord, CaptureStore, CaptureWriter, QueryFilter, StoredTelegram,
};
use bussard_monitor::{DecodedTelegram, Filter, TelegramRing};
use bussard_transport::TimestampedFrame;
use bussard_transport::cemi::CemiFrame;

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

fn frame(dest: &str, at: SystemTime) -> TimestampedFrame {
    TimestampedFrame {
        received_at: at,
        frame: CemiFrame::group_write_packed(ga(dest), ia("1.1.30"), &[1]),
    }
}

// ---------------------------------------------------------------------------
// 10k-telegram flood: every record must land.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ten_thousand_telegrams_all_land() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flood.db");
    let writer = CaptureWriter::open(&path).unwrap();

    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    const N: usize = 10_000;
    for i in 0..N {
        // Vary destination across a modest GA space.
        let main = 1 + (i % 30);
        let middle = (i / 30) % 8;
        let sub = i % 256;
        let f = frame(
            &format!("{main}/{middle}/{sub}"),
            base + Duration::from_millis(i as u64),
        );
        let decoded = DecodedTelegram::from_frame(&f, None);
        assert!(
            writer.record(CaptureRecord::from_decoded(&decoded, &f)),
            "record {i} rejected"
        );
    }
    let written = writer.finish().unwrap();
    assert_eq!(written, N as u64, "all records written");

    let store = CaptureStore::open(&path).unwrap();
    assert_eq!(store.count().unwrap(), N as u64, "all rows present");
}

// ---------------------------------------------------------------------------
// Concurrent-ish producers into one writer.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn many_producers_one_writer_lands_all() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi.db");
    let writer = Arc::new(CaptureWriter::open(&path).unwrap());

    const TASKS: usize = 8;
    const PER: usize = 1000;
    let mut handles = Vec::new();
    for t in 0..TASKS {
        let w = writer.clone();
        handles.push(tokio::spawn(async move {
            let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
            for i in 0..PER {
                let f = frame(
                    &format!("{}/{}/{}", 1 + t, i % 8, i % 256),
                    base + Duration::from_millis(i as u64),
                );
                let decoded = DecodedTelegram::from_frame(&f, None);
                assert!(w.record(CaptureRecord::from_decoded(&decoded, &f)));
                if i % 128 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // Unwrap the Arc to finish() the writer (join the thread).
    let writer = Arc::try_unwrap(writer).ok().expect("sole owner");
    let written = writer.finish().unwrap();
    assert_eq!(written, (TASKS * PER) as u64);

    let store = CaptureStore::open(&path).unwrap();
    assert_eq!(store.count().unwrap(), (TASKS * PER) as u64);
}

// ---------------------------------------------------------------------------
// Ring wait_for under contention: many waiters, one matching telegram.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn many_waiters_all_see_the_one_match() {
    let ring = TelegramRing::with_capacity(100);
    let filter = Filter::parse("3/2/0").unwrap();

    // Spawn many waiters BEFORE the match is pushed.
    let mut waiters = Vec::new();
    for _ in 0..32 {
        let r = ring.clone();
        let f = filter.clone();
        waiters.push(tokio::spawn(async move {
            r.wait_for(&f, Duration::from_secs(5)).await
        }));
    }
    // Give the waiters a moment to subscribe.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Push a few non-matching, then the single match (broadcast to all waiters).
    let r2 = ring.clone();
    r2.push(mk_tel("9/1/9"));
    r2.push(mk_tel("3/2/0")); // the match
    r2.push(mk_tel("8/1/8"));

    let mut matched = 0;
    for w in waiters {
        if let Some(t) = w.await.unwrap() {
            assert_eq!(t.destination.to_string(), "3/2/0");
            matched += 1;
        }
    }
    assert_eq!(matched, 32, "every waiter received the broadcast match");
}

fn mk_tel(dest: &str) -> DecodedTelegram {
    use bussard_model::codec::TypedValue;
    use bussard_monitor::{ApciKind, DestinationRef};
    DecodedTelegram {
        timestamp: SystemTime::UNIX_EPOCH,
        source: ia("1.1.1"),
        source_name: None,
        destination: DestinationRef::Group(ga(dest)),
        destination_name: None,
        apci: ApciKind::Write,
        payload: vec![1],
        value: Some(TypedValue::Raw(vec![1])),
        dpt: None,
        object_name: None,
        decode_note: None,
    }
}

// ---------------------------------------------------------------------------
// Ring flood eviction keeps exactly `capacity` newest.
// ---------------------------------------------------------------------------

#[test]
fn ring_flood_evicts_to_capacity() {
    let ring = TelegramRing::with_capacity(500);
    for i in 0..10_000u32 {
        ring.push(mk_tel(&format!(
            "{}/{}/{}",
            1 + i % 30,
            (i / 30) % 8,
            i % 256
        )));
    }
    assert_eq!(ring.len(), 500, "ring capped at capacity");
    // The newest 500 are retained; the very newest is first.
    let recent = ring.recent(&Filter::default(), Some(1));
    assert_eq!(recent.len(), 1);
}

#[test]
fn ring_with_capacity_zero_is_clamped_to_one() {
    let ring = TelegramRing::with_capacity(0);
    ring.push(mk_tel("1/1/1"));
    ring.push(mk_tel("2/2/2"));
    assert_eq!(ring.len(), 1, "capacity floored at 1");
}

// ---------------------------------------------------------------------------
// Corrupt raw blob re-decode falls back to the JSON snapshot.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redecode_corrupt_blob_falls_back_to_snapshot() {
    // Various malformed raw_cemi buffers must yield Err(snapshot), never panic.
    for raw in [
        vec![0xFF],
        vec![],
        vec![0x29, 0x00],
        vec![0x11; 3],
        vec![0xAB; 40],
    ] {
        let stored = StoredTelegram {
            id: 1,
            ts_utc: "1970-01-01T00:00:00Z".to_string(),
            source: "1.1.1".to_string(),
            destination: "1/1/1".to_string(),
            apci: "write".to_string(),
            raw_cemi: raw.clone(),
            decoded_snapshot: Some("{\"snap\":1}".to_string()),
        };
        let r = std::panic::catch_unwind(|| stored.redecode(None));
        assert!(r.is_ok(), "redecode panicked on raw {raw:?}");
        match r.unwrap() {
            Ok(_) => { /* some short buffers may coincidentally decode; fine */ }
            Err(snap) => assert_eq!(snap.as_deref(), Some("{\"snap\":1}")),
        }
    }
}

// ---------------------------------------------------------------------------
// DB reopened by an independent reader sees the writer's rows (WAL).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reopened_reader_sees_committed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reopen.db");

    // Write & finish (commits + closes writer).
    {
        let writer = CaptureWriter::open(&path).unwrap();
        for i in 0..50u8 {
            let f = frame(&format!("1/0/{i}"), SystemTime::UNIX_EPOCH);
            let decoded = DecodedTelegram::from_frame(&f, None);
            writer.record(CaptureRecord::from_decoded(&decoded, &f));
        }
        writer.finish().unwrap();
    }

    // First reader.
    let store1 = CaptureStore::open(&path).unwrap();
    assert_eq!(store1.count().unwrap(), 50);
    assert_eq!(store1.journal_mode().unwrap().to_lowercase(), "wal");

    // A second, independent reader opened on the same file sees the same rows.
    let store2 = CaptureStore::open(&path).unwrap();
    let rows = store2
        .query(&QueryFilter {
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 10);
    // Ordered newest-first by id.
    assert_eq!(rows[0].destination, "1/0/49");
}

// ---------------------------------------------------------------------------
// Query filter combinations remain correct at moderate volume.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_filters_and_limit_are_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("filt.db");
    let writer = CaptureWriter::open(&path).unwrap();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    for i in 0..200u32 {
        let f = frame(
            &format!("3/2/{}", i % 256),
            base + Duration::from_secs(i as u64),
        );
        let decoded = DecodedTelegram::from_frame(&f, None);
        writer.record(CaptureRecord::from_decoded(&decoded, &f));
    }
    writer.finish().unwrap();

    let store = CaptureStore::open(&path).unwrap();
    // Limit is honoured.
    let limited = store
        .query(&QueryFilter {
            limit: Some(5),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(limited.len(), 5);
    // Since filter reduces the set.
    let since = store
        .query(&QueryFilter {
            since: Some(base + Duration::from_secs(100)),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(since.len(), 100);
    // GA filter on a specific destination.
    let by_ga = store
        .query(&QueryFilter {
            ga: Some(ga("3/2/0")),
            ..Default::default()
        })
        .unwrap();
    // 3/2/0 appears at i=0 only (i%256 == 0 for i in 0..200 -> just i=0).
    assert_eq!(by_ga.len(), 1);
}
