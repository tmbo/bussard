//! SQLite capture store.
//!
//! Telegrams are persisted with **both** their raw cEMI bytes and a decoded
//! JSON snapshot, so a capture can be re-decoded later against a fixed model
//! while still reading fine with no model at all.
//!
//! The transport is async but `rusqlite` is synchronous, so the writer runs on
//! a dedicated blocking thread fed by a [`tokio::sync::mpsc`] channel. Callers
//! push [`CaptureRecord`]s through a [`CaptureWriter`]; the reader API
//! ([`CaptureStore::query`]) is a plain synchronous SQLite read intended for
//! later MCP use.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE telegrams (
//!   id INTEGER PRIMARY KEY,
//!   ts_utc TEXT NOT NULL,
//!   source TEXT NOT NULL,
//!   destination TEXT NOT NULL,
//!   apci TEXT NOT NULL,
//!   raw_cemi BLOB NOT NULL,
//!   decoded TEXT
//! );
//! CREATE INDEX idx_telegrams_dest_ts ON telegrams (destination, ts_utc);
//! ```
//! WAL journalling is enabled so reads don't block the writer.

use std::path::Path;
use std::time::SystemTime;

use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::TimestampedFrame;
use rusqlite::Connection;
use tokio::sync::mpsc;

use crate::decode::{DecodedTelegram, DestinationRef};
use crate::format::json_line;
use crate::timefmt;

/// An error from the capture store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Failed to spawn the writer thread.
    #[error("failed to start capture writer thread: {0}")]
    Spawn(#[source] std::io::Error),
}

/// One telegram to persist: its raw cEMI bytes, arrival time, and a decoded
/// snapshot rendered by the caller.
#[derive(Debug, Clone)]
pub struct CaptureRecord {
    /// Arrival time.
    pub timestamp: SystemTime,
    /// Source individual address (textual).
    pub source: String,
    /// Destination address (textual).
    pub destination: String,
    /// APCI tag (`read`/`write`/`response`/`other`).
    pub apci: String,
    /// The raw cEMI frame bytes, re-decodable later.
    pub raw_cemi: Vec<u8>,
    /// A decoded JSON snapshot (a JSON Lines record), or `None`.
    pub decoded: Option<String>,
}

impl CaptureRecord {
    /// Builds a record from a decoded telegram and the original frame.
    ///
    /// The raw cEMI is taken from `frame` (so it can be re-decoded against a
    /// future model) and the JSON snapshot from `decoded`.
    pub fn from_decoded(decoded: &DecodedTelegram, frame: &TimestampedFrame) -> CaptureRecord {
        CaptureRecord {
            timestamp: decoded.timestamp,
            source: decoded.source.to_string(),
            destination: decoded.destination.to_string(),
            apci: decoded.apci.tag().to_string(),
            raw_cemi: frame.frame.encode(),
            decoded: Some(json_line(decoded)),
        }
    }
}

/// Formats a `SystemTime` as an RFC3339 UTC string for stable, sortable storage.
fn to_rfc3339(ts: SystemTime) -> String {
    timefmt::to_rfc3339(ts)
}

/// Opens (creating if needed) the database at `path`, applying the schema and
/// WAL mode.
fn open_and_init(path: &Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    // WAL lets readers run concurrently with the single writer.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS telegrams (
            id INTEGER PRIMARY KEY,
            ts_utc TEXT NOT NULL,
            source TEXT NOT NULL,
            destination TEXT NOT NULL,
            apci TEXT NOT NULL,
            raw_cemi BLOB NOT NULL,
            decoded TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_telegrams_dest_ts
            ON telegrams (destination, ts_utc);",
    )?;
    Ok(conn)
}

/// The write side of a capture: an async handle over a background writer thread.
///
/// Records pushed through [`record`](CaptureWriter::record) are batched onto a
/// dedicated blocking thread. Dropping the writer (and any clones) closes the
/// channel; call [`finish`](CaptureWriter::finish) to flush and join cleanly.
pub struct CaptureWriter {
    tx: Option<mpsc::UnboundedSender<CaptureRecord>>,
    handle: Option<std::thread::JoinHandle<Result<u64, rusqlite::Error>>>,
}

impl CaptureWriter {
    /// Opens the database at `path` and starts the background writer thread.
    pub fn open(path: &Path) -> Result<CaptureWriter, StoreError> {
        // Open once here so schema/permission errors surface synchronously.
        let conn = open_and_init(path)?;
        let (tx, mut rx) = mpsc::unbounded_channel::<CaptureRecord>();

        let handle = std::thread::Builder::new()
            .name("bussard-capture".to_string())
            .spawn(move || -> Result<u64, rusqlite::Error> {
                let mut conn = conn;
                let mut count = 0u64;
                // Drain the channel on this blocking thread. `blocking_recv`
                // parks the thread until a record arrives or the channel closes.
                while let Some(rec) = rx.blocking_recv() {
                    insert(&mut conn, &rec)?;
                    count += 1;
                }
                Ok(count)
            })
            .map_err(StoreError::Spawn)?;

        Ok(CaptureWriter {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    /// Queues a record for persistence. Returns `false` if the writer thread
    /// has stopped (e.g. after a fatal SQLite error).
    pub fn record(&self, rec: CaptureRecord) -> bool {
        match &self.tx {
            Some(tx) => tx.send(rec).is_ok(),
            None => false,
        }
    }

    /// Closes the channel and joins the writer thread, returning the total
    /// number of rows written.
    pub fn finish(mut self) -> Result<u64, StoreError> {
        // Drop the sender to close the channel so the thread's loop ends.
        self.tx = None;
        match self.handle.take() {
            Some(h) => match h.join() {
                Ok(res) => res.map_err(StoreError::from),
                // A panicked writer thread; surface as an I/O-ish error.
                Err(_) => Err(StoreError::Spawn(std::io::Error::other(
                    "capture writer thread panicked",
                ))),
            },
            None => Ok(0),
        }
    }
}

impl Drop for CaptureWriter {
    fn drop(&mut self) {
        // Ensure the channel closes even if `finish` was not called, so the
        // writer thread can exit rather than leak.
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Inserts a single record.
fn insert(conn: &mut Connection, rec: &CaptureRecord) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO telegrams (ts_utc, source, destination, apci, raw_cemi, decoded)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            to_rfc3339(rec.timestamp),
            rec.source,
            rec.destination,
            rec.apci,
            rec.raw_cemi,
            rec.decoded,
        ],
    )?;
    Ok(())
}

/// A filter for [`CaptureStore::query`]. All set fields must match (AND).
#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    /// Restrict to a single destination group address.
    pub ga: Option<GroupAddress>,
    /// Restrict to a single source individual address.
    pub source: Option<IndividualAddress>,
    /// Only telegrams at or after this time.
    pub since: Option<SystemTime>,
    /// Maximum number of rows (most recent first).
    pub limit: Option<usize>,
}

/// A stored telegram, re-decodable against a current model.
#[derive(Debug, Clone)]
pub struct StoredTelegram {
    /// Row id.
    pub id: i64,
    /// Stored timestamp text (RFC3339 UTC).
    pub ts_utc: String,
    /// Source address text.
    pub source: String,
    /// Destination address text.
    pub destination: String,
    /// APCI tag.
    pub apci: String,
    /// The raw cEMI bytes.
    pub raw_cemi: Vec<u8>,
    /// The decoded JSON snapshot stored at capture time, if any.
    pub decoded_snapshot: Option<String>,
}

impl StoredTelegram {
    /// Re-decodes the raw cEMI bytes against `model`, falling back to the stored
    /// JSON snapshot if the bytes no longer decode (they always should, but the
    /// snapshot is the durable record).
    ///
    /// Returns the freshly-decoded telegram on success, or `Err(snapshot)` with
    /// the stored JSON when the raw bytes cannot be decoded.
    pub fn redecode(&self, model: Option<&Model>) -> Result<DecodedTelegram, Option<String>> {
        match CemiFrame::decode(&self.raw_cemi) {
            Ok(frame) => {
                let stamped = TimestampedFrame {
                    received_at: parse_rfc3339(&self.ts_utc),
                    frame,
                };
                Ok(DecodedTelegram::from_frame(&stamped, model))
            }
            Err(_) => Err(self.decoded_snapshot.clone()),
        }
    }
}

/// Parses an RFC3339 string back to `SystemTime`, defaulting to the epoch.
fn parse_rfc3339(s: &str) -> SystemTime {
    timefmt::from_rfc3339(s)
}

/// The read side of a capture: a synchronous SQLite reader.
///
/// Intended for later MCP use (`knx_recent_telegrams` over a stored capture).
/// Open independently of any writer; WAL mode makes concurrent reads safe.
pub struct CaptureStore {
    conn: Connection,
}

impl CaptureStore {
    /// Opens the capture database at `path` for reading (creating the schema if
    /// the file is new).
    pub fn open(path: &Path) -> Result<CaptureStore, StoreError> {
        let conn = open_and_init(path)?;
        Ok(CaptureStore { conn })
    }

    /// Queries stored telegrams matching `filter`, most-recent first.
    pub fn query(&self, filter: &QueryFilter) -> Result<Vec<StoredTelegram>, StoreError> {
        let mut sql = String::from(
            "SELECT id, ts_utc, source, destination, apci, raw_cemi, decoded
             FROM telegrams WHERE 1=1",
        );
        // Build the parameter list positionally to keep the query prepared.
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(ga) = filter.ga {
            sql.push_str(" AND destination = ?");
            params.push(Box::new(ga.to_string()));
        }
        if let Some(source) = filter.source {
            sql.push_str(" AND source = ?");
            params.push(Box::new(source.to_string()));
        }
        if let Some(since) = filter.since {
            sql.push_str(" AND ts_utc >= ?");
            params.push(Box::new(to_rfc3339(since)));
        }
        sql.push_str(" ORDER BY id DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(limit as i64));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(StoredTelegram {
                id: row.get(0)?,
                ts_utc: row.get(1)?,
                source: row.get(2)?,
                destination: row.get(3)?,
                apci: row.get(4)?,
                raw_cemi: row.get(5)?,
                decoded_snapshot: row.get(6)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// The total number of stored telegrams.
    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM telegrams", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Whether the database is in WAL journal mode (used by tests and health
    /// checks).
    pub fn journal_mode(&self) -> Result<String, StoreError> {
        let mode: String = self
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        Ok(mode)
    }

    /// Convenience for callers that hold a decoded destination and want to
    /// restrict by it.
    pub fn dest_ref_to_string(dest: DestinationRef) -> String {
        dest.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use bussard_transport::cemi::CemiFrame;

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }
    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }

    fn frame(dest: &str, src: &str, at: SystemTime) -> TimestampedFrame {
        TimestampedFrame {
            received_at: at,
            frame: CemiFrame::group_write(ga(dest), ia(src), &[1]),
        }
    }

    #[tokio::test]
    async fn insert_and_query_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus.db");

        let writer = CaptureWriter::open(&path).unwrap();
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        for i in 0..3u8 {
            let f = frame(
                &format!("3/2/{i}"),
                "1.1.30",
                base + Duration::from_secs(i as u64),
            );
            let decoded = DecodedTelegram::from_frame(&f, None);
            assert!(writer.record(CaptureRecord::from_decoded(&decoded, &f)));
        }
        let written = writer.finish().unwrap();
        assert_eq!(written, 3);

        let store = CaptureStore::open(&path).unwrap();
        assert_eq!(store.count().unwrap(), 3);

        // All rows, newest first.
        let all = store.query(&QueryFilter::default()).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].destination, "3/2/2");

        // Filter by GA.
        let by_ga = store
            .query(&QueryFilter {
                ga: Some(ga("3/2/1")),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_ga.len(), 1);
        assert_eq!(by_ga[0].destination, "3/2/1");

        // Filter by source + limit.
        let by_src = store
            .query(&QueryFilter {
                source: Some(ia("1.1.30")),
                limit: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_src.len(), 2);

        // Filter by since.
        let since = store
            .query(&QueryFilter {
                since: Some(base + Duration::from_secs(2)),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].destination, "3/2/2");
    }

    #[tokio::test]
    async fn wal_mode_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.db");
        let store = CaptureStore::open(&path).unwrap();
        assert_eq!(store.journal_mode().unwrap().to_lowercase(), "wal");
    }

    #[tokio::test]
    async fn redecode_uses_model_then_falls_back() {
        use bussard_model::schema::{BussardConfig, Group, Groups, Links};
        use std::collections::BTreeMap;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("redecode.db");

        // Capture a 1-bit write to 3/2/0 with NO model (snapshot is raw).
        let writer = CaptureWriter::open(&path).unwrap();
        let f = frame("3/2/0", "1.1.30", SystemTime::UNIX_EPOCH);
        let decoded_nomodel = DecodedTelegram::from_frame(&f, None);
        writer.record(CaptureRecord::from_decoded(&decoded_nomodel, &f));
        writer.finish().unwrap();

        // Later: a model that knows 3/2/0 is DPT 1.005 (alarm).
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/2/0"),
            Group {
                name: "Windalarm".to_string(),
                dpt: Some("1.005".parse().unwrap()),
                description: None,
            },
        );
        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };

        let store = CaptureStore::open(&path).unwrap();
        let rows = store.query(&QueryFilter::default()).unwrap();
        assert_eq!(rows.len(), 1);

        // Re-decoding against the model now resolves the name + value.
        let redecoded = rows[0].redecode(Some(&model)).expect("raw bytes decode");
        assert_eq!(redecoded.destination_name.as_deref(), Some("Windalarm"));
        assert!(matches!(
            redecoded.value,
            Some(bussard_model::codec::TypedValue::Bool { .. })
        ));

        // The stored snapshot is still available as the durable fallback.
        assert!(rows[0].decoded_snapshot.is_some());
    }

    #[tokio::test]
    async fn redecode_fallback_on_corrupt_bytes() {
        // A row whose raw_cemi is not a valid frame yields the snapshot.
        let stored = StoredTelegram {
            id: 1,
            ts_utc: "1970-01-01T00:00:00Z".to_string(),
            source: "1.1.1".to_string(),
            destination: "1/1/1".to_string(),
            apci: "write".to_string(),
            raw_cemi: vec![0xFF], // not decodable
            decoded_snapshot: Some("{\"snapshot\":true}".to_string()),
        };
        let res = stored.redecode(None);
        assert_eq!(res.unwrap_err().as_deref(), Some("{\"snapshot\":true}"));
    }
}
