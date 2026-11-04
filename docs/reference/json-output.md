# JSON output

The shape of a telegram in `bussard monitor --json` and in the SQLite database `bussard capture` writes. For scripts and tools that consume the bus traffic bussard decodes.

## Telegram JSON

`monitor --json` emits one object per line, each starting with `"schema": 1`. The MCP telegram tools mirror the same fields without it. Absent fields are `null`, so the shape is uniform. The schema number and the rules for when it changes are on [Global options](global-options.md); a consumer must ignore fields it does not know.

| Field | Meaning |
|---|---|
| `ts_utc` | RFC 3339 UTC timestamp, the same name as the capture column. |
| `source` | The sender's address. |
| `source_name` | The sending device's name from the project. |
| `destination` | The destination group address. |
| `destination_name` | The group address's name from `groups.toml`. |
| `dest_type` | The destination address type. |
| `apci` | The APCI, the telegram's service, for example `GroupValueWrite`. |
| `payload` | The raw payload, hex. |
| `value` | The decoded, typed value. |
| `dpt` | The DPT used to decode. |
| `object_name` | The sending object's text, from the lock or the link's `name` in the device file. |
| `note` | Decode diagnostics, for example a size mismatch. |

### KNX Data Secure fields

With `--keyring`, a KNX Data Secure group telegram adds five fields. Plain telegrams carry none of them, so their records are unchanged.

| Field | Meaning |
|---|---|
| `secured` | `true` when the MAC verified under the group address's key; the other fields then describe the decrypted inner telegram. `false` otherwise. |
| `secure_status` | `ok`, `mac_failed`, or `no_key` (the key store or keyring has no key for the address). |
| `secure_seq` | The sender's sequence number. |
| `secure_raw` | The raw `A_SecureData` ASDU, hex, when it did not verify; else `null`. |
| `secure_warning` | An advisory freshness warning (the sequence did not increase over the last one from this sender), else `null`. |

## The capture database

`capture --to <DB>` writes SQLite. The `telegrams` table stores the raw cEMI bytes plus a decoded snapshot, so you can re-decode telegrams after fixing the project:

```sql
CREATE TABLE telegrams (
  id          INTEGER PRIMARY KEY,
  ts_utc      TEXT NOT NULL,     -- RFC3339 UTC
  source      TEXT NOT NULL,     -- IA
  destination TEXT NOT NULL,     -- GA
  apci        TEXT NOT NULL,
  raw_cemi    BLOB NOT NULL,
  decoded     TEXT               -- JSON snapshot at capture time
);
CREATE INDEX idx_telegrams_dest_ts ON telegrams (destination, ts_utc);
```

| Column | Meaning |
|---|---|
| `id` | Row id. |
| `ts_utc` | RFC 3339 UTC timestamp. |
| `source` | The sender's address. |
| `destination` | The destination group address. |
| `apci` | The APCI. |
| `raw_cemi` | The raw cEMI frame. |
| `decoded` | The telegram JSON as decoded at capture time. |

## Related

- [Bus commands](commands/bus.md): `monitor` and `capture` and their flags.
- [Watch the bus](../how-to/watch-the-bus.md): monitor, capture and history in practice.
- [Global options](global-options.md): `--json` and the `schema` field.
