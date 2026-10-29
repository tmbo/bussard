//! `bussard flash --dry-run --dump-images <dir>`: write the memory images a
//! flash WOULD stream, without touching the bus (the offline conformance
//! oracle, issue #89).
//!
//! The dump is what `scripts/campaign/95-offline-oracle.sh` diffs against the
//! memory an ETS download wrote to the same device (`knxtrace image`). It holds:
//!
//! - `plan.json`: the ordered steps as the pre-flight renders them, and for
//!   every step that streams memory its absolute address where the plan knows
//!   it (System 7 AbsSegments, `WriteMem`), else the target object and offset
//!   (System B `WriteRelMem`: the device chooses the segment base), plus the
//!   segment id, length and SHA-256 (and, for a System 7 segment, its
//!   `write_mode`: `read-compare` or `blind`, issue #133), and the octets a
//!   parameter placement wrote in it (`placed`: count and offset ranges, the
//!   denominator of the oracle's coverage, issue #347); the allocation
//!   records; and the table images with their addresses;
//! - one `.bin` per streamed image with the exact bytes the executor sends
//!   (`0x<addr>.bin` for an absolute write, `obj<N>_<segment>.bin` for a
//!   relative one), and a `.mask.bin` beside it when a System 7 segment masks
//!   device-owned octets;
//! - `table-obj<N>.bin` (System B) or `table-lsm<N>.bin` (System 7).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Context;
use bussard_download::{FlashPlan, FlashStep, ImageRef, trace};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The environment variable that carries the offline oracle's per-run salt
/// (issue #378). When set, each group key table record also lists its
/// entries: the address table index, the group address, and
/// `sha256(salt || key)[:8]`, so `knxtrace imgdiff` can name the group whose
/// key differs. Without it only the whole-chunk hash is written. The salt is
/// never written to the dump.
const ORACLE_SALT_ENV: &str = "BUSSARD_ORACLE_SALT";

/// Octets of one group key table entry: address table index (2) + key (16).
const GROUP_KEY_ENTRY_LEN: usize = 18;

/// The per-entry records of group key table entries: the address table index
/// the device stores, the group address it names, and the salted short hash
/// of the key, never the key.
fn group_key_entries(entries: &[bussard_download::GroupKeyEntry], salt: &str) -> Vec<Value> {
    entries
        .iter()
        .map(|e| {
            let encoded = e.encode();
            let mut salted = salt.as_bytes().to_vec();
            salted.extend_from_slice(&encoded[2..]);
            json!({
                "index": e.address_index,
                "ga": e.group_address.to_string(),
                "key": &sha256_hex(&salted)[..8],
            })
        })
        .collect()
}

/// A segment id reduced to characters safe in a file name.
fn file_safe(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Writes one image file, de-duplicating the name when two steps would
/// collide (the same segment streamed twice). Returns the file name used.
fn write_file(
    dir: &Path,
    used: &mut BTreeSet<String>,
    stem: &str,
    step: usize,
    suffix: &str,
    bytes: &[u8],
) -> anyhow::Result<String> {
    let mut name = format!("{stem}{suffix}");
    if !used.insert(name.clone()) {
        name = format!("{stem}_s{step}{suffix}");
        used.insert(name.clone());
    }
    std::fs::write(dir.join(&name), bytes)
        .with_context(|| format!("writing {}", dir.join(&name).display()))?;
    Ok(name)
}

/// Writes an image (and its System 7 mask, when present) and returns its
/// `plan.json` record.
#[allow(clippy::too_many_arguments)] // one record's worth of distinct fields
fn image_record(
    dir: &Path,
    used: &mut BTreeSet<String>,
    plan: &FlashPlan,
    step: usize,
    stem: &str,
    image: &ImageRef,
    address: Option<u32>,
    object: Option<u32>,
    offset: Option<u32>,
    part: Option<(usize, usize)>,
) -> anyhow::Result<Value> {
    let whole = plan.image_bytes(&image.segment_id).unwrap_or_default();
    // A System 7 allocation that holds a part of its segment's image (issue
    // #413) streams only that part, at its own address: dump the part, its
    // mask and the placements inside it, offsets relative to the part.
    let (start, end) = part.map_or((0, whole.len()), |(at, len)| {
        let start = at.min(whole.len());
        (start, at.saturating_add(len).min(whole.len()))
    });
    let bytes = &whole[start..end];
    let file = write_file(dir, used, stem, step, ".bin", bytes)?;
    let mask_file = match plan.segment_mask(&image.segment_id) {
        Some(mask) => {
            let mask = &mask[start.min(mask.len())..end.min(mask.len())];
            Some(write_file(dir, used, stem, step, ".mask.bin", mask)?)
        }
        None => None,
    };
    // The octets a parameter placement wrote (issue #347): the denominator of
    // the oracle's coverage figure. `null` for a segment no parameter lands in.
    let placed = plan.placed_octets(&image.segment_id).map(|set| {
        let set: BTreeSet<usize> = set.range(start..end).map(|i| i - start).collect();
        let ranges = placed_ranges(&set);
        json!({ "octets": set.len(), "ranges": ranges })
    });
    Ok(json!({
        "segment_id": image.segment_id,
        "image_kind": image.kind.to_string(),
        "address": address,
        "object": object,
        "offset": offset,
        "length": bytes.len(),
        "sha256": sha256_hex(bytes),
        "file": file,
        "mask_file": mask_file,
        "placed": placed,
    }))
}

/// The half-open `[start, end)` offset runs of a set of placed octets.
fn placed_ranges(set: &BTreeSet<usize>) -> Vec<[usize; 2]> {
    let mut ranges: Vec<[usize; 2]> = Vec::new();
    for &i in set {
        match ranges.last_mut() {
            Some(last) if last[1] == i => last[1] = i + 1,
            _ => ranges.push([i, i + 1]),
        }
    }
    ranges
}

/// The `PID_MAX_APDU_LENGTH` the dump assumes when it splits the security
/// object's element writes into telegrams: the reference device of issue #156
/// (Jung 52911ST) advertises 233. The executor uses the negotiated value; the
/// dump has no device, and the offline oracle compares against that capture.
const DUMP_NOMINAL_MAX_APDU: u16 = 233;

/// The wire writes of a Data Secure security-object step as `plan.json`
/// property records (`knxtrace imgdiff` aligns them with ETS's
/// `properties.json`, issue #156). A group key table value is reduced to the
/// same `redacted:<sha256[:8]>` the tool writes, never the key bytes.
///
/// `salt` is the oracle's per-run salt (`BUSSARD_ORACLE_SALT`); with it a
/// group key table record also lists its entries (see `group_key_entries`).
fn security_property_records(step: &FlashStep, salt: Option<&str>) -> Vec<serde_json::Value> {
    use bussard_mgmt::property_ext::{
        OT_SECURITY, PID_GO_SECURITY_FLAGS, PID_GRP_KEY_TABLE,
        PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, PID_SECURITY_LOAD_STATE_CONTROL,
        PROPERTY_EXT_WRITE_OVERHEAD,
    };
    let budget = usize::from(
        DUMP_NOMINAL_MAX_APDU - bussard_mgmt::SECURE_APDU_OVERHEAD - PROPERTY_EXT_WRITE_OVERHEAD,
    );
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // `secret` holds the group key entries behind `bytes` (one per element)
    // when the value is key material: it is then hashed, never written as hex.
    let chunked = |pid: u16,
                   elem: usize,
                   bytes: &[u8],
                   secret: Option<&[bussard_download::GroupKeyEntry]>|
     -> Vec<serde_json::Value> {
        let per = (budget / elem).max(1) * elem;
        bytes
            .chunks(per)
            .enumerate()
            .map(|(i, chunk)| {
                let data = if secret.is_some() {
                    format!("redacted:{}", &sha256_hex(chunk)[..8])
                } else {
                    hex(chunk)
                };
                let mut record = json!({
                    "object_type": OT_SECURITY, "instance": 1, "pid": pid,
                    "start_element": 1 + i * per / elem, "length": chunk.len(), "data": data,
                });
                if let (Some(entries), Some(salt)) = (secret, salt) {
                    let first = i * per / elem;
                    let n = chunk.len() / elem;
                    if let Some(slice) = entries.get(first..first + n) {
                        record["entries"] = json!(group_key_entries(slice, salt));
                    }
                }
                record
            })
            .collect()
    };
    match step {
        FlashStep::SecurityLoadControl { control } => vec![json!({
            "object_type": OT_SECURITY, "instance": 1, "pid": PID_SECURITY_LOAD_STATE_CONTROL,
            "length": 10, "data": hex(&control.encode_full()),
        })],
        FlashStep::SecurityClearAddressTable => vec![json!({
            "object_type": OT_SECURITY, "instance": 1,
            "pid": PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, "start_element": 0, "length": 2,
            "data": "0000",
        })],
        FlashStep::SecuritySenders { entries } => chunked(
            PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
            bussard_download::SecureSenderEntry::LEN,
            &bussard_download::sender_table_bytes(entries),
            None,
        ),
        FlashStep::SecurityGroupKeys { entries } => {
            let table: Vec<u8> = entries.iter().flat_map(|e| e.encode()).collect();
            chunked(
                PID_GRP_KEY_TABLE,
                GROUP_KEY_ENTRY_LEN,
                &table,
                Some(entries),
            )
        }
        FlashStep::SecurityGoFlags { flags } => chunked(PID_GO_SECURITY_FLAGS, 1, flags, None),
        _ => Vec::new(),
    }
}

/// The load-control records of `step` as `plan.json` carries them: the form
/// (`property` with the object index, null when the device resolves it, or
/// `memory` with the LSM and the control address), the event and the octets.
fn load_control_records(plan: &FlashPlan, step: &FlashStep) -> Vec<Value> {
    plan.load_control_records(step)
        .into_iter()
        .map(|rec| {
            let mut out = match rec.form {
                bussard_download::LoadControlForm::Property { object } => {
                    json!({ "form": "property", "object": object })
                }
                bussard_download::LoadControlForm::Memory { lsm, address } => {
                    json!({ "form": "memory", "lsm": lsm, "address": address })
                }
            };
            out["event"] = json!(rec.event);
            out["data"] = json!(
                rec.bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            out
        })
        .collect()
}

/// Writes the dry-run dump for `plan` into `dir` (created if missing).
///
/// `table_images` are the System B table images keyed by object index (1 =
/// address, 2 = association, 3 = group-object), exactly as `plan_flash`
/// received them; a System 7 plan dumps their LSM form instead.
pub fn write_dump(
    dir: &Path,
    device: &str,
    device_mask: u16,
    plan: &FlashPlan,
    table_images: &BTreeMap<u32, Vec<u8>>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let labels = trace(plan);
    let salt = std::env::var(ORACLE_SALT_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    let mut used = BTreeSet::new();
    let mut steps = Vec::with_capacity(plan.steps.len());
    let mut allocations = Vec::new();
    // Where each table image went: System B object index / System 7 LSM →
    // (step number, absolute address when known).
    let mut table_steps: BTreeMap<u32, (usize, Option<u32>)> = BTreeMap::new();
    let mut load_control_count = 0usize;

    for (i, step) in plan.steps.iter().enumerate() {
        let n = i + 1;
        let label = labels.get(i).cloned().unwrap_or_default();
        let mut record = json!({ "index": n, "label": label.trim() });
        // The load-control records the step sends (issue #419), for the
        // oracle's load-control parity.
        let load_controls = load_control_records(plan, step);
        if !load_controls.is_empty() {
            load_control_count += load_controls.len();
            record["load_controls"] = json!(load_controls);
        }
        match step {
            FlashStep::WriteRelMem {
                offset,
                image,
                target,
            } => {
                let obj = target.map_or_else(|| "app".to_string(), |t| t.to_string());
                let stem = format!("obj{obj}_{}", file_safe(&image.segment_id));
                let rec = image_record(
                    dir,
                    &mut used,
                    plan,
                    n,
                    &stem,
                    image,
                    None,
                    *target,
                    Some(*offset),
                    None,
                )?;
                if image.kind == bussard_download::ImageKind::Table
                    && let Some(t) = target
                {
                    table_steps.insert(*t, (n, None));
                }
                record["image"] = rec;
            }
            FlashStep::WriteMem { address, image } => {
                let stem = format!("0x{address:06X}");
                record["image"] = image_record(
                    dir,
                    &mut used,
                    plan,
                    n,
                    &stem,
                    image,
                    Some(*address),
                    None,
                    None,
                    None,
                )?;
            }
            FlashStep::Sys7AbsSegment {
                lsm,
                address,
                size,
                mem_type,
                seg_flags,
                checksum_ctrl,
                image,
                ..
            } => {
                allocations.push(json!({
                    "step": n,
                    "kind": "abs-segment",
                    "lsm": lsm,
                    "address": address,
                    "size": size,
                    "mem_type": mem_type,
                    "access": seg_flags,
                    "checksum_ctrl": checksum_ctrl,
                }));
                if let Some(image) = image {
                    let stem = format!("0x{address:06X}");
                    let whole = plan.image_bytes(&image.segment_id).map_or(0, <[u8]>::len);
                    let part = (image.offset != 0 || image.len != whole)
                        .then_some((image.offset, image.len));
                    record["image"] = image_record(
                        dir,
                        &mut used,
                        plan,
                        n,
                        &stem,
                        image,
                        Some(*address),
                        None,
                        None,
                        part,
                    )?;
                    // How the executor streams it: `read-compare` reads each
                    // chunk and writes only differing ones (a mask without a
                    // Hawk VerifyMode, issue #133), `blind` writes it whole.
                    record["image"]["write_mode"] = json!(if plan.sys7_read_compare() {
                        "read-compare"
                    } else {
                        "blind"
                    });
                    if image.kind == bussard_download::ImageKind::Table {
                        table_steps.insert(*lsm, (n, Some(*address)));
                    }
                }
            }
            FlashStep::AllocateSegment { size, target, fill } => {
                allocations.push(json!({
                    "step": n,
                    "kind": "rel-segment",
                    "object": target,
                    "size": size,
                    "fill": fill.is_some(),
                    "fill_byte": fill,
                }));
            }
            // ETS's verify-mode write (issue #116): on a device that holds 00,
            // as every Jung 0705 capture shows, it writes 04.
            FlashStep::Sys7EnableVerifyMode => {
                record["property"] = json!({
                    "object": bussard_mgmt::apci::DEVICE_OBJECT_INDEX,
                    "pid": bussard_mgmt::PID_DEVICE_CONTROL,
                    "start_element": 1,
                    "length": 1,
                    "data": format!("{:02x}", bussard_mgmt::DEVICE_CONTROL_VERIFY_MODE),
                });
            }
            // A load procedure's property write (issue #390), as the wire
            // carries it: an index-addressed object with the plain service,
            // one named by type with the extended service (instance 1-based).
            // A System B plan keeps the label-only record the oracle rows
            // were recorded with.
            FlashStep::WriteProp {
                object,
                prop_id,
                value,
                start_element,
                count,
                verify,
            } if plan.is_sys7() || plan.is_property_only() => {
                let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
                let mut prop = match object {
                    bussard_download::PropObject::Index(index) => json!({ "object": index }),
                    bussard_download::PropObject::Type {
                        object_type,
                        occurrence,
                    } => json!({
                        "object_type": object_type,
                        "instance": u32::from(*occurrence) + 1,
                    }),
                };
                prop["pid"] = json!(prop_id);
                prop["start_element"] = json!(start_element);
                prop["count"] = json!(count);
                prop["length"] = json!(value.len());
                prop["data"] = json!(hex);
                prop["verify"] = json!(verify);
                prop["source"] = json!("load-procedure");
                record["property"] = prop;
            }
            FlashStep::SecurityLoadControl { .. }
            | FlashStep::SecurityClearAddressTable
            | FlashStep::SecuritySenders { .. }
            | FlashStep::SecurityGroupKeys { .. }
            | FlashStep::SecurityGoFlags { .. } => {
                record["properties"] = json!(security_property_records(step, salt.as_deref()));
            }
            _ => {}
        }
        steps.push(record);
    }

    // The table images, with where they are streamed.
    let mut tables = Vec::new();
    if plan.is_sys7() {
        let lsm_tables = bussard_download::flash::sys7_tables_from_system_b(table_images);
        for (lsm, table) in &lsm_tables {
            let stem = format!("table-lsm{lsm}");
            let file = write_file(dir, &mut used, &stem, 0, ".bin", &table.image)?;
            let mask_file = match &table.mask {
                Some(mask) => Some(write_file(dir, &mut used, &stem, 0, ".mask.bin", mask)?),
                None => None,
            };
            let (step, address) = table_steps.get(lsm).copied().unzip();
            tables.push(json!({
                "name": format!("lsm{lsm}"),
                "lsm": lsm,
                "address": address.flatten(),
                "step": step,
                "length": table.image.len(),
                "sha256": sha256_hex(&table.image),
                "file": file,
                "mask_file": mask_file,
            }));
        }
    } else {
        for (obj, bytes) in table_images {
            let stem = format!("table-obj{obj}");
            let file = write_file(dir, &mut used, &stem, 0, ".bin", bytes)?;
            let step = table_steps.get(obj).map(|(n, _)| *n);
            tables.push(json!({
                "name": format!("obj{obj}"),
                "object": obj,
                // A relative segment: the device picks the base at allocation.
                "address": Value::Null,
                "step": step,
                "length": bytes.len(),
                "sha256": sha256_hex(bytes),
                "file": file,
            }));
        }
    }

    let doc = json!({
        "device": device,
        "device_mask": format!("{device_mask:04X}"),
        "system": if plan.is_sys7() {
            "7"
        } else if plan.is_property_only() {
            "properties"
        } else {
            "B"
        },
        "sys7_segment_write": if plan.is_sys7() {
            json!(if plan.sys7_read_compare() { "read-compare" } else { "blind" })
        } else {
            Value::Null
        },
        "application": {
            "id": plan.identity.id,
            "name": plan.identity.name,
            "number": plan.identity.application_number,
            "version": plan.identity.application_version,
            "mask": plan.identity.mask_version,
        },
        "write_bytes": plan.total_write_bytes(),
        // How many load-control records the steps carry (issue #419); its
        // presence tells the oracle the dump lists them at all.
        "load_control_records": load_control_count,
        "procedure": labels,
        "steps": steps,
        "allocations": allocations,
        "tables": tables,
    });
    let path = dir.join("plan.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc)? + "\n")
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_safe_replaces_separators() {
        assert_eq!(file_safe("M-0004_A-1/RS 04"), "M-0004_A-1_RS_04");
    }

    #[test]
    fn test_placed_ranges_merges_adjacent_offsets() {
        let set: BTreeSet<usize> = [0, 1, 2, 5, 7, 8].into_iter().collect();
        assert_eq!(placed_ranges(&set), vec![[0, 3], [5, 6], [7, 9]]);
        assert!(placed_ranges(&BTreeSet::new()).is_empty());
    }

    #[test]
    fn test_group_key_entries_names_group_and_salts_key() -> anyhow::Result<()> {
        use bussard_download::GroupKeyEntry;
        let entry = |index: u16, ga: &str, fill: u8| -> anyhow::Result<GroupKeyEntry> {
            Ok(GroupKeyEntry {
                address_index: index,
                group_address: ga.parse()?,
                key: bussard_secure::Key16::new([fill; 16]),
            })
        };
        let entries = [entry(2, "0/0/6", 0x11)?, entry(5, "1/2/3", 0x22)?];
        let a = group_key_entries(&entries, "salt-a");
        assert_eq!(a.len(), 2);
        assert_eq!(
            (a[0]["index"].as_u64(), a[0]["ga"].as_str()),
            (Some(2), Some("0/0/6"))
        );
        assert_eq!(a[1]["ga"], "1/2/3");
        let mut salted = b"salt-a".to_vec();
        salted.extend_from_slice(&[0x11; 16]);
        assert_eq!(a[0]["key"], sha256_hex(&salted)[..8]);
        // Never the unsalted hash of the key alone.
        assert_ne!(a[0]["key"], sha256_hex(&[0x11; 16])[..8]);
        let b = group_key_entries(&entries, "salt-b");
        assert_ne!(a[0]["key"], b[0]["key"]);
        Ok(())
    }

    #[test]
    fn test_sha256_hex_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
