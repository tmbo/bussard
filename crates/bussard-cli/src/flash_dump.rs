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
//!   `write_mode`: `read-compare` or `blind`, issue #133); the allocation records; and the table
//!   images with their addresses;
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
) -> anyhow::Result<Value> {
    let bytes = plan.image_bytes(&image.segment_id).unwrap_or_default();
    let file = write_file(dir, used, stem, step, ".bin", bytes)?;
    let mask_file = match plan.segment_mask(&image.segment_id) {
        Some(mask) => Some(write_file(dir, used, stem, step, ".mask.bin", mask)?),
        None => None,
    };
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
    }))
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
    let mut used = BTreeSet::new();
    let mut steps = Vec::with_capacity(plan.steps.len());
    let mut allocations = Vec::new();
    // Where each table image went: System B object index / System 7 LSM →
    // (step number, absolute address when known).
    let mut table_steps: BTreeMap<u32, (usize, Option<u32>)> = BTreeMap::new();

    for (i, step) in plan.steps.iter().enumerate() {
        let n = i + 1;
        let label = labels.get(i).cloned().unwrap_or_default();
        let mut record = json!({ "index": n, "label": label.trim() });
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
                )?;
                if image.kind == bussard_download::ImageKind::Table {
                    if let Some(t) = target {
                        table_steps.insert(*t, (n, None));
                    }
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
        "system": if plan.is_sys7() { "7" } else { "B" },
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
    fn test_sha256_hex_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
