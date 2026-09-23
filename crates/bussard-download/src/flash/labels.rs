//! Human labels for flash steps: the progress line and the dry-run [`trace`].

use super::{FlashPlan, FlashStep};

/// A `" (LsmIdx/ObjIdx N)"` suffix for a step label, naming the object index the
/// op targets, or empty when it targets the discovered application object.
pub(super) fn target_suffix(target: Option<u32>) -> String {
    match target {
        Some(idx) if idx != 0 => format!(" (obj {idx})"),
        _ => " (app object)".to_string(),
    }
}

/// A short human label for a step, for the progress line and the dry-run trace.
pub(super) fn step_label(step: &FlashStep) -> String {
    match step {
        FlashStep::Unload { target } => format!("unload{}", target_suffix(*target)),
        FlashStep::StartLoading { target } => {
            format!("open for loading{}", target_suffix(*target))
        }
        FlashStep::AllocateSegment { size, target, fill } => {
            let fill_note = match fill {
                Some(b) => format!(", fill 0x{b:02X}"),
                None => String::new(),
            };
            format!(
                "allocate segment ({size} bytes{fill_note}){}",
                target_suffix(*target)
            )
        }
        FlashStep::WriteRelMem {
            offset,
            image,
            target,
        } => {
            format!(
                "write {} image ({} bytes) at segment+{offset}{}",
                image.kind,
                image.len,
                target_suffix(*target)
            )
        }
        FlashStep::WriteMem { address, image } => {
            format!(
                "write {} image ({} bytes) at {address:#010X}",
                image.kind, image.len
            )
        }
        FlashStep::WriteProp {
            obj_idx,
            obj_type,
            prop_id,
            value,
            start_element,
        } => {
            format!(
                "write property (object {obj_idx}, type {obj_type}, PID {prop_id}, {} byte(s) from element {start_element})",
                value.len()
            )
        }
        FlashStep::CompareProp {
            obj_idx,
            prop_id,
            expected,
            ..
        } => match expected {
            Some(bytes) => format!(
                "verify property (object {obj_idx}, PID {prop_id} == {} byte(s))",
                bytes.len()
            ),
            None => format!("verify property (object {obj_idx}, PID {prop_id}, range — skipped)"),
        },
        FlashStep::CompareRelMem {
            target,
            offset,
            expected,
            invert,
            ..
        } => match expected {
            Some(bytes) => format!(
                "verify relative memory (segment+{offset}{} {} {} byte(s))",
                target_suffix(*target),
                if *invert { "!=" } else { "==" },
                bytes.len()
            ),
            None => format!(
                "verify relative memory (segment+{offset}{}, no data — skipped)",
                target_suffix(*target)
            ),
        },
        FlashStep::LoadImageProp {
            obj_idx,
            prop_id,
            image,
            ..
        } => match image {
            Some(img) => format!(
                "verify image (object {obj_idx}, PID {prop_id} MCB CRC over {} bytes)",
                img.len
            ),
            None => format!("read image MCB (object {obj_idx}, PID {prop_id})"),
        },
        FlashStep::LoadCompleted { target } => {
            format!("complete load{}", target_suffix(*target))
        }
        FlashStep::Restart => "restart device".to_string(),
        FlashStep::FactoryReset { erase_code } => format!(
            "factory reset (A_Restart master reset, erase code {erase_code}): erase application, \
             parameters and links, keep the individual address; reconnect"
        ),
        FlashStep::MasterReset {
            erase_code,
            channel_number,
        } => format!(
            "master reset (erase code {erase_code}, channel {channel_number}) — reconnect and resume"
        ),
        FlashStep::Sys7Unload { lsm } => format!("[S7] unload LSM {lsm}"),
        FlashStep::Sys7StartLoading { lsm } => format!("[S7] open LSM {lsm} for loading"),
        FlashStep::Sys7AbsSegment {
            lsm,
            address,
            size,
            image,
            ..
        } => match image {
            Some(img) => format!(
                "[S7] alloc + stream segment ({} bytes) to {address:#06X} on LSM {lsm}",
                img.len
            ),
            None => format!("[S7] alloc segment ({size} bytes) at {address:#06X} on LSM {lsm}"),
        },
        FlashStep::Sys7TaskSegment {
            lsm,
            address,
            marker,
        } => {
            format!("[S7] finalize LSM {lsm} task segment at {address:#06X} (marker {marker:02X?})")
        }
        FlashStep::Sys7TaskCtrl1 {
            lsm,
            address,
            count,
        } => format!("[S7] task control 1 at {address:#06X} x{count} on LSM {lsm}"),
        FlashStep::Sys7LoadCompleted { lsm } => format!("[S7] complete load of LSM {lsm}"),
        FlashStep::Sys7CompareMem { address, expected } => format!(
            "[S7] verify memory at {address:#06X} == {} byte(s)",
            expected.len()
        ),
    }
}

/// Renders a plan's step list as a dry-run trace: one line per step, in order.
/// Used by the CLI pre-flight and the env-gated golden trace test to prove the
/// interpreter digests a real vendor procedure without touching a device.
pub fn trace(plan: &FlashPlan) -> Vec<String> {
    plan.steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{:>3}. {}", i + 1, plan.step_label(s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::plan::plan_flash;
    use crate::flash::test_support::{fabricated_app, no_overrides};
    use std::collections::BTreeMap;

    #[test]
    fn trace_renders_every_step() {
        let app = fabricated_app();
        let plan = plan_flash(
            &app,
            "1.1.4",
            0x07B0,
            &no_overrides(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let lines = trace(&plan);
        assert_eq!(lines.len(), plan.steps.len());
        assert!(lines[0].contains("unload"));
        assert!(lines.last().unwrap().contains("restart"));
    }
}
