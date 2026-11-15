//! Property writes the device holds already after its parameters are reset
//! (issue #951).
//!
//! The catalogue's `Hardware2Program/@LoadedImage` lists, for six Hager
//! programs of the sweep corpus, the property values the device holds when
//! its parameters are at their factory state
//! ([`bussard_product::ApplicationProgram::factory_properties`]). Their load
//! procedures reset the parameters (`LdCtrlMasterReset EraseCode="5"`) and
//! then write those properties, and ETS sends only the writes whose value
//! differs from the image, each whole as the op names it. The `plain-defaults`
//! sweep captures (`captures/ets-sweep/<application>/plain-defaults/ops.txt`):
//!
//! - `M-0009_A-E0D0-11-434F` and `A-E0D2-11-6B74`: no write at all; every one
//!   of their 11 and 9 writes holds the image's value at the defaults (the
//!   repeat captures of 2026-11-08 show the same).
//! - `M-0009_A-E0D1-11-99AD` and `A-E0D3-12-35BF`: 24 of 71 and 69 writes, the
//!   elements 97 to 104 and 141 to 158 of the twelve thermostat objects, where
//!   the image holds `...0003` and `02...` and the parameters `...0002` and
//!   `00...` (ops 35 to 106 of E0D1).
//! - `M-0009_A-E0EE-10-ADF8`: only the count-less `ObjIdx="12"
//!   StartElement="16"` (`count=1 index=16`, the image holds `00`, the
//!   parameter `01`, op 34).
//!
//! The newer generation of the same products (`M-0009_A-E801-13-F381`,
//! `A-E802-13-7620`), with the same parameter placements, carries no
//! `LoadedImage`, and ETS sends every write. A write ETS leaves out is still
//! preceded by the description read ETS makes before any write to a property
//! no `LdCtrlDeclarePropDesc` describes (`M-0009_A-E0D0-11-434F` op 34, the
//! first write to object 6).
//!
//! bussard leaves a write out only after a reset of every channel's
//! parameters in the same procedure ([`resets_parameters`]): without one the
//! device holds whatever an earlier download left. A write of the procedure
//! after the reset changes what the device holds, so a later write to the
//! same elements is always sent ([`DeviceImage`]). A value the image leaves
//! partly undefined (a mask bit of 0) is not held. The executor reads every
//! held property and writes it as before when the device holds something
//! else or does not answer, so a device (or knx-sim, #1012) whose reset does
//! not restore the image still ends with the model's value. Only one-octet
//! elements are compared (every entry of the corpus is `PDT_UNSIGNED_CHAR` or
//! `PDT_GENERIC_01`): whether an entry's offset counts octets or elements is
//! not known for a wider type.

use std::collections::{BTreeMap, BTreeSet};

use super::{FlashStep, PropObject};
use bussard_product::application::ApplicationProgram;

/// Whether a master reset with `erase_code` on `channel` resets every
/// channel's parameters to their default: the factory reset without the
/// individual address (7) and ResetParam (5) on channel 0 (the factory reset
/// 2 is refused at plan time, issue #1065), KNX
/// 3/5/2 §3.7.1.2.3, Table 4 (a channel other than 0 resets that channel
/// only).
pub(super) fn resets_parameters(erase_code: u8, channel: u8) -> bool {
    channel == 0
        && bussard_mgmt::apci::EraseCode::from_code(erase_code)
            .is_some_and(bussard_mgmt::apci::EraseCode::resets_parameters)
}

/// What the procedure has done to the device's properties so far, as the
/// planner walks it: whether a reset of every channel's parameters ran, and
/// which elements a write sent since (issue #951). The device holds the
/// `LoadedImage` value of an element only while no write of the procedure
/// has touched it since the reset.
#[derive(Debug, Default)]
pub(super) struct DeviceImage {
    /// A reset of every channel's parameters ran ([`resets_parameters`]).
    reset: bool,
    /// The elements (1-based) written since that reset, per object index and
    /// PID.
    written: BTreeMap<(u32, u32), BTreeSet<u32>>,
}

impl DeviceImage {
    /// Records an `LdCtrlMasterReset` with `erase_code` on `channel`: one
    /// that resets every channel's parameters puts the image's values back
    /// and forgets the writes before it.
    pub(super) fn master_reset(&mut self, erase_code: u8, channel: u8) {
        if resets_parameters(erase_code, channel) {
            self.reset = true;
            self.written.clear();
        }
    }

    /// Settles `step`, lowered from an `LdCtrlWriteProp`: a write whose
    /// value the device holds (a reset ran, no write of the procedure
    /// touched its elements since, and the program's `LoadedImage` holds the
    /// value) becomes a [`FlashStep::FactoryHeldProp`]; any other write is
    /// sent and marks its elements as written, so a later write to them is
    /// always sent. `declared`: a declaration describes the property, so ETS
    /// reads no description for it.
    pub(super) fn settle(
        &mut self,
        step: &mut FlashStep,
        app: &ApplicationProgram,
        declared: bool,
    ) {
        let FlashStep::WriteProp {
            object: PropObject::Index(index),
            prop_id,
            value,
            start_element,
            count,
            verify,
            from_parameters,
        } = step
        else {
            return;
        };
        let elements = u32::from(*start_element)..u32::from(*start_element) + u32::from(*count);
        let key = (*index, *prop_id);
        let untouched = self
            .written
            .get(&key)
            .is_none_or(|w| elements.clone().all(|e| !w.contains(&e)));
        // One octet per element: whether an entry's offset counts octets or
        // elements is not known for a wider type (module docs).
        let held = self.reset
            && untouched
            && value.len() == usize::from(*count)
            && app
                .factory_properties
                .iter()
                .any(|f| f.holds(*index, *prop_id, u32::from(*start_element), value));
        if !held {
            self.written.entry(key).or_default().extend(elements);
            return;
        }
        *step = FlashStep::FactoryHeldProp {
            object: PropObject::Index(*index),
            prop_id: *prop_id,
            value: std::mem::take(value),
            start_element: *start_element,
            count: *count,
            verify: *verify,
            from_parameters: *from_parameters,
            describe: !declared,
        };
    }
}

/// The first property value a parameter reset of `steps` undoes (issue
/// #1065), in words with its reset's step: `resets` lists each Master
/// Reset's index in `steps` and its procedure step number. A reset of every
/// channel's parameters ([`resets_parameters`]) puts what the program's
/// `LoadedImage` defines back. So the last value a sent write gave an
/// element before the reset (since the previous parameter reset) is undone
/// when an octet of it overlaps a `LoadedImage` entry and differs in a bit
/// the entry defines (its mask), and no write after the reset sends the
/// element again. Element `e` of a write of `count` elements spans the
/// octets `(e - 1) * size` on, `size` = value length / count, as the
/// coverage check counts them; a write whose value does not split into its
/// elements is left out. Equal octets, undefined bits and octets no entry
/// covers do not count: what a reset does to those is not known, and the
/// flash's read-back compares them.
pub(super) fn reverted_write(
    steps: &[FlashStep],
    resets: &[(usize, usize)],
    app: &ApplicationProgram,
) -> Option<String> {
    let elements = |step: &FlashStep| -> Vec<((u32, u32, u32), Vec<u8>)> {
        let FlashStep::WriteProp {
            object: PropObject::Index(index),
            prop_id,
            value,
            start_element,
            count,
            ..
        } = step
        else {
            return Vec::new();
        };
        let count = usize::from(*count);
        if count == 0 || value.is_empty() || !value.len().is_multiple_of(count) {
            return Vec::new();
        }
        value
            .chunks(value.len() / count)
            .enumerate()
            .map(|(k, octets)| {
                (
                    (*index, *prop_id, u32::from(*start_element) + k as u32),
                    octets.to_vec(),
                )
            })
            .collect()
    };
    let mut since = 0usize;
    for &(at, step_no) in resets {
        let Some(FlashStep::MasterReset {
            erase_code,
            channel_number,
        }) = steps.get(at)
        else {
            continue;
        };
        if !resets_parameters(*erase_code, *channel_number) {
            continue;
        }
        let mut last: BTreeMap<(u32, u32, u32), Vec<u8>> = BTreeMap::new();
        for step in steps.get(since..at).unwrap_or_default() {
            last.extend(elements(step));
        }
        since = at + 1;
        let rewritten: BTreeSet<(u32, u32, u32)> = steps
            .get(at + 1..)
            .unwrap_or_default()
            .iter()
            .flat_map(|s| elements(s).into_iter().map(|(k, _)| k))
            .collect();
        for ((index, prop_id, element), octets) in &last {
            if rewritten.contains(&(*index, *prop_id, *element)) {
                continue;
            }
            let size = octets.len();
            let first = (*element as usize).saturating_sub(1) * size;
            let undone = app
                .factory_properties
                .iter()
                .filter(|f| f.object == *index && f.prop_id == *prop_id)
                .any(|f| {
                    let entry = usize::try_from(f.start)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(size);
                    octets.iter().enumerate().any(|(k, written)| {
                        let Some(at) = (first + k).checked_sub(entry) else {
                            return false;
                        };
                        let Some(held) = f.data.get(at) else {
                            return false;
                        };
                        let defined = match f.mask.get(at) {
                            Some(m) => *m,
                            None if f.mask.is_empty() => 0xFF,
                            None => 0,
                        };
                        (held ^ written) & defined != 0
                    })
                });
            if undone {
                let hex: String = octets.iter().map(|b| format!("{b:02X}")).collect();
                return Some(format!(
                    "the Master Reset with EraseCode {erase_code} (step {step_no}) resets the \
                     parameters and so undoes the property write before it (object {index} PID \
                     {prop_id} element {element} = {hex}): the program's LoadedImage restores \
                     another value there"
                ));
            }
        }
    }
    None
}

/// A property write of a plan, sent or held, borrowed
/// ([`FlashStep::property_write`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyWrite<'a> {
    /// The interface object.
    pub object: PropObject,
    /// The property id.
    pub prop_id: u32,
    /// The value the model gives the elements.
    pub value: &'a [u8],
    /// The 1-based first element.
    pub start_element: u16,
    /// How many elements `value` spans.
    pub count: u16,
    /// The op's `Verify`.
    pub verify: bool,
    /// The value comes from the program's property-located parameters.
    pub from_parameters: bool,
    /// The full flash leaves it out as held after the parameter reset.
    pub held: bool,
}

impl FlashStep {
    /// The property write a [`FlashStep::WriteProp`] or a
    /// [`FlashStep::FactoryHeldProp`] stands for, borrowed; `None` for any
    /// other step.
    pub fn property_write(&self) -> Option<PropertyWrite<'_>> {
        match self {
            FlashStep::WriteProp {
                object,
                prop_id,
                value,
                start_element,
                count,
                verify,
                from_parameters,
            } => Some(PropertyWrite {
                object: *object,
                prop_id: *prop_id,
                value,
                start_element: *start_element,
                count: *count,
                verify: *verify,
                from_parameters: *from_parameters,
                held: false,
            }),
            FlashStep::FactoryHeldProp {
                object,
                prop_id,
                value,
                start_element,
                count,
                verify,
                from_parameters,
                ..
            } => Some(PropertyWrite {
                object: *object,
                prop_id: *prop_id,
                value,
                start_element: *start_element,
                count: *count,
                verify: *verify,
                from_parameters: *from_parameters,
                held: true,
            }),
            _ => None,
        }
    }

    /// The step as a download that resets no parameters runs it: a
    /// [`FlashStep::FactoryHeldProp`] is the write it leaves out, every other
    /// step itself. A parameter-only download cut from the complete one
    /// resets nothing, so the device may hold another value there; one run
    /// by the mask's `par` procedure keeps the procedure's own reset and
    /// its held writes as they are (issue #1052).
    pub fn without_parameter_reset(&self) -> FlashStep {
        match self {
            FlashStep::FactoryHeldProp {
                object,
                prop_id,
                value,
                start_element,
                count,
                verify,
                from_parameters,
                ..
            } => FlashStep::WriteProp {
                object: *object,
                prop_id: *prop_id,
                value: value.clone(),
                start_element: *start_element,
                count: *count,
                verify: *verify,
                from_parameters: *from_parameters,
            },
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_product::FactoryProperty;

    /// A write of `value` (`count` elements from `start`) to object 9 PID 60.
    fn write_60(start: u16, count: u16, value: &[u8]) -> FlashStep {
        FlashStep::WriteProp {
            object: PropObject::Index(9),
            prop_id: 60,
            value: value.to_vec(),
            start_element: start,
            count,
            verify: false,
            from_parameters: false,
        }
    }

    fn reset(erase_code: u8) -> FlashStep {
        FlashStep::MasterReset {
            erase_code,
            channel_number: 0,
        }
    }

    /// The program whose LoadedImage holds `data` for object 9 PID 60 from
    /// element 1, with `mask`.
    fn image(data: &[u8], mask: &[u8]) -> ApplicationProgram {
        ApplicationProgram {
            factory_properties: vec![FactoryProperty {
                object: 9,
                prop_id: 60,
                start: 0,
                data: data.to_vec(),
                mask: mask.to_vec(),
            }],
            ..Default::default()
        }
    }

    /// `steps` with every Master Reset numbered by its index.
    fn reverted(steps: &[FlashStep], app: &ApplicationProgram) -> Option<String> {
        let resets: Vec<(usize, usize)> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, FlashStep::MasterReset { .. }))
            .map(|(i, _)| (i, i + 1))
            .collect();
        reverted_write(steps, &resets, app)
    }

    /// A parameter reset undoes a written octet that overlaps a
    /// `LoadedImage` entry and differs in a bit it defines (issue #1065),
    /// also inside a longer entry; equal, undefined and uncovered octets do
    /// not count.
    #[test]
    fn test_reverted_write_compares_overlapping_defined_octets() {
        let full = image(&[1, 2, 3, 4], &[]);
        assert_eq!(reverted(&[write_60(3, 1, &[3]), reset(5)], &full), None);
        let err = reverted(&[write_60(3, 1, &[9]), reset(5)], &full).unwrap_or_default();
        assert!(err.contains("object 9 PID 60 element 3 = 09"), "{err}");
        assert!(err.contains("EraseCode 5 (step 2)"), "{err}");
        // Past the entry: not described, kept.
        assert_eq!(reverted(&[write_60(5, 1, &[9]), reset(5)], &full), None);
        // A bit the entry leaves undefined does not count.
        let low = image(&[1, 2, 3, 4], &[0xFF, 0xFF, 0x0F, 0xFF]);
        assert_eq!(reverted(&[write_60(3, 1, &[0x93]), reset(5)], &low), None);
        assert!(reverted(&[write_60(3, 1, &[0x94]), reset(5)], &low).is_some());
        // A reset of the links resets no parameter.
        assert_eq!(reverted(&[write_60(3, 1, &[9]), reset(6)], &full), None);
    }

    /// Element 2 of a property with 2-octet elements spans octets 2 and 3.
    #[test]
    fn test_reverted_write_scales_by_the_element_size() {
        let app = image(&[0, 0, 0xAB, 0xCD], &[]);
        assert_eq!(
            reverted(&[write_60(2, 1, &[0xAB, 0xCD]), reset(5)], &app),
            None
        );
        assert!(reverted(&[write_60(2, 1, &[0x11, 0x22]), reset(5)], &app).is_some());
        // A value that does not split into its elements is left out.
        assert_eq!(
            reverted(&[write_60(2, 2, &[0x11, 0x22, 0x33]), reset(5)], &app),
            None
        );
    }

    /// What the writes leave counts, not each write (issue #1065): a later
    /// write of the LoadedImage value before the reset, or a write of the
    /// element after it, keeps the plan.
    #[test]
    fn test_reverted_write_judges_what_the_writes_leave() {
        let app = image(&[0x0F], &[]);
        assert_eq!(
            reverted(
                &[write_60(1, 1, &[0x0A]), write_60(1, 1, &[0x0F]), reset(5)],
                &app
            ),
            None
        );
        assert_eq!(
            reverted(
                &[write_60(1, 1, &[0x0A]), reset(5), write_60(1, 1, &[0x0A])],
                &app
            ),
            None
        );
        assert!(
            reverted(
                &[write_60(1, 1, &[0x0F]), write_60(1, 1, &[0x0A]), reset(5)],
                &app
            )
            .is_some()
        );
    }

    fn app(held: &[(u32, u32, u32, &[u8])]) -> ApplicationProgram {
        ApplicationProgram {
            factory_properties: held
                .iter()
                .map(|(object, prop_id, start, data)| FactoryProperty {
                    object: *object,
                    prop_id: *prop_id,
                    start: *start,
                    data: data.to_vec(),
                    mask: Vec::new(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn write(index: u32, start_element: u16, value: &[u8]) -> FlashStep {
        FlashStep::WriteProp {
            object: PropObject::Index(index),
            prop_id: 208,
            value: value.to_vec(),
            start_element,
            count: value.len() as u16,
            verify: false,
            from_parameters: true,
        }
    }

    /// A device image after an erase code 5 reset.
    fn after_reset() -> DeviceImage {
        let mut image = DeviceImage::default();
        image.master_reset(5, 0);
        image
    }

    /// `step` settled on a fresh image after the reset.
    fn settled(step: FlashStep, app: &ApplicationProgram, declared: bool) -> FlashStep {
        let mut step = step;
        after_reset().settle(&mut step, app, declared);
        step
    }

    #[test]
    fn test_resets_parameters_names_the_factory_and_parameter_resets() {
        let resets: Vec<u8> = (0..=8).filter(|c| resets_parameters(*c, 0)).collect();
        // 2 resets the parameters too, but never reaches a plan (refused,
        // issue #1065).
        assert_eq!(resets, vec![2, 5, 7]);
        assert!(!resets_parameters(5, 1));
    }

    /// E0D1 object 13: element 97 holds `...03` in the image, the parameters
    /// give `...02`: written, as ETS writes it; element 1 holds the value:
    /// left out, with no description read under a declaration.
    #[test]
    fn test_settle_leaves_out_only_the_held_value() {
        let app = app(&[(13, 208, 0, &[0, 0, 0, 2]), (13, 208, 96, &[1, 0, 4, 3])]);
        assert_eq!(
            settled(write(13, 1, &[0, 0, 0, 2]), &app, true),
            FlashStep::FactoryHeldProp {
                object: PropObject::Index(13),
                prop_id: 208,
                value: vec![0, 0, 0, 2],
                start_element: 1,
                count: 4,
                verify: false,
                from_parameters: true,
                describe: false,
            }
        );
        assert_eq!(
            settled(write(13, 97, &[1, 0, 4, 2]), &app, true),
            write(13, 97, &[1, 0, 4, 2])
        );
    }

    /// The image names the property, the start and the length: another
    /// object, start or length is written.
    #[test]
    fn test_settle_needs_the_same_property_start_and_length() {
        let app = app(&[(6, 208, 0, &[0x14])]);
        for step in [
            write(7, 1, &[0x14]),
            write(6, 2, &[0x14]),
            write(6, 1, &[0x14, 0]),
        ] {
            assert_eq!(settled(step.clone(), &app, false), step);
        }
        assert!(matches!(
            settled(write(6, 1, &[0x14]), &app, false),
            FlashStep::FactoryHeldProp { describe: true, .. }
        ));
    }

    /// Without a reset of every channel's parameters the device holds what
    /// an earlier download left: nothing is held.
    #[test]
    fn test_settle_holds_nothing_without_a_parameter_reset() {
        let app = app(&[(6, 208, 0, &[0x14])]);
        for (erase, channel) in [(6, 0), (5, 1), (1, 0)] {
            let mut image = DeviceImage::default();
            image.master_reset(erase, channel);
            let mut step = write(6, 1, &[0x14]);
            image.settle(&mut step, &app, true);
            assert_eq!(
                step,
                write(6, 1, &[0x14]),
                "erase code {erase} channel {channel}"
            );
        }
    }

    /// Review of #1011: an earlier write of the procedure to the same
    /// elements leaves its value on the device, so a later write of the
    /// image's value is sent; a reset after it puts the image back.
    #[test]
    fn test_settle_sends_a_write_to_elements_written_before() {
        let app = app(&[(6, 208, 0, &[1, 2])]);
        let mut image = after_reset();
        let mut first = write(6, 2, &[9]);
        image.settle(&mut first, &app, true);
        assert_eq!(first, write(6, 2, &[9]));
        let mut later = write(6, 1, &[1, 2]);
        image.settle(&mut later, &app, true);
        assert_eq!(later, write(6, 1, &[1, 2]));
        // Another property's write does not count.
        let mut image = after_reset();
        let mut other = write(7, 1, &[1, 2]);
        image.settle(&mut other, &app, true);
        let mut held = write(6, 1, &[1, 2]);
        image.settle(&mut held, &app, true);
        assert!(matches!(held, FlashStep::FactoryHeldProp { .. }));
        // A reset after the write puts the image's value back.
        let mut image = after_reset();
        let mut first = write(6, 1, &[9, 9]);
        image.settle(&mut first, &app, true);
        image.master_reset(5, 0);
        let mut again = write(6, 1, &[1, 2]);
        image.settle(&mut again, &app, true);
        assert!(matches!(again, FlashStep::FactoryHeldProp { .. }));
    }

    /// A download that resets nothing writes the held value; the view
    /// borrows either step.
    #[test]
    fn test_without_parameter_reset_writes_the_held_value() {
        let app = app(&[(6, 208, 0, &[0x14])]);
        let held = settled(write(6, 1, &[0x14]), &app, true);
        assert_eq!(held.without_parameter_reset(), write(6, 1, &[0x14]));
        assert_eq!(
            write(7, 1, &[1]).without_parameter_reset(),
            write(7, 1, &[1])
        );
        let view = held
            .property_write()
            .ok_or("a held write is a property write");
        assert!(matches!(
            view,
            Ok(PropertyWrite {
                held: true,
                value: [0x14],
                ..
            })
        ));
        assert!(FlashStep::Restart.property_write().is_none());
    }

    /// Review of #1011: an image bit the mask leaves undefined is not held;
    /// the write goes out.
    #[test]
    fn test_settle_writes_a_value_the_mask_leaves_undefined() {
        let mut app = app(&[(6, 208, 0, &[0x10])]);
        app.factory_properties[0].mask = vec![0xF0];
        assert_eq!(
            settled(write(6, 1, &[0x10]), &app, true),
            write(6, 1, &[0x10])
        );
    }
}
