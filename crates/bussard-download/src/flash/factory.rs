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
//! device holds whatever an earlier download left. Only one-octet
//! elements are compared (every entry of the corpus is `PDT_UNSIGNED_CHAR` or
//! `PDT_GENERIC_01`): whether an entry's offset counts octets or elements is
//! not known for a wider type.

use super::{FlashStep, PropObject};
use bussard_product::application::ApplicationProgram;

/// Whether a master reset with `erase_code` on `channel` resets every
/// channel's parameters to their default: the factory resets (2, and 7
/// without the individual address) and ResetParam (5) on channel 0, KNX
/// 3/5/2 §3.7.1.2.3, Table 4 (a channel other than 0 resets that channel
/// only).
pub(super) fn resets_parameters(erase_code: u8, channel: u8) -> bool {
    channel == 0 && matches!(erase_code, 2 | 5 | 7)
}

/// Turns `step`, lowered from an `LdCtrlWriteProp` after a reset of the
/// parameters, into a [`FlashStep::FactoryHeldProp`] when the program's
/// `LoadedImage` holds its value; any other step stays. `declared`: a
/// declaration describes the property, so ETS reads no description for it.
pub(super) fn hold_after_reset(step: &mut FlashStep, app: &ApplicationProgram, declared: bool) {
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
    if value.len() != usize::from(*count) {
        return;
    }
    let held = app
        .factory_properties
        .iter()
        .any(|f| f.holds(*index, *prop_id, u32::from(*start_element), value));
    if !held {
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

impl FlashStep {
    /// The step as a download that resets no parameters runs it: a
    /// [`FlashStep::FactoryHeldProp`] is the write it leaves out, every other
    /// step itself. The parameter-only download resets nothing, so the
    /// device may hold another value there.
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

    #[test]
    fn test_resets_parameters_names_the_factory_and_parameter_resets() {
        let resets: Vec<u8> = (0..=8).filter(|c| resets_parameters(*c, 0)).collect();
        assert_eq!(resets, vec![2, 5, 7]);
        assert!(!resets_parameters(5, 1));
    }

    /// E0D1 object 13: element 97 holds `...03` in the image, the parameters
    /// give `...02`: written, as ETS writes it; element 1 holds the value:
    /// left out, with no description read under a declaration.
    #[test]
    fn test_hold_after_reset_leaves_out_only_the_held_value() {
        let app = app(&[(13, 208, 0, &[0, 0, 0, 2]), (13, 208, 96, &[1, 0, 4, 3])]);
        let mut held = write(13, 1, &[0, 0, 0, 2]);
        hold_after_reset(&mut held, &app, true);
        assert_eq!(
            held,
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
        let mut differs = write(13, 97, &[1, 0, 4, 2]);
        hold_after_reset(&mut differs, &app, true);
        assert_eq!(differs, write(13, 97, &[1, 0, 4, 2]));
    }

    /// The image names the property, the start and the length: another
    /// object, start or length is written.
    #[test]
    fn test_hold_after_reset_needs_the_same_property_start_and_length() {
        let app = app(&[(6, 208, 0, &[0x14])]);
        for mut step in [
            write(7, 1, &[0x14]),
            write(6, 2, &[0x14]),
            write(6, 1, &[0x14, 0]),
        ] {
            let before = step.clone();
            hold_after_reset(&mut step, &app, false);
            assert_eq!(step, before);
        }
        let mut undeclared = write(6, 1, &[0x14]);
        hold_after_reset(&mut undeclared, &app, false);
        assert!(matches!(
            undeclared,
            FlashStep::FactoryHeldProp { describe: true, .. }
        ));
    }

    /// A download that resets nothing writes the held value.
    #[test]
    fn test_without_parameter_reset_writes_the_held_value() {
        let app = app(&[(6, 208, 0, &[0x14])]);
        let mut step = write(6, 1, &[0x14]);
        hold_after_reset(&mut step, &app, true);
        assert_eq!(step.without_parameter_reset(), write(6, 1, &[0x14]));
        assert_eq!(
            write(7, 1, &[1]).without_parameter_reset(),
            write(7, 1, &[1])
        );
    }

    /// The mask leaves the bits the image does not define free.
    #[test]
    fn test_hold_after_reset_compares_under_the_mask() {
        let mut app = app(&[(6, 208, 0, &[0x10])]);
        app.factory_properties[0].mask = vec![0xF0];
        let mut step = write(6, 1, &[0x1F]);
        hold_after_reset(&mut step, &app, true);
        assert!(matches!(step, FlashStep::FactoryHeldProp { .. }));
        let mut other = write(6, 1, &[0x2F]);
        hold_after_reset(&mut other, &app, true);
        assert!(matches!(other, FlashStep::WriteProp { .. }));
    }
}
