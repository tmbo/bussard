//! The property description reads ETS makes before a load procedure first
//! touches a property it has no type for (issue #1014).
//!
//! Before the first `LdCtrlWriteProp` or `LdCtrlCompareProp` of a property
//! on a connection, ETS sends `A_PropertyDescription_Read` (by index) or
//! `A_PropertyExtDescription_Read` (by type) for it, unless it already knows
//! the property's datatype:
//!
//! - an earlier `LdCtrlDeclarePropDesc` of the procedure declares it, or
//! - the KNX master data (`knx_master.xml`, `<InterfaceObjectProperty>` with
//!   a `PDT`) gives it one: a general property (PID 1 to 30, except 3, 4, 10,
//!   20 and 22, which carry no `PDT` there), or a device object property
//!   (PID 51 to 86) of object index 0 or of object type 0.
//!
//! It reads each property once per connection: a property the procedure
//! touches again after a restart is described again.
//!
//! Evidence: the sweep's plain-defaults captures (ETS 6.4.1 into knx-sim)
//! joined with each application's load procedure, 5232 first accesses with
//! no exception: 3702 declared and 1060 known properties got no read, the
//! 470 others got one (356 writes and 100 compares by index, 9 writes and 5
//! compares by type). `M-0001_A-9A01-03-E6C8` reads object 4 PID 246 before
//! its five compares and PID 206 before its write, not PID 13; a PID 20
//! write (`M-0002_A-A074-20-C1A3` op 3131) gets one although PID 20 is a
//! general property, since the master data gives it no `PDT`;
//! `M-0009_A-20B6-11-52E9` reads object 5 PID 51 in its first and again in
//! its third connection. Which type ETS takes an object index other than 0
//! for, and whether it knows the type-specific properties of an object named
//! by a type other than 0, no capture shows (no undeclared write or compare
//! of such a property); both read the description here.

use std::collections::BTreeSet;

use super::{FlashStep, PropObject};

/// The general properties (any object) the KNX master data gives a `PDT`:
/// PID 1 to 30 without 3 (`PID_SEMAPHOR`), 4 (`PID_GROUP_OBJECT_REFERENCE`),
/// 10, 20 (`PID_ENABLE`) and 22.
fn general_typed(prop_id: u32) -> bool {
    (1..=30).contains(&prop_id) && !matches!(prop_id, 3 | 4 | 10 | 20 | 22)
}

/// The device object properties (object type 0) the KNX master data gives a
/// `PDT`: PID 51 (`PID_ROUTING_COUNT`) to 86.
fn device_typed(prop_id: u32) -> bool {
    (51..=86).contains(&prop_id)
}

/// Whether ETS knows the datatype of `prop_id` of `object` without reading
/// its description (module docs).
pub(super) fn type_known(object: PropObject, prop_id: u32) -> bool {
    general_typed(prop_id)
        || match object {
            PropObject::Index(index) => index == 0 && device_typed(prop_id),
            PropObject::Type { object_type, .. } => object_type == 0 && device_typed(prop_id),
        }
}

/// Whether `step` ends the connection the procedure runs on: the device
/// restarts and the executor connects again.
fn ends_connection(step: &FlashStep) -> bool {
    matches!(
        step,
        FlashStep::Restart
            | FlashStep::MasterReset { .. }
            | FlashStep::FactoryReset { .. }
            | FlashStep::Sys7PreDownloadRestart { .. }
    )
}

/// The property a step reads or writes for which ETS may read a description
/// first: a [`FlashStep::WriteProp`] or a [`FlashStep::CompareProp`].
fn touched(step: &FlashStep) -> Option<(PropObject, u32)> {
    match step {
        FlashStep::WriteProp {
            object, prop_id, ..
        }
        | FlashStep::CompareProp {
            object, prop_id, ..
        } => Some((*object, *prop_id)),
        _ => None,
    }
}

/// `steps` with a [`FlashStep::DescribeProp`] before each first write or
/// compare of a property on a connection that ETS has no type for (module
/// docs). A description the plan already reads (issue #841, or a held step's
/// `describe`, issue #951) counts as read; a held step does not read the
/// description of a property ETS has a type for or already described on the
/// connection.
///
/// Idempotent, and run again on the final step list: after a step removal
/// that ends no connection any more ([`FlashPlan::skip_factory_reset`],
/// [`FlashPlan::skip_sys7_prelude`], [`FlashPlan::use_par_procedure`]) a
/// read the joined connection already made is dropped, and on a
/// parameter-only plan ([`FlashPlan::parameters_only`]) the reads its writes
/// need are put back.
///
/// [`FlashPlan::skip_factory_reset`]: super::FlashPlan::skip_factory_reset
/// [`FlashPlan::skip_sys7_prelude`]: super::FlashPlan::skip_sys7_prelude
/// [`FlashPlan::use_par_procedure`]: super::FlashPlan::use_par_procedure
/// [`FlashPlan::parameters_only`]: super::FlashPlan::parameters_only
pub(super) fn describe_untyped_properties(steps: Vec<FlashStep>) -> Vec<FlashStep> {
    let mut out = Vec::with_capacity(steps.len());
    let mut declared: BTreeSet<(PropObject, u32)> = BTreeSet::new();
    let mut described: BTreeSet<(PropObject, u32)> = BTreeSet::new();
    for mut step in steps {
        if ends_connection(&step) {
            described.clear();
        }
        match &mut step {
            FlashStep::DeclareProp {
                object, prop_id, ..
            } => {
                declared.insert((*object, *prop_id));
            }
            // A second read of a property on one connection goes: the pass
            // runs again after a step removal joins two connections.
            FlashStep::DescribeProp { object, prop_id } => {
                if !described.insert((*object, *prop_id)) {
                    continue;
                }
            }
            FlashStep::FactoryHeldProp {
                object,
                prop_id,
                describe,
                ..
            } if *describe
                && (type_known(*object, *prop_id) || !described.insert((*object, *prop_id))) =>
            {
                *describe = false;
            }
            _ => {}
        }
        if let Some(key) = touched(&step)
            && !declared.contains(&key)
            && !type_known(key.0, key.1)
            && described.insert(key)
        {
            out.push(FlashStep::DescribeProp {
                object: key.0,
                prop_id: key.1,
            });
        }
        out.push(step);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(object: PropObject, prop_id: u32) -> FlashStep {
        FlashStep::WriteProp {
            object,
            prop_id,
            value: vec![1],
            start_element: 1,
            count: 1,
            verify: false,
            from_parameters: false,
        }
    }

    fn compare(object: PropObject, prop_id: u32, start_element: u16) -> FlashStep {
        FlashStep::CompareProp {
            object,
            prop_id,
            expected: Some(vec![1]),
            mask: None,
            start_element,
        }
    }

    fn describe(object: PropObject, prop_id: u32) -> FlashStep {
        FlashStep::DescribeProp { object, prop_id }
    }

    const OBJ4: PropObject = PropObject::Index(4);

    #[test]
    fn test_type_known_general_device_and_untyped() {
        // PID 13 and 27 anywhere, PID 78 of the device object.
        assert!(type_known(OBJ4, 13));
        assert!(type_known(PropObject::Index(4), 27));
        assert!(type_known(PropObject::Index(0), 78));
        assert!(type_known(
            PropObject::Type {
                object_type: 0,
                occurrence: 0
            },
            78
        ));
        // PID 20 has no PDT in the master data; PID 78 means nothing on
        // object 3; a manufacturer PID is never known.
        assert!(!type_known(PropObject::Index(3), 20));
        assert!(!type_known(PropObject::Index(3), 78));
        assert!(!type_known(OBJ4, 206));
        assert!(!type_known(
            PropObject::Type {
                object_type: 11,
                occurrence: 0
            },
            236
        ));
    }

    #[test]
    fn test_describe_untyped_properties_siemens_9a01_shape() {
        // M-0001_A-9A01-03-E6C8: five compares of object 4 PID 246 (one
        // read), one of PID 202 (one read), the write of PID 206 (one read),
        // the program version write (none).
        let steps = vec![
            compare(OBJ4, 246, 1),
            compare(OBJ4, 246, 2),
            compare(OBJ4, 202, 1),
            write(OBJ4, 206),
            write(OBJ4, 13),
            write(OBJ4, 206),
        ];
        let out = describe_untyped_properties(steps);
        assert_eq!(
            out,
            vec![
                describe(OBJ4, 246),
                compare(OBJ4, 246, 1),
                compare(OBJ4, 246, 2),
                describe(OBJ4, 202),
                compare(OBJ4, 202, 1),
                describe(OBJ4, 206),
                write(OBJ4, 206),
                write(OBJ4, 13),
                write(OBJ4, 206),
            ]
        );
    }

    #[test]
    fn test_describe_untyped_properties_declared_after_the_first_write() {
        // M-0009_A-E0EE-10-ADF8: object 12 PID 208 is written once before its
        // declaration (ETS op 33 reads it) and then declared.
        let obj12 = PropObject::Index(12);
        let declare = FlashStep::DeclareProp {
            object: obj12,
            prop_id: 208,
            prop_type: "PDT_GENERIC_01".to_string(),
            max_elements: 46,
        };
        let out = describe_untyped_properties(vec![
            write(obj12, 208),
            declare.clone(),
            write(obj12, 208),
        ]);
        assert_eq!(
            out,
            vec![
                describe(obj12, 208),
                write(obj12, 208),
                declare,
                write(obj12, 208)
            ]
        );
        // A property declared first is never described.
        let obj10 = PropObject::Index(10);
        let declare10 = FlashStep::DeclareProp {
            object: obj10,
            prop_id: 208,
            prop_type: "PDT_GENERIC_01".to_string(),
            max_elements: 8,
        };
        let out = describe_untyped_properties(vec![declare10.clone(), write(obj10, 208)]);
        assert_eq!(out, vec![declare10, write(obj10, 208)]);
    }

    #[test]
    fn test_describe_untyped_properties_once_per_connection() {
        // M-0009_A-20B6-11-52E9 reads object 5 PID 51 in its first and in its
        // third connection.
        let obj5 = PropObject::Index(5);
        let reset = FlashStep::MasterReset {
            erase_code: 5,
            channel_number: 0,
        };
        let out = describe_untyped_properties(vec![
            write(obj5, 51),
            write(obj5, 51),
            reset.clone(),
            write(obj5, 51),
        ]);
        assert_eq!(
            out,
            vec![
                describe(obj5, 51),
                write(obj5, 51),
                write(obj5, 51),
                reset,
                describe(obj5, 51),
                write(obj5, 51),
            ]
        );
    }

    #[test]
    fn test_describe_untyped_properties_keeps_an_existing_read() {
        // The #841 read of a property no value decides, and a held step's
        // read, count as the read.
        let typed = PropObject::Type {
            object_type: 50001,
            occurrence: 0,
        };
        let held = |describe: bool| FlashStep::FactoryHeldProp {
            object: OBJ4,
            prop_id: 206,
            value: vec![1],
            start_element: 1,
            count: 1,
            verify: false,
            from_parameters: false,
            describe,
        };
        let out = describe_untyped_properties(vec![
            describe(typed, 211),
            held(true),
            write(OBJ4, 206),
            held(true),
        ]);
        assert_eq!(
            out,
            vec![
                describe(typed, 211),
                held(true),
                write(OBJ4, 206),
                held(false)
            ]
        );
    }
}
