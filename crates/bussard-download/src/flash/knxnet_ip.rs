//! The KNXnet/IP parameter object writes of a full download into a TP device
//! with a KNX IP interface built in (issue #455).
//!
//! ETS 6.4.1 writes the device's KNXnet/IP parameter object (interface object
//! type 11) after the application, right before the closing restart. The ETS
//! sweep captured it on every IP-enabled application it downloaded (Zennio
//! ALLinBOX 1612/88/46 and KIPI-RC on mask 07B0, the COMIP2 on 0701), always
//! in this order and with these sources:
//!
//! | PID | name | value |
//! |---|---|---|
//! | 51 | project installation id | `0000` |
//! | 66 | routing multicast address | 224.0.23.12 |
//! | 67 | routing TTL | `20` (32) |
//! | 76 | friendly name | `[knxnet] friendly_name`, 30 octets ISO 8859-1 |
//! | 55 | IP assignment method | `[knxnet] assignment` (`04` DHCP) |
//! | 53 | additional individual addresses | `[knxnet] tunnels`, `AdditionalAddressesCount` of them |
//!
//! PIDs 51, 66 and 67 held the same value in all eleven captures (projects
//! with ETS's default backbone settings); bussard writes those values. The
//! rest comes from the device file's `[knxnet]` table (issue #391): a device
//! whose table is missing, lists another number of tunnels than the
//! application declares, or names no friendly name is refused at plan time,
//! because a download that left the IP side unconfigured would report a
//! success the device does not match. A static assignment is refused too:
//! no capture shows which properties ETS writes for one.
//!
//! The carrier follows the captures. A Data-Secure-capable application
//! (`IsSecureEnabled`, the ALLinBOX v2 2.3 family, 1331-16, 6391-11) gets the
//! extended property services by object type 11, instance 1, with the friendly
//! name in one 30-element write. Any other gets the plain services at the
//! object index ETS uses on its mask (6 on 07B0, 5 on 0701), with the friendly
//! name in writes of 15 elements on 07B0 (the element count is a 4-bit field)
//! and of 10 on 0701 (the COMIP2's 15-octet APDU). The
//! executor first reads `PID_OBJECT_TYPE` there, as ETS does, and looks the
//! object up by type when that index holds another one.
//!
//! The writes go through the property step executor every load procedure
//! uses ([`super::write_property_value`], the `[knxnet]` apply path of #391),
//! each read back right after it is written; `bussard-service` reads them all
//! back again once the device has restarted.

use super::PropObject;
use super::props::{index_of_type, read_property_value, write_property_value};
use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::knxnet::{
    FRIENDLY_NAME_OCTETS, OT_KNXNET_IP_PARAMETER, PID_ADDITIONAL_INDIVIDUAL_ADDRESSES,
    PID_FRIENDLY_NAME, PID_IP_ASSIGNMENT_METHOD, PID_PROJECT_INSTALLATION_ID,
    PID_ROUTING_MULTICAST_ADDRESS, PID_TTL, encode_friendly_name,
};
use bussard_mgmt::load::{WriteError, is_connection_death};
use bussard_model::IndividualAddress;
use bussard_model::knxnet::{IpAssignment, KnxnetConfig};
use bussard_prod::application::ApplicationProgram;

/// `PID_PROJECT_INSTALLATION_ID` as ETS writes it in every sweep capture: no
/// project or installation number (11 captures, 2026-10-28).
pub const ETS_PROJECT_INSTALLATION_ID: [u8; 2] = [0x00, 0x00];

/// `PID_ROUTING_MULTICAST_ADDRESS` as ETS writes it: the KNX default routing
/// multicast address 224.0.23.12 (11 captures, 2026-10-28).
pub const ETS_ROUTING_MULTICAST: [u8; 4] = [224, 0, 23, 12];

/// `PID_TTL` as ETS writes it: 32 (11 captures, 2026-10-28).
pub const ETS_ROUTING_TTL: u8 = 0x20;

/// `PID_OBJECT_TYPE`.
const PID_OBJECT_TYPE: u8 = 1;

/// Where ETS addresses the KNXnet/IP parameter object with the plain
/// services, per mask, and how many friendly-name elements it puts in one
/// write:
///
/// - 07B0: object 6, 15 elements (the most a plain write's 4-bit count
///   carries), as five Zennio sweep captures show (ALLinBOX 1612 1.3, ops
///   1926 to 1934);
/// - 0701: object 5, 10 elements (what an APDU of 15 octets holds, the
///   device's `PID_MAX_APDU_LENGTH`), as the COMIP2 capture shows
///   (`M-00E1_A-A00D-10-12FB-O00C5`).
///
/// `None` on any other mask, whose device is then addressed by type.
fn plain_object(device_mask: u16) -> Option<(u32, u16)> {
    match device_mask {
        0x07B0 => Some((6, 15)),
        0x0701 => Some((5, 10)),
        _ => None,
    }
}

/// One property write of the KNXnet/IP block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxnetIpWrite {
    /// The property id.
    pub prop_id: u8,
    /// The first element written (1-based).
    pub start: u16,
    /// How many elements `value` spans.
    pub count: u16,
    /// The octets written.
    pub value: Vec<u8>,
}

/// The KNXnet/IP parameter object writes of one download: where the object
/// is and what is written to it, in ETS's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxnetIpProgram {
    /// The object: by index (plain services, `PID_OBJECT_TYPE` checked first)
    /// or by type 11 (extended services).
    pub object: PropObject,
    /// The writes, in order.
    pub writes: Vec<KnxnetIpWrite>,
}

/// The KNXnet/IP parameter writes a full download of `app` into `target`
/// makes, from the device file's `[knxnet]` table `config` (see the module
/// docs). `Ok(None)` when the application declares no tunnelling addresses
/// (`AdditionalAddressesCount` absent or 0): the device has no KNX IP
/// interface to configure.
///
/// # Errors
///
/// A sentence naming the value that has no source: no `[knxnet]` table, a
/// tunnel list of another length than the application declares, no or an
/// unencodable friendly name, or a static assignment.
pub fn knxnet_ip_program(
    app: &ApplicationProgram,
    device_mask: u16,
    target: IndividualAddress,
    config: Option<&KnxnetConfig>,
) -> Result<Option<KnxnetIpProgram>, String> {
    let Some(slots) = app.additional_addresses_count.filter(|n| *n > 0) else {
        return Ok(None);
    };
    let what = format!(
        "{} has a KNX IP interface built in ({slots} tunnelling addresses); a full download \
         writes its KNXnet/IP parameters after the application, as ETS does",
        app.id
    );
    let Some(config) = config else {
        return Err(format!(
            "{what}, and devices/{target}.toml has no [knxnet] table to take them from. Add one \
             with `friendly_name` and the {slots} `tunnels`"
        ));
    };
    if config.tunnels.len() != usize::from(slots) {
        return Err(format!(
            "{what}: [knxnet] lists {} tunnel address(es), the application holds {slots}; list \
             exactly {slots}",
            config.tunnels.len()
        ));
    }
    let Some(name) = config.friendly_name.as_deref() else {
        return Err(format!(
            "{what}: [knxnet] has no `friendly_name` to write to PID_FRIENDLY_NAME"
        ));
    };
    let Some(name) = encode_friendly_name(name) else {
        return Err(format!(
            "{what}: [knxnet] friendly_name is longer than 30 characters or not ISO 8859-1"
        ));
    };
    if config.assignment == IpAssignment::Static {
        return Err(format!(
            "{what}: [knxnet] asks for a static address, and no ETS capture shows which \
             properties a download writes for one (issue #455); use assignment = \"dhcp\""
        ));
    }
    let (object, name_chunk) = match plain_object(device_mask) {
        Some((index, chunk)) if !app.is_secure_enabled => (PropObject::Index(index), chunk),
        _ => (
            PropObject::Type {
                object_type: OT_KNXNET_IP_PARAMETER,
                occurrence: 0,
            },
            u16::try_from(FRIENDLY_NAME_OCTETS).unwrap_or(u16::MAX),
        ),
    };
    let one = |prop_id: u8, value: Vec<u8>| KnxnetIpWrite {
        prop_id,
        start: 1,
        count: 1,
        value,
    };
    let mut writes = vec![
        one(
            PID_PROJECT_INSTALLATION_ID,
            ETS_PROJECT_INSTALLATION_ID.to_vec(),
        ),
        one(
            PID_ROUTING_MULTICAST_ADDRESS,
            ETS_ROUTING_MULTICAST.to_vec(),
        ),
        one(PID_TTL, vec![ETS_ROUTING_TTL]),
    ];
    let mut start = 1u16;
    for chunk in name.chunks(usize::from(name_chunk.max(1))) {
        let count = u16::try_from(chunk.len()).unwrap_or(name_chunk);
        writes.push(KnxnetIpWrite {
            prop_id: PID_FRIENDLY_NAME,
            start,
            count,
            value: chunk.to_vec(),
        });
        start = start.saturating_add(count);
    }
    writes.push(one(
        PID_IP_ASSIGNMENT_METHOD,
        vec![config.assignment.method_bits()],
    ));
    writes.push(KnxnetIpWrite {
        prop_id: PID_ADDITIONAL_INDIVIDUAL_ADDRESSES,
        start: 1,
        count: slots,
        value: config
            .tunnels
            .iter()
            .flat_map(|ia| ia.raw().to_be_bytes())
            .collect(),
    });
    Ok(Some(KnxnetIpProgram { object, writes }))
}

/// Writes `program` to the device behind `l4`, each write read back right
/// after it (see the module docs).
///
/// # Errors
///
/// The device has no KNXnet/IP parameter object, refuses a write, or holds
/// another value afterwards; or a transport failure.
pub async fn write_knxnet_ip<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    program: &KnxnetIpProgram,
) -> Result<(), WriteError> {
    let object = resolve_object(l4, program.object).await?;
    for write in &program.writes {
        write_property_value(
            l4,
            object,
            u32::from(write.prop_id),
            write.start,
            write.count,
            &write.value,
            true,
        )
        .await?;
    }
    Ok(())
}

/// The object the writes go to. An index is used when its `PID_OBJECT_TYPE`
/// says 11, as ETS checks before writing (ALLinBOX 1612 capture, op 1926);
/// otherwise the device's object list or walk names the index. An object
/// named by type stays so: the extended services find it.
async fn resolve_object<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
) -> Result<PropObject, WriteError> {
    let PropObject::Index(index) = object else {
        return Ok(object);
    };
    match read_property_value(l4, object, u32::from(PID_OBJECT_TYPE), 1, 1, 2).await {
        Ok(held) if held == OT_KNXNET_IP_PARAMETER.to_be_bytes() => return Ok(object),
        Ok(_) => {}
        Err(err) if is_connection_death(&err) => return Err(err),
        Err(_) => {}
    }
    match index_of_type(l4, OT_KNXNET_IP_PARAMETER, 0).await {
        Ok(found) => Ok(PropObject::Index(u32::from(found))),
        Err(err) if is_connection_death(&err) => Err(err),
        Err(_) => Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "the device has no KNXnet/IP parameter object (interface object type 11) at \
                 object {index} or in its object list, so its [knxnet] settings cannot be \
                 written"
            ),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(count: Option<u16>, secure: bool) -> ApplicationProgram {
        ApplicationProgram {
            id: "M-0071_A-4A11-13-48E1".to_string(),
            additional_addresses_count: count,
            is_secure_enabled: secure,
            ..ApplicationProgram::default()
        }
    }

    fn sweep_config() -> Result<KnxnetConfig, Box<dyn std::error::Error>> {
        Ok(KnxnetConfig {
            friendly_name: Some("ALLinBOX 1612".to_string()),
            tunnels: ["1.1.251", "1.1.252", "1.1.253", "1.1.254", "1.1.255"]
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?,
            ..KnxnetConfig::default()
        })
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The ALLinBOX 1612 1.3 sweep capture (`M-0071_A-4A11-13-48E1`,
    /// plain-defaults, ops 1928 to 1934): obj 6 PIDs 51, 66, 67, 76 (15 + 15),
    /// 55 and 53, with the values knx-sim logged.
    #[test]
    fn test_knxnet_ip_program_matches_the_allinbox_capture()
    -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.1".parse()?;
        let config = sweep_config()?;
        let program = knxnet_ip_program(&app(Some(5), false), 0x07B0, target, Some(&config))?
            .ok_or("an IP-enabled application gets the writes")?;
        assert_eq!(program.object, PropObject::Index(6));
        let shape: Vec<(u8, u16, u16, String)> = program
            .writes
            .iter()
            .map(|w| (w.prop_id, w.start, w.count, hex(&w.value)))
            .collect();
        assert_eq!(
            shape,
            [
                (51, 1, 1, "0000".to_string()),
                (66, 1, 1, "e000170c".to_string()),
                (67, 1, 1, "20".to_string()),
                (76, 1, 15, "414c4c696e424f5820313631320000".to_string()),
                (76, 16, 15, "00".repeat(15)),
                (55, 1, 1, "04".to_string()),
                (53, 1, 5, "11fb11fc11fd11fe11ff".to_string()),
            ]
        );
        Ok(())
    }

    /// A Data-Secure-capable application (ALLinBOX 88 v2 2.3
    /// `M-0071_A-4A61-23-2BEB`, ops 2592 to 2597): the extended services by
    /// type 11, the friendly name in one 30-element write.
    #[test]
    fn test_knxnet_ip_program_secure_application_goes_by_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.1".parse()?;
        let config = sweep_config()?;
        let program = knxnet_ip_program(&app(Some(5), true), 0x07B0, target, Some(&config))?
            .ok_or("writes")?;
        assert_eq!(
            program.object,
            PropObject::Type {
                object_type: 11,
                occurrence: 0
            }
        );
        let pids: Vec<(u8, u16)> = program
            .writes
            .iter()
            .map(|w| (w.prop_id, w.count))
            .collect();
        assert_eq!(
            pids,
            [(51, 1), (66, 1), (67, 1), (76, 30), (55, 1), (53, 5)]
        );
        Ok(())
    }

    /// The COMIP2 (mask 0701, `M-00E1_A-A00D-10-12FB-O00C5`): object 5, the
    /// friendly name in three writes of 10.
    #[test]
    fn test_knxnet_ip_program_mask_0701_object_5_in_tens() -> Result<(), Box<dyn std::error::Error>>
    {
        let target: IndividualAddress = "1.1.1".parse()?;
        let config = sweep_config()?;
        let program = knxnet_ip_program(&app(Some(5), false), 0x0701, target, Some(&config))?
            .ok_or("writes")?;
        assert_eq!(program.object, PropObject::Index(5));
        let names: Vec<(u16, u16)> = program
            .writes
            .iter()
            .filter(|w| w.prop_id == 76)
            .map(|w| (w.start, w.count))
            .collect();
        assert_eq!(names, [(1, 10), (11, 10), (21, 10)]);
        Ok(())
    }

    #[test]
    fn test_knxnet_ip_program_none_without_tunnelling_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.1".parse()?;
        assert_eq!(
            knxnet_ip_program(&app(None, false), 0x07B0, target, None)?,
            None
        );
        assert_eq!(
            knxnet_ip_program(&app(Some(0), false), 0x07B0, target, None)?,
            None
        );
        Ok(())
    }

    #[test]
    fn test_knxnet_ip_program_refuses_a_value_without_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.1".parse()?;
        let ip = app(Some(5), false);
        let err = knxnet_ip_program(&ip, 0x07B0, target, None)
            .err()
            .ok_or("no table")?;
        assert!(err.contains("no [knxnet] table"), "{err}");
        let mut short = sweep_config()?;
        short.tunnels.truncate(2);
        let err = knxnet_ip_program(&ip, 0x07B0, target, Some(&short))
            .err()
            .ok_or("two tunnels")?;
        assert!(err.contains("lists 2 tunnel"), "{err}");
        let mut unnamed = sweep_config()?;
        unnamed.friendly_name = None;
        let err = knxnet_ip_program(&ip, 0x07B0, target, Some(&unnamed))
            .err()
            .ok_or("no name")?;
        assert!(err.contains("friendly_name"), "{err}");
        let mut fixed = sweep_config()?;
        fixed.assignment = IpAssignment::Static;
        let err = knxnet_ip_program(&ip, 0x07B0, target, Some(&fixed))
            .err()
            .ok_or("static")?;
        assert!(err.contains("static"), "{err}");
        Ok(())
    }
}
