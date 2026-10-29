//! The KNXnet/IP Secure properties of a KNX IP interface (issue #398): the
//! wire operations that switch IP Secure on and off, as ETS performs them.
//!
//! # Sources
//!
//! - Property ids and data types: the KNX master data an ETS 6 export ships
//!   (`knx_master.xml`, `<InterfaceObjectProperty>` rows `PID-11-91` to
//!   `PID-11-97` and `PID-17-51`, `PID-17-56`, `PID-17-59`, export of
//!   2026-10-26). `PID_SECURED_SERVICE_FAMILIES` and `PID_SECURITY_MODE` are
//!   function properties (`PDT-62`).
//! - Value layouts: the ETS captures of 1.1.200 (Jung IPS 300 SREG,
//!   2026-10-26, `26-10-ipinterface/`), decoded with `tools/knxtrace`:
//!   - a function command carries a reserved octet, a service id octet (0,
//!     "set") and its arguments: `00 00 fam on` for the secured service
//!     families, `00 00 mode` for the security mode. The state response
//!     carries the return code and one octet;
//!   - `PID_PASSWORD_HASHES`: element 0 the element count, element n the
//!     16-octet password key of user id n (1 the management user, 2 and up
//!     the tunnelling users), the key being `PBKDF2-HMAC-SHA256(password,
//!     "user-password.1.secure.ip.knx.org", 65536, 16)`; every entry equals
//!     the key the ETS keyring export derives;
//!   - `PID_DEVICE_AUTHENTICATION_CODE`: the 16-octet key of the code, salt
//!     `device-authentication-code.1.secure.ip.knx.org` (same derivation;
//!     dev/knx-secure-spec.md §3.4);
//!   - `PID_TUNNELLING_USERS`: element 0 the count, then one 2-octet entry per
//!     user, `user id, tunnelling address index`, sorted by user id then
//!     index (KNX IP Secure 3/8/9 §2.3.1.8.3). The index is 1-based into
//!     `PID_TUNNELLING_ADDRESSES` (PID 79), whose element is 0 for the
//!     interface's own address or the 1-based index into
//!     `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES` (PID 53; Device Management 3/8/3
//!     §2.5.29; issue #520). The 1.1.200 capture writes `02 01 03 02 .. 09
//!     08` and the keyring pairs user 2 with the first tunnel address: its
//!     PID 79 is the identity `1..n`;
//!   - the tool key write: the request goes under the key the device holds
//!     (its FDSK in factory state), the confirmation already under the new
//!     key ([`Layer4Connection::request_rekeyed`]).
//!
//! Nothing here prints or logs key material: keys are written, never echoed.

use bussard_secure::Key16;

use crate::connection::{L4Channel, Layer4Connection};
use crate::error::{MgmtError, Result};
use crate::property_ext::{
    A_PROPERTY_EXT_VALUE_WRITE_CON, A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE, PID_SECURITY_MODE,
    PID_SEQUENCE_NUMBER_SENDING, PID_TOOL_KEY, PropertyExtAddress,
    decode_property_ext_write_con_response, encode_property_ext_value_write,
    function_property_ext_command, function_property_ext_state_read, read_property_ext_table,
    write_property_ext_con,
};

/// The KNXnet/IP parameter object type (`OT-11`).
pub const OT_KNXNET_IP_PARAMETER: u16 = 11;
/// `PID_BACKBONE_KEY` (91, write-only key material).
pub const PID_BACKBONE_KEY: u16 = 91;
/// `PID_DEVICE_AUTHENTICATION_CODE` (92, write-only key material).
pub const PID_DEVICE_AUTHENTICATION_CODE: u16 = 92;
/// `PID_PASSWORD_HASHES` (93, array of 16-octet keys, write-only).
pub const PID_PASSWORD_HASHES: u16 = 93;
/// `PID_SECURED_SERVICE_FAMILIES` (94, function property).
pub const PID_SECURED_SERVICE_FAMILIES: u16 = 94;
/// `PID_TUNNELLING_USERS` (97, array of `user id, address index`; the index
/// points into [`PID_TUNNELLING_ADDRESSES`]).
pub const PID_TUNNELLING_USERS: u16 = 97;
/// `PID_TUNNELLING_ADDRESSES` (79, read-only array of one octet: 0 the
/// interface's own address, n the n-th `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`
/// entry; Device Management 3/8/3 §2.5.29).
pub const PID_TUNNELLING_ADDRESSES: u16 = 79;

/// The length of one password hash or key.
pub const KEY_OCTETS: usize = 16;
/// The length of `PID_SEQUENCE_NUMBER_SENDING`.
pub const SEQUENCE_OCTETS: usize = 6;

/// KNXnet/IP service family ids (KNXnet/IP Core, the `SUPP_SVC_FAMILIES` DIB).
pub mod family {
    /// Device management.
    pub const DEVICE_MANAGEMENT: u8 = 0x03;
    /// Tunnelling.
    pub const TUNNELLING: u8 = 0x04;
    /// Routing.
    pub const ROUTING: u8 = 0x05;
}

/// The command data of `PID_SECURITY_MODE`: reserved, service id 0, mode.
pub fn security_mode_command(on: bool) -> [u8; 3] {
    [0x00, 0x00, u8::from(on)]
}

/// The command data of `PID_SECURED_SERVICE_FAMILIES`: reserved, service id
/// 0, the family, on or off.
pub fn secured_family_command(family: u8, on: bool) -> [u8; 4] {
    [0x00, 0x00, family, u8::from(on)]
}

/// The address of a KNXnet/IP parameter object property (instance 1).
pub fn knxnet(property_id: u16) -> PropertyExtAddress {
    PropertyExtAddress {
        object_type: OT_KNXNET_IP_PARAMETER,
        object_instance: 1,
        property_id,
    }
}

/// Switches the security mode (`PID_SECURITY_MODE` of the security object).
///
/// # Errors
///
/// A non-zero return code or a malformed answer, and the connection's errors.
pub async fn set_security_mode<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    on: bool,
) -> Result<()> {
    function_property_ext_command(
        l4,
        PropertyExtAddress::security(PID_SECURITY_MODE),
        &security_mode_command(on),
    )
    .await
    .map(|_| ())
}

/// Reads the security mode with `A_FunctionPropertyExt_State_Read` (data
/// `00 00`, as ETS reads it in the deactivation capture of 1.1.200): `true`
/// when the last octet of the answer is non-zero, `None` when the answer
/// carries no octet.
///
/// # Errors
///
/// A non-zero return code or a malformed answer, and the connection's errors.
pub async fn read_security_mode<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<bool>> {
    let state = function_property_ext_state_read(
        l4,
        PropertyExtAddress::security(PID_SECURITY_MODE),
        &[0x00, 0x00],
    )
    .await?;
    Ok(state.data.last().map(|&b| b != 0))
}

/// Writes a new tool key (`PID_TOOL_KEY`) and continues the connection under
/// it: the request is wrapped under the current key, the confirmation and
/// everything after it under `tool_key`.
///
/// # Errors
///
/// A plain connection, a refused or malformed confirmation, and the
/// connection's errors. After an error the connection holds the new key.
pub async fn write_tool_key<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    tool_key: &Key16,
) -> Result<()> {
    let addr = PropertyExtAddress::security(PID_TOOL_KEY);
    let payload = encode_property_ext_value_write(&addr, 1, 1, tool_key.bytes());
    let (apci, resp) = l4
        .request_rekeyed(A_PROPERTY_EXT_VALUE_WRITE_CON, &payload, tool_key.clone())
        .await?;
    let target = l4.target();
    let malformed = |reason: String| MgmtError::MalformedResponse {
        address: target,
        reason,
    };
    if apci != A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE {
        return Err(malformed(format!(
            "expected A_PropertyExtValue_WriteConResponse to the tool key write, got APCI {apci:#05X}"
        )));
    }
    let conf = decode_property_ext_write_con_response(&resp).ok_or_else(|| {
        malformed("A_PropertyExtValue_WriteConResponse to the tool key write too short".into())
    })?;
    if conf.addr != addr || conf.count != 1 || conf.start != 1 {
        return Err(malformed(format!(
            "the tool key write was confirmed for {} count {} start {}",
            conf.addr, conf.count, conf.start
        )));
    }
    if conf.return_code != 0 {
        return Err(MgmtError::ServiceRejected {
            address: target,
            service: "A_PropertyExtValue_WriteCon",
            target: format!("{addr} (the tool key)"),
            return_code: Some(conf.return_code),
        });
    }
    Ok(())
}

/// Writes the device's Data Secure send sequence (`PID_SEQUENCE_NUMBER_SENDING`,
/// 6 octets), as ETS does right after the tool key.
///
/// # Errors
///
/// As [`write_property_ext_con`].
pub async fn write_sequence_number<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    sequence: u64,
) -> Result<()> {
    let octets = sequence.to_be_bytes();
    write_property_ext_con(
        l4,
        PropertyExtAddress::security(PID_SEQUENCE_NUMBER_SENDING),
        1,
        1,
        &octets[2..],
    )
    .await
}

/// Switches one KNXnet/IP service family secured or plain
/// (`PID_SECURED_SERVICE_FAMILIES`). Takes effect at the next restart.
///
/// # Errors
///
/// A non-zero return code or a malformed answer, and the connection's errors.
pub async fn set_secured_family<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    family: u8,
    on: bool,
) -> Result<()> {
    function_property_ext_command(
        l4,
        knxnet(PID_SECURED_SERVICE_FAMILIES),
        &secured_family_command(family, on),
    )
    .await
    .map(|_| ())
}

/// Writes the device authentication code's key (`PID_DEVICE_AUTHENTICATION_CODE`).
///
/// # Errors
///
/// As [`write_property_ext_con`].
pub async fn write_device_authentication<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    key: &Key16,
) -> Result<()> {
    write_property_ext_con(
        l4,
        knxnet(PID_DEVICE_AUTHENTICATION_CODE),
        1,
        1,
        key.bytes(),
    )
    .await
}

/// Writes the password hashes (`PID_PASSWORD_HASHES`): the element count,
/// then the keys of users 1 to `keys.len()` in one write, as ETS does.
///
/// # Errors
///
/// More than 15 users (the count field of one write) and as
/// [`write_property_ext_con`].
pub async fn write_password_hashes<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    keys: &[Key16],
) -> Result<()> {
    let count = u8::try_from(keys.len())
        .ok()
        .filter(|&n| n > 0 && n <= 15)
        .ok_or_else(|| MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!("refusing to write {} password hashes (1 to 15)", keys.len()),
        })?;
    let addr = knxnet(PID_PASSWORD_HASHES);
    write_property_ext_con(l4, addr, 1, 0, &u16::from(count).to_be_bytes()).await?;
    let mut data = zeroize::Zeroizing::new(Vec::with_capacity(keys.len() * KEY_OCTETS));
    for key in keys {
        data.extend_from_slice(key.bytes());
    }
    write_property_ext_con(l4, addr, count, 1, &data).await
}

/// Writes the tunnelling users (`PID_TUNNELLING_USERS`): the element count,
/// then the `(user id, address index)` entries in one write, as ETS does.
///
/// # Errors
///
/// No entry or more than 15, and as [`write_property_ext_con`].
pub async fn write_tunnelling_users<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    users: &[(u8, u8)],
) -> Result<()> {
    let count = u8::try_from(users.len())
        .ok()
        .filter(|&n| n > 0 && n <= 15)
        .ok_or_else(|| MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "refusing to write {} tunnelling users (1 to 15)",
                users.len()
            ),
        })?;
    let addr = knxnet(PID_TUNNELLING_USERS);
    write_property_ext_con(l4, addr, 1, 0, &u16::from(count).to_be_bytes()).await?;
    let data: Vec<u8> = users.iter().flat_map(|&(u, i)| [u, i]).collect();
    write_property_ext_con(l4, addr, count, 1, &data).await
}

/// Reads `PID_TUNNELLING_ADDRESSES` (PID 79): which addresses the interface
/// uses for tunnelling connections, 0 for its own address and n for the n-th
/// `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES` entry (Device Management 3/8/3
/// §2.5.29). `None` when the device refuses the read or holds no element (it
/// does not serve the property).
///
/// # Errors
///
/// As [`read_property_ext_table`], except a refusal.
pub async fn read_tunnelling_addresses<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<Vec<u8>>> {
    match read_property_ext_table(l4, knxnet(PID_TUNNELLING_ADDRESSES), 1).await {
        Ok(table) if table.is_empty() => Ok(None),
        Ok(table) => Ok(Some(table)),
        Err(MgmtError::ServiceRejected { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Reads the tunnelling users back (`PID_TUNNELLING_USERS`).
///
/// # Errors
///
/// As [`read_property_ext_table`].
pub async fn read_tunnelling_users<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Vec<(u8, u8)>> {
    let raw = read_property_ext_table(l4, knxnet(PID_TUNNELLING_USERS), 2).await?;
    Ok(raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[u, i]| (u, i))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_mode_command_matches_the_capture() {
        // The 1.1.200 activation capture: `00 00 01` switches it on.
        assert_eq!(security_mode_command(true), [0x00, 0x00, 0x01]);
        assert_eq!(security_mode_command(false), [0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_secured_family_command_matches_the_capture() {
        // Activation: routing off, device management on, tunnelling on.
        assert_eq!(
            secured_family_command(family::ROUTING, false),
            [0x00, 0x00, 0x05, 0x00]
        );
        assert_eq!(
            secured_family_command(family::DEVICE_MANAGEMENT, true),
            [0x00, 0x00, 0x03, 0x01]
        );
        assert_eq!(
            secured_family_command(family::TUNNELLING, true),
            [0x00, 0x00, 0x04, 0x01]
        );
    }

    #[test]
    fn test_knxnet_addresses_instance_one_of_object_type_11() {
        let addr = knxnet(PID_TUNNELLING_USERS);
        assert_eq!(addr.encode(), [0x00, 0x0B, 0x00, 0x10, 0x61]);
    }
}
