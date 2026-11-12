//! The KNXnet/IP settings of a KNX IP interface or router (issue #391): the
//! `[knxnet]` table of its device file (what the user means) and the values
//! read off its KNXnet/IP parameter object (interface object type 11), which
//! are device facts, not model state.
//!
//! ```toml
//! [knxnet]
//! assignment = "dhcp"            # or "static"
//! address = "192.0.2.74"       # static only
//! netmask = "255.255.255.0"      # static only
//! gateway = "192.168.1.1"        # static only
//! friendly_name = "Demohouse Alpha"
//! tunnels = ["1.1.22", "1.1.23"]
//! ```
//!
//! The read side lives in `bussard_mgmt::knxnet`; this module holds the shapes,
//! the validation rules (E043 to E046) and the decoding of the raw values into
//! [`KnxnetFacts`]. Nothing here touches KNXnet/IP Secure: no device
//! authentication code, management password or tool key is ever part of
//! either shape.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::address::IndividualAddress;

/// The length of the friendly name the device stores (`PID_FRIENDLY_NAME`, 30
/// octets of ISO 8859-1).
pub const FRIENDLY_NAME_MAX: usize = 30;

/// How the interface gets its IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpAssignment {
    /// From a DHCP server (the ETS default).
    #[default]
    Dhcp,
    /// The static `address`, `netmask` and `gateway` of the table.
    Static,
}

impl IpAssignment {
    /// The word the device file uses.
    pub fn label(self) -> &'static str {
        match self {
            IpAssignment::Dhcp => "dhcp",
            IpAssignment::Static => "static",
        }
    }

    /// The `PID_IP_ASSIGNMENT_METHOD` bit of this method: manual 0x01, DHCP
    /// 0x04 (KNX standard 3/8/3).
    pub fn method_bits(self) -> u8 {
        match self {
            IpAssignment::Dhcp => METHOD_DHCP,
            IpAssignment::Static => METHOD_MANUAL,
        }
    }

    /// The model's method for the bits a device reports: manual alone is
    /// static, any bits with DHCP is dhcp, anything else (BootP, AutoIP alone,
    /// nothing) has no model spelling.
    pub fn from_method_bits(bits: u8) -> Option<IpAssignment> {
        if bits & METHOD_DHCP != 0 {
            Some(IpAssignment::Dhcp)
        } else if bits == METHOD_MANUAL {
            Some(IpAssignment::Static)
        } else {
            None
        }
    }
}

/// `PID_IP_ASSIGNMENT_METHOD` bit: manual (static).
pub const METHOD_MANUAL: u8 = 0x01;
/// `PID_IP_ASSIGNMENT_METHOD` bit: BootP.
pub const METHOD_BOOTP: u8 = 0x02;
/// `PID_IP_ASSIGNMENT_METHOD` bit: DHCP.
pub const METHOD_DHCP: u8 = 0x04;
/// `PID_IP_ASSIGNMENT_METHOD` bit: AutoIP.
pub const METHOD_AUTOIP: u8 = 0x08;

/// The names of the assignment-method bits set in `bits`, in bit order
/// (`["dhcp", "autoip"]`).
pub fn method_names(bits: u8) -> Vec<&'static str> {
    [
        (METHOD_MANUAL, "manual"),
        (METHOD_BOOTP, "bootp"),
        (METHOD_DHCP, "dhcp"),
        (METHOD_AUTOIP, "autoip"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

/// The names of the `PID_KNXNETIP_DEVICE_CAPABILITIES` bits set in `bits`
/// (KNX standard 3/8/3): device management, tunnelling, routing, remote
/// logging, remote configuration and diagnosis, object server.
pub fn capability_names(bits: u16) -> Vec<&'static str> {
    [
        (0x0001, "device management"),
        (0x0002, "tunnelling"),
        (0x0004, "routing"),
        (0x0008, "remote logging"),
        (0x0010, "remote configuration"),
        (0x0020, "object server"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

/// The `PID_KNXNETIP_DEVICE_STATE` reading (KNX standard 3/8/3): bit 0 is a
/// KNX (bus) fault, bit 1 an IP fault; `ok` when neither is set.
pub fn state_label(bits: u8) -> String {
    let mut faults = Vec::new();
    if bits & 0x01 != 0 {
        faults.push("KNX fault");
    }
    if bits & 0x02 != 0 {
        faults.push("IP fault");
    }
    if faults.is_empty() {
        "ok".to_string()
    } else {
        faults.join(", ")
    }
}

/// The `[knxnet]` table of a device file: the KNXnet/IP settings the user
/// wants on the interface. Intent only; what the device reports is
/// [`KnxnetFacts`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnxnetConfig {
    /// How the interface gets its address.
    #[serde(default)]
    pub assignment: IpAssignment,
    /// The static address (`static` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
    /// The static netmask (`static` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Ipv4Addr>,
    /// The static default gateway (`static` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    /// The friendly name (`PID_FRIENDLY_NAME`, at most 30 ISO 8859-1
    /// characters). Absent: bussard leaves the device's name alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    /// The tunnelling addresses (`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`), in
    /// slot order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<IndividualAddress>,
}

/// What a device's KNXnet/IP parameter object reported, decoded (a device
/// fact, kept in `.bussard/facts/<ia>.toml`, issue #391). A property the
/// device did not serve is absent.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnxnetFacts {
    /// When the values were read, RFC 3339 UTC.
    pub read_at: String,
    /// The object index the values were read from, when read by index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_index: Option<u8>,
    /// `PID_KNX_INDIVIDUAL_ADDRESS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub individual_address: Option<IndividualAddress>,
    /// `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`, in slot order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<IndividualAddress>,
    /// `PID_CURRENT_IP_ASSIGNMENT_METHOD`, as method names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_assignment: Option<Vec<String>>,
    /// `PID_IP_ASSIGNMENT_METHOD`, as method names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment: Option<Vec<String>>,
    /// The model spelling of `PID_IP_ASSIGNMENT_METHOD`, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_mode: Option<IpAssignment>,
    /// `PID_CURRENT_IP_ADDRESS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_address: Option<Ipv4Addr>,
    /// `PID_CURRENT_SUBNET_MASK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_netmask: Option<Ipv4Addr>,
    /// `PID_CURRENT_DEFAULT_GATEWAY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_gateway: Option<Ipv4Addr>,
    /// `PID_IP_ADDRESS` (the configured static address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
    /// `PID_SUBNET_MASK`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Ipv4Addr>,
    /// `PID_DEFAULT_GATEWAY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    /// `PID_MAC_ADDRESS`, `00:00:5E:00:53:7D`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// `PID_SYSTEM_SETUP_MULTICAST_ADDRESS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_setup_multicast: Option<Ipv4Addr>,
    /// `PID_ROUTING_MULTICAST_ADDRESS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_multicast: Option<Ipv4Addr>,
    /// `PID_TTL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    /// `PID_KNXNETIP_DEVICE_CAPABILITIES`, as capability names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// `PID_KNXNETIP_DEVICE_STATE`, `ok` or the faults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// `PID_FRIENDLY_NAME`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

impl KnxnetFacts {
    /// The `[knxnet]` table that describes the device as read: the configured
    /// method (DHCP when the device reports none the model spells), the static
    /// settings when static, the friendly name and the tunnels. What `adopt`
    /// writes into a new device file.
    pub fn as_config(&self) -> KnxnetConfig {
        let assignment = self.assignment_mode.unwrap_or_default();
        let static_ = assignment == IpAssignment::Static;
        KnxnetConfig {
            assignment,
            address: self.address.filter(|_| static_),
            netmask: self.netmask.filter(|_| static_),
            gateway: self.gateway.filter(|_| static_),
            friendly_name: self.friendly_name.clone().filter(|n| !n.is_empty()),
            tunnels: self.tunnels.clone(),
        }
    }

    /// The lines `status` and `describe` print, one fact each, in a fixed
    /// order: `("IP address", "192.0.2.74 (dhcp)")`.
    pub fn lines(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(addr) = self.current_address {
            let how = self
                .current_assignment
                .as_ref()
                .filter(|m| !m.is_empty())
                .map(|m| format!(" ({})", m.join(", ")))
                .unwrap_or_default();
            out.push(("IP address", format!("{addr}{how}")));
        }
        if let Some(mask) = self.current_netmask {
            out.push(("netmask", mask.to_string()));
        }
        if let Some(gw) = self.current_gateway {
            out.push(("gateway", gw.to_string()));
        }
        if let Some(methods) = &self.assignment {
            out.push(("assignment", methods.join(", ")));
        }
        if self.assignment_mode == Some(IpAssignment::Static) {
            let fmt = |a: Option<Ipv4Addr>| a.map_or("-".to_string(), |a| a.to_string());
            out.push((
                "static",
                format!(
                    "{} / {} via {}",
                    fmt(self.address),
                    fmt(self.netmask),
                    fmt(self.gateway)
                ),
            ));
        }
        if let Some(mac) = &self.mac {
            out.push(("MAC", mac.clone()));
        }
        if let Some(name) = &self.friendly_name {
            out.push(("friendly name", name.clone()));
        }
        if let Some(ia) = self.individual_address {
            out.push(("KNX address", ia.to_string()));
        }
        if !self.tunnels.is_empty() {
            out.push(("tunnels", join_addresses(&self.tunnels)));
        }
        if let Some(mc) = self.routing_multicast {
            out.push(("routing multicast", mc.to_string()));
        }
        if let Some(caps) = &self.capabilities {
            out.push(("capabilities", caps.join(", ")));
        }
        if let Some(state) = &self.state {
            out.push(("state", state.clone()));
        }
        out
    }

    /// The differences between `config` (the device file) and these facts,
    /// one sentence each (`friendly name: "Alpha" in your project, "Beta" on the
    /// device`). Only fields both sides carry are compared.
    pub fn drift(&self, config: &KnxnetConfig) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(mode) = self.assignment_mode
            && mode != config.assignment
        {
            out.push(format!(
                "assignment: {} in your project, {} on the device",
                config.assignment.label(),
                mode.label()
            ));
        }
        if config.assignment == IpAssignment::Static {
            for (what, want, have) in [
                ("address", config.address, self.address),
                ("netmask", config.netmask, self.netmask),
                ("gateway", config.gateway, self.gateway),
            ] {
                if let (Some(want), Some(have)) = (want, have)
                    && want != have
                {
                    out.push(format!(
                        "{what}: {want} in your project, {have} on the device"
                    ));
                }
            }
        }
        if let (Some(want), Some(have)) = (&config.friendly_name, &self.friendly_name)
            && want != have
        {
            out.push(format!(
                "friendly name: {want:?} in your project, {have:?} on the device"
            ));
        }
        if config.tunnels != self.tunnels {
            out.push(format!(
                "tunnels: {} in your project, {} on the device",
                list_or_none(&config.tunnels),
                list_or_none(&self.tunnels)
            ));
        }
        out
    }
}

/// `1.1.22, 1.1.23`.
pub fn join_addresses(list: &[IndividualAddress]) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// [`join_addresses`], or `none`.
fn list_or_none(list: &[IndividualAddress]) -> String {
    if list.is_empty() {
        "none".to_string()
    } else {
        join_addresses(list)
    }
}

/// Formats a MAC address as `00:00:5E:00:53:7D`.
pub fn format_mac(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// One rule violation of a `[knxnet]` table: the code and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxnetIssue {
    /// `E043` to `E046`.
    pub code: &'static str,
    /// The sentence.
    pub message: String,
}

/// Checks the `[knxnet]` table of `device` (an interface at `device`)
/// against itself and the model's device addresses (`devices`):
///
/// - **E043**: the table contradicts itself: `static` without `address` or
///   `netmask`, static settings under `dhcp`, or a friendly name that is not
///   at most 30 ISO 8859-1 characters;
/// - **E044**: a tunnel address appears twice, or is the interface's own;
/// - **E045**: a tunnel address is outside the interface's line;
/// - **E046**: a tunnel address is a device of the model.
pub fn check_config<'a>(
    device: IndividualAddress,
    config: &KnxnetConfig,
    devices: impl IntoIterator<Item = &'a IndividualAddress>,
) -> Vec<KnxnetIssue> {
    let mut out = Vec::new();
    let mut e043 = |message: String| {
        out.push(KnxnetIssue {
            code: "E043",
            message,
        })
    };
    match config.assignment {
        IpAssignment::Static => {
            if config.address.is_none() {
                e043("assignment = \"static\" needs `address`".to_string());
            }
            if config.netmask.is_none() {
                e043("assignment = \"static\" needs `netmask`".to_string());
            }
        }
        IpAssignment::Dhcp => {
            let set: Vec<&str> = [
                ("address", config.address.is_some()),
                ("netmask", config.netmask.is_some()),
                ("gateway", config.gateway.is_some()),
            ]
            .into_iter()
            .filter(|(_, set)| *set)
            .map(|(k, _)| k)
            .collect();
            if !set.is_empty() {
                e043(format!(
                    "{} only apply to assignment = \"static\"; with \"dhcp\" the DHCP server \
                     decides (the address in use is a device fact: `bussard status {device}`)",
                    set.join(", ")
                ));
            }
        }
    }
    if let Some(name) = &config.friendly_name {
        let chars = name.chars().count();
        if chars > FRIENDLY_NAME_MAX {
            e043(format!(
                "friendly_name has {chars} characters; the device stores at most \
                 {FRIENDLY_NAME_MAX}"
            ));
        }
        if name.chars().any(|c| u32::from(c) > 0xFF) {
            e043(
                "friendly_name holds a character outside ISO 8859-1 (Latin-1), which the \
                 device cannot store"
                    .to_string(),
            );
        }
    }
    let mut seen: BTreeMap<IndividualAddress, usize> = BTreeMap::new();
    for ia in &config.tunnels {
        *seen.entry(*ia).or_default() += 1;
    }
    for (ia, n) in &seen {
        if *n > 1 {
            out.push(KnxnetIssue {
                code: "E044",
                message: format!("tunnel address {ia} is listed {n} times"),
            });
        }
    }
    if seen.contains_key(&device) {
        out.push(KnxnetIssue {
            code: "E044",
            message: format!("tunnel address {device} is the interface's own address"),
        });
    }
    for ia in seen.keys() {
        if (ia.area(), ia.line()) != (device.area(), device.line()) {
            out.push(KnxnetIssue {
                code: "E045",
                message: format!(
                    "tunnel address {ia} is not on the interface's line {}.{}",
                    device.area(),
                    device.line()
                ),
            });
        }
    }
    let taken: std::collections::BTreeSet<&IndividualAddress> = devices.into_iter().collect();
    for ia in seen.keys() {
        if *ia != device && taken.contains(ia) {
            out.push(KnxnetIssue {
                code: "E046",
                message: format!(
                    "tunnel address {ia} is the address of a device in your project \
                     (devices/{ia}.toml)"
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn codes(issues: &[KnxnetIssue]) -> Vec<&'static str> {
        issues.iter().map(|i| i.code).collect()
    }

    fn base() -> Result<KnxnetConfig, Box<dyn std::error::Error>> {
        Ok(KnxnetConfig {
            assignment: IpAssignment::Dhcp,
            friendly_name: Some("Demohouse Alpha".to_string()),
            tunnels: vec![ia("1.1.22")?, ia("1.1.23")?],
            ..KnxnetConfig::default()
        })
    }

    #[test]
    fn test_check_config_clean_table_has_no_issue() -> TestResult {
        let devices = [ia("1.1.200")?, ia("1.1.5")?];
        assert!(check_config(ia("1.1.200")?, &base()?, &devices).is_empty());
        Ok(())
    }

    #[test]
    fn test_check_config_static_without_address_is_e043() -> TestResult {
        let mut c = base()?;
        c.assignment = IpAssignment::Static;
        assert_eq!(
            codes(&check_config(ia("1.1.200")?, &c, &[])),
            ["E043", "E043"]
        );
        c.address = Some(Ipv4Addr::new(192, 0, 2, 74));
        c.netmask = Some(Ipv4Addr::new(255, 255, 255, 0));
        assert!(check_config(ia("1.1.200")?, &c, &[]).is_empty());
        Ok(())
    }

    #[test]
    fn test_check_config_static_fields_under_dhcp_is_e043() -> TestResult {
        let mut c = base()?;
        c.gateway = Some(Ipv4Addr::new(192, 168, 1, 1));
        let issues = check_config(ia("1.1.200")?, &c, &[]);
        assert_eq!(codes(&issues), ["E043"]);
        assert!(issues[0].message.contains("gateway"));
        Ok(())
    }

    #[test]
    fn test_check_config_friendly_name_limits_are_e043() -> TestResult {
        let mut c = base()?;
        c.friendly_name = Some("x".repeat(31));
        assert_eq!(codes(&check_config(ia("1.1.200")?, &c, &[])), ["E043"]);
        c.friendly_name = Some("Küche €".to_string());
        assert_eq!(codes(&check_config(ia("1.1.200")?, &c, &[])), ["E043"]);
        c.friendly_name = Some("Küche".to_string());
        assert!(check_config(ia("1.1.200")?, &c, &[]).is_empty());
        Ok(())
    }

    #[test]
    fn test_check_config_duplicate_tunnel_is_e044() -> TestResult {
        let mut c = base()?;
        c.tunnels.push(ia("1.1.22")?);
        assert_eq!(codes(&check_config(ia("1.1.200")?, &c, &[])), ["E044"]);
        c.tunnels = vec![ia("1.1.200")?];
        assert_eq!(codes(&check_config(ia("1.1.200")?, &c, &[])), ["E044"]);
        Ok(())
    }

    #[test]
    fn test_check_config_tunnel_off_line_is_e045() -> TestResult {
        let mut c = base()?;
        c.tunnels.push(ia("1.2.30")?);
        let issues = check_config(ia("1.1.200")?, &c, &[]);
        assert_eq!(codes(&issues), ["E045"]);
        assert!(issues[0].message.contains("1.2.30"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn test_check_config_tunnel_on_a_device_is_e046() -> TestResult {
        let c = base()?;
        let devices = [ia("1.1.200")?, ia("1.1.23")?];
        let issues = check_config(ia("1.1.200")?, &c, &devices);
        assert_eq!(codes(&issues), ["E046"]);
        assert!(issues[0].message.contains("1.1.23"));
        Ok(())
    }

    #[test]
    fn test_ip_assignment_from_method_bits() {
        assert_eq!(
            IpAssignment::from_method_bits(0x01),
            Some(IpAssignment::Static)
        );
        assert_eq!(
            IpAssignment::from_method_bits(0x04),
            Some(IpAssignment::Dhcp)
        );
        assert_eq!(
            IpAssignment::from_method_bits(0x0C),
            Some(IpAssignment::Dhcp)
        );
        assert_eq!(IpAssignment::from_method_bits(0x02), None);
        assert_eq!(method_names(0x0C), ["dhcp", "autoip"]);
        assert_eq!(IpAssignment::Static.method_bits(), 0x01);
    }

    #[test]
    fn test_knxnet_facts_as_config_and_drift() -> TestResult {
        let facts = KnxnetFacts {
            read_at: "2026-10-26T10:00:00Z".to_string(),
            assignment_mode: Some(IpAssignment::Dhcp),
            current_address: Some(Ipv4Addr::new(192, 0, 2, 74)),
            address: Some(Ipv4Addr::new(10, 0, 0, 5)),
            friendly_name: Some("Alpha".to_string()),
            tunnels: vec![ia("1.1.22")?],
            ..KnxnetFacts::default()
        };
        let config = facts.as_config();
        assert_eq!(config.assignment, IpAssignment::Dhcp);
        assert_eq!(config.address, None, "a dhcp table carries no address");
        assert_eq!(config.friendly_name.as_deref(), Some("Alpha"));
        assert!(facts.drift(&config).is_empty());
        let mut want = config.clone();
        want.tunnels.push(ia("1.1.23")?);
        want.friendly_name = Some("Beta".to_string());
        let drift = facts.drift(&want);
        assert_eq!(drift.len(), 2, "{drift:?}");
        assert!(drift[1].contains("1.1.22, 1.1.23 in your project, 1.1.22 on the device"));
        Ok(())
    }

    #[test]
    fn test_state_and_capability_labels() {
        assert_eq!(state_label(0), "ok");
        assert_eq!(state_label(3), "KNX fault, IP fault");
        assert_eq!(
            capability_names(0x0003),
            ["device management", "tunnelling"]
        );
        assert_eq!(
            format_mac(&[0, 0, 0x5E, 0, 0x53, 0x7D]),
            "00:00:5E:00:53:7D"
        );
    }
}
