//! Device identity as `bussard.lock` records it, and the comparison with what
//! a device reports (lock v2, issue #228).
//!
//! The application id a device reports in `PID_PROGRAM_VERSION` is five
//! octets: the manufacturer id (2), the application number (2) and the
//! application version (1). An ETS application ref encodes the same three
//! numbers: `M-0004_A-D141-22-151B` is manufacturer `0004`, application number
//! `D141`, version `22` (hex), so the lock can name the id every device must
//! report without reading the product data.

use serde::{Deserialize, Serialize};

use crate::schema::Device;

/// The application id (`PID_PROGRAM_VERSION` as ten hex digits, `0004D14122`)
/// and the `ApplicationVersion` an ETS application ref encodes, or `None` when
/// the ref does not have the `M-xxxx_A-yyyy-vv-...` shape.
pub fn application_id_from_ref(application_ref: &str) -> Option<(String, u32)> {
    let rest = application_ref.strip_prefix("M-")?;
    let (manufacturer, rest) = rest.split_once("_A-")?;
    let mut parts = rest.split('-');
    let number = parts.next()?;
    let version = parts.next()?;
    let hex4 = |s: &str| s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit());
    if !hex4(manufacturer) || !hex4(number) {
        return None;
    }
    if version.len() != 2 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let version_number = u32::from_str_radix(version, 16).ok()?;
    Some((
        format!("{manufacturer}{number}{version}").to_ascii_uppercase(),
        version_number,
    ))
}

/// The identity `bussard.lock` pins for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LockIdentity {
    /// The mask version, four hex digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    /// The application program ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// The application id the device must report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// The `[[product]]` hash the device's application comes from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_sha256: Option<String>,
}

impl LockIdentity {
    /// The identity the lock pins for `device`: the lock-side application
    /// (the device file may override it) and its id.
    pub fn of(device: &Device) -> Self {
        let product = device.product.as_ref();
        let application = device
            .lock
            .application
            .clone()
            .or_else(|| product.and_then(|p| p.application_ref.clone()));
        let application_id = device.lock.application_id.clone().or_else(|| {
            application
                .as_deref()
                .and_then(application_id_from_ref)
                .map(|(id, _)| id)
        });
        Self {
            mask: product.and_then(|p| p.mask.clone()),
            application,
            application_id,
            product_sha256: device.lock.product_sha256.clone(),
        }
    }

    /// Whether the lock pins nothing to compare with.
    pub fn is_empty(&self) -> bool {
        self.mask.is_none() && self.application_id.is_none()
    }
}

/// What a device reported about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReportedIdentity {
    /// The mask version from the device descriptor, four hex digits.
    pub mask: String,
    /// The application id (`PID_PROGRAM_VERSION`), when read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
}

/// The verdict of comparing a device with its lock entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityVerdict {
    /// Everything the lock pins and the device reported agrees.
    Match,
    /// The device reports another mask or application id than the lock pins.
    Drift,
    /// The model has no device there, or its lock entry pins nothing.
    Unmodelled,
}

/// A device's identity compared with its lock entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCheck {
    /// What the lock pins (`None` for a device the model does not hold).
    pub lock: Option<LockIdentity>,
    /// What the device reported.
    pub device: ReportedIdentity,
    /// The verdict.
    pub verdict: IdentityVerdict,
    /// One sentence per disagreement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differences: Vec<String>,
}

impl IdentityCheck {
    /// Compares what a device reported with what the lock pins for it.
    ///
    /// A mask of `FFFF` (a Data Secure device read without its tool key) and
    /// an unread application id compare as unknown, never as drift.
    pub fn compare(device: Option<&Device>, reported: ReportedIdentity) -> Self {
        let lock = device.map(LockIdentity::of);
        let Some(pinned) = lock.as_ref().filter(|l| !l.is_empty()) else {
            return Self {
                lock,
                device: reported,
                verdict: IdentityVerdict::Unmodelled,
                differences: Vec::new(),
            };
        };
        let mut differences = Vec::new();
        if let Some(mask) = &pinned.mask
            && !reported.mask.eq_ignore_ascii_case("FFFF")
            && !reported.mask.eq_ignore_ascii_case(mask)
        {
            differences.push(format!(
                "the device reports mask {} but the lock pins {mask}",
                reported.mask
            ));
        }
        if let (Some(pinned_id), Some(device_id)) =
            (&pinned.application_id, &reported.application_id)
            && !device_id.eq_ignore_ascii_case(pinned_id)
        {
            differences.push(format!(
                "the device reports application id {device_id} but the lock pins {pinned_id}{}",
                pinned
                    .application
                    .as_deref()
                    .map(|a| format!(" ({a})"))
                    .unwrap_or_default()
            ));
        }
        let verdict = if differences.is_empty() {
            IdentityVerdict::Match
        } else {
            IdentityVerdict::Drift
        };
        Self {
            lock,
            device: reported,
            verdict,
            differences,
        }
    }

    /// One sentence for a text report.
    pub fn summary(&self) -> String {
        match self.verdict {
            IdentityVerdict::Match => {
                let pinned = self.lock.as_ref();
                let id = pinned
                    .and_then(|l| l.application_id.as_deref())
                    .map(|id| format!("application id {id}"));
                let mask = pinned
                    .and_then(|l| l.mask.as_deref())
                    .map(|m| format!("mask {m}"));
                let what: Vec<String> = id.into_iter().chain(mask).collect();
                format!("matches bussard.lock ({})", what.join(", "))
            }
            IdentityVerdict::Drift => {
                format!("drift from bussard.lock: {}", self.differences.join("; "))
            }
            IdentityVerdict::Unmodelled => "not pinned in bussard.lock".to_string(),
        }
    }

    /// Whether the device disagrees with its lock entry.
    pub fn is_drift(&self) -> bool {
        self.verdict == IdentityVerdict::Drift
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Product;

    fn device(mask: &str, application: &str) -> Result<Device, crate::AddressParseError> {
        Ok(Device {
            address: "1.1.4".parse()?,
            product: Some(Product {
                manufacturer: None,
                manufacturer_ref: None,
                order_number: Some("AKK-0216.03".to_string()),
                hardware_ref: None,
                application_ref: Some(application.to_string()),
                mask: Some(mask.to_string()),
            }),
            name: "Aktor".to_string(),
            description: None,
            location: None,
            replaced: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            application_override: None,
            lock: Default::default(),
            security: None,
        })
    }

    fn reported(mask: &str, id: Option<&str>) -> ReportedIdentity {
        ReportedIdentity {
            mask: mask.to_string(),
            application_id: id.map(str::to_string),
        }
    }

    #[test]
    fn test_application_id_from_ref_decodes_ets_refs() {
        assert_eq!(
            application_id_from_ref("M-0004_A-D141-22-151B-O000A"),
            Some(("0004D14122".to_string(), 0x22))
        );
        assert_eq!(
            application_id_from_ref("M-00FA_A-2500-10-ABCD"),
            Some(("00FA250010".to_string(), 16))
        );
        assert_eq!(application_id_from_ref("M-00FA_A-25-10"), None);
        assert_eq!(application_id_from_ref("not a ref"), None);
    }

    #[test]
    fn test_compare_match() -> Result<(), crate::AddressParseError> {
        let d = device("07B0", "M-0004_A-D141-22-151B")?;
        let check = IdentityCheck::compare(Some(&d), reported("07B0", Some("0004d14122")));
        assert_eq!(check.verdict, IdentityVerdict::Match);
        Ok(())
    }

    #[test]
    fn test_compare_application_drift() -> Result<(), crate::AddressParseError> {
        let d = device("07B0", "M-0004_A-D141-22-151B")?;
        let check = IdentityCheck::compare(Some(&d), reported("07B0", Some("0004D14123")));
        assert!(check.is_drift());
        assert_eq!(check.differences.len(), 1);
        assert!(check.differences[0].contains("0004D14123"));
        Ok(())
    }

    #[test]
    fn test_compare_mask_drift_but_hidden_mask_is_unknown() -> Result<(), crate::AddressParseError>
    {
        let d = device("07B0", "M-0004_A-D141-22-151B")?;
        assert!(IdentityCheck::compare(Some(&d), reported("0705", None)).is_drift());
        let hidden = IdentityCheck::compare(Some(&d), reported("FFFF", None));
        assert_eq!(hidden.verdict, IdentityVerdict::Match);
        Ok(())
    }

    #[test]
    fn test_compare_unmodelled() {
        let check = IdentityCheck::compare(None, reported("07B0", None));
        assert_eq!(check.verdict, IdentityVerdict::Unmodelled);
    }
}
