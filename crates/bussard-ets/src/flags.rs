//! Mapping ETS com-object flag attributes to the model's [`Flags`].
//!
//! ETS spells each flag as a separate attribute whose value is `"Enabled"` or
//! `"Disabled"`:
//!
//! | ETS attribute        | model flag       |
//! |----------------------|------------------|
//! | `CommunicationFlag`  | C (communication)|
//! | `ReadFlag`           | R (read)         |
//! | `WriteFlag`          | W (write)        |
//! | `TransmitFlag`       | T (transmit)     |
//! | `UpdateFlag`         | U (update)       |
//! | `ReadOnInitFlag`     | I (read-on-init) |
//!
//! Flags are resolved with an override chain: a value present on the
//! com-object *instance* wins over the *ref*, which wins over the *base*
//! com-object. This struct models one layer of that chain; [`FlagSet::merge`]
//! applies a higher-priority layer on top of a lower one.

use bussard_model::Flags;

/// One layer of com-object flags, where each flag may be unspecified (`None`)
/// and therefore inherited from a lower-priority layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlagSet {
    /// Communication flag, if specified at this layer.
    pub communication: Option<bool>,
    /// Read flag, if specified at this layer.
    pub read: Option<bool>,
    /// Write flag, if specified at this layer.
    pub write: Option<bool>,
    /// Transmit flag, if specified at this layer.
    pub transmit: Option<bool>,
    /// Update flag, if specified at this layer.
    pub update: Option<bool>,
    /// Read-on-init flag, if specified at this layer.
    pub read_on_init: Option<bool>,
}

/// Parses an ETS flag attribute value (`"Enabled"`/`"Disabled"`) into a bool.
///
/// Returns `None` for absent or unrecognized values so the layer stays
/// inherited.
pub fn parse_flag_value(value: &str) -> Option<bool> {
    match value {
        "Enabled" => Some(true),
        "Disabled" => Some(false),
        _ => None,
    }
}

impl FlagSet {
    /// Overlays `higher` (higher priority) on top of `self`: any flag specified
    /// in `higher` replaces the value from `self`.
    pub fn merge(self, higher: FlagSet) -> FlagSet {
        FlagSet {
            communication: higher.communication.or(self.communication),
            read: higher.read.or(self.read),
            write: higher.write.or(self.write),
            transmit: higher.transmit.or(self.transmit),
            update: higher.update.or(self.update),
            read_on_init: higher.read_on_init.or(self.read_on_init),
        }
    }

    /// Collapses the layer into concrete [`Flags`], treating any still-unset
    /// flag as disabled.
    pub fn to_flags(self) -> Flags {
        let mut flags = Flags::empty();
        if self.communication.unwrap_or(false) {
            flags |= Flags::COMMUNICATION;
        }
        if self.read.unwrap_or(false) {
            flags |= Flags::READ;
        }
        if self.write.unwrap_or(false) {
            flags |= Flags::WRITE;
        }
        if self.transmit.unwrap_or(false) {
            flags |= Flags::TRANSMIT;
        }
        if self.update.unwrap_or(false) {
            flags |= Flags::UPDATE;
        }
        if self.read_on_init.unwrap_or(false) {
            flags |= Flags::INIT;
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_values() {
        assert_eq!(parse_flag_value("Enabled"), Some(true));
        assert_eq!(parse_flag_value("Disabled"), Some(false));
        assert_eq!(parse_flag_value(""), None);
        assert_eq!(parse_flag_value("Whatever"), None);
    }

    #[test]
    fn base_only() {
        let base = FlagSet {
            communication: Some(true),
            write: Some(true),
            transmit: Some(true),
            ..Default::default()
        };
        assert_eq!(base.to_flags().to_string(), "CWT");
    }

    #[test]
    fn instance_overrides_base() {
        let base = FlagSet {
            communication: Some(true),
            read: Some(false),
            write: Some(true),
            ..Default::default()
        };
        // instance enables Read.
        let instance = FlagSet {
            read: Some(true),
            ..Default::default()
        };
        let merged = base.merge(instance);
        assert_eq!(merged.to_flags().to_string(), "CRW");
    }

    #[test]
    fn ref_layer_between() {
        let base = FlagSet {
            communication: Some(true),
            write: Some(true),
            ..Default::default()
        };
        let refl = FlagSet {
            transmit: Some(true),
            ..Default::default()
        };
        let instance = FlagSet::default();
        let merged = base.merge(refl).merge(instance);
        assert_eq!(merged.to_flags().to_string(), "CWT");
    }
}
