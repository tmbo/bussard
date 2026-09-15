//! Mapping ETS com-object flag attributes to the model's [`Flags`].
//!
//! Each flag is a separate `"Enabled"`/`"Disabled"` attribute, resolved with an
//! override chain (instance over ref over base). This mirrors the identical
//! helper in `bussard-project::flag_map`; see the crate `lib.rs` dedup note.

use bussard_model::Flags;

/// One layer of com-object flags, where each flag may be unspecified (`None`)
/// and therefore inherited from a lower-priority layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Parses an ETS flag attribute value (`"Enabled"`/`"Disabled"`) into a bool,
/// returning `None` for absent or unrecognized values.
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
        assert_eq!(parse_flag_value("x"), None);
    }

    #[test]
    fn instance_overrides_base() {
        let base = FlagSet {
            communication: Some(true),
            read: Some(false),
            write: Some(true),
            ..Default::default()
        };
        let instance = FlagSet {
            read: Some(true),
            ..Default::default()
        };
        assert_eq!(base.merge(instance).to_flags().to_string(), "CRW");
    }
}
