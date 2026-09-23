//! The KNX Data Secure wrapping seam over the layer-4 management connection
//! (spec §6.1).
//!
//! [`SecureLayer`] is a thin `Option<DataSecureSession>` carried by a
//! [`Layer4Connection`](crate::connection::Layer4Connection). When it is `None`
//! (a plain, non-security-activated device) the management path is byte-identical
//! to today's plain behaviour. When it is `Some`, every outgoing management APDU
//! is wrapped into an `A_SecureData` (`0x03F1`) ASDU before the cEMI frame is
//! built, and every incoming secured APDU is verified + unwrapped before it
//! reaches the state machine.
//!
//! The layer does not own the transport; it only transforms `(apci, data)` pairs
//! given the addressing context of the carrying frame. The tool key, send
//! sequence, and per-source freshness table live in the wrapped
//! [`DataSecureSession`] (spec §6.1) and are never printed or logged (spec §2.3).

use bussard_model::IndividualAddress;
use bussard_secure::{AsduError, DataSecureSession, TpAddressing, UnwrapOutcome};

use crate::error::{MgmtError, Result};

/// The Data Secure wrapping state for one management connection.
///
/// Built from a [`DataSecureSession`] via [`SecureLayer::activated`], or absent
/// via [`SecureLayer::plain`] (the default). A connection whose layer is plain
/// behaves exactly as it did before KNX Secure existed.
#[derive(Debug, Default)]
pub struct SecureLayer {
    session: Option<DataSecureSession>,
}

impl SecureLayer {
    /// A plain (non-secure) layer: management APDUs pass through unchanged. This
    /// is the state of every device that is not security-activated (spec §6.4).
    pub fn plain() -> Self {
        SecureLayer { session: None }
    }

    /// A security-activated layer wrapping every APDU with `session`'s tool key
    /// (spec §6.4).
    pub fn activated(session: DataSecureSession) -> Self {
        SecureLayer {
            session: Some(session),
        }
    }

    /// Whether this layer wraps management APDUs (the device is activated).
    pub fn is_active(&self) -> bool {
        self.session.is_some()
    }

    /// Whether the S-A_Sync handshake still has to run before the first wrapped
    /// APDU (spec §6.3): `true` on an activated layer that has not verified a
    /// Sync_Res yet, always `false` on a plain layer.
    pub fn needs_sync(&self) -> bool {
        self.session.as_ref().is_some_and(|s| !s.is_synced())
    }

    /// Whether an activated layer has completed the S-A_Sync handshake.
    pub fn is_synced(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_synced())
    }

    /// Builds the S-A_Sync_Req for a frame `source → target` with `tpci`,
    /// returning the `(outer_apci, outer_data)` to send (spec §6.3).
    ///
    /// # Errors
    ///
    /// [`MgmtError::Secure`] if the layer is plain (there is nothing to sync) or
    /// the codec rejects the request.
    pub fn sync_request(
        &mut self,
        target: IndividualAddress,
        source: IndividualAddress,
        tpci: u8,
    ) -> Result<(u16, Vec<u8>)> {
        let addr = tp_addressing(source, target, tpci);
        match &mut self.session {
            None => Err(MgmtError::Secure {
                address: target,
                source: AsduError::UnexpectedService(0x92),
            }),
            Some(session) => session
                .sync_request(&addr)
                .map_err(|source| MgmtError::Secure {
                    address: target,
                    source,
                }),
        }
    }

    /// Wraps an outgoing `(apci, data)` for a frame addressed `source → target`
    /// with `tpci`, returning the `(outer_apci, outer_data)` to actually send.
    ///
    /// On a plain layer this returns `(apci, data)` untouched — the byte-identical
    /// plain path. On an activated layer it returns
    /// `(A_SecureData, SCF||seq||secured||MAC)` (spec §6.1).
    ///
    /// # Errors
    ///
    /// Surfaces an [`MgmtError::Secure`] if the ASDU codec rejects the payload.
    pub fn wrap_outgoing(
        &mut self,
        target: IndividualAddress,
        source: IndividualAddress,
        tpci: u8,
        apci: u16,
        data: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        match &mut self.session {
            None => Ok((apci, data.to_vec())),
            Some(session) => {
                let addr = tp_addressing(source, target, tpci);
                session
                    .wrap(&addr, apci, data)
                    .map_err(|source| MgmtError::Secure {
                        address: target,
                        source,
                    })
            }
        }
    }

    /// Unwraps an incoming `(apci, data)` from a frame addressed `source → dest`
    /// with `tpci`, returning the inner `(apci, data)`.
    ///
    /// On a plain layer this returns `(apci, data)` untouched. On an activated
    /// layer: an `A_SecureData` frame is MAC-verified, freshness-checked, and
    /// unwrapped; any non-secured frame passes through unchanged (a device may
    /// still send plain transport/control frames, spec §6.1). A verified
    /// S-A_Sync_Res is applied to the session and surfaces as
    /// `(A_SECURE_DATA, [])`; the caller checks [`is_synced`](Self::is_synced).
    ///
    /// # Errors
    ///
    /// Surfaces [`MgmtError::Secure`] on a MAC mismatch or a stale (replayed)
    /// sequence — a wrong-MAC response is rejected, not silently accepted.
    pub fn unwrap_incoming(
        &mut self,
        source: IndividualAddress,
        dest: IndividualAddress,
        tpci: u8,
        apci: u16,
        data: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        match &mut self.session {
            None => Ok((apci, data.to_vec())),
            Some(session) => {
                let addr = tp_addressing(source, dest, tpci);
                match session
                    .unwrap(&addr, apci, data)
                    .map_err(|src| MgmtError::Secure {
                        address: source,
                        source: src,
                    })? {
                    UnwrapOutcome::Secured { apci, data } => Ok((apci, data)),
                    UnwrapOutcome::Plain => Ok((apci, data.to_vec())),
                    UnwrapOutcome::Synced { .. } => Ok((bussard_secure::A_SECURE_DATA, Vec::new())),
                }
            }
        }
    }
}

/// Builds the [`TpAddressing`] nonce context for a connection-oriented
/// individually-addressed frame (spec §5.4): individual destination, standard
/// frame format.
fn tp_addressing(source: IndividualAddress, dest: IndividualAddress, tpci: u8) -> TpAddressing {
    TpAddressing {
        source: source.raw(),
        destination: dest.raw(),
        // Management is individually addressed, not a group frame.
        address_type_group: false,
        // Management frames are standard-format (ext-format nibble 0).
        extended_frame_format: 0,
        tpci,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_secure::{Key16, Sequence};

    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }

    #[test]
    fn test_plain_layer_passes_through() {
        let mut layer = SecureLayer::plain();
        assert!(!layer.is_active());
        let (apci, data) = layer
            .wrap_outgoing(ia("1.1.10"), ia("1.1.1"), 0x42, 0x280, &[0x00, 0x10])
            .unwrap();
        assert_eq!(apci, 0x280);
        assert_eq!(data, vec![0x00, 0x10]);
    }

    #[test]
    fn test_activated_layer_wraps() {
        let session =
            DataSecureSession::new(Key16::new([0x24; 16])).with_send_sequence(Sequence::new(500));
        let mut layer = SecureLayer::activated(session);
        assert!(layer.is_active());
        let (apci, data) = layer
            .wrap_outgoing(ia("1.1.10"), ia("1.1.1"), 0x42, 0x280, &[0x00, 0x10])
            .unwrap();
        assert_eq!(apci, bussard_secure::A_SECURE_DATA);
        // The wrapped ASDU is longer than the plain payload.
        assert!(data.len() > 2);
    }

    #[test]
    fn test_round_trip_through_two_layers() {
        // A "tool" layer wraps; a "device" layer with the same key unwraps.
        let key = [0x24u8; 16];
        let mut tool = SecureLayer::activated(
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(500)),
        );
        let mut device = SecureLayer::activated(DataSecureSession::new(Key16::new(key)));

        let src = ia("1.1.1");
        let dst = ia("1.1.10");
        let (outer_apci, outer_data) = tool
            .wrap_outgoing(dst, src, 0x42, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();
        // The device sees the frame as src → dst with the same tpci.
        let (apci, data) = device
            .unwrap_incoming(src, dst, 0x42, outer_apci, &outer_data)
            .unwrap();
        assert_eq!(apci, 0x3D1);
        assert_eq!(data, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_wrong_mac_rejected() {
        let key = [0x24u8; 16];
        let mut tool = SecureLayer::activated(
            DataSecureSession::new(Key16::new(key)).with_send_sequence(Sequence::new(500)),
        );
        // The device has a DIFFERENT key, so the MAC will not verify.
        let mut device = SecureLayer::activated(DataSecureSession::new(Key16::new([0x99; 16])));
        let src = ia("1.1.1");
        let dst = ia("1.1.10");
        let (outer_apci, outer_data) = tool
            .wrap_outgoing(dst, src, 0x42, 0x280, &[0x00, 0x10])
            .unwrap();
        let err = device
            .unwrap_incoming(src, dst, 0x42, outer_apci, &outer_data)
            .unwrap_err();
        assert!(matches!(err, MgmtError::Secure { .. }), "got {err:?}");
    }
}
