//! KNX Secure crypto primitives and the Data Secure ASDU codec (issue #71,
//! Phase A).
//!
//! This crate is the clean-room, GPL-free home of everything KNX Secure needs
//! below the management/transport layers:
//!
//! - [`key`]: the zeroizing, non-`Debug`-leaking, non-`Serialize` [`Key16`]
//!   wrapper for all 128-bit key material (spec §2.3).
//! - [`crypto`]: the decomposed AES-CCM (AES-CBC-MAC + AES-CTR) and the PBKDF2
//!   key schedule with the KNX Secure salts (spec §3).
//! - [`sequence`]: the 6-byte "milliseconds since 2018-01-05" Data Secure
//!   sequence number (spec §5.8).
//! - [`asdu`]: the A_SecureData (`0x03F1`) wire codec — SCF, nonce assembly,
//!   MAC-only and MAC+encrypt modes (spec §5).
//! - [`group`]: secured **group** communication (S-A_Data on a group
//!   address, keyed by the GA's group key) and the advisory per-sender
//!   freshness table a bus monitor keeps.
//! - [`session`]: the stateful per-device [`DataSecureSession`] that owns the
//!   tool key, the send sequence, and the replay-protection table (spec §6.1).
//!
//! - [`ipsecure`]: the KNXnet/IP Secure session handshake (X25519, device and
//!   user authentication MACs) and the SECURE_WRAPPER codec (Phase B, spec
//!   §7-§9). The transport drives it over TCP.
//!
//! Both bussard and the knx-sim converge on these bytes from the spec alone —
//! no code is shared.
//!
//! # Key hygiene
//!
//! Key material never leaves this crate as raw bytes except through the
//! controlled [`Key16::bytes`] accessor at the crypto boundary. Nothing here
//! prints, logs, or serializes a key (spec §2.3).

#![forbid(unsafe_code)]

pub mod asdu;
pub mod crypto;
pub mod group;
pub mod ipsecure;
pub mod key;
pub mod sequence;
pub mod session;

pub use asdu::{
    A_SECURE_DATA, AsduError, DecodedInner, Scf, SecureService, SecurityAlgorithm, TpAddressing,
};
pub use crypto::{CryptoError, aes_cbc_decrypt, aes_cbc_encrypt, pbkdf2_key, pbkdf2_sha256, salt};
pub use group::{Freshness, GroupPlain, decode_group, encode_group, is_group_data, peek_header};
pub use key::{Key16, Password};
pub use sequence::{Sequence, SequenceHighWater};
pub use session::{DataSecureSession, UnwrapOutcome};
