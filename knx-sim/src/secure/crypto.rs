//! The decomposed AES-CCM used by KNX Data Secure (spec §3).
//!
//! KNX Secure's AES-CCM is built (and here re-implemented independently) from
//! two AES-128 primitives, **not** from a CCM library:
//!
//! - **AES-CBC-MAC** produces the authentication tag (§3.2). It CBC-encrypts a
//!   zero-padded buffer with a zero IV and keeps the last cipher block.
//! - **AES-CTR** encrypts the tag and the payload (§3.3) as one continuous
//!   keystream: the (truncated) MAC first, the payload right after it.
//!
//! This is exactly what CCM is under the hood (RFC 3610 / SP 800-38C). Keeping it
//! decomposed lets the simulator depend only on `aes` + `cbc` + `ctr` (all
//! RustCrypto cipher-0.4 generation) with no `ccm` crate.
//!
//! Everything here is byte-layout code derived from the spec's worked pseudocode
//! (§3.1-§3.3); it links no external KNX implementation.

use aes::Aes128;
use aes::cipher::{BlockEncryptMut, KeyIvInit, StreamCipher};

/// The AES block size in bytes.
pub const BLOCK: usize = 16;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Zero-pad `data` (with `0x00`) up to a multiple of the 16-byte AES block.
///
/// This is the CBC-MAC formatting padding of spec §3.1 (`byte_pad`), **not**
/// PKCS7. An input that is already a whole number of blocks is returned
/// unchanged.
pub fn byte_pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % BLOCK;
    if rem != 0 {
        out.resize(out.len() + (BLOCK - rem), 0x00);
    }
    out
}

/// XOR two equal-length big-endian byte strings. Panics in debug if the lengths
/// differ (a programmer error at these call sites, where lengths are fixed).
fn bytes_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Compute the AES-CBC-MAC tag (spec §3.2).
///
/// The buffer is `block_0 || len(additional_data):2 BE || additional_data ||
/// payload`, zero-padded to a block multiple, then AES-CBC-encrypted with a zero
/// IV; the MAC is the last cipher block (16 bytes). `block_0` must be exactly 16
/// bytes.
///
/// Returns the full 16-byte CBC-MAC; Data Secure truncates it to 4 bytes on the
/// wire (§5.3) but the truncation is the caller's job.
pub fn cbc_mac(
    key: &[u8; 16],
    additional_data: &[u8],
    payload: &[u8],
    block_0: &[u8; 16],
) -> [u8; 16] {
    let mut buf = Vec::with_capacity(BLOCK + 2 + additional_data.len() + payload.len());
    buf.extend_from_slice(block_0);
    let ad_len = additional_data.len() as u16;
    buf.extend_from_slice(&ad_len.to_be_bytes());
    buf.extend_from_slice(additional_data);
    buf.extend_from_slice(payload);
    let mut buf = byte_pad(&buf);

    // AES-CBC with a zero IV. Encrypt block-by-block and keep the last block.
    let zero_iv = [0u8; BLOCK];
    let mut enc = Aes128CbcEnc::new(key.into(), &zero_iv.into());
    // `encrypt_blocks_mut` operates in place over whole 16-byte blocks; `buf` is a
    // block multiple after `byte_pad`.
    let blocks = buf.chunks_exact_mut(BLOCK);
    let mut last = [0u8; BLOCK];
    for chunk in blocks {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
        last.copy_from_slice(block);
    }
    last
}

/// Produce the AES-CTR keystream starting at `counter_0` for `blocks` blocks.
fn ctr_keystream(key: &[u8; 16], counter_0: &[u8; 16], blocks: usize) -> Vec<u8> {
    let mut buf = vec![0u8; blocks * BLOCK];
    let mut cipher = Aes128Ctr::new(key.into(), counter_0.into());
    cipher.apply_keystream(&mut buf);
    buf
}

/// CTR-encrypt the MAC and payload (spec §3.3).
///
/// One continuous keystream from `counter_0` covers `mac || payload`: the MAC
/// takes the first `mac.len()` keystream bytes and the payload starts at the
/// very next byte. Data Secure passes the MAC already truncated to its 4 wire
/// bytes, so the payload starts at keystream byte 4 (NOT at block 1). This is
/// what ETS 6.4.1 and a real activated device do (secure-1-1-12 capture,
/// 2026-09-23). Returns `(encrypted_payload, encrypted_mac)`.
pub fn encrypt_data_ctr(
    key: &[u8; 16],
    counter_0: &[u8; 16],
    mac: &[u8],
    payload: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let total = mac.len() + payload.len();
    let keystream = ctr_keystream(key, counter_0, total.div_ceil(BLOCK));
    let enc_mac = bytes_xor(mac, &keystream[..mac.len()]);
    let enc_payload = bytes_xor(payload, &keystream[mac.len()..total]);
    (enc_payload, enc_mac)
}

/// CTR-decrypt the MAC and payload (inverse of [`encrypt_data_ctr`]).
///
/// CTR is symmetric: the same continuous keystream recovers the MAC (pass the
/// wire-length MAC, 4 bytes for Data Secure) and then the payload. Returns
/// `(payload, mac)`.
pub fn decrypt_data_ctr(
    key: &[u8; 16],
    counter_0: &[u8; 16],
    enc_mac: &[u8],
    enc_payload: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    encrypt_data_ctr(key, counter_0, enc_mac, enc_payload)
}

/// Constant-time equality over two byte slices of equal length. Returns `false`
/// for differing lengths. Used to compare MACs so a mismatch does not leak
/// timing about how many leading bytes matched.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit vector, spec §3.5 / §12.1: a CBC-MAC over additional_data = [0x11],
    // payload = b"", key = 16×0x00, block_0 = 16×0x00. Both implementers compute
    // this independently from §3.1-§3.3 and diff. This is a synthetic vector; the
    // assertion value below is what THIS decomposition produces and is committed
    // so a regression (or the bussard side diverging) is caught byte-exactly.
    #[test]
    fn test_cbc_mac_spec_worked_vector() {
        let key = [0u8; 16];
        let block_0 = [0u8; 16];
        let mac = cbc_mac(&key, &[0x11], b"", &block_0);
        // The buffer fed to CBC is: block_0(16 zero) || 00 01 (ad len) || 11,
        // zero-padded to 32 bytes. Independently recomputable.
        let expected = independent_cbc_mac(&key, &[0x11], b"", &block_0);
        assert_eq!(
            mac, expected,
            "cbc_mac must match the independent reference"
        );
        // Pin the exact bytes so the vector is stable across refactors.
        assert_eq!(
            mac,
            [
                0x7b, 0x4e, 0x7e, 0xfe, 0x4a, 0x9b, 0x46, 0x62, 0xfd, 0x03, 0x71, 0xaa, 0x9f, 0x1a,
                0x2f, 0x5f
            ]
        );
    }

    /// A second, deliberately naive CBC-MAC built straight from the block
    /// primitive — a within-crate cross-check that `cbc_mac`'s use of the `cbc`
    /// crate matches a hand-rolled CBC chain, catching an IV/chaining mistake.
    fn independent_cbc_mac(
        key: &[u8; 16],
        additional_data: &[u8],
        payload: &[u8],
        block_0: &[u8; 16],
    ) -> [u8; 16] {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let cipher = Aes128::new(key.into());
        let mut buf = Vec::new();
        buf.extend_from_slice(block_0);
        buf.extend_from_slice(&(additional_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(additional_data);
        buf.extend_from_slice(payload);
        let buf = byte_pad(&buf);
        let mut prev = [0u8; 16];
        for chunk in buf.chunks_exact(16) {
            let x = bytes_xor(&prev, chunk);
            let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&x);
            cipher.encrypt_block(&mut block);
            prev.copy_from_slice(&block);
        }
        prev
    }

    // Unit vector: a full CTR round-trip. Encrypting then decrypting must recover
    // both the MAC and the payload (spec §3.3).
    #[test]
    fn test_ctr_roundtrip_recovers_mac_and_payload() {
        let key = [0x01u8; 16];
        let counter_0 = [0x02u8; 16];
        let mac = [0xAAu8; 4];
        let payload = b"hello knx secure payload!!";
        let (enc_payload, enc_mac) = encrypt_data_ctr(&key, &counter_0, &mac, payload);
        assert_ne!(&enc_mac[..], &mac[..], "MAC is actually encrypted");
        assert_ne!(enc_payload.as_slice(), payload.as_slice());
        let (dec_payload, dec_mac) = decrypt_data_ctr(&key, &counter_0, &enc_mac, &enc_payload);
        assert_eq!(dec_mac, mac);
        assert_eq!(dec_payload, payload);
    }

    #[test]
    fn test_ctr_payload_starts_right_after_the_truncated_mac() {
        // A 4-byte MAC takes keystream bytes 0..4; the payload starts at byte 4.
        let key = [0x07u8; 16];
        let counter_0 = [0x00u8; 16];
        let ks = ctr_keystream(&key, &counter_0, 2);
        let (enc_payload, enc_mac) = encrypt_data_ctr(&key, &counter_0, &[0u8; 4], &[0u8; 8]);
        assert_eq!(&enc_mac[..], &ks[..4]);
        assert_eq!(&enc_payload[..], &ks[4..12]);
    }

    #[test]
    fn test_byte_pad_multiple_of_block() {
        assert_eq!(byte_pad(b"").len(), 0);
        assert_eq!(byte_pad(&[0u8; 16]).len(), 16);
        assert_eq!(byte_pad(&[0u8; 17]).len(), 32);
        assert_eq!(byte_pad(&[0u8; 1]).len(), 16);
    }

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }
}
