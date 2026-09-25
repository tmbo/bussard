//! The decomposed AES-CCM and the PBKDF2 key schedule (spec §3).
//!
//! # Why CCM is decomposed
//!
//! KNX Secure's AES-CCM is not built on a `ccm` crate. It is assembled from
//! **AES-CBC-MAC** (to produce the authentication tag) plus **AES-CTR** (to
//! encrypt the payload and the tag). This is exactly what CCM is under the hood
//! (RFC 3610 / NIST SP 800-38C), and reproducing that decomposition lets bussard
//! stay on the RustCrypto cipher-0.4 generation already in the tree (`aes 0.8`,
//! `cbc 0.1`, `ctr 0.9`) with no `ccm` crate. See spec §3 / §10.
//!
//! All functions here are pure and I/O-free. No GPL source was consulted; the
//! layout is reimplemented from the public KNX specification and RFCs.

use aes::Aes128;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::key::Key16;

/// AES-128-CBC encryptor (used to drive the CBC-MAC).
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
/// AES-128-CBC decryptor (used to decrypt keyring attribute blobs, spec §4.2).
type Aes128CbcDec = cbc::Decryptor<Aes128>;
/// AES-128-CTR keystream (big-endian 128-bit counter), matching KNX Secure.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// The AES block size in bytes.
pub const BLOCK: usize = 16;

/// Big-endian XOR of two equal-length byte slices (`bytes_xor`, spec §3.1).
///
/// # Panics
///
/// Panics if the slices differ in length; callers always pass equal-length
/// blocks, so this is a programming-error guard, not a runtime path.
pub fn bytes_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "bytes_xor requires equal-length inputs");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Zero-pads `data` to a multiple of 16 (`byte_pad`, spec §3.1).
///
/// This is the CBC-MAC *formatting* padding (append `0x00`), NOT PKCS#7. The
/// keyring code uses real PKCS#7 separately; do not confuse the two.
pub fn byte_pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % BLOCK;
    if rem != 0 {
        out.resize(out.len() + (BLOCK - rem), 0x00);
    }
    out
}

/// Computes the KNX Secure CBC-MAC (spec §3.2).
///
/// The MAC buffer is `block_0 || len(additional_data):2 (BE) || additional_data
/// || payload`, zero-padded to a 16-byte multiple, then AES-CBC-encrypted with a
/// **zero IV**. The MAC is the last cipher block. `block_0` must be exactly 16
/// bytes.
///
/// # Errors
///
/// Returns [`CryptoError::BadBlockLen`] if `block_0` is not 16 bytes.
pub fn cbc_mac(
    key: &Key16,
    additional_data: &[u8],
    payload: &[u8],
    block_0: &[u8],
) -> Result<[u8; BLOCK], CryptoError> {
    if block_0.len() != BLOCK {
        return Err(CryptoError::BadBlockLen(block_0.len()));
    }
    let ad_len = u16::try_from(additional_data.len())
        .map_err(|_| CryptoError::AdditionalDataTooLong(additional_data.len()))?;

    let mut buf = Vec::with_capacity(BLOCK + 2 + additional_data.len() + payload.len());
    buf.extend_from_slice(block_0);
    buf.extend_from_slice(&ad_len.to_be_bytes());
    buf.extend_from_slice(additional_data);
    buf.extend_from_slice(payload);
    let mut buf = byte_pad(&buf);

    // AES-CBC with a zero IV; the CBC-MAC is the final cipher block. We encrypt
    // in place block by block (the buffer is already a 16-byte multiple).
    let zero_iv = [0u8; BLOCK];
    let mut enc = Aes128CbcEnc::new(key.bytes().into(), &zero_iv.into());
    let n_blocks = buf.len() / BLOCK;
    for i in 0..n_blocks {
        let block = &mut buf[i * BLOCK..(i + 1) * BLOCK];
        // `encrypt_block_mut` chains against the running IV internally, so a
        // sequential per-block call reproduces full CBC over the buffer.
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        enc.encrypt_block_mut(ga);
    }
    let mut mac = [0u8; BLOCK];
    mac.copy_from_slice(&buf[buf.len() - BLOCK..]);
    Ok(mac)
}

/// Encrypts the (truncated) CBC-MAC and the payload with one AES-CTR keystream
/// from `counter_0` (spec §3.3).
///
/// The keystream is a single continuous stream over `mac || payload`: the first
/// `mac.len()` keystream bytes encrypt the MAC and the payload continues with the
/// **next** keystream byte. For KNX Data Secure the caller passes the MAC
/// already truncated to its 4 wire bytes, so the payload starts at byte 4 of the
/// first keystream block, not at the second block. CONFIRMED against ETS 6.4.1
/// (secure-1-1-12 capture, 2026-09-23): every ETS and device `A_SecureData`
/// frame verifies with this layout and none with a block-aligned payload. For
/// IP Secure the MAC is the full 16 bytes, which makes the payload start at the
/// second block, so the same rule covers both.
///
/// Returns `(encrypted_payload, encrypted_mac)`, each as long as its input.
///
/// # Errors
///
/// Returns [`CryptoError::BadBlockLen`] if `counter_0` is not 16 bytes or the
/// MAC is longer than one block.
pub fn encrypt_ctr(
    key: &Key16,
    counter_0: &[u8],
    mac: &[u8],
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if counter_0.len() != BLOCK {
        return Err(CryptoError::BadBlockLen(counter_0.len()));
    }
    if mac.len() > BLOCK {
        return Err(CryptoError::BadBlockLen(mac.len()));
    }
    let mut cipher = Aes128Ctr::new(key.bytes().into(), counter_0.into());

    // One stream: the MAC takes the first `mac.len()` keystream bytes, the
    // payload the bytes right after it.
    let mut enc_mac = mac.to_vec();
    cipher.apply_keystream(&mut enc_mac);
    let mut enc_payload = payload.to_vec();
    cipher.apply_keystream(&mut enc_payload);

    Ok((enc_payload, enc_mac))
}

/// Decrypts an AES-CTR payload+MAC produced by [`encrypt_ctr`] (spec §3.3).
///
/// CTR is symmetric, so this is the inverse of [`encrypt_ctr`] with the same
/// continuous-keystream rule: pass the MAC exactly as long as it was on the wire
/// (4 bytes for Data Secure) so the payload lines up with the right keystream
/// bytes. Returns `(payload, mac)`.
///
/// # Errors
///
/// Returns [`CryptoError::BadBlockLen`] if `counter_0` is not 16 bytes or the
/// MAC is longer than one block.
pub fn decrypt_ctr(
    key: &Key16,
    counter_0: &[u8],
    enc_mac: &[u8],
    enc_payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // CTR decryption is identical to encryption.
    encrypt_ctr(key, counter_0, enc_mac, enc_payload)
}

/// Decrypts an AES-128-CBC ciphertext with the given key and IV, returning the
/// raw padded plaintext (spec §4.2, keyring attribute decryption).
///
/// No un-padding is done here: the keyring's `extract_password` strips its own
/// PKCS#7-style padding, and raw-key attributes carry no padding. `ciphertext`
/// must be a whole number of 16-byte blocks.
///
/// # Errors
///
/// Returns [`CryptoError::BadBlockLen`] if `iv` is not 16 bytes or `ciphertext`
/// is not a 16-byte multiple.
pub fn aes_cbc_decrypt(key: &Key16, iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != BLOCK {
        return Err(CryptoError::BadBlockLen(iv.len()));
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
        return Err(CryptoError::BadBlockLen(ciphertext.len()));
    }
    let mut dec = Aes128CbcDec::new(key.bytes().into(), iv.into());
    let mut buf = ciphertext.to_vec();
    let n_blocks = buf.len() / BLOCK;
    for i in 0..n_blocks {
        let block = &mut buf[i * BLOCK..(i + 1) * BLOCK];
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        dec.decrypt_block_mut(ga);
    }
    Ok(buf)
}

/// Encrypts a plaintext with AES-128-CBC and the given key and IV, returning the
/// ciphertext (the inverse of [`aes_cbc_decrypt`]).
///
/// No padding is added: `plaintext` must already be a whole number of 16-byte
/// blocks (callers apply their own PKCS#7 / zero padding before calling). The
/// key store and the `.knxkeys` export use it through
/// [`keyring_encrypt_key`] and [`keyring_encrypt_password`] (issue #241).
///
/// # Errors
///
/// Returns [`CryptoError::BadBlockLen`] if `iv` is not 16 bytes or `plaintext`
/// is not a 16-byte multiple.
pub fn aes_cbc_encrypt(key: &Key16, iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != BLOCK {
        return Err(CryptoError::BadBlockLen(iv.len()));
    }
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(BLOCK) {
        return Err(CryptoError::BadBlockLen(plaintext.len()));
    }
    let mut enc = Aes128CbcEnc::new(key.bytes().into(), iv.into());
    let mut buf = plaintext.to_vec();
    let n_blocks = buf.len() / BLOCK;
    for i in 0..n_blocks {
        let block = &mut buf[i * BLOCK..(i + 1) * BLOCK];
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        enc.encrypt_block_mut(ga);
    }
    Ok(buf)
}

/// Constant-time comparison of two byte slices of equal length.
///
/// Returns `false` immediately for differing lengths (a length mismatch is not
/// secret), otherwise compares all bytes without early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The PBKDF2 salts used by KNX Secure and ETS (spec §3.4).
///
/// Every derivation is PBKDF2-HMAC-SHA256, 65536 iterations, 16-byte output. The
/// input encoding differs per row (see [`pbkdf2_key`]).
pub mod salt {
    /// Salt for the device authentication code (Latin-1 password input).
    pub const DEVICE_AUTHENTICATION_CODE: &[u8] = b"device-authentication-code.1.secure.ip.knx.org";
    /// Salt for the user password (Latin-1 password input).
    pub const USER_PASSWORD: &[u8] = b"user-password.1.secure.ip.knx.org";
    /// Salt for the keyring password key (Latin-1 password input).
    pub const KEYRING: &[u8] = b"1.keyring.ets.knx.org";
}

/// The PBKDF2 iteration count shared by every KNX Secure / ETS derivation.
pub const PBKDF2_ITERATIONS: u32 = 65_536;

/// Derives a 16-byte KNX Secure key from a password and salt (spec §3.4).
///
/// `password_latin1` must already be Latin-1-encoded bytes (the IP-handshake and
/// keyring passwords use Latin-1; the ETS6 *project* zip password uses UTF-16-LE
/// and is encoded in `bussard-project::password` before it calls
/// [`pbkdf2_sha256`]). PBKDF2-HMAC-SHA256, [`PBKDF2_ITERATIONS`] iterations,
/// 16-byte output wrapped in a [`Key16`].
pub fn pbkdf2_key(password_latin1: &[u8], salt: &[u8]) -> Key16 {
    let derived = pbkdf2_sha256(password_latin1, salt, PBKDF2_ITERATIONS, BLOCK);
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(&derived);
    Key16::new(out)
}

/// PBKDF2-HMAC-SHA256 over already-encoded password bytes: the one key
/// derivation behind every KNX Secure and ETS password in bussard.
///
/// The caller owns the password encoding, which differs per use and is
/// calibrated against real files: Latin-1 for the keyring and IP-secure
/// passwords ([`pbkdf2_key`]), UTF-16-LE for the ETS 6 project-zip password
/// (`bussard-project::password`). The derived bytes are returned in a
/// [`zeroize::Zeroizing`] buffer so they are wiped when dropped.
pub fn pbkdf2_sha256(
    password_bytes: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = zeroize::Zeroizing::new(vec![0u8; out_len]);
    pbkdf2_hmac::<Sha256>(password_bytes, salt, iterations, &mut out);
    out
}

/// Encodes a `&str` as Latin-1 (ISO-8859-1) bytes, the encoding KNX Secure uses
/// for password inputs to PBKDF2 (spec §3.4).
///
/// Each Unicode scalar in `0..=0xFF` maps to a single byte; a scalar above
/// `0xFF` cannot be represented in Latin-1 and is replaced with `?` (0x3F),
/// matching the lossy behaviour of the reference implementations for
/// out-of-range characters. KNX passwords are ASCII/Latin-1 in practice.
pub fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            if cp <= 0xFF { cp as u8 } else { b'?' }
        })
        .collect()
}

/// The length of the prefix ahead of an encrypted keyring password (spec §4.3).
pub const KEYRING_PASSWORD_PREFIX_LEN: usize = 8;

/// The AES-CBC IV of every encrypted keyring attribute:
/// `sha256(created)[..16]`, where `created` is the root `Created` attribute
/// (spec §4.2).
pub fn keyring_iv(created: &str) -> [u8; BLOCK] {
    use sha2::Digest as _;
    let digest = Sha256::digest(created.as_bytes());
    let mut iv = [0u8; BLOCK];
    iv.copy_from_slice(&digest[..BLOCK]);
    iv
}

/// Encrypts a raw 16-byte key for a keyring attribute (`ToolKey`,
/// `Backbone/@Key`, a group `@Key`): one AES-128-CBC block under the keyring
/// key, no prefix, no padding (spec §4.3). The inverse of the reader's key
/// decryption.
///
/// # Errors
///
/// Never in practice; [`CryptoError::BadBlockLen`] is the block-size guard.
pub fn keyring_encrypt_key(
    keyring_key: &Key16,
    iv: &[u8; BLOCK],
    key: &Key16,
) -> Result<[u8; BLOCK], CryptoError> {
    let ct = aes_cbc_encrypt(keyring_key, iv, key.bytes())?;
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(&ct[..BLOCK]);
    Ok(out)
}

/// Encrypts a password for a keyring attribute (`Password`, `Authentication`,
/// `ManagementPassword`): `prefix || utf8(password) || PKCS#7`, AES-128-CBC
/// under the keyring key (spec §4.3). The inverse of the reader's
/// `extract_password`.
///
/// # Errors
///
/// Never in practice; [`CryptoError::BadBlockLen`] is the block-size guard.
pub fn keyring_encrypt_password(
    keyring_key: &Key16,
    iv: &[u8; BLOCK],
    prefix: &[u8; KEYRING_PASSWORD_PREFIX_LEN],
    password: &crate::key::Password,
) -> Result<Vec<u8>, CryptoError> {
    let body = password.expose().as_bytes();
    let unpadded = KEYRING_PASSWORD_PREFIX_LEN + body.len();
    // PKCS#7: 1..=16 bytes, a full block when already aligned.
    let pad = BLOCK - unpadded % BLOCK;
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(unpadded + pad));
    plain.extend_from_slice(prefix);
    plain.extend_from_slice(body);
    plain.extend(std::iter::repeat_n(pad as u8, pad));
    aes_cbc_encrypt(keyring_key, iv, &plain)
}

/// A deterministic password prefix for the key store (issue #241):
/// `HMAC-SHA256(keyring_key, context || 0x00 || password)[..8]`.
///
/// ETS fills the prefix with random bytes, so every export re-encrypts every
/// password differently. The git-tracked store instead keeps an unchanged
/// password's ciphertext unchanged, so a diff shows only what moved; the
/// prefix is keyed, so it reveals nothing without the keyring key.
pub fn keyring_password_prefix(
    keyring_key: &Key16,
    context: &str,
    password: &crate::key::Password,
) -> [u8; KEYRING_PASSWORD_PREFIX_LEN] {
    use hmac::{Hmac, Mac};
    let mut out = [0u8; KEYRING_PASSWORD_PREFIX_LEN];
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    if let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(keyring_key.bytes()) {
        mac.update(context.as_bytes());
        mac.update(&[0]);
        mac.update(password.expose().as_bytes());
        let tag = mac.finalize().into_bytes();
        out.copy_from_slice(&tag[..KEYRING_PASSWORD_PREFIX_LEN]);
    }
    out
}

/// `N` bytes from the operating system's random source.
///
/// # Errors
///
/// [`CryptoError::Random`] when the OS source fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(out)
}

/// Errors from the KNX Secure crypto primitives.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A `block_0`/`counter_0` argument was not exactly 16 bytes, or a MAC
    /// handed to the CTR stage was longer than one block.
    #[error("crypto block must be 16 bytes, got {0}")]
    BadBlockLen(usize),
    /// The additional-data length did not fit in the 2-byte length prefix.
    #[error("additional data too long for the 2-byte length prefix: {0} bytes")]
    AdditionalDataTooLong(usize),
    /// The operating system's random source failed.
    #[error("the OS random source failed: {0}")]
    Random(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_encrypt_key_round_trips() -> Result<(), CryptoError> {
        let kk = Key16::new([0x5A; 16]);
        let iv = keyring_iv("2026-02-03T04:05:06");
        let ct = keyring_encrypt_key(&kk, &iv, &Key16::new([0x42; 16]))?;
        assert_ne!(ct, [0x42; 16]);
        assert_eq!(aes_cbc_decrypt(&kk, &iv, &ct)?, vec![0x42; 16]);
        Ok(())
    }

    #[test]
    fn test_keyring_encrypt_password_pads_pkcs7() -> Result<(), CryptoError> {
        let kk = Key16::new([0x5A; 16]);
        let iv = keyring_iv("x");
        for pw in ["", "hi", "exactly8", "a-longer-password-than-a-block"] {
            let password = crate::key::Password::new(pw);
            let ct = keyring_encrypt_password(&kk, &iv, &[7u8; 8], &password)?;
            let plain = aes_cbc_decrypt(&kk, &iv, &ct)?;
            let pad = usize::from(*plain.last().ok_or(CryptoError::BadBlockLen(0))?);
            assert!((1..=16).contains(&pad));
            assert_eq!(&plain[..8], &[7u8; 8]);
            assert_eq!(&plain[8..plain.len() - pad], pw.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn test_keyring_password_prefix_is_keyed_and_stable() {
        let pw = crate::key::Password::new("pw");
        let a = keyring_password_prefix(&Key16::new([1; 16]), "Device/1.1.1", &pw);
        assert_eq!(
            a,
            keyring_password_prefix(&Key16::new([1; 16]), "Device/1.1.1", &pw)
        );
        assert_ne!(
            a,
            keyring_password_prefix(&Key16::new([2; 16]), "Device/1.1.1", &pw)
        );
        assert_ne!(
            a,
            keyring_password_prefix(&Key16::new([1; 16]), "Device/1.1.2", &pw)
        );
    }

    #[test]
    fn test_byte_pad_zero_pads_to_block_multiple() {
        assert_eq!(byte_pad(&[]).len(), 0);
        assert_eq!(byte_pad(&[1]).len(), 16);
        assert_eq!(byte_pad(&[0u8; 16]).len(), 16);
        assert_eq!(byte_pad(&[0u8; 17]).len(), 32);
        let padded = byte_pad(&[0xAA, 0xBB]);
        assert_eq!(padded[0], 0xAA);
        assert_eq!(padded[1], 0xBB);
        assert!(padded[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_bytes_xor() {
        assert_eq!(bytes_xor(&[0x0F, 0xF0], &[0xFF, 0x0F]), vec![0xF0, 0xFF]);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    /// Spec §3.5 worked vector #1: a CBC-MAC over `additional_data = [0x11]`,
    /// empty payload, all-zero key and all-zero block_0. Both implementers derive
    /// this independently and diff; a mismatch means one side's CCM decomposition
    /// diverged.
    ///
    /// The buffer is `block_0(16×00) || len(1):BE(00 01) || ad(11)` = 19 bytes,
    /// zero-padded to 32, AES-CBC-encrypted under a zero key with a zero IV; the
    /// MAC is the last cipher block. Computed independently in Python:
    ///
    /// ```python
    /// from Crypto.Cipher import AES
    /// buf = bytes(16) + (1).to_bytes(2,"big") + bytes([0x11])
    /// buf += bytes((-len(buf)) % 16)
    /// ct = AES.new(bytes(16), AES.MODE_CBC, bytes(16)).encrypt(buf)
    /// print(ct[-16:].hex())
    /// ```
    #[test]
    fn test_cbc_mac_worked_vector_zero_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = Key16::new([0u8; 16]);
        let mac = cbc_mac(&key, &[0x11], &[], &[0u8; 16])?;
        assert_eq!(
            mac,
            [
                0x7b, 0x4e, 0x7e, 0xfe, 0x4a, 0x9b, 0x46, 0x62, 0xfd, 0x03, 0x71, 0xaa, 0x9f, 0x1a,
                0x2f, 0x5f,
            ]
        );
        Ok(())
    }

    #[test]
    fn test_cbc_mac_rejects_bad_block_len() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            cbc_mac(&key, &[], &[], &[0u8; 8]),
            Err(CryptoError::BadBlockLen(8))
        );
    }

    /// CTR encryption then decryption round-trips the MAC and payload.
    #[test]
    fn test_ctr_round_trip() -> Result<(), CryptoError> {
        let key = Key16::new([0x24; 16]);
        let counter_0 = [0x01u8; 16];
        let mac_cbc = [0xEE; 4];
        let payload = b"secure management apdu".to_vec();
        let (enc_payload, enc_mac) = encrypt_ctr(&key, &counter_0, &mac_cbc, &payload)?;
        assert_ne!(enc_payload, payload);
        assert_ne!(enc_mac, mac_cbc);
        let (dec_payload, dec_mac) = decrypt_ctr(&key, &counter_0, &enc_mac, &enc_payload)?;
        assert_eq!(dec_payload, payload);
        assert_eq!(dec_mac, mac_cbc);
        Ok(())
    }

    /// The keystream is one stream over `mac || payload`: with a 4-byte MAC the
    /// payload starts at keystream byte 4, with a 16-byte MAC at byte 16. This is
    /// the layout ETS uses (secure-1-1-12 capture, 2026-09-23).
    #[test]
    fn test_ctr_payload_continues_after_the_mac() -> Result<(), CryptoError> {
        let key = Key16::new([0x5A; 16]);
        let counter_0 = [0x02u8; 16];
        // The raw keystream: encrypt 32 zero bytes with an empty MAC.
        let (stream, _) = encrypt_ctr(&key, &counter_0, &[], &[0u8; 32])?;
        let (enc4, mac4) = encrypt_ctr(&key, &counter_0, &[0u8; 4], &[0u8; 8])?;
        assert_eq!(mac4, stream[..4].to_vec());
        assert_eq!(enc4, stream[4..12].to_vec());
        let (enc16, mac16) = encrypt_ctr(&key, &counter_0, &[0u8; 16], &[0u8; 8])?;
        assert_eq!(mac16, stream[..16].to_vec());
        assert_eq!(enc16, stream[16..24].to_vec());
        Ok(())
    }

    #[test]
    fn test_ctr_rejects_an_oversized_mac() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            encrypt_ctr(&key, &[0u8; 16], &[0u8; 17], &[]),
            Err(CryptoError::BadBlockLen(17))
        );
    }

    /// Spec §3.4 PBKDF2 vector: the keyring password key for a known password.
    /// Computed independently in Python:
    ///
    /// ```python
    /// import hashlib
    /// hashlib.pbkdf2_hmac("sha256", b"secret", b"1.keyring.ets.knx.org", 65536, 16).hex()
    /// ```
    #[test]
    fn test_pbkdf2_keyring_salt_vector() {
        let key = pbkdf2_key(b"secret", salt::KEYRING);
        assert_eq!(
            key.bytes(),
            &[
                0x35, 0x40, 0x73, 0x6b, 0xa4, 0x5a, 0x49, 0xe0, 0xfd, 0xa3, 0xfc, 0x49, 0xc4, 0x76,
                0x7d, 0x61,
            ]
        );
    }

    /// Spec §3.4 PBKDF2 vector: the user-password key for a known password.
    /// Computed independently in Python:
    ///
    /// ```python
    /// import hashlib
    /// hashlib.pbkdf2_hmac("sha256", b"secret", b"user-password.1.secure.ip.knx.org", 65536, 16).hex()
    /// ```
    #[test]
    fn test_pbkdf2_user_password_salt_vector() {
        let key = pbkdf2_key(b"secret", salt::USER_PASSWORD);
        assert_eq!(
            key.bytes(),
            &[
                0x03, 0xfc, 0xed, 0xb6, 0x66, 0x60, 0x25, 0x1e, 0xc8, 0x1a, 0x1a, 0x71, 0x69, 0x01,
                0x69, 0x6a,
            ]
        );
    }

    /// AES-CBC decrypt inverts an independently-encrypted CBC ciphertext.
    #[test]
    fn test_aes_cbc_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        let key = Key16::new([0x33; 16]);
        let iv = [0x07u8; 16];
        let plaintext = *b"sixteen byte blk";
        let mut ct = plaintext;
        let mut enc = Aes128CbcEnc::new(key.bytes().into(), &iv.into());
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut ct);
        enc.encrypt_block_mut(ga);
        let dec = aes_cbc_decrypt(&key, &iv, &ct)?;
        assert_eq!(dec, plaintext);
        Ok(())
    }

    /// `aes_cbc_encrypt` and `aes_cbc_decrypt` round-trip a multi-block message.
    #[test]
    fn test_aes_cbc_encrypt_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = Key16::new([0x5A; 16]);
        let iv = [0x11u8; 16];
        let plaintext = b"thirty-two bytes across 2 blocks".to_vec();
        assert_eq!(plaintext.len() % BLOCK, 0);
        let ct = aes_cbc_encrypt(&key, &iv, &plaintext)?;
        assert_ne!(ct, plaintext);
        let dec = aes_cbc_decrypt(&key, &iv, &ct)?;
        assert_eq!(dec, plaintext);
        Ok(())
    }

    #[test]
    fn test_aes_cbc_encrypt_rejects_bad_len() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            aes_cbc_encrypt(&key, &[0u8; 8], &[0u8; 16]),
            Err(CryptoError::BadBlockLen(8))
        );
        assert_eq!(
            aes_cbc_encrypt(&key, &[0u8; 16], &[0u8; 20]),
            Err(CryptoError::BadBlockLen(20))
        );
    }

    #[test]
    fn test_aes_cbc_decrypt_rejects_bad_len() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            aes_cbc_decrypt(&key, &[0u8; 8], &[0u8; 16]),
            Err(CryptoError::BadBlockLen(8))
        );
        assert_eq!(
            aes_cbc_decrypt(&key, &[0u8; 16], &[0u8; 20]),
            Err(CryptoError::BadBlockLen(20))
        );
    }

    #[test]
    fn test_latin1_bytes() {
        assert_eq!(latin1_bytes("abc"), vec![0x61, 0x62, 0x63]);
        // U+00FC (ü) is representable in Latin-1 as 0xFC.
        assert_eq!(latin1_bytes("ü"), vec![0xFC]);
        // Above 0xFF is replaced with '?'.
        assert_eq!(latin1_bytes("€"), vec![b'?']);
    }
}
