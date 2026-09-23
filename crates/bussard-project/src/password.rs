//! ETS zip-password derivation, forked by ETS release family.
//!
//! A password-protected `.knxproj` stores its inner project as an encrypted
//! ZIP, but *which* encryption and *what* archive password depends on the ETS
//! version that produced the export:
//!
//! * **ETS 4 and ETS 5** (schema < 21): the inner archive uses traditional
//!   PKWARE ZipCrypto, and the archive password is simply the user's project
//!   password encoded as **UTF-8** — there is no key derivation.
//! * **ETS 6** (schema ≥ 21): the inner archive is WinZip-AES, and the archive
//!   password is *derived* from the user's password as
//!
//!   ```text
//!   base64(PBKDF2-HMAC-SHA256(utf16le(password), salt, 65536, 32))
//!   ```
//!
//!   with a fixed salt of `"21.project.ets.knx.org"`.
//!
//! These are format facts (reimplemented here, not copied). [`archive_password`]
//! is the version-aware switch the container calls; [`derive_zip_password`]
//! remains the public ETS 6 primitive (also re-exported at the crate root).

use base64::Engine;
use bussard_secure::pbkdf2_sha256;
use zeroize::Zeroizing;

use crate::version::SchemaVersion;

/// The bytes to hand the ZIP decryptor as the inner-archive password, chosen by
/// the export's ETS family.
///
/// For ETS 6 this is the base64 of the PBKDF2-derived key (ASCII); for ETS 4/5
/// it is the raw project password encoded as UTF-8. Returning owned bytes keeps
/// both branches uniform for the caller.
pub fn archive_password(project_password: &str, schema: SchemaVersion) -> Vec<u8> {
    if schema.uses_ets6_encryption() {
        derive_zip_password(project_password).into_bytes()
    } else {
        // ETS 4/5 traditional ZipCrypto: the raw password, UTF-8 encoded.
        project_password.as_bytes().to_vec()
    }
}

/// The fixed PBKDF2 salt used by ETS 6 for the inner-zip password.
const ETS6_SALT: &[u8] = b"21.project.ets.knx.org";

/// The PBKDF2 iteration count used by ETS 6.
const ETS6_ITERATIONS: u32 = 65_536;

/// The derived-key length in bytes.
const ETS6_KEY_LEN: usize = 32;

/// Derives the WinZip-AES password for the inner project archive from the
/// user's project password, using the ETS 6 scheme.
///
/// The password is encoded as UTF-16 little-endian before hashing (this is the
/// detail that differs from a naive UTF-8 implementation and is required to
/// match ETS / xknxproject).
pub fn derive_zip_password(project_password: &str) -> String {
    let mut utf16 = Zeroizing::new(Vec::with_capacity(project_password.len() * 2));
    for unit in project_password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }

    let key = pbkdf2_sha256(&utf16, ETS6_SALT, ETS6_ITERATIONS, ETS6_KEY_LEN);

    base64::engine::general_purpose::STANDARD.encode(key.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic vector: derive against a known password and cross-check the
    /// PBKDF2 output computed independently (Python:
    /// `base64.b64encode(hashlib.pbkdf2_hmac("sha256",
    /// "test".encode("utf-16-le"), b"21.project.ets.knx.org", 65536, 32))`).
    #[test]
    fn known_vector_test_password() {
        let got = derive_zip_password("test");
        assert_eq!(got, "2+IIP7ErCPPKxFjJXc59GFx2+w/1VTLHjJ2duc04CYQ=");
    }

    /// A second synthetic vector with non-ASCII input to exercise the UTF-16-LE
    /// encoding path.
    #[test]
    fn known_vector_unicode_password() {
        let got = derive_zip_password("bü");
        assert_eq!(got, "9fCm2E7lxlqqk1aRvZxHuJKdWAFqk6C5anltvcxRrwM=");
    }

    #[test]
    fn deterministic() {
        assert_eq!(derive_zip_password("abc"), derive_zip_password("abc"));
    }

    /// A third documented ETS 6 vector with an astral-plane emoji, exercising
    /// UTF-16-LE surrogate-pair encoding. This is a KNX-format fact (the ETS 6
    /// derived-password scheme), reproduced independently here.
    #[test]
    fn known_vector_emoji_password() {
        let got = derive_zip_password("Penn¥w1se 🤡");
        assert_eq!(got, "ZjlYlh+eTtoHvFadU7+EKvF4jOdEm7WkP49uanOMMk0=");
    }

    /// The ETS 6 branch of the version switch matches [`derive_zip_password`].
    #[test]
    fn test_archive_password_ets6_derives() {
        let schema = SchemaVersion::from_version(21).unwrap();
        assert_eq!(
            archive_password("test", schema),
            derive_zip_password("test").into_bytes()
        );
    }

    /// The ETS 4/5 branch passes the raw UTF-8 password through, with no KDF.
    #[test]
    fn test_archive_password_ets4_and_ets5_are_raw_utf8() {
        for version in [11u32, 14, 20] {
            let schema = SchemaVersion::from_version(version).unwrap();
            // ETS 5.7 (20) still uses the ETS 4/5 ZipCrypto password path.
            assert_eq!(
                archive_password("test", schema),
                b"test".to_vec(),
                "schema {version} should use the raw password"
            );
        }
    }
}
