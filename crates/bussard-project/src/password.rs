//! ETS 6 zip-password derivation.
//!
//! A password-protected `.knxproj` stores its inner project as a WinZip-AES
//! archive whose password is *not* the user's project password directly.
//! Instead ETS 6 derives the archive password as
//!
//! ```text
//! base64(PBKDF2-HMAC-SHA256(utf16le(password), salt, 65536, 32))
//! ```
//!
//! with a fixed salt of `"21.project.ets.knx.org"`. This matches the scheme
//! implemented by the Python `xknxproject` library.

use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

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
    let mut utf16 = Vec::with_capacity(project_password.len() * 2);
    for unit in project_password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }

    let mut key = [0u8; ETS6_KEY_LEN];
    pbkdf2_hmac::<Sha256>(&utf16, ETS6_SALT, ETS6_ITERATIONS, &mut key);

    base64::engine::general_purpose::STANDARD.encode(key)
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
}
