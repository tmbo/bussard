//! The `LoadedImage` attribute of a catalogue `<Hardware2Program>` (bussard
//! issue #1012).
//!
//! ETS stores in it, per hardware and program, a list of memory segments and
//! property values: base64 of a raw deflate stream. The layout is read from
//! the product catalogue, not from a published specification (bussard issues
//! #949 and #951). All integers are little-endian:
//!
//! ```text
//! u16 1, u16 1, u32 n
//! n × { u32 kind, u16 object, u16 pid, u32 offset, u32 len, u8 tag,
//!       data[len], mask[len] (when tag bit 1 is set) }
//! ```
//!
//! Kind 12 is an interface object's memory segment, kind 5 a property value
//! and kind 4 a property compare. A kind 5 entry names its object relative to
//! the mask's first application object (`FirstAppObjectIdx` in
//! `knx_master.xml`: 6 on System B, 5 on System 7) and its offset is the
//! 0-based element the value starts at (`StartElement - 1` of the
//! `LdCtrlWriteProp` it matches). Its values are what the device holds when
//! its parameters are at their factory state: ETS leaves out a write the
//! value already holds after the procedure's `LdCtrlMasterReset
//! EraseCode="5"` (the sweep captures of `M-0009_A-E0D0-11-434F` and its
//! siblings).
//!
//! The simulator decodes the attribute itself: it has no dependency on the
//! bussard crates.

use std::io::Read;

use base64::Engine;

/// Kind of an entry that is a property value.
pub const KIND_PROPERTY_VALUE: u32 = 5;

/// The most octets a `LoadedImage` may inflate to; the cap only stops a
/// deflate bomb (the largest image of the sweep corpus is well under 1 MiB).
const MAX_INFLATED: u64 = 16 * 1024 * 1024;

/// One entry of a decoded `LoadedImage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedImageEntry {
    /// What the entry is: 12 a memory segment, [`KIND_PROPERTY_VALUE`], 4 a
    /// property compare.
    pub kind: u32,
    /// The interface object (relative to the mask's first application
    /// object for a property value).
    pub object: u16,
    /// The property id.
    pub pid: u16,
    /// The offset of `data`: the 0-based start element for a property value.
    pub offset: u32,
    /// The entry's tag octet (bit 1: a mask follows the data).
    pub tag: u8,
    /// The stored octets.
    pub data: Vec<u8>,
    /// The bits of `data` the entry defines, as long as `data`; empty when
    /// the tag carries no mask (every bit defined).
    pub mask: Vec<u8>,
}

/// Why a `LoadedImage` did not decode.
#[derive(Debug, thiserror::Error)]
pub enum LoadedImageError {
    /// The attribute is not valid base64.
    #[error("not base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The payload is not a raw deflate stream.
    #[error("not a deflate stream: {0}")]
    Inflate(#[from] std::io::Error),
    /// The stream inflates past the size cap.
    #[error("inflates past {MAX_INFLATED} octets")]
    TooLarge,
    /// The header is not `u16 1, u16 1`.
    #[error("unknown header {0:#06x} {1:#06x}")]
    Header(u16, u16),
    /// The entry list ends inside entry `.0` (counted from 0).
    #[error("truncated at entry {0}")]
    Truncated(u32),
}

/// The index of the first application interface object on the mask
/// `mask_version` (`07B0`, `MV-0701`, ...), the base a kind 5 entry's object
/// is relative to: the `FirstAppObjectIdx` of the mask in `knx_master.xml`
/// (4 on the 0020 family, 5 on System 7, 6 on System B). `None` for a mask
/// that declares none.
pub fn first_app_object_index(mask_version: &str) -> Option<u8> {
    let mask = mask_version.trim().to_ascii_uppercase();
    match mask.strip_prefix("MV-").unwrap_or(&mask) {
        "0020" | "0021" | "0025" => Some(4),
        "0701" | "0705" | "2705" | "5705" => Some(5),
        "07B0" | "1310" | "27B0" | "57B0" => Some(6),
        _ => None,
    }
}

/// Decodes a `LoadedImage` attribute value into its entries.
///
/// # Errors
///
/// The value is not base64 of a raw deflate stream, or the inflated list is
/// not in the layout of the module documentation.
pub fn decode_loaded_image(value: &str) -> Result<Vec<LoadedImageEntry>, LoadedImageError> {
    let compressed = base64::engine::general_purpose::STANDARD.decode(value.trim())?;
    let mut inflated = Vec::new();
    flate2::read::DeflateDecoder::new(compressed.as_slice())
        .take(MAX_INFLATED + 1)
        .read_to_end(&mut inflated)?;
    if inflated.len() as u64 > MAX_INFLATED {
        return Err(LoadedImageError::TooLarge);
    }
    parse_loaded_image(&inflated)
}

/// Parses an inflated `LoadedImage` entry list.
///
/// # Errors
///
/// The header is not `u16 1, u16 1`, or the list ends inside an entry.
pub fn parse_loaded_image(bytes: &[u8]) -> Result<Vec<LoadedImageEntry>, LoadedImageError> {
    let mut cursor = Cursor { bytes, at: 0 };
    let (Some(major), Some(minor), Some(count)) = (cursor.u16(), cursor.u16(), cursor.u32()) else {
        return Err(LoadedImageError::Truncated(0));
    };
    if (major, minor) != (1, 1) {
        return Err(LoadedImageError::Header(major, minor));
    }
    // Every entry takes at least 17 octets: never reserve more than the
    // input can hold.
    let mut entries = Vec::with_capacity((count as usize).min(bytes.len() / 17));
    for index in 0..count {
        entries.push(cursor.entry().ok_or(LoadedImageError::Truncated(index))?);
    }
    Ok(entries)
}

/// A little-endian reader over the inflated list.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn entry(&mut self) -> Option<LoadedImageEntry> {
        let kind = self.u32()?;
        let object = self.u16()?;
        let pid = self.u16()?;
        let offset = self.u32()?;
        let len = usize::try_from(self.u32()?).ok()?;
        let tag = self.u8()?;
        let data = self.take(len)?.to_vec();
        let mask = if tag & 0x02 != 0 {
            self.take(len)?.to_vec()
        } else {
            Vec::new()
        };
        Some(LoadedImageEntry {
            kind,
            object,
            pid,
            offset,
            tag,
            data,
            mask,
        })
    }
}

/// Builders of `LoadedImage` values for tests.
#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine;
    use std::io::Write;

    /// One entry with tag 3 and an all-ones mask.
    pub(crate) fn entry(kind: u32, object: u16, pid: u16, offset: u32, data: &[u8]) -> Vec<u8> {
        entry_masked(kind, object, pid, offset, data, &vec![0xFF; data.len()])
    }

    /// One entry with tag 3 and `mask`.
    pub(crate) fn entry_masked(
        kind: u32,
        object: u16,
        pid: u16,
        offset: u32,
        data: &[u8],
        mask: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(kind.to_le_bytes());
        out.extend(object.to_le_bytes());
        out.extend(pid.to_le_bytes());
        out.extend(offset.to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.push(3);
        out.extend(data);
        out.extend(mask);
        out
    }

    /// The entry list with its header.
    pub(crate) fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![1, 0, 1, 0];
        out.extend((entries.len() as u32).to_le_bytes());
        for e in entries {
            out.extend(e);
        }
        out
    }

    /// base64 of the raw deflate of `bytes`, as the attribute stores it.
    pub(crate) fn attribute(bytes: &[u8]) -> Result<String, std::io::Error> {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(enc.finish()?))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{attribute, entry, entry_masked, list};
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The shape of `M-0009_A-E0D0-11-434F`: PID 208 values on relative
    /// objects 0 to 10, each with a mask of `FF`.
    #[test]
    fn test_decode_loaded_image_property_values() -> TestResult {
        let image = list(&[
            entry(5, 0, 208, 0, &[0x8E, 0x05, 0x02]),
            entry_masked(5, 9, 208, 0x60, &[0x14, 0x30], &[0xFF, 0x0F]),
            entry(12, 3, 7, 0, &[0, 0]),
        ]);
        let entries = decode_loaded_image(&attribute(&image)?)?;
        assert_eq!(entries.len(), 3);
        assert_eq!(
            (
                entries[0].kind,
                entries[0].object,
                entries[0].pid,
                entries[0].offset
            ),
            (5, 0, 208, 0)
        );
        assert_eq!(entries[0].data, vec![0x8E, 0x05, 0x02]);
        assert_eq!((entries[1].object, entries[1].offset), (9, 0x60));
        assert_eq!(entries[1].mask, vec![0xFF, 0x0F]);
        assert_eq!(entries[2].kind, 12);
        Ok(())
    }

    /// Tag 1 (the System 7 `M-0009_A-E0ED-10-0B6F`): no mask follows.
    #[test]
    fn test_parse_loaded_image_entry_without_mask() -> TestResult {
        let mut e = entry(5, 1, 208, 0, &[7, 8]);
        e[16] = 1;
        e.truncate(19);
        let next = entry(5, 2, 208, 0, &[9]);
        let entries = parse_loaded_image(&list(&[e, next]))?;
        assert_eq!(entries[0].data, vec![7, 8]);
        assert!(entries[0].mask.is_empty());
        assert_eq!((entries[1].object, entries[1].data.clone()), (2, vec![9]));
        Ok(())
    }

    #[test]
    fn test_decode_loaded_image_refuses_malformed_input() -> TestResult {
        assert!(matches!(
            decode_loaded_image("not base64!"),
            Err(LoadedImageError::Base64(_))
        ));
        let mut truncated = list(&[entry(5, 0, 208, 0, &[0; 40])]);
        truncated.truncate(30);
        assert!(matches!(
            decode_loaded_image(&attribute(&truncated)?),
            Err(LoadedImageError::Truncated(0))
        ));
        assert!(matches!(
            parse_loaded_image(&[2, 0, 1, 0, 0, 0, 0, 0]),
            Err(LoadedImageError::Header(2, 1))
        ));
        assert!(matches!(
            parse_loaded_image(&[1, 0]),
            Err(LoadedImageError::Truncated(0))
        ));
        Ok(())
    }

    /// `FirstAppObjectIdx` of the masks in `knx_master.xml`.
    #[test]
    fn test_first_app_object_index_follows_the_master_data() {
        assert_eq!(first_app_object_index("MV-07B0"), Some(6));
        assert_eq!(first_app_object_index("57b0"), Some(6));
        assert_eq!(first_app_object_index("MV-0701"), Some(5));
        assert_eq!(first_app_object_index("0705"), Some(5));
        assert_eq!(first_app_object_index("0021"), Some(4));
        assert_eq!(first_app_object_index("MV-0010"), None);
    }
}
