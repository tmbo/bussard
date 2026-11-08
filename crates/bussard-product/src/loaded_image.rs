//! The `LoadedImage` attribute of a catalogue `<Hardware2Program>`.
//!
//! ETS stores in it, per hardware and program, a list of memory segments and
//! property values: base64 of a raw deflate stream. The layout below is read
//! from the product catalogue, not from a published specification (issue
//! #949). All integers are little-endian: the decoded header of every sample
//! starts `01 00 01 00 <n as u32 LE>` (`M-0001_A-9A01-03-E6C8`:
//! `0100 0100 0200 0000`, two entries).
//!
//! ```text
//! u16 1, u16 1, u32 n
//! n × { u32 kind, u16 object, u16 pid, u32 offset, u32 len, u8 tag,
//!       data[len], mask[len] (when tag bit 1 is set) }
//! ```
//!
//! Kind 12 is an interface object's memory segment (object 3 the group-object
//! table, object 4 the application), kind 5 a property value (PID 208) and
//! kind 4 a property compare (PID 78). Every tag seen in the sweep corpus is
//! `3`, so every entry there carries a mask.
//!
//! bussard uses the list for one thing: whether it holds a segment of the
//! group-object table, one of the two triggers of the ETS download-plugin
//! table shape ([`crate::ApplicationProgram::ets_download_plugin_shape`]).

use std::io::Read;

use base64::Engine;

/// Kind of an entry that is an interface object's memory segment.
pub const KIND_MEMORY_SEGMENT: u32 = 12;

/// Interface object index of the group-object table.
pub const OBJECT_GROUP_OBJECT_TABLE: u16 = 3;

/// The most octets a `LoadedImage` may inflate to. The largest one in the
/// sweep corpus is well under 1 MiB; the cap only stops a deflate bomb.
const MAX_INFLATED: u64 = 16 * 1024 * 1024;

/// One entry of a decoded `LoadedImage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedImageEntry {
    /// What the entry is: [`KIND_MEMORY_SEGMENT`], 5 a property value, 4 a
    /// property compare.
    pub kind: u32,
    /// The interface object index (for a memory segment: 3 the group-object
    /// table, 4 the application).
    pub object: u16,
    /// The property id the entry names.
    pub pid: u16,
    /// The offset of `data` within the object's memory or property.
    pub offset: u32,
    /// The entry's tag octet (bit 1: a mask follows the data).
    pub tag: u8,
    /// The stored octets.
    pub data: Vec<u8>,
}

/// Why a `LoadedImage` did not decode.
#[derive(Debug, thiserror::Error)]
pub enum LoadedImageError {
    /// The attribute is not valid base64.
    #[error("not base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The base64 payload is not a raw deflate stream.
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

/// Parses an inflated `LoadedImage` entry list (little-endian, see the module
/// documentation).
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
        let entry = cursor.entry().ok_or(LoadedImageError::Truncated(index))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Whether `entries` hold a memory segment of the group-object table
/// (interface object 3), of any length.
pub fn has_group_object_table_segment(entries: &[LoadedImageEntry]) -> bool {
    entries
        .iter()
        .any(|e| e.kind == KIND_MEMORY_SEGMENT && e.object == OBJECT_GROUP_OBJECT_TABLE)
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
        if tag & 0x02 != 0 {
            self.take(len)?;
        }
        Some(LoadedImageEntry {
            kind,
            object,
            pid,
            offset,
            tag,
            data,
        })
    }
}

/// Builders of `LoadedImage` values for tests.
#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine;
    use std::io::Write;

    /// One entry as ETS stores it, with tag 3 (a mask follows the data).
    pub(crate) fn entry(kind: u32, object: u16, pid: u16, offset: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(kind.to_le_bytes());
        out.extend(object.to_le_bytes());
        out.extend(pid.to_le_bytes());
        out.extend(offset.to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.push(3);
        out.extend(data);
        out.extend(std::iter::repeat_n(0xFF, data.len()));
        out
    }

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
    use super::test_support::{attribute, entry, list};
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The layout of `M-0001_A-9A01-03-E6C8` (Siemens): two memory
    /// segments, the group-object table (object 3, 1158 octets) and the
    /// application (object 4, 4664 octets), both PID 7 at offset 0.
    fn siemens_9a01() -> Vec<u8> {
        let mut table = vec![0x02, 0x42];
        table.resize(1158, 0x13);
        list(&[
            entry(12, 3, 7, 0, &table),
            entry(12, 4, 7, 0, &vec![0; 4664]),
        ])
    }

    /// The layout of `M-0009_A-E0D0-11-434F` (Hager): eleven PID 208
    /// property values, objects 0 to 10, and no memory segment.
    fn hager_e0d0() -> Vec<u8> {
        let lens = [124, 124, 124, 124, 124, 124, 76, 4, 4, 1, 32];
        let entries: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(i, &n)| entry(5, i as u16, 0xD0, 0, &vec![0; n]))
            .collect();
        list(&entries)
    }

    /// The layout of `M-0009_A-E0D3-12-35BF` (Hager): property values and,
    /// last, an empty group-object table, the 2-octet segment `00 00`.
    fn hager_e0d3() -> Vec<u8> {
        list(&[
            entry(5, 0, 0xD0, 0, &[0; 124]),
            entry(5, 8, 0xD0, 0x60, &[0; 8]),
            entry(12, 3, 7, 0, &[0, 0]),
        ])
    }

    #[test]
    fn test_decode_loaded_image_siemens_9a01_has_the_table() -> TestResult {
        let entries = decode_loaded_image(&attribute(&siemens_9a01())?)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(
            (entries[0].kind, entries[0].object, entries[0].pid),
            (12, 3, 7)
        );
        assert_eq!(entries[0].data.len(), 1158);
        assert_eq!(&entries[0].data[..2], &[0x02, 0x42]);
        assert_eq!((entries[1].object, entries[1].data.len()), (4, 4664));
        assert!(has_group_object_table_segment(&entries));
        Ok(())
    }

    #[test]
    fn test_decode_loaded_image_hager_e0d0_has_no_segment() -> TestResult {
        let entries = decode_loaded_image(&attribute(&hager_e0d0())?)?;
        assert_eq!(entries.len(), 11);
        assert!(entries.iter().all(|e| e.kind == 5 && e.pid == 0xD0));
        assert!(!has_group_object_table_segment(&entries));
        Ok(())
    }

    #[test]
    fn test_decode_loaded_image_hager_e0d3_empty_table_counts() -> TestResult {
        let entries = decode_loaded_image(&attribute(&hager_e0d3())?)?;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].offset, 0);
        assert_eq!(entries[1].offset, 0x60);
        assert_eq!(entries[2].data, vec![0, 0]);
        assert!(has_group_object_table_segment(&entries));
        Ok(())
    }

    #[test]
    fn test_parse_loaded_image_entry_without_mask() -> TestResult {
        let mut e = entry(12, 3, 7, 0, &[0, 0]);
        e[16] = 1; // tag without bit 1: no mask follows
        e.truncate(19);
        let entries = parse_loaded_image(&list(&[e]))?;
        assert_eq!(entries[0].data, vec![0, 0]);
        Ok(())
    }

    #[test]
    fn test_decode_loaded_image_refuses_malformed_input() -> TestResult {
        assert!(matches!(
            decode_loaded_image("not base64!"),
            Err(LoadedImageError::Base64(_))
        ));
        let mut truncated = siemens_9a01();
        truncated.truncate(100);
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
}
