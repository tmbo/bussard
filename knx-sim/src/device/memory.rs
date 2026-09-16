//! A sparse device memory model with allocated segments.
//!
//! A real KNX device has a small address space (System B uses a 16-bit address,
//! with the table/segment bases in the ETS capture at 0x6000/0x8000/0xA000/
//! 0xC000). Memory is modelled sparsely: only written cells are stored, and
//! writes are bounded to *allocated segments*. A write to an address that no
//! open segment covers is rejected — this strictness is what catches a tool
//! that targets the wrong base.

use std::collections::BTreeMap;

/// One allocated memory segment: a base address, a length and the object (LSM
/// index) that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// The object (LSM index) that owns this segment.
    pub owner: u8,
    /// The base address.
    pub base: u16,
    /// The allocated length in bytes.
    pub len: u32,
}

impl Segment {
    /// True if `[addr, addr+len)` lies wholly within this segment.
    pub fn contains(&self, addr: u16, len: usize) -> bool {
        let end = self.base as u32 + self.len;
        let req_end = addr as u32 + len as u32;
        addr as u32 >= self.base as u32 && req_end <= end
    }
}

/// The reason a memory write was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemoryError {
    /// The write did not fall entirely within any allocated segment.
    #[error("memory write to 0x{addr:04x}+{len} is outside any allocated segment")]
    OutOfSegment {
        /// The write base address.
        addr: u16,
        /// The write length.
        len: usize,
    },
    /// The write fell within a segment owned by a different object than the one
    /// currently being programmed.
    #[error(
        "memory write to 0x{addr:04x} lands in object {found}'s segment, expected object {expected}"
    )]
    WrongOwner {
        /// The write address.
        addr: u16,
        /// The object owning the segment hit.
        found: u8,
        /// The object the caller expected to be writing.
        expected: u8,
    },
}

/// The sparse memory with its allocated segments.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    cells: BTreeMap<u16, u8>,
    segments: Vec<Segment>,
}

impl Memory {
    /// Create an empty memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate (or replace) the segment owned by `owner` at `base` of `len`
    /// bytes. Any previous segment for the same owner is dropped so a re-flash
    /// starts clean.
    pub fn allocate(&mut self, owner: u8, base: u16, len: u32) {
        self.segments.retain(|s| s.owner != owner);
        self.segments.push(Segment { owner, base, len });
    }

    /// The allocated segment owned by `owner`, if any.
    pub fn segment_of(&self, owner: u8) -> Option<Segment> {
        self.segments.iter().copied().find(|s| s.owner == owner)
    }

    /// The segment covering `addr`, if any.
    pub fn segment_at(&self, addr: u16) -> Option<Segment> {
        self.segments.iter().copied().find(|s| s.contains(addr, 1))
    }

    /// Write `data` at `addr`, bounded to the segment owned by `expected_owner`.
    /// Strict: rejects writes outside any segment or into another object's
    /// segment.
    pub fn write(&mut self, expected_owner: u8, addr: u16, data: &[u8]) -> Result<(), MemoryError> {
        let seg = self
            .segments
            .iter()
            .copied()
            .find(|s| s.contains(addr, data.len()))
            .ok_or(MemoryError::OutOfSegment {
                addr,
                len: data.len(),
            })?;
        if seg.owner != expected_owner {
            return Err(MemoryError::WrongOwner {
                addr,
                found: seg.owner,
                expected: expected_owner,
            });
        }
        for (i, b) in data.iter().enumerate() {
            self.cells.insert(addr.wrapping_add(i as u16), *b);
        }
        Ok(())
    }

    /// Read `len` bytes starting at `addr`; unwritten cells read back as `0x00`.
    /// This models verify-on-read for the tool.
    pub fn read(&self, addr: u16, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                self.cells
                    .get(&addr.wrapping_add(i as u16))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }

    /// Total number of written cells (for tests/observability).
    pub fn written_len(&self) -> usize {
        self.cells.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_within_segment_roundtrips() -> Result<(), MemoryError> {
        let mut mem = Memory::new();
        mem.allocate(4, 0x6000, 256);
        mem.write(4, 0x6000, &[0x05, 0x05, 0xff])?;
        assert_eq!(mem.read(0x6000, 3), vec![0x05, 0x05, 0xff]);
        Ok(())
    }

    #[test]
    fn test_write_outside_segment_rejected() {
        let mut mem = Memory::new();
        mem.allocate(4, 0x6000, 256);
        // 0x8000 is not covered.
        assert!(matches!(
            mem.write(4, 0x8000, &[0x00]),
            Err(MemoryError::OutOfSegment { .. })
        ));
    }

    #[test]
    fn test_write_wrong_owner_rejected() {
        let mut mem = Memory::new();
        mem.allocate(4, 0x6000, 256);
        // Object 3 tries to write into object 4's segment.
        assert!(matches!(
            mem.write(3, 0x6000, &[0x00]),
            Err(MemoryError::WrongOwner {
                found: 4,
                expected: 3,
                ..
            })
        ));
    }

    #[test]
    fn test_write_straddling_segment_end_rejected() {
        let mut mem = Memory::new();
        mem.allocate(4, 0x6000, 4);
        assert!(mem.write(4, 0x6002, &[0, 0, 0, 0]).is_err());
    }
}
