//! A sparse device memory model with allocated segments.
//!
//! A real KNX device addresses memory with up to a 24-bit address. Classic
//! System B tables/segments sit low (the DA.tp capture bases at
//! 0x6000/0x8000/0xA000/0xC000), while a capable 07B0 device places its loadable
//! segments above 0x10000 (the Jung/ABB actuators at 0xf000..0x16000, writes to
//! 0x1aad3) and streams them with the extended memory service. Addresses are
//! therefore modelled as `u32`. Memory is modelled sparsely: only written cells
//! are stored, and writes are bounded to *allocated segments*. A write to an
//! address that no open segment covers is rejected — this strictness is what
//! catches a tool that targets the wrong base, and it applies identically to the
//! plain and extended write services.

use std::collections::BTreeMap;

/// One allocated memory segment: a base address, a length and the object (LSM
/// index) that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// The object (LSM index) that owns this segment.
    pub owner: u8,
    /// The base address (up to 24-bit).
    pub base: u32,
    /// The allocated length in bytes.
    pub len: u32,
}

impl Segment {
    /// True if `[addr, addr+len)` lies wholly within this segment.
    pub fn contains(&self, addr: u32, len: usize) -> bool {
        let end = self.base as u64 + self.len as u64;
        let req_end = addr as u64 + len as u64;
        addr as u64 >= self.base as u64 && req_end <= end
    }

    /// True if the two segments share an address.
    pub fn overlaps(&self, other: &Segment) -> bool {
        let (a0, a1) = (
            u64::from(self.base),
            u64::from(self.base) + u64::from(self.len),
        );
        let (b0, b1) = (
            u64::from(other.base),
            u64::from(other.base) + u64::from(other.len),
        );
        a0 < b1 && b0 < a1
    }
}

/// The reason a memory write was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemoryError {
    /// The write did not fall entirely within any allocated segment.
    #[error("memory write to 0x{addr:06x}+{len} is outside any allocated segment")]
    OutOfSegment {
        /// The write base address.
        addr: u32,
        /// The write length.
        len: usize,
    },
    /// The write fell within a segment owned by a different object than the one
    /// currently being programmed.
    #[error(
        "memory write to 0x{addr:06x} lands in object {found}'s segment, expected object {expected}"
    )]
    WrongOwner {
        /// The write address.
        addr: u32,
        /// The object owning the segment hit.
        found: u8,
        /// The object the caller expected to be writing.
        expected: u8,
    },
}

/// The sparse memory with its allocated segments.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    cells: BTreeMap<u32, u8>,
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
    pub fn allocate(&mut self, owner: u8, base: u32, len: u32) {
        self.segments.retain(|s| s.owner != owner);
        self.segments.push(Segment { owner, base, len });
    }

    /// Allocate one more segment for `owner` at `base` of `len` bytes, keeping
    /// the owner's other segments. A System 7 load-state machine owns several
    /// absolute segments at once (the Theben 0701 LSM 3 holds `0x1C00`,
    /// `0x4400`, `0x4800` and `0x4C00`), and a later partial download writes
    /// into any of them without allocating again. Only a segment of the same
    /// owner that overlaps the new range is dropped, so a re-flash with the
    /// same layout starts clean.
    pub fn allocate_additional(&mut self, owner: u8, base: u32, len: u32) {
        let new = Segment { owner, base, len };
        self.segments
            .retain(|s| s.owner != owner || !s.overlaps(&new));
        self.segments.push(new);
    }

    /// Whether `[base, base+len)` overlaps a segment some other object owns.
    pub fn overlaps_other(&self, owner: u8, base: u32, len: u32) -> bool {
        let new = Segment { owner, base, len };
        self.segments
            .iter()
            .any(|s| s.owner != owner && s.overlaps(&new))
    }

    /// The lowest 4 KiB-aligned base at or above `from` where `len` bytes
    /// overlap no segment of another object.
    pub fn free_base(&self, owner: u8, from: u32, len: u32) -> u32 {
        let mut base = from;
        while let Some(end) = self
            .segments
            .iter()
            .filter(|s| s.owner != owner && s.overlaps(&Segment { owner, base, len }))
            .map(|s| s.base.saturating_add(s.len))
            .max()
        {
            base = end.saturating_add(0xFFF) & !0xFFF;
        }
        base
    }

    /// Whether any segment owned by `owner` covers `addr`.
    pub fn owner_covers(&self, owner: u8, addr: u32) -> bool {
        self.segments
            .iter()
            .any(|s| s.owner == owner && s.contains(addr, 1))
    }

    /// Erase the segment owned by `owner`: drop its allocation and every cell
    /// written inside it, so it reads back as `0x00` (a master reset with an
    /// erasing code). A no-op when `owner` holds no segment.
    pub fn erase_owner(&mut self, owner: u8) {
        let Some(seg) = self.segment_of(owner) else {
            return;
        };
        let end = u64::from(seg.base) + u64::from(seg.len);
        self.cells
            .retain(|&addr, _| u64::from(addr) < u64::from(seg.base) || u64::from(addr) >= end);
        self.segments.retain(|s| s.owner != owner);
    }

    /// Release the segment owned by `owner` without clearing its cells (an
    /// Unload: the allocation is freed, the stored octets stay where they were,
    /// so a partial download that reallocates the same place and writes only
    /// the differing octets keeps the rest, as ETS relies on).
    pub fn release_owner(&mut self, owner: u8) {
        self.segments.retain(|s| s.owner != owner);
    }

    /// The allocated segment owned by `owner`, if any.
    pub fn segment_of(&self, owner: u8) -> Option<Segment> {
        self.segments.iter().copied().find(|s| s.owner == owner)
    }

    /// The segment covering `addr`, if any.
    pub fn segment_at(&self, addr: u32) -> Option<Segment> {
        self.segments.iter().copied().find(|s| s.contains(addr, 1))
    }

    /// Write `data` at `addr`, bounded to the segment owned by `expected_owner`.
    /// Strict: rejects writes outside any segment or into another object's
    /// segment.
    pub fn write(&mut self, expected_owner: u8, addr: u32, data: &[u8]) -> Result<(), MemoryError> {
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
            self.cells.insert(addr.wrapping_add(i as u32), *b);
        }
        Ok(())
    }

    /// Place factory content at `addr` outside every segment: memory the
    /// device holds from the factory (a hardware id a vendor procedure's
    /// `LdCtrlCompareMem` checks) rather than memory a download writes. No
    /// tool write can reach it, since a write must land in a segment.
    pub fn seed(&mut self, addr: u32, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.cells.insert(addr.wrapping_add(i as u32), *b);
        }
    }

    /// Read `len` bytes starting at `addr`; unwritten cells read back as `0x00`.
    /// This models verify-on-read for the tool.
    pub fn read(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                self.cells
                    .get(&addr.wrapping_add(i as u32))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }

    /// Read `len` bytes at `addr` **bounded to one allocated segment**: `None`
    /// unless `[addr, addr+len)` lies wholly inside a single allocated segment.
    ///
    /// [`Memory::read`] models the tool's verify-on-read and is deliberately
    /// permissive (unwritten cells read back as zero). The device's own table
    /// parsers must not be: a table whose count word says `0xFFFF` would
    /// otherwise read hundreds of kilobytes past the segment the tool actually
    /// allocated and accept the garbage as routing. Bounding the read to the
    /// segment turns that into a refusal, which is what a real device does.
    pub fn read_bounded(&self, addr: u32, len: usize) -> Option<Vec<u8>> {
        self.segments
            .iter()
            .find(|s| s.contains(addr, len))
            .map(|_| self.read(addr, len))
    }

    /// Total number of written cells (for tests/observability).
    pub fn written_len(&self) -> usize {
        self.cells.len()
    }

    /// The bytes actually written into the segment owned by `owner`, as a
    /// contiguous block starting at the segment base and ending at the highest
    /// written cell within the segment (inclusive). Unwritten gaps below that
    /// high-water mark read back as `0x00`.
    ///
    /// This is what a device's `PID_MCB_TABLE` covers: the loaded image the tool
    /// streamed, not the (possibly larger) allocated segment. A tool that writes
    /// a short table image into a larger allocation gets an MCB CRC over exactly
    /// those bytes. Returns `None` if the owner has no segment, and an empty vec
    /// if the segment was allocated but never written.
    pub fn written_span(&self, owner: u8) -> Option<Vec<u8>> {
        let seg = self.segment_of(owner)?;
        let base = seg.base as u64;
        let end = base + seg.len as u64;
        // The highest written address within the segment, if any.
        let high = self
            .cells
            .keys()
            .map(|&a| a as u64)
            .filter(|&a| a >= base && a < end)
            .max();
        let Some(high) = high else {
            return Some(Vec::new());
        };
        let len = (high - base + 1) as usize;
        Some(self.read(seg.base, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_additional_keeps_the_owners_other_segments() -> Result<(), MemoryError> {
        let mut m = Memory::new();
        m.allocate_additional(3, 0x4400, 0x400);
        m.allocate_additional(3, 0x4800, 0x400);
        m.write(3, 0x480C, &[0x55])?;
        m.write(3, 0x4400, &[0x01])?;
        assert!(m.owner_covers(3, 0x4400) && m.owner_covers(3, 0x4BFF));
        // An overlapping allocation of the same owner replaces the old one.
        m.allocate_additional(3, 0x4700, 0x200);
        assert!(!m.owner_covers(3, 0x4400));
        assert!(m.owner_covers(3, 0x4700));
        Ok(())
    }

    #[test]
    fn test_erase_owner_clears_only_that_segment() -> Result<(), MemoryError> {
        let mut m = Memory::new();
        m.allocate(1, 0x1000, 4);
        m.allocate(4, 0x2000, 4);
        m.write(1, 0x1000, &[1, 2, 3, 4])?;
        m.write(4, 0x2000, &[5, 6, 7, 8])?;
        m.erase_owner(4);
        assert_eq!(m.read(0x2000, 4), vec![0, 0, 0, 0]);
        assert!(m.segment_of(4).is_none());
        assert_eq!(m.read(0x1000, 4), vec![1, 2, 3, 4]);
        Ok(())
    }

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

    #[test]
    fn test_read_bounded_refuses_reads_past_the_segment() -> Result<(), MemoryError> {
        let mut mem = Memory::new();
        mem.allocate(1, 0xA000, 16);
        mem.write(1, 0xA000, &[0xAB; 4])?;
        assert_eq!(mem.read_bounded(0xA000, 4), Some(vec![0xAB; 4]));
        // Exactly the segment: allowed. One byte past it: refused.
        assert!(mem.read_bounded(0xA000, 16).is_some());
        assert_eq!(mem.read_bounded(0xA000, 17), None);
        // An absurd length (a 0xFFFF count word * 4) is refused outright.
        assert_eq!(mem.read_bounded(0xA000, 0xFFFF * 4), None);
        // An address in no segment at all is refused.
        assert_eq!(mem.read_bounded(0x1000, 1), None);
        Ok(())
    }

    #[test]
    fn test_write_above_16bit_space_roundtrips() -> Result<(), MemoryError> {
        // A capable 07B0 object places its segment above 0xFFFF (the Jung/ABB
        // actuators at 0xf000..0x16000, writes to 0x1aad3). The sparse memory now
        // addresses the full 24-bit space, so an extended write there round-trips.
        let mut mem = Memory::new();
        mem.allocate(4, 0x01_6000, 0x5000);
        mem.write(4, 0x01_AAD0, &[0xDE, 0xAD, 0xBE, 0xEF])?;
        assert_eq!(mem.read(0x01_AAD0, 4), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(mem.segment_at(0x01_AAD0).map(|s| s.owner), Some(4));
        Ok(())
    }
}
