//! Group-key and sender admission lookups on the security object: the group
//! key table (PID 53) rows by address-table index and the security individual
//! address table (PID 54) rows by sender. The secured group path
//! (`secure_group.rs`) uses these to pick a key and admit a sender.

use super::{GRP_KEY_ROW, IA_ROW, SecurityObject};

impl SecurityObject {
    /// Number of rows in the group key table.
    pub fn group_key_rows(&self) -> usize {
        self.group_keys.count()
    }

    /// The address-table index of group key row `row` (1-based), if written.
    /// Only the index is exposed, never the key.
    pub fn group_key_address_index(&self, row: u16) -> Option<u16> {
        let off = usize::from(row).checked_sub(1)? * GRP_KEY_ROW;
        let b = self.group_keys.bytes.get(off..off + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    /// The group key of the first row naming address-table index `index` (the
    /// 1-based TSAP of a group address). Crate-internal: the key only feeds the
    /// group crypto path and is never logged ([`crate::secure::Key16`] redacts).
    pub(crate) fn group_key_for_address_index(&self, index: u16) -> Option<crate::secure::Key16> {
        self.group_keys
            .bytes
            .chunks_exact(GRP_KEY_ROW)
            .find(|row| u16::from_be_bytes([row[0], row[1]]) == index)
            .and_then(|row| <[u8; 16]>::try_from(&row[2..]).ok())
            .map(crate::secure::Key16::new)
    }

    /// Number of rows in the security individual address table.
    pub fn ia_table_rows(&self) -> usize {
        self.ia_table.count()
    }

    /// The sequence number of the security individual address table row for
    /// sender `ia` (raw individual address), or `None` when the table does not
    /// list it (issue #181: a device drops secured group telegrams from
    /// senders it does not list).
    pub fn ia_table_sequence(&self, ia: u16) -> Option<u64> {
        self.ia_table
            .bytes
            .chunks_exact(IA_ROW)
            .take(self.ia_table.count())
            .find(|row| u16::from_be_bytes([row[0], row[1]]) == ia)
            .map(|row| {
                let mut buf = [0u8; 8];
                buf[2..].copy_from_slice(&row[2..]);
                u64::from_be_bytes(buf)
            })
    }
}
