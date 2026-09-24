//! The security object's value properties (`A_PropertyExtValue_Read` and
//! `_WriteCon`): the group key table (PID 53), the security individual address
//! table (PID 54), the tool key (PID 56), the sending sequence number (PID 59)
//! and the group-object security flags (PID 61), with their range checks.

use crate::wire::apdu::Apci;

use super::{
    ExtHeader, ExtReply, ExtServiceError, FALLBACK_MAX_GROUP_OBJECTS, GO_FLAG, GRP_KEY_ROW, IA_ROW,
    IOT_SECURITY, MAX_GO_FLAG, MAX_GROUP_KEY_ROWS, MAX_IA_TABLE_ROWS, SEQ_LEN, SecLoadState,
    SecurityLimits, SecurityObject, TOOL_KEY_LEN, pid, rc,
};

impl SecurityObject {
    /// The element count PID 61 reports: the group-object count when known,
    /// else the number of flags written.
    fn go_flag_elements(&self, limits: SecurityLimits) -> usize {
        limits
            .group_objects
            .map_or(self.go_flags.count(), usize::from)
            .max(self.go_flags.count())
    }

    /// `A_PropertyExtValue_Read`. Start 0 reads the element count (2 octets).
    /// A refused read answers count 0 and no data. Refused: unknown object or
    /// PID, the key tables (PID 53, PID 56: keys are write-only), a count of 0,
    /// and any element past the property's element count.
    pub(super) fn on_value_read(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtValue_Read", data)?;
        let Some(&[count, s_hi, s_lo]) = data.get(5..8) else {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtValue_Read",
                detail: "missing count/start".into(),
            });
        };
        let start = u16::from_be_bytes([s_hi, s_lo]);
        let value = self.read_value(h, count, start, limits);
        let mut out = h.encode().to_vec();
        let answered = if value.is_some() { count } else { 0 };
        out.push(answered);
        out.extend_from_slice(&start.to_be_bytes());
        if let Some(v) = &value {
            out.extend_from_slice(v);
        }
        let detail = format!(" start={start} count={count}");
        let rc = if value.is_some() {
            rc::SUCCESS
        } else {
            rc::ADDRESS_VOID
        };
        Ok(ExtReply {
            apci: Apci::PropertyExtValueResponse,
            data: out,
            summary: self.describe("ValueRead", h, &detail, rc),
        })
    }

    fn read_value(
        &self,
        h: ExtHeader,
        count: u8,
        start: u16,
        limits: SecurityLimits,
    ) -> Option<Vec<u8>> {
        if !h.is_security_object() || count == 0 {
            return None;
        }
        // Single-element scalar properties: count 1 start 1 (start 0 = count 1).
        let scalar = |v: Vec<u8>| -> Option<Vec<u8>> {
            match (start, count) {
                (0, 1) => Some(1u16.to_be_bytes().to_vec()),
                (1, 1) => Some(v),
                _ => None,
            }
        };
        let table = |bytes: &[u8], elem: usize, elements: usize| -> Option<Vec<u8>> {
            if start == 0 {
                return (count == 1).then(|| (elements as u16).to_be_bytes().to_vec());
            }
            let last = usize::from(start) + usize::from(count) - 1;
            if last > elements {
                return None;
            }
            let mut v = vec![0u8; usize::from(count) * elem];
            let off = (usize::from(start) - 1) * elem;
            let avail = bytes.len().saturating_sub(off).min(v.len());
            v[..avail].copy_from_slice(&bytes[off..off + avail]);
            Some(v)
        };
        match h.pid {
            pid::OBJECT_TYPE => scalar(IOT_SECURITY.to_be_bytes().to_vec()),
            pid::LOAD_STATE_CONTROL => scalar(vec![self.load_state.to_byte()]),
            pid::SECURITY_MODE => scalar(vec![self.security_mode]),
            pid::SEQUENCE_NUMBER_SENDING => scalar(self.seq_sending.to_vec()),
            pid::SECURITY_IA_TABLE => table(&self.ia_table.bytes, IA_ROW, self.ia_table.count()),
            // Unwritten flags within the group-object count read as 0x00.
            pid::GO_SECURITY_FLAGS => {
                table(&self.go_flags.bytes, GO_FLAG, self.go_flag_elements(limits))
            }
            // PID 53 and PID 56 hold keys: write-only, every read is refused.
            _ => None,
        }
    }

    /// `A_PropertyExtValue_WriteCon`, answered with a WriteConResponse
    /// `[count][start:16][rc]`.
    ///
    /// Checks, in order (rc):
    /// 1. unknown object or PID: `ADDRESS_VOID`; PID 1: `ACCESS_READ_ONLY`;
    ///    PID 5 and PID 51 are function properties: `INVALID_COMMAND`;
    /// 2. count 0: `INVALID_COMMAND`;
    /// 3. PID 56 (tool key, 16 octets) and PID 59 (sequence, 6 octets): only
    ///    `count 1 start 1` with the exact length (`INVALID_COMMAND`). Accepted
    ///    in any load state, since real activation writes them outside a load
    ///    bracket. The tool key is only counted, the session key stays as
    ///    configured (changing it is out of scope for the sim);
    /// 4. PID 53/54/61 only while `Loading` (`TEMPORARILY_NOT_AVAILABLE`);
    /// 5. start 0 is an element-count write: count 1, 2 octets, value not above
    ///    the current count (`INVALID_COMMAND` / `OUT_OF_MAX_RANGE`); it
    ///    truncates the table (0 clears it);
    /// 6. `data.len() == count * element size` (`INVALID_COMMAND`);
    /// 7. no holes: `start <= element count + 1`, and the last element within
    ///    the table capacity (group-object count for PID 61) (`OUT_OF_MAX_RANGE`);
    /// 8. PID 61 flag octets 0x00..=0x03 (`OUT_OF_MAX_RANGE`); PID 53 rows name
    ///    an address-table index `>= 1` (`OUT_OF_MIN_RANGE`) and, when the
    ///    address table is known, `<=` its length (`OUT_OF_MAX_RANGE`).
    pub(super) fn on_value_write(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtValue_WriteCon", data)?;
        if data.len() < 8 {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtValue_WriteCon",
                detail: "missing count/start".into(),
            });
        }
        let count = data[5];
        let start = u16::from_be_bytes([data[6], data[7]]);
        let value = &data[8..];
        let rc = self.write_value(h, count, start, value, limits);
        let mut out = h.encode().to_vec();
        out.push(count);
        out.extend_from_slice(&start.to_be_bytes());
        out.push(rc);
        let detail = format!(" start={start} count={count}");
        Ok(ExtReply {
            apci: Apci::PropertyExtValueWriteConResponse,
            data: out,
            summary: self.describe("WriteCon", h, &detail, rc),
        })
    }

    fn write_value(
        &mut self,
        h: ExtHeader,
        count: u8,
        start: u16,
        value: &[u8],
        limits: SecurityLimits,
    ) -> u8 {
        if !h.is_security_object() {
            return rc::ADDRESS_VOID;
        }
        match h.pid {
            pid::OBJECT_TYPE => return rc::ACCESS_READ_ONLY,
            pid::LOAD_STATE_CONTROL | pid::SECURITY_MODE => return rc::INVALID_COMMAND,
            pid::TOOL_KEY | pid::SEQUENCE_NUMBER_SENDING | pid::GRP_KEY_TABLE => {}
            pid::SECURITY_IA_TABLE | pid::GO_SECURITY_FLAGS => {}
            _ => return rc::ADDRESS_VOID,
        }
        if count == 0 {
            return rc::INVALID_COMMAND;
        }
        match h.pid {
            pid::TOOL_KEY => {
                if start != 1 || count != 1 || value.len() != TOOL_KEY_LEN {
                    return rc::INVALID_COMMAND;
                }
                self.tool_key_writes += 1;
                return rc::SUCCESS;
            }
            pid::SEQUENCE_NUMBER_SENDING => {
                if start != 1 || count != 1 || value.len() != SEQ_LEN {
                    return rc::INVALID_COMMAND;
                }
                self.seq_sending.copy_from_slice(value);
                return rc::SUCCESS;
            }
            _ => {}
        }
        if self.load_state != SecLoadState::Loading {
            return rc::TEMPORARILY_NOT_AVAILABLE;
        }
        let (elem, capacity) = match h.pid {
            pid::GRP_KEY_TABLE => (
                GRP_KEY_ROW,
                limits
                    .address_table_len
                    .map_or(MAX_GROUP_KEY_ROWS, |n| n.min(MAX_GROUP_KEY_ROWS)),
            ),
            pid::SECURITY_IA_TABLE => (IA_ROW, MAX_IA_TABLE_ROWS),
            _ => (
                GO_FLAG,
                limits.group_objects.unwrap_or(FALLBACK_MAX_GROUP_OBJECTS),
            ),
        };
        let table = match h.pid {
            pid::GRP_KEY_TABLE => &mut self.group_keys,
            pid::SECURITY_IA_TABLE => &mut self.ia_table,
            _ => &mut self.go_flags,
        };
        if start == 0 {
            if count != 1 || value.len() != 2 {
                return rc::INVALID_COMMAND;
            }
            let n = usize::from(u16::from_be_bytes([value[0], value[1]]));
            if n > table.count() {
                return rc::OUT_OF_MAX_RANGE;
            }
            table.truncate(n);
            return rc::SUCCESS;
        }
        if value.len() != usize::from(count) * elem {
            return rc::INVALID_COMMAND;
        }
        let last = usize::from(start) + usize::from(count) - 1;
        if usize::from(start) > table.count() + 1 || last > usize::from(capacity) {
            return rc::OUT_OF_MAX_RANGE;
        }
        match h.pid {
            pid::GO_SECURITY_FLAGS => {
                if value.iter().any(|&f| f > MAX_GO_FLAG) {
                    return rc::OUT_OF_MAX_RANGE;
                }
            }
            pid::GRP_KEY_TABLE => {
                for row in value.chunks_exact(GRP_KEY_ROW) {
                    let index = u16::from_be_bytes([row[0], row[1]]);
                    if index == 0 {
                        return rc::OUT_OF_MIN_RANGE;
                    }
                    if limits.address_table_len.is_some_and(|len| index > len) {
                        return rc::OUT_OF_MAX_RANGE;
                    }
                }
            }
            _ => {}
        }
        table.write(start, value);
        rc::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::{SecurityLimits, SecurityObject};

    /// The full ETS-order load for a 1333-object device: Unload, StartLoading,
    /// clear PID 54, one PID 53 row, PID 61 in 211-element chunks, LoadCompleted.
    #[test]
    fn test_full_ets_sequence_succeeds() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(1333),
            address_table_len: Some(40),
        };
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            exchange(&mut obj, UNLOAD, limits)?,
            hex("01d6 0011 001005 00 00")?
        );
        assert_eq!(
            exchange(&mut obj, START, limits)?,
            hex("01d6 0011 001005 00 02")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001036 01 0000 0000", limits)?,
            hex("01cf 0011 001036 01 0000 00")?
        );
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 7), limits)?,
            hex("01cf 0011 001035 01 0001 00")?
        );
        let mut start = 1u16;
        while start <= 1333 {
            let count = (1334 - start).min(211) as u8;
            let resp = exchange(&mut obj, &go_flags_write(start, count), limits)?;
            let mut want = hex("01cf 0011 00103d")?;
            want.push(count);
            want.extend_from_slice(&start.to_be_bytes());
            want.push(0x00);
            assert_eq!(resp, want, "chunk at start {start}");
            start += u16::from(count);
        }
        // The capture's first and last chunk headers.
        assert_eq!(go_flags_write(1, 0xd3)[..20], *"01ce 0011 00103d d3 ");
        assert_eq!(go_flags_write(1267, 67)[..25], *"01ce 0011 00103d 43 04f3 ");
        assert_eq!(
            exchange(&mut obj, COMPLETE, limits)?,
            hex("01d6 0011 001005 00 01")?
        );
        assert_eq!(obj.go_flag_count(), 1333);
        assert_eq!(obj.go_flag(1333), Some(0x03));
        assert_eq!(obj.group_key_rows(), 1);
        assert_eq!(obj.group_key_address_index(1), Some(7));
        assert_eq!(obj.ia_table_rows(), 0);
        Ok(())
    }

    #[test]
    fn test_table_writes_outside_loading_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        // Loaded: every table write is TEMPORARILY_NOT_AVAILABLE.
        assert_eq!(
            cmd(&mut obj, &go_flags_write(1, 2))?,
            hex("01cf 0011 00103d 02 0001 f9")?
        );
        assert_eq!(
            cmd(&mut obj, &group_key_write(1, 1))?,
            hex("01cf 0011 001035 01 0001 f9")?
        );
        assert_eq!(
            cmd(&mut obj, "01ce 0011 001036 01 0000 0000")?,
            hex("01cf 0011 001036 01 0000 f9")?
        );
        // Tool key and sequence are accepted outside a load bracket.
        let tool_key = format!("01ce 0011 001038 01 0001 {}", "11".repeat(16));
        assert_eq!(
            cmd(&mut obj, &tool_key)?,
            hex("01cf 0011 001038 01 0001 00")?
        );
        assert_eq!(
            cmd(&mut obj, "01ce 0011 00103b 01 0001 000000001234")?,
            hex("01cf 0011 00103b 01 0001 00")?
        );
        assert_eq!(obj.tool_key_writes(), 1);
        Ok(())
    }

    #[test]
    fn test_bad_lengths_and_ranges_refused() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(10),
            address_table_len: Some(5),
        };
        let mut obj = SecurityObject::new_activated();
        exchange(&mut obj, START, limits)?;
        // Count 3 with 2 octets of data.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 03 0001 0303", limits)?,
            hex("01cf 0011 00103d 03 0001 f2")?
        );
        // Count 0.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 00 0001", limits)?,
            hex("01cf 0011 00103d 00 0001 f2")?
        );
        // A PID 53 row one octet short.
        let short = format!("01ce 0011 001035 01 0001 0001 {}", "a5".repeat(15));
        assert_eq!(
            exchange(&mut obj, &short, limits)?,
            hex("01cf 0011 001035 01 0001 f2")?
        );
        // Flag octet 0x04.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 00103d 01 0001 04", limits)?,
            hex("01cf 0011 00103d 01 0001 f7")?
        );
        // Beyond the 10 group objects.
        assert_eq!(
            exchange(&mut obj, &go_flags_write(1, 11), limits)?,
            hex("01cf 0011 00103d 0b 0001 f7")?
        );
        // A hole: start 3 on an empty table.
        assert_eq!(
            exchange(&mut obj, &go_flags_write(3, 1), limits)?,
            hex("01cf 0011 00103d 01 0003 f7")?
        );
        // Address-table index 0 and index past the 5-entry address table.
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 0), limits)?,
            hex("01cf 0011 001035 01 0001 f6")?
        );
        assert_eq!(
            exchange(&mut obj, &group_key_write(1, 6), limits)?,
            hex("01cf 0011 001035 01 0001 f7")?
        );
        // Element-count write above the current count.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001036 01 0000 0001", limits)?,
            hex("01cf 0011 001036 01 0000 f7")?
        );
        // Tool key of the wrong length; PID 1 is read-only; PID 5 via WriteCon.
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001038 01 0001 1122", limits)?,
            hex("01cf 0011 001038 01 0001 f2")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001001 01 0001 0011", limits)?,
            hex("01cf 0011 001001 01 0001 fb")?
        );
        assert_eq!(
            exchange(&mut obj, "01ce 0011 001005 01 0001 01", limits)?,
            hex("01cf 0011 001005 01 0001 f2")?
        );
        assert_eq!(obj.go_flag_count(), 0);
        assert_eq!(obj.group_key_rows(), 0);
        Ok(())
    }

    #[test]
    fn test_key_reads_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, START)?;
        cmd(&mut obj, &group_key_write(1, 1))?;
        // PID 53 (element and count) and PID 56: count 0, no data.
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001035 01 0001")?,
            hex("01cd 0011 001035 00 0001")?
        );
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001035 01 0000")?,
            hex("01cd 0011 001035 00 0000")?
        );
        assert_eq!(
            cmd(&mut obj, "01cc 0011 001038 01 0001")?,
            hex("01cd 0011 001038 00 0001")?
        );
        Ok(())
    }

    #[test]
    fn test_value_reads_of_flags_and_counts() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(5),
            address_table_len: None,
        };
        let mut obj = SecurityObject::new_activated();
        exchange(&mut obj, START, limits)?;
        exchange(&mut obj, "01ce 0011 00103d 02 0001 0301", limits)?;
        // Start 0: the element count is the group-object count.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 01 0000", limits)?,
            hex("01cd 0011 00103d 01 0000 0005")?
        );
        // Unwritten flags within the GO count read as 0x00.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 03 0001", limits)?,
            hex("01cd 0011 00103d 03 0001 030100")?
        );
        // Past the element count: refused.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 00103d 02 0005", limits)?,
            hex("01cd 0011 00103d 00 0005")?
        );
        // PID 5 and PID 1 via value read.
        assert_eq!(
            exchange(&mut obj, "01cc 0011 001005 01 0001", limits)?,
            hex("01cd 0011 001005 01 0001 02")?
        );
        assert_eq!(
            exchange(&mut obj, "01cc 0011 001001 01 0001", limits)?,
            hex("01cd 0011 001001 01 0001 0011")?
        );
        Ok(())
    }
}
