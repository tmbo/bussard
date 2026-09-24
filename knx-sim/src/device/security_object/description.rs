//! The security object's property descriptions (`A_PropertyExtDescription_Read`):
//! the property list in index order and the descriptor each entry answers.

use crate::wire::apdu::Apci;

use super::{
    ExtHeader, ExtReply, ExtServiceError, FALLBACK_MAX_GROUP_OBJECTS, MAX_GROUP_KEY_ROWS,
    MAX_IA_TABLE_ROWS, PDT_CONTROL, PDT_FUNCTION, PDT_GENERIC_01, PDT_GENERIC_06, PDT_GENERIC_08,
    PDT_GENERIC_16, PDT_GENERIC_18, PDT_UNSIGNED_INT, SecurityLimits, SecurityObject, pid, rc,
};

/// One entry of the object's property list, used for description reads.
struct PropDesc {
    pid: u16,
    pdt: u8,
    writable: bool,
    max_elements: u16,
    read_level: u8,
    write_level: u8,
}

impl SecurityObject {
    /// The object's property list, in property-index order (index 1 first).
    fn properties(limits: SecurityLimits) -> [PropDesc; 8] {
        let go_max = limits
            .group_objects
            .unwrap_or(FALLBACK_MAX_GROUP_OBJECTS)
            .min(0x0FFF);
        let d = |pid, pdt, writable, max_elements, read_level, write_level| PropDesc {
            pid,
            pdt,
            writable,
            max_elements,
            read_level,
            write_level,
        };
        [
            d(pid::OBJECT_TYPE, PDT_UNSIGNED_INT, false, 1, 3, 15),
            d(pid::LOAD_STATE_CONTROL, PDT_CONTROL, true, 1, 3, 0),
            d(pid::SECURITY_MODE, PDT_FUNCTION, true, 1, 3, 0),
            // Key tables: not readable at any level (read level 15).
            d(
                pid::GRP_KEY_TABLE,
                PDT_GENERIC_18,
                true,
                MAX_GROUP_KEY_ROWS,
                15,
                0,
            ),
            d(
                pid::SECURITY_IA_TABLE,
                PDT_GENERIC_08,
                true,
                MAX_IA_TABLE_ROWS,
                3,
                0,
            ),
            d(pid::TOOL_KEY, PDT_GENERIC_16, true, 1, 15, 0),
            d(pid::SEQUENCE_NUMBER_SENDING, PDT_GENERIC_06, true, 1, 3, 0),
            d(pid::GO_SECURITY_FLAGS, PDT_GENERIC_01, true, go_max, 3, 0),
        ]
    }

    /// `A_PropertyExtDescription_Read`. A non-zero PID addresses the property
    /// by id; PID 0 addresses it by the 12-bit property index (1-based, the
    /// same convention as the sim's plain description read). An unknown object,
    /// PID or index answers a descriptor with type 0, max 0 and access 0, the
    /// "no property here" signal. DPTs are not modelled and report 0.0.
    pub(super) fn on_description_read(
        &mut self,
        data: &[u8],
        limits: SecurityLimits,
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_PropertyExtDescription_Read", data)?;
        let Some(idx) = data.get(5..7) else {
            return Err(ExtServiceError::Malformed {
                service: "A_PropertyExtDescription_Read",
                detail: "missing description type / index".into(),
            });
        };
        let desc_type = idx[0] >> 4;
        let req_index = (u16::from(idx[0] & 0x0F) << 8) | u16::from(idx[1]);
        let props = Self::properties(limits);
        let found = if !h.is_security_object() {
            None
        } else if h.pid != 0 {
            props
                .iter()
                .position(|p| p.pid == h.pid)
                .map(|i| (i as u16 + 1, &props[i]))
        } else {
            usize::from(req_index)
                .checked_sub(1)
                .and_then(|i| props.get(i))
                .map(|p| (req_index, p))
        };
        let (index, rh, tail): (u16, ExtHeader, [u8; 8]) = match found {
            Some((index, p)) => {
                let [m_hi, m_lo] = (p.max_elements & 0x0FFF).to_be_bytes();
                (
                    index,
                    ExtHeader { pid: p.pid, ..h },
                    [
                        0,
                        0,
                        0,
                        0,
                        (if p.writable { 0x80 } else { 0 }) | (p.pdt & 0x3F),
                        m_hi,
                        m_lo,
                        ((p.read_level & 0x0F) << 4) | (p.write_level & 0x0F),
                    ],
                )
            }
            None => (req_index, h, [0; 8]),
        };
        let mut out = rh.encode().to_vec();
        out.push((desc_type << 4) | ((index >> 8) as u8 & 0x0F));
        out.push((index & 0xFF) as u8);
        out.extend_from_slice(&tail);
        let rc = if found.is_some() {
            rc::SUCCESS
        } else {
            rc::ADDRESS_VOID
        };
        let detail = format!(" index={index}");
        Ok(ExtReply {
            apci: Apci::PropertyExtDescriptionResponse,
            data: out,
            summary: self.describe("DescriptionRead", rh, &detail, rc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::{SecurityLimits, SecurityObject};

    #[test]
    fn test_description_read_by_pid_and_index() -> TestResult {
        let limits = SecurityLimits {
            group_objects: Some(1333),
            address_table_len: None,
        };
        let mut obj = SecurityObject::new_activated();
        // By PID 61: index 8, dpt 0.0, writable GENERIC_01, max 1333, r3/w0.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 00103d 0000", limits)?,
            hex("01d3 0011 00103d 0008 0000 0000 91 0535 30")?
        );
        // By index 4 (PID 0): the group key table, GENERIC_18, not readable.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001000 0004", limits)?,
            hex("01d3 0011 001035 0004 0000 0000 a2 0400 f0")?
        );
        // Index past the list: the "no property" descriptor.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001000 0009", limits)?,
            hex("01d3 0011 001000 0009 0000 0000 00 0000 00")?
        );
        // The response payload after the APCI is 15 octets.
        assert_eq!(
            exchange(&mut obj, "01d2 0011 001005 0000", limits)?.len(),
            2 + 15
        );
        Ok(())
    }
}
