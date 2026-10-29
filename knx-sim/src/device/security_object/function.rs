//! The security object's function properties (`A_FunctionPropertyExt_Command`
//! and `_State_Read`): the PID 5 load-state machine and the PID 51 security mode.

use crate::wire::apdu::Apci;

use super::{ExtReply, ExtServiceError, SecLoadState, SecurityObject, pid, rc};

impl SecurityObject {
    /// `A_FunctionPropertyExt_Command`. PID 5 drives the load-state machine,
    /// PID 51 sets the security mode. The answer is a State_Response carrying
    /// `[rc][state]`.
    pub(super) fn on_function_command(&mut self, data: &[u8]) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_FunctionPropertyExt_Command", data)?;
        let body = &data[5..];
        let (rc, state_data, detail): (u8, Vec<u8>, String) = if !h.is_security_object() {
            (rc::ADDRESS_VOID, Vec::new(), String::new())
        } else {
            match h.pid {
                pid::LOAD_STATE_CONTROL => {
                    let (rc, event) = self.apply_load_event(body);
                    (
                        rc,
                        vec![self.load_state.to_byte()],
                        format!(" event={event}"),
                    )
                }
                pid::SECURITY_MODE => {
                    let (rc, service) = self.apply_security_mode(body);
                    (rc, vec![service], format!(" mode={}", self.security_mode))
                }
                pid::SECURITY_FAILURES_LOG => {
                    let (rc, data) = self.failures_log_command(body);
                    (rc, data, " sfl=clear".to_string())
                }
                // Any other PID is not a function property of this object.
                _ => (rc::ADDRESS_VOID, Vec::new(), String::new()),
            }
        };
        let mut out = h.encode().to_vec();
        out.push(rc);
        out.extend_from_slice(&state_data);
        Ok(ExtReply {
            apci: Apci::FunctionPropertyExtStateResponse,
            data: out,
            summary: self.describe("FunctionCommand", h, &detail, rc),
        })
    }

    /// Apply a 10-octet load-control value to the load-state machine.
    ///
    /// Checks (rc):
    /// - the value must be exactly 10 octets, like every load-control write in
    ///   the capture (`INVALID_COMMAND` otherwise);
    /// - event 0 (no operation) leaves the state alone (`SUCCESS`);
    /// - event 1 StartLoading enters `Loading` from any state (`SUCCESS`);
    /// - event 2 LoadCompleted enters `Loaded` only from `Loading`; from any
    ///   other state the state is kept and the answer is `IMPOSSIBLE_COMMAND`;
    /// - event 4 Unload enters `Unloaded` from any state and clears the group
    ///   key table, the IA table and the GO flags (`SUCCESS`);
    /// - any other event is refused with `INVALID_COMMAND`.
    fn apply_load_event(&mut self, body: &[u8]) -> (u8, &'static str) {
        if body.len() != 10 {
            return (rc::INVALID_COMMAND, "malformed");
        }
        match body[0] {
            0 => (rc::SUCCESS, "NoOperation"),
            1 => {
                self.load_state = SecLoadState::Loading;
                (rc::SUCCESS, "StartLoading")
            }
            2 => {
                if self.load_state == SecLoadState::Loading {
                    self.load_state = SecLoadState::Loaded;
                    (rc::SUCCESS, "LoadCompleted")
                } else {
                    (rc::IMPOSSIBLE_COMMAND, "LoadCompleted")
                }
            }
            4 => {
                self.load_state = SecLoadState::Unloaded;
                self.group_keys.clear();
                self.ia_table.clear();
                self.go_flags.clear();
                (rc::SUCCESS, "Unload")
            }
            _ => (rc::INVALID_COMMAND, "unsupported"),
        }
    }

    /// Apply a PID 51 security-mode command. INFERRED layout: the last two
    /// octets are `[service id][mode]` (the capture's `00 00 01` switches the
    /// mode on and is answered `rc=00 00`, the service id echoed). Service id
    /// must be 0 and mode 0 or 1, otherwise `INVALID_COMMAND`.
    fn apply_security_mode(&mut self, body: &[u8]) -> (u8, u8) {
        let [.., service, mode] = body else {
            return (rc::INVALID_COMMAND, 0);
        };
        if *service != 0 || *mode > 1 {
            return (rc::INVALID_COMMAND, *service);
        }
        self.security_mode = *mode;
        (rc::SUCCESS, *service)
    }

    /// The PID 55 command (KNX 3/5/1 §6.3.9.3.1): `[00][WriteServiceID 00]
    /// [ServiceInfo 00]` clears the counters and the latest failure (not the
    /// report) and answers `[rc 00][00]`. Another service id is
    /// `INVALID_COMMAND`, another reserved or info octet `DATA_VOID`, each
    /// with the service id repeated (§6.3.9.3.3).
    fn failures_log_command(&mut self, body: &[u8]) -> (u8, Vec<u8>) {
        let [reserved, service, info] = body else {
            return (rc::DATA_VOID, body.get(1).copied().into_iter().collect());
        };
        if *service != 0x00 {
            return (rc::INVALID_COMMAND, vec![*service]);
        }
        if *reserved != 0x00 || *info != 0x00 {
            return (rc::DATA_VOID, vec![*service]);
        }
        self.failures = super::FailuresLog::default();
        (rc::SUCCESS, vec![0x00])
    }

    /// The PID 55 state read (KNX 3/5/1 §6.3.9.3.2): `[00][00][00]` answers
    /// the counters `[00][00][0000][seq:2][crypto:2][access:2]`, `[00][01][n]`
    /// the latest failure `[01][n][ia:2][xx xx][xx][seq:6][type]` for n = 0
    /// when one is logged; no logged failure or n > 0 is `DATA_VOID`.
    fn failures_log_read(&self, body: &[u8]) -> (u8, Vec<u8>) {
        let [reserved, service, info] = body else {
            return (rc::DATA_VOID, body.get(1).copied().into_iter().collect());
        };
        if *reserved != 0x00 {
            return (rc::DATA_VOID, vec![*service]);
        }
        match (*service, *info) {
            (0x00, 0x00) => {
                let f = self.failures;
                let mut out = vec![0x00, 0x00, 0x00, 0x00];
                out.extend_from_slice(&f.seq.to_be_bytes());
                out.extend_from_slice(&f.crypto.to_be_bytes());
                out.extend_from_slice(&f.access.to_be_bytes());
                (rc::SUCCESS, out)
            }
            (0x01, 0x00) => match self.failures.latest {
                Some((ia, seq, kind)) => {
                    let mut out = vec![0x01, 0x00];
                    out.extend_from_slice(&ia.to_be_bytes());
                    out.extend_from_slice(&[0x00, 0x00, 0x00]);
                    out.extend_from_slice(&seq);
                    out.push(kind.to_byte());
                    (rc::SUCCESS, out)
                }
                None => (rc::DATA_VOID, vec![0x01]),
            },
            (0x00 | 0x01, _) => (rc::DATA_VOID, vec![*service]),
            (other, _) => (rc::INVALID_COMMAND, vec![other]),
        }
    }

    /// `A_FunctionPropertyExt_State_Read`: PID 5 answers `[rc][state]`, PID 51
    /// answers `[rc][mode]`, PID 55 the failures log; anything else answers
    /// `ADDRESS_VOID`.
    pub(super) fn on_function_state_read(
        &mut self,
        data: &[u8],
    ) -> Result<ExtReply, ExtServiceError> {
        let h = Self::header("A_FunctionPropertyExt_State_Read", data)?;
        let (rc, state_data) = match (h.is_security_object(), h.pid) {
            (true, pid::LOAD_STATE_CONTROL) => (rc::SUCCESS, vec![self.load_state.to_byte()]),
            (true, pid::SECURITY_MODE) => (rc::SUCCESS, vec![self.security_mode]),
            (true, pid::SECURITY_FAILURES_LOG) => self.failures_log_read(&data[5..]),
            _ => (rc::ADDRESS_VOID, Vec::new()),
        };
        let mut out = h.encode().to_vec();
        out.push(rc);
        out.extend_from_slice(&state_data);
        Ok(ExtReply {
            apci: Apci::FunctionPropertyExtStateResponse,
            data: out,
            summary: self.describe("FunctionStateRead", h, "", rc),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::SecLoadState;
    use super::super::SecurityObject;
    use super::super::test_support::*;

    #[test]
    fn test_function_command_load_transitions_match_capture() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(obj.load_state(), SecLoadState::Loaded);
        assert_eq!(cmd(&mut obj, UNLOAD)?, hex("01d6 0011 001005 00 00")?);
        assert_eq!(cmd(&mut obj, START)?, hex("01d6 0011 001005 00 02")?);
        assert_eq!(cmd(&mut obj, COMPLETE)?, hex("01d6 0011 001005 00 01")?);
        assert_eq!(obj.load_state(), SecLoadState::Loaded);
        Ok(())
    }

    #[test]
    fn test_function_command_load_completed_outside_loading_refused() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, UNLOAD)?;
        // LoadCompleted from Unloaded: IMPOSSIBLE_COMMAND, state kept.
        assert_eq!(cmd(&mut obj, COMPLETE)?, hex("01d6 0011 001005 f3 00")?);
        // Unsupported event 3 and a short value: INVALID_COMMAND.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001005 03000000000000000000")?,
            hex("01d6 0011 001005 f2 00")?
        );
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001005 01")?,
            hex("01d6 0011 001005 f2 00")?
        );
        assert_eq!(obj.load_state(), SecLoadState::Unloaded);
        Ok(())
    }

    #[test]
    fn test_function_command_security_mode_matches_capture() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001033 000001")?,
            hex("01d6 0011 001033 00 00")?
        );
        assert_eq!(obj.security_mode(), 1);
        // Mode 2 does not exist.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001033 000002")?,
            hex("01d6 0011 001033 f2 00")?
        );
        Ok(())
    }

    #[test]
    fn test_function_state_read_reports_load_state() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001005 00")?,
            hex("01d6 0011 001005 00 01")?
        );
        cmd(&mut obj, START)?;
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001005")?,
            hex("01d6 0011 001005 00 02")?
        );
        Ok(())
    }

    #[test]
    fn test_failures_log_counts_reads_and_clears() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        // Empty log: zero counters, no latest failure.
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001037 000000")?,
            hex("01d6 0011 001037 00 000000 00 0000 0000 0000")?
        );
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001037 000100")?,
            hex("01d6 0011 001037 f8 01")?
        );
        assert!(!obj.record_failure(
            super::super::FailureKind::Access,
            0x1118,
            [0, 0, 0, 0, 0, 9]
        ));
        obj.record_failure(
            super::super::FailureKind::Cryptographic,
            0x1118,
            [0, 0, 0, 0, 0, 7],
        );
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001037 000000")?,
            hex("01d6 0011 001037 00 000000 00 0000 0001 0001")?
        );
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001037 000100")?,
            hex("01d6 0011 001037 00 0100 1118 000000 000000000007 03")?
        );
        assert_eq!(obj.security_report(), 0x01);
        // Clear: counters and latest gone, the report stays.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001037 000000")?,
            hex("01d6 0011 001037 00 00")?
        );
        assert_eq!(
            cmd(&mut obj, "01d5 0011 001037 000000")?,
            hex("01d6 0011 001037 00 000000 00 0000 0000 0000")?
        );
        assert_eq!(obj.security_report(), 0x01);
        // An unknown service id.
        assert_eq!(
            cmd(&mut obj, "01d4 0011 001037 000500")?,
            hex("01d6 0011 001037 f2 05")?
        );
        Ok(())
    }

    #[test]
    fn test_unload_clears_tables() -> TestResult {
        let mut obj = SecurityObject::new_activated();
        cmd(&mut obj, START)?;
        cmd(&mut obj, &go_flags_write(1, 4))?;
        cmd(&mut obj, &group_key_write(1, 1))?;
        cmd(&mut obj, "01ce 0011 001036 01 0001 1101 000000000001")?;
        assert_eq!(
            (
                obj.go_flag_count(),
                obj.group_key_rows(),
                obj.ia_table_rows()
            ),
            (4, 1, 1)
        );
        cmd(&mut obj, UNLOAD)?;
        assert_eq!(
            (
                obj.go_flag_count(),
                obj.group_key_rows(),
                obj.ia_table_rows()
            ),
            (0, 0, 0)
        );
        Ok(())
    }
}
