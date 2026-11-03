//! The server side of a KNXnet/IP device management connection (issue #523)
//! for [`MockGateway`](crate::MockGateway): what the interface device answers
//! to the cEMI frames of a DEVICE_CONFIGURATION_REQUEST.
//!
//! * `M_PropRead.req` / `M_PropWrite.req` (EMI 3/6/3 §4.1.7.3) are served by
//!   the device's extended property services on the same object type,
//!   instance and property id, and answered with the matching `.con`.
//! * cEMI `T_Data_Connected.req` / `T_Data_Individual.req` (§4.1.6.4-§4.1.6.5)
//!   go to the device as `L_Data` from `0.0.0`; the transport connection is
//!   the server's (3/8/3 §2.6.1.2): it is opened on first use, the device's
//!   numbered answers are acknowledged here and come back as
//!   `T_Data_Connected.ind`.
//! * `M_Reset.req` is counted and not answered.

use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame};
use bussard_transport::tpci::{self, TpciKind};

use crate::device::{MockDevice, Reaction};
use crate::gateway::{Out, line_output};

/// `A_PropertyExtValue_Read`.
const EXT_READ: u16 = 0x1CC;
/// `A_PropertyExtValue_Response`.
const EXT_RESPONSE: u16 = 0x1CD;
/// `A_PropertyExtValue_WriteCon`.
const EXT_WRITE_CON: u16 = 0x1CE;
/// `A_PropertyExtValue_WriteConResponse`.
const EXT_WRITE_CON_RESPONSE: u16 = 0x1CF;

/// The device management state of one connection.
#[derive(Debug, Default)]
pub(crate) struct MgmtSession {
    /// The server's transport-layer sequence towards the device; `None`
    /// before the connection to it is opened.
    tl_seq: Option<u8>,
}

impl MgmtSession {
    /// The answers (raw cEMI frames) of the interface device `device` on
    /// `line` to one cEMI frame of the client.
    pub(crate) fn serve(
        &mut self,
        line: &mut [MockDevice],
        device: IndividualAddress,
        cemi: &[u8],
    ) -> Vec<Vec<u8>> {
        match cemi.first() {
            Some(&(0xFC | 0xF6)) => line
                .iter_mut()
                .find(|d| d.address == device)
                .and_then(|dev| local_management(dev, cemi))
                .into_iter()
                .collect(),
            Some(&(mc @ 0x41 | mc @ 0x4A)) => self.transport(line, device, cemi, mc == 0x41),
            _ => Vec::new(),
        }
    }

    /// Delivers a cEMI transport-layer frame to the device and returns its
    /// answers as `T_Data_*.ind`.
    fn transport(
        &mut self,
        line: &mut [MockDevice],
        device: IndividualAddress,
        cemi: &[u8],
        connected: bool,
    ) -> Vec<Vec<u8>> {
        let tool = IndividualAddress::from_raw(0);
        let add = usize::from(cemi.get(1).copied().unwrap_or(0));
        let Some(tpdu) = cemi.get(2 + add + 7..).filter(|t| t.len() >= 2) else {
            return Vec::new();
        };
        let apci = (u16::from(tpdu[0] & 0x03) << 8) | u16::from(tpdu[1]);
        let data = &tpdu[2..];
        let request = if connected {
            let seq = match self.tl_seq {
                Some(seq) => seq,
                None => {
                    let _ = line_output(line, &CemiFrame::t_control(device, tool, tpci::T_CONNECT));
                    0
                }
            };
            self.tl_seq = Some((seq + 1) & 0x0F);
            CemiFrame::t_data_connected(device, tool, tpci::ndt(seq), apci, data)
        } else {
            let mut frame = CemiFrame::t_data_connected(device, tool, 0x00, apci, data);
            frame.tpci = bussard_transport::cemi::Tpci::Other(0x00);
            frame
        };
        let mut answers = Vec::new();
        let frames: Vec<CemiFrame> = line_output(line, &request)
            .into_iter()
            .flat_map(|out| match out {
                Out::Frame(frame) => vec![frame],
                Out::Delayed(_, frames) => frames,
                Out::Pause(_) => Vec::new(),
            })
            .collect();
        for frame in frames {
            let octet = frame.tpci_octet();
            let (indication, data) = match (tpci::classify(octet), &frame.apdu) {
                (TpciKind::NumberedData(seq), Apdu::Other { apci, data }) => {
                    let _ =
                        line_output(line, &CemiFrame::t_control(device, tool, tpci::t_ack(seq)));
                    (0x89u8, (*apci, data.clone()))
                }
                (TpciKind::UnnumberedData, Apdu::Other { apci, data }) => {
                    (0x94u8, (*apci, data.clone()))
                }
                (TpciKind::Disconnect, _) => {
                    self.tl_seq = None;
                    continue;
                }
                _ => continue,
            };
            let (apci, data) = data;
            let mut out = vec![indication, 0x00, 0, 0, 0, 0, 0, 0];
            out.push((data.len() + 1) as u8);
            out.push((apci >> 8) as u8 & 0x03);
            out.push(apci as u8);
            out.extend_from_slice(&data);
            answers.push(out);
        }
        answers
    }
}

/// Serves an `M_PropRead.req` / `M_PropWrite.req` with the device's extended
/// property services and returns the `.con`.
fn local_management(dev: &mut MockDevice, cemi: &[u8]) -> Option<Vec<u8>> {
    let (&mc, rest) = cemi.split_first()?;
    let h = rest.get(..6)?;
    let write = mc == 0xF6;
    let packed = (u32::from(h[2]) << 12) | u32::from(h[3]);
    let count = h[4] >> 4;
    let start = (u16::from(h[4] & 0x0F) << 8) | u16::from(h[5]);
    let mut request = h[..2].to_vec();
    request.extend_from_slice(&packed.to_be_bytes()[1..]);
    request.push(count);
    request.extend_from_slice(&start.to_be_bytes());
    request.extend_from_slice(rest.get(6..).unwrap_or_default());
    let (apci, expected) = if write {
        (EXT_WRITE_CON, EXT_WRITE_CON_RESPONSE)
    } else {
        (EXT_READ, EXT_RESPONSE)
    };
    let mut out = vec![if write { 0xF5 } else { 0xFB }];
    out.extend_from_slice(&h[..4]);
    let negative = |mut out: Vec<u8>, error: u8| {
        out.extend_from_slice(&[h[4] & 0x0F, h[5], error]);
        out
    };
    match dev.handle_request(apci, &request) {
        Reaction::Answer(rapci, rdata) if rapci == expected => {
            if write {
                match rdata.get(8) {
                    Some(0) => {
                        out.extend_from_slice(&h[4..6]);
                        Some(out)
                    }
                    _ => Some(negative(out, 0x01)),
                }
            } else {
                match rdata.get(5) {
                    Some(&served) if served > 0 => {
                        out.push((served << 4) | (h[4] & 0x0F));
                        out.push(h[5]);
                        out.extend_from_slice(rdata.get(8..).unwrap_or_default());
                        Some(out)
                    }
                    _ => Some(negative(out, 0x07)),
                }
            }
        }
        _ => Some(negative(out, 0x07)),
    }
}
