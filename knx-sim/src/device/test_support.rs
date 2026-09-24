//! Helpers shared by the device unit tests: fixture and synthetic devices,
//! `T_Connect`, and connected NDT frames at the expected sequence.

use super::*;
use crate::bus::event::RecordingSink;
use crate::device::profile::LsmAccess;
use crate::prod::read_knxprod_bytes;

/// Build a DA.tp device, or `Ok(None)` if the (un-committed) fixture is
/// absent so the caller can skip.
pub(super) fn da_tp_device() -> Result<Option<Device>, Box<dyn std::error::Error>> {
    let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(None);
    };
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
    let sink = std::sync::Arc::new(RecordingSink::new());
    Ok(Some(Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        sink,
    )))
}

pub(super) fn connect(dev: &mut Device) -> Result<(), DeviceError> {
    let cemi = CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: dev.address().raw(),
        tpdu: vec![0x80],
    };
    dev.handle_cemi(&cemi)?;
    Ok(())
}

/// Build a connected NDT at the device's **currently expected** receive
/// sequence, so a sequence of `handle_cemi(&data(&dev, ...))` calls carries a
/// correctly-incrementing L4 sequence (matching what a real tool sends). The
/// device advances `rx_seq` as it accepts each frame.
pub(super) fn data(dev: &Device, apci10: u16, payload: &[u8]) -> CemiLData {
    data_seq(dev, dev.rx_seq, apci10, payload)
}

/// Build a connected NDT at an explicit sequence (for out-of-order tests).
pub(super) fn data_seq(dev: &Device, seq: u8, apci10: u16, payload: &[u8]) -> CemiLData {
    let mut tpdu = vec![
        0x40 | ((seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
        (apci10 & 0xFF) as u8,
    ];
    tpdu.extend_from_slice(payload);
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: dev.address().raw(),
        tpdu,
    }
}

/// Build a fixture-free System 7 device (from the synthetic MDT product) at
/// `1.1.2`, optionally starting in programming mode.
pub(super) fn prog_device(prog_mode: bool) -> Result<Device, String> {
    let pd = crate::testfixtures::synthetic_mdt_sys7_product();
    let sink = std::sync::Arc::new(RecordingSink::new());
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        ProfileOverrides {
            prog_mode,
            ..Default::default()
        },
        sink,
    )
}

/// Extract the value bytes from a single A_PropertyValue_Response reaction:
/// the payload after the 4-byte obj/pid/(count|start_hi)/start_lo header.
pub(super) fn prop_response_value(reaction: &DeviceReaction) -> Vec<u8> {
    let resp = &reaction.responses[0];
    // TPDU: [tpci][apci_lo][obj][pid][count|start_hi][start_lo][value...].
    resp.tpdu[6..].to_vec()
}

/// Build a fixture-free **System B** device: the synthetic MDT product with
/// its mask forced to `07B0`, so the test needs no un-committed `.knxprod`.
pub(super) fn system_b_device() -> Result<Device, String> {
    let pd = crate::testfixtures::synthetic_mdt_sys7_product();
    let sink = std::sync::Arc::new(RecordingSink::new());
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        ProfileOverrides {
            mask: Some("07B0".into()),
            ..Default::default()
        },
        sink,
    )
}

/// Build a System 7 device from the synthetic MDT-canonical product (no
/// fixture needed), at 1.1.5, starting Unloaded.
pub(super) fn sys7_device(access: LsmAccess) -> Device {
    let product = crate::testfixtures::synthetic_mdt_sys7_product();
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 5),
        &product,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: None,
            lsm_access: access,
            bcu_key: None,
            prog_mode: false,
            secure: None,
        },
        std::sync::Arc::new(RecordingSink::new()),
    )
    .expect("System 7 device builds")
}

/// Build a standard-frame A_MemoryWrite NDT at the device's expected seq.
pub(super) fn mem_write_frame(dev: &Device, addr: u16, payload: &[u8]) -> CemiLData {
    let apci10 = 0x280 | (payload.len() as u16 & 0x3F);
    let mut d = addr.to_be_bytes().to_vec();
    d.extend_from_slice(payload);
    data(dev, apci10, &d)
}
