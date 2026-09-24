//! The one place device **memory** is read and written.
//!
//! Every memory access bussard makes — the download engine streaming a segment,
//! the table read-back resolving a `PID_TABLE_REFERENCE`, the System 7 LSM
//! records, `DeviceConnection`'s dump primitive — funnels through this module.
//! Before it existed the same primitives were re-implemented in `load.rs`,
//! `device.rs`, `tables.rs` and `sys7.rs`, and only one copy had learned about
//! extended memory and APDU-scaled chunking (issue #80): a table above `0xFFFF`
//! was refused on one path and served on another, and a 15-octet-APDU device was
//! handed 63-octet chunks by a path that had not been updated. One module, one
//! behaviour.
//!
//! # The two services
//!
//! KNX offers two memory services and they are **not** interchangeable:
//!
//! - **plain** `A_Memory_Read`/`A_Memory_Write` (APCI `0x200`/`0x280`): a 16-bit
//!   address and an octet count in the low 6 APCI bits, so at most 63 octets and
//!   never past `0xFFFF`.
//! - **extended** `A_MemoryExtended_Read`/`_Write` (APCI `0x1FD`/`0x1FB`): a
//!   3-octet (24-bit) address and a full count octet, confirmed inline by a
//!   response carrying a return code.
//!
//! [`select_extended_memory`] picks between them **per access, from the address**
//! — not per device — which is exactly what the real ETS6 captures do and what
//! keeps every ≤16-bit device (KV, DA.tp, Steinel, BM/A4) byte-identical to the
//! historical plain path.
//!
//! # Chunking follows the negotiated APDU
//!
//! A device advertising `PID_MAX_APDU_LENGTH = 15` must receive ≤12-octet chunks
//! in **standard** frames; a 63-octet chunk is an extended frame such a device may
//! reject (issue #58). Every loop here sizes its chunk from
//! [`Layer4Connection::max_memory_chunk`] /
//! [`Layer4Connection::max_extended_memory_chunk`], which fall back to the
//! conservative standard-frame floor when the property was never negotiated.
//!
//! Clean-room: the service encodings live in [`crate::apci`] and come from the
//! published KNX application layer (KNX 3/3/7) plus the ETS6 capture analysis in
//! `scratchpad/ets-analysis/sysb-{a,c}.md`. No GPL KNX source was consulted.

use crate::apci;
use crate::connection::{L4Channel, Layer4Connection};
use crate::error::{MgmtError, raw_response_detail};
use crate::load::{Result, WriteError};

/// Whether a memory access at `addr` spanning `len` octets must use the System B
/// **extended** memory service rather than the plain `A_Memory_*` service.
///
/// The rule, matched to the real ETS6 captures
/// (`scratchpad/ets-analysis/sysb-{a,c}.md`): use the extended service **iff the
/// top address of the access exceeds the 16-bit space** (`addr + len - 1 >
/// 0xFFFF`). ETS drives Steinel (segment `0x3400..0x3BD6`, all ≤ `0xFFFF`) with
/// plain `A_Memory_Write`, and the Jung/ABB 07B0 devices whose segments live at
/// `0xf000..0x1aad3` with `A_MemoryExtended_Write` — the selection is per address
/// range, not per device. This keeps every ≤16-bit device (KV, DA.tp, Steinel,
/// BM/A4) on the byte-identical plain path.
pub fn select_extended_memory(addr: u32, len: usize) -> bool {
    let top = u64::from(addr).saturating_add(len.max(1) as u64 - 1);
    top > 0xFFFF
}

/// The data-octet chunk this connection may carry for an access at `addr`
/// spanning `len` octets, on whichever service [`select_extended_memory`] picks.
///
/// Both caps come from the negotiated `PID_MAX_APDU_LENGTH` (issue #58) and fall
/// back to the conservative standard-frame floor when it was never read. The
/// result is clamped to `1..=255` because the single-telegram primitives take a
/// `u8` count.
pub(crate) fn chunk_for(l4: &Layer4Connection<impl L4Channel>, addr: u32, len: usize) -> usize {
    let raw = if select_extended_memory(addr, len) {
        usize::from(l4.max_extended_memory_chunk())
    } else {
        usize::from(l4.max_memory_chunk())
    };
    raw.clamp(1, usize::from(u8::MAX))
}

/// Reads `len` octets of device memory starting at `addr` over a borrowed
/// [`Layer4Connection`], in **one** telegram. `len` is clamped to
/// [`apci::MAX_MEMORY_READ_LEN`] by the encoder — use [`read_memory_range`] for
/// a span larger than a single telegram.
///
/// When the address fits the 16-bit space this uses the plain `A_Memory_Read`
/// (byte-identical to before); an address above `0xFFFF` uses
/// `A_MemoryExtended_Read` (APCI `0x1FD`, 3-octet address) — the System B
/// extended service the ≥16-bit devices require (see [`select_extended_memory`]).
pub async fn read_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    len: u8,
) -> Result<Vec<u8>> {
    if select_extended_memory(addr, usize::from(len)) {
        return read_memory_extended(l4, addr, len).await;
    }
    let addr16 = addr as u16;
    let (req_apci, payload) = apci::encode_memory_read(addr16, len);
    let (mut resp_apci, mut data) = l4.request(req_apci, &payload).await?;
    // A verify-mode device (PID_DEVICE_CONTROL bit 2, which a System 7 download
    // switches on like ETS, issue #116) echoes every A_Memory_Write with an
    // A_Memory_Response. An echo of the last write that arrives only after this
    // read went out looks like its answer; it names the written address, not
    // ours, so skip it and take the next response.
    for _ in 0..STALE_ECHO_SKIPS {
        match apci::decode_memory_response(resp_apci, &data) {
            Some(echo) if echo.addr != addr16 => {
                (resp_apci, data) = l4.recv_response().await?;
            }
            _ => break,
        }
    }
    let resp = apci::decode_memory_response(resp_apci, &data).ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "expected A_Memory_Response with matching count ({})",
                raw_response_detail(resp_apci, &data)
            ),
        })
    })?;
    Ok(resp.data)
}

/// How many late verify-mode write echoes [`read_memory`] skips before it takes
/// a response as its answer. One write leaves at most one echo; two covers an
/// echo retransmitted by the device.
const STALE_ECHO_SKIPS: usize = 2;

/// Reads `len` octets at the 24-bit `addr` via `A_MemoryExtended_Read` (APCI
/// `0x1FD`), validating the response's return code and echoed address.
async fn read_memory_extended<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    len: u8,
) -> Result<Vec<u8>> {
    let (req_apci, payload) = apci::encode_memory_extended_read(addr, u16::from(len));
    let (resp_apci, data) = l4.request(req_apci, &payload).await?;
    let resp = apci::decode_memory_extended_response(resp_apci, &data).ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "expected A_MemoryExtended_Read_Response ({})",
                raw_response_detail(resp_apci, &data)
            ),
        })
    })?;
    if resp.return_code != 0 {
        return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "A_MemoryExtended_Read at {addr:#08X} returned non-zero code {:#04X}",
                resp.return_code
            ),
        }));
    }
    Ok(resp.data)
}

/// Reads a `len`-octet **span** of device memory starting at `addr`, looping over
/// as many telegrams as it takes.
///
/// This is the read counterpart of [`write_memory_chunked`] and the primitive
/// every multi-telegram reader in the crate uses (the table read-back, the
/// `LdCtrlCompareRelMem` verify). Two things it gets right that a hand-rolled
/// loop repeatedly did not (issue #80):
///
/// - the chunk is the **negotiated** max-APDU cap, not a fixed 63, so a device
///   advertising `PID_MAX_APDU_LENGTH = 15` never sees an extended frame;
/// - the service is chosen from the address, so a span above `0xFFFF` reads via
///   `A_MemoryExtended_Read` instead of being refused.
///
/// The whole span is bounds-checked against the 24-bit extended-memory address
/// space up front, so a caller can never truncate an address into the wrong
/// device memory. A device that answers a chunk with **zero** octets cannot make
/// progress, so the read stops there and fails with
/// [`MgmtError::MalformedResponse`] rather than spinning.
pub async fn read_memory_range<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    len: usize,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    // Bound the whole span before the first telegram: `end` is exclusive, so the
    // last addressed octet is `end - 1` and must fit the 24-bit space.
    u64::from(addr)
        .checked_add(len as u64)
        .filter(|&e| e <= u64::from(apci::MAX_MEMORY_ADDRESS) + 1)
        .ok_or_else(|| WriteError::AddressOutOfRange {
            address: l4.target(),
            detail: format!("read of {len} octet(s) from {addr:#X}"),
        })?;

    let chunk = chunk_for(l4, addr, len);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while out.len() < len {
        let want = (len - out.len()).min(chunk);
        let at = u32::try_from(out.len())
            .ok()
            .and_then(|off| addr.checked_add(off))
            .filter(|&a| a <= apci::MAX_MEMORY_ADDRESS)
            .ok_or_else(|| WriteError::AddressOutOfRange {
                address: l4.target(),
                detail: format!("read chunk at {addr:#X} + {}", out.len()),
            })?;
        let got = read_memory(l4, at, want as u8).await?;
        if got.is_empty() {
            return Err(WriteError::Mgmt(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!("memory read at {at:#X} came back empty"),
            }));
        }
        out.extend_from_slice(&got);
    }
    out.truncate(len);
    Ok(out)
}

/// Writes `data` to device memory starting at `addr`, in negotiated-max-APDU
/// chunks. An empty `data` is a no-op.
///
/// This is [`write_memory_chunked`] with no progress callback; see that function
/// for what each chunk does on the wire (and what it does **not** do — there is
/// no per-chunk read-back).
pub async fn write_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    data: &[u8],
) -> Result<()> {
    write_memory_chunked(l4, addr, data, |_| {}).await
}

/// Writes `data` to device memory at `addr` in negotiated-max-APDU chunks,
/// invoking `on_written` with the cumulative octet count after each chunk the
/// device accepted (for progress reporting).
///
/// # What a chunk costs on the wire
///
/// The service is chosen once for the whole write from its top address (see
/// [`select_extended_memory`]) and the chunk sized from the negotiated
/// `PID_MAX_APDU_LENGTH`:
///
/// - **plain** `A_Memory_Write` is fire-and-forget: the telegram is sent, its
///   `T_ACK` awaited, and the optional verify-mode echo discarded. There is **no**
///   per-chunk read-back — ETS does not do one either, and adding one doubles the
///   numbered exchanges (exhausting a device's per-connection L4 budget on a large
///   segment) and interleaves stray `A_Memory_Response`s into the stream.
///   Integrity is confirmed afterwards by the device's own MCB CRC
///   (`LdCtrlLoadImageProp`) and the flash engine's end-of-segment spot check.
/// - **extended** `A_MemoryExtended_Write` confirms every chunk inline with an
///   `A_MemoryExtended_Write_Response`; a non-zero return code fails the write.
///
/// # No retry here
///
/// This used to wrap each chunk in a bounded retry for "transient connection
/// blips". That loop could never succeed (issue #80): every error it matched —
/// `NoResponse`, `MidSessionSilence`, `Disconnected` — is raised by
/// [`Layer4Connection`] only *after* it has set the connection to closed, so the
/// retry's next `send_data` returned `Disconnected` immediately. Recovery from a
/// dead connection needs a **new** connection, which only the call site can open;
/// the flash engine does exactly that (`resumable_death` → `cycle_l4` → replay the
/// step, see [`crate::load::is_connection_death`]). So a connection death now
/// propagates on the first failure, straight to the layer that can actually act
/// on it.
pub async fn write_memory_chunked<Ch: L4Channel, F: FnMut(usize)>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    data: &[u8],
    mut on_written: F,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    // Choose plain vs extended for the whole write from its top address (see
    // `select_extended_memory`): a segment that fits 16 bits stays byte-identical
    // to the historical plain `A_Memory_Write` path; one that runs past `0xFFFF`
    // uses the System B extended service.
    let extended = select_extended_memory(addr, data.len());
    // Scale the chunk to the device's negotiated max APDU (issue #58). The plain
    // service caps at 63 (the 6-bit count field); the extended service scales to
    // the 228-octet extended-frame budget ETS uses. Both fall back to the
    // conservative cap when `PID_MAX_APDU_LENGTH` was never negotiated.
    let write_chunk = if extended {
        usize::from(l4.max_extended_memory_chunk())
    } else {
        usize::from(l4.max_memory_chunk())
    };
    let mut offset = 0usize;
    while offset < data.len() {
        let take = write_chunk.min(data.len() - offset);
        let piece = &data[offset..offset + take];
        write_one_chunk(l4, addr, offset, piece, extended).await?;
        offset += take;
        on_written(offset);
    }
    Ok(())
}

/// The historical name of [`write_memory_chunked`], kept so callers outside this
/// crate keep compiling.
///
/// **It performs no read-back**, despite the name — see
/// [`write_memory_chunked`], which is the honest one and what new code should
/// call.
#[doc(hidden)]
pub async fn write_memory_verified<Ch: L4Channel, F: FnMut(usize)>(
    l4: &mut Layer4Connection<Ch>,
    addr: u32,
    data: &[u8],
    on_written: F,
) -> Result<()> {
    write_memory_chunked(l4, addr, data, on_written).await
}

/// Writes one memory chunk at `base + offset`.
///
/// When `extended` is false this is the historical plain `A_Memory_Write` path,
/// byte-identical to before: a fire-and-forget write whose optional echo is
/// discarded (integrity is confirmed later by the MCB CRC and the end-of-segment
/// spot-check). When `extended` is true it sends `A_MemoryExtended_Write` (APCI
/// `0x1FB`, 3-octet address) and awaits the device's inline
/// `A_MemoryExtended_Write_Response` (`0x1FC`), failing on a non-zero return code
/// — the extended service confirms every chunk on the wire, so no separate
/// read-back is needed.
async fn write_one_chunk<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    base: u32,
    offset: usize,
    piece: &[u8],
    extended: bool,
) -> Result<()> {
    let chunk_addr = chunk_address(l4, base, offset)?;
    if extended {
        let (req_apci, payload) = apci::encode_memory_extended_write(chunk_addr, piece);
        let (resp_apci, data) = l4.request(req_apci, &payload).await?;
        let resp = apci::decode_memory_extended_response(resp_apci, &data).ok_or_else(|| {
            WriteError::Mgmt(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!(
                    "expected A_MemoryExtended_Write_Response ({})",
                    raw_response_detail(resp_apci, &data)
                ),
            })
        })?;
        if resp.return_code != 0 {
            return Err(WriteError::Mgmt(MgmtError::MemoryVerifyFailed {
                address: l4.target(),
                addr: chunk_addr,
                expected: piece.to_vec(),
                got: Vec::new(),
            }));
        }
        return Ok(());
    }
    let addr16 = chunk_addr as u16;
    let (req_apci, payload) = apci::encode_memory_write(addr16, piece);
    // Write only, no per-chunk read-back. ETS streams the whole image and does
    // NOT read each chunk back — a read-back after every write doubles the
    // exchanges (exhausting a device's per-connection L4 budget on a large
    // segment) and, worse, interleaves stray A_Memory_Responses into the stream
    // so a following property read correlates the wrong response. Integrity is
    // confirmed after the load by the device's own MCB CRC (LdCtrlLoadImageProp)
    // and the flash engine's end-of-segment spot-check.
    l4.send_data(req_apci, &payload).await?;
    // A verify-mode device answers the write with an unsolicited A_Memory_Response
    // echo that await_ack folds into the pending slot. This write expects no
    // response, so drop the echo — otherwise it satisfies the next request's
    // recv_response with the wrong APDU (a "malformed response").
    l4.discard_pending_response();
    Ok(())
}

/// Computes `base + offset` as a device address, failing if it runs past the
/// 24-bit extended-memory address space (a programming error, not a device
/// fault). The plain-service caller keeps the same behaviour for ≤16-bit
/// addresses; the extended service reaches the full 24-bit space.
fn chunk_address<Ch: L4Channel>(
    l4: &Layer4Connection<Ch>,
    base: u32,
    offset: usize,
) -> Result<u32> {
    u32::try_from(offset)
        .ok()
        .and_then(|off| base.checked_add(off))
        .filter(|&a| a <= apci::MAX_MEMORY_ADDRESS)
        .ok_or_else(|| {
            WriteError::Mgmt(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: "memory write range exceeds the 24-bit address space".to_string(),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_extended_memory_picks_the_service_by_top_address() {
        // A whole access that fits 0xFFFF stays on the plain service — the
        // byte-identical KV/DA.tp/Steinel path.
        assert!(!select_extended_memory(0x4000, 63));
        assert!(!select_extended_memory(0xFFC0, 64)); // ends exactly at 0xFFFF
        assert!(!select_extended_memory(0x0000, 1));
        // An access whose top address crosses 0xFFFF uses the extended service —
        // the real 07B0 actuators (bases 0xf000..0x16000, ends to 0x1aad3).
        assert!(select_extended_memory(0xFFFF, 2)); // 0xFFFF..0x10000
        assert!(select_extended_memory(0x01_6000, 6));
        assert!(select_extended_memory(0x0F_000, 0x8000)); // 0xf000 base, big span
        // A zero-length access is treated as one octet at `addr`.
        assert!(!select_extended_memory(0xFFFF, 0));
        assert!(select_extended_memory(0x1_0000, 0));
    }
}
