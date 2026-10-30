# /// script
# requires-python = ">=3.10"
# ///
"""Distil a sweep capture into knx-sim's request fixture format (epic #596).

    uv run tools/ets-sweep/synthetic/distil.py <ets.pcapng> [<out.txt>] [--note TEXT]

Writes one line per tool request, `<src_ia_hex> <dst_ia_hex> <tpdu_hex>`, the
form of `knx-sim/tests/fixtures/ets_da_tp_flash_requests.txt` that
`knx-sim/tests/ets_calibration.rs` replays. A request is every tunnelled cEMI
`L_Data.req` in the capture, whichever port it came from; a tunnelling
retransmission (same channel, sequence number and bytes) is kept once and a
CONNECT_REQUEST resets that memory. This is the same selection as knx-sim's
`replay::requests_from_capture`, so a fixture and a `replay:` of the capture
deliver the same requests. Without `<out.txt>` the lines go to stdout.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "knxtrace"))
import capture  # noqa: E402

TUNNELLING_REQUEST = 0x0420
CONNECT_REQUEST = 0x0205
L_DATA_REQ = 0x11


def requests(path: Path) -> list[tuple[int, int, bytes]]:
    """The tool's requests in `path` as (source, destination, TPDU), in order."""
    out: list[tuple[int, int, bytes]] = []
    last: dict[int, tuple[int, bytes]] = {}
    for pkt in capture.packets(str(path)):
        if pkt.proto != capture.IPPROTO_UDP:
            continue
        d = pkt.payload
        if len(d) < 6 or d[0] != 0x06 or d[1] != 0x10:
            continue
        svc = int.from_bytes(d[2:4], "big")
        if svc == CONNECT_REQUEST:
            last.clear()
            continue
        if svc != TUNNELLING_REQUEST or len(d) < 10:
            continue
        hdr_len, channel, seq = d[6], d[7], d[8]
        cemi = d[6 + hdr_len:]
        if len(cemi) < 2 or cemi[0] != L_DATA_REQ:
            continue
        at = 2 + cemi[1]  # message code, additional-info length, additional info
        if len(cemi) < at + 7:
            continue
        src = int.from_bytes(cemi[at + 2:at + 4], "big")
        dst = int.from_bytes(cemi[at + 4:at + 6], "big")
        n = cemi[at + 6]
        tpdu = cemi[at + 7:at + 8 + n]
        key = (seq, bytes(cemi))
        if last.get(channel) == key:
            continue
        last[channel] = key
        out.append((src, dst, bytes(tpdu)))
    return out


def render(reqs: list[tuple[int, int, bytes]], source: str, note: str = "") -> str:
    head = [
        f"# ETS request-direction TPDUs in capture order, distilled from {source}",
        "# by tools/ets-sweep/synthetic/distil.py.",
        "# Each line: <src_ia_hex> <dst_ia_hex> <tpdu_hex>. Requests only (L_Data.req).",
    ]
    if note:
        head.append(f"# {note}")
    return "\n".join(head + [f"{s:04x} {d:04x} {t.hex()}" for s, d, t in reqs]) + "\n"


def main(argv: list[str]) -> int:
    note = ""
    if "--note" in argv:
        i = argv.index("--note")
        note = argv[i + 1]
        del argv[i:i + 2]
    if not argv:
        print(__doc__)
        return 2
    src = Path(argv[0])
    text = render(requests(src), src.name, note)
    if len(argv) > 1:
        Path(argv[1]).write_text(text)
        print("wrote", argv[1], text.count("\n") - text.count("#"), "requests")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
