# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""knxtrace — read a KNXnet/IP capture, decode it, and diff two downloads.

    uv run tools/knxtrace/knxtrace.py devices flash.pcapng
    uv run tools/knxtrace/knxtrace.py trace flash.pcapng
    uv run tools/knxtrace/knxtrace.py ops flash.pcapng --device 1.1.5
    uv run tools/knxtrace/knxtrace.py diff ets.pcapng bussard.pcapng --device 1.1.5
    uv run tools/knxtrace/knxtrace.py image ets.pcapng --device 1.1.5 --out ets-img/
    uv run tools/knxtrace/knxtrace.py imgdiff bussard-dump/ ets-img/

Why no scapy: the campaign machine reads captures offline, and this repository
refuses copyleft dependencies (scapy is GPLv2, see CLAUDE.md "License Policy").
The reader is stdlib-only, which also keeps every parse failure ours to handle:
a malformed record is skipped, never fatal.

Nothing here ever prints key material. `A_Authorize` keys are hashed,
`A_SecureData` payloads are reported as a length and a hash, and KNXnet/IP
Secure frames are named and sized but never decrypted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capture import CaptureError  # noqa: E402
from knxip import KnxFrame, frames_from_file  # noqa: E402
from normalize import (  # noqa: E402
    DeviceOps,
    normalize,
    normalize_tpdu_file,
    resolve_device,
)
from opsdiff import DIFFERENT, diff  # noqa: E402
import image as memimage  # noqa: E402

TPDU_SUFFIXES = (".txt", ".tpdu")


def load_frames(path: str) -> list:
    try:
        return frames_from_file(path)
    except CaptureError as exc:
        raise SystemExit(str(exc))
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))


def load_ops(path: str) -> dict:
    """Normalizes either a capture file or a TPDU fixture, by extension.

    Every device is normalized, not just the requested one: when the requested
    address is absent, the error then names what the capture does contain, which
    is the difference between "no operations for 1.1.2" and a useful message.
    """
    if path.endswith(TPDU_SUFFIXES):
        try:
            return normalize_tpdu_file(path)
        except OSError as exc:
            raise SystemExit("cannot read %s: %s" % (path, exc))
    return normalize(load_frames(path))


# --------------------------------------------------------------------------
# devices
# --------------------------------------------------------------------------


def cmd_devices(args) -> int:
    buckets = load_ops(args.capture)
    if not buckets:
        print("no KNX operations found in %s" % args.capture)
        return 0
    print("%-10s %6s  %s" % ("device", "ops", "operation kinds"))
    for name in sorted(buckets):
        ops = buckets[name]
        counts = ops.counts()
        kinds = ", ".join("%s x%d" % (k, v) for k, v in sorted(counts.items()))
        print("%-10s %6d  %s" % (name, len(ops.requests()), kinds))
    return 0


# --------------------------------------------------------------------------
# trace
# --------------------------------------------------------------------------


def cmd_trace(args) -> int:
    frames = load_frames(args.capture)
    if not frames:
        print("no KNXnet/IP frames in %s" % args.capture)
        return 0
    base = frames[0].ts
    for frame in frames:
        if args.device and not _touches(frame, args.device):
            continue
        if args.service and frame.service_name not in args.service:
            continue
        print(_trace_line(frame, base))
    return 0


def _touches(frame: KnxFrame, device: str) -> bool:
    return frame.cemi is not None and device in (frame.cemi.src, frame.cemi.dst)


def _trace_line(frame: KnxFrame, base: float) -> str:
    rel = frame.ts - base
    head = "%9.4f %-21s -> %-21s %s" % (rel, frame.src, frame.dst, frame.service_name)
    bits = []
    for key, value in frame.fields.items():
        bits.append("%s=%s" % (key, value))
    if bits:
        head += " [" + " ".join(bits) + "]"
    cemi = frame.cemi
    if cemi is not None:
        head += "\n%11s%s %s -> %s" % ("", cemi.mc_name, cemi.src or "?", cemi.dst or "?")
        if cemi.l4 is not None:
            head += " | " + cemi.l4.summary()
            if cemi.l4.apdu is not None:
                head += " | " + cemi.l4.apdu.summary()
    if frame.note:
        head += "\n%11s(%s)" % ("", frame.note)
    return head


# --------------------------------------------------------------------------
# ops
# --------------------------------------------------------------------------


def cmd_ops(args) -> int:
    buckets = load_ops(args.capture)
    ops = resolve_device(buckets, args.device)
    if args.json:
        print(json.dumps(_ops_json(ops, args.capture), indent=2))
        return 0
    print("normalized operation sequence for %s (%s)" % (ops.device, args.capture))
    print(
        "dropped: %d L_Data.con echo(es), %d repeat(s), %d L4 ack(s)"
        % (ops.dropped_confirms, ops.dropped_repeats, ops.dropped_acks)
    )
    print()
    for n, op in enumerate(ops.requests(), 1):
        print("%4d  %s" % (n, op.describe()))
    image = ops.memory_image()
    if image:
        print()
        print("memory image (%d region(s), chunking removed):" % len(image))
        for region in image:
            print("    %s" % region)
    return 0


def _ops_json(ops: DeviceOps, source: str) -> dict:
    return {
        "source": source,
        "device": ops.device,
        "dropped": {
            "confirms": ops.dropped_confirms,
            "repeats": ops.dropped_repeats,
            "acks": ops.dropped_acks,
        },
        "counts": ops.counts(),
        "ops": [
            {
                "kind": op.kind,
                "key": op.key,
                "direction": op.direction,
                "detail": {k: _jsonable(v) for k, v in op.detail.items()},
            }
            for op in ops.requests()
        ],
        "memory_image": [
            {"start": r.start, "length": len(r.data), "sha": r.sha}
            for r in ops.memory_image()
        ],
    }


def _jsonable(value):
    if isinstance(value, bytes):
        return value.hex()
    return value


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------


def cmd_diff(args) -> int:
    ops_a = resolve_device(load_ops(args.a), args.device)
    ops_b = resolve_device(load_ops(args.b), args.device)
    if ops_a.device != ops_b.device:
        raise SystemExit(
            "the two captures name different devices (%s vs %s); pass --device"
            % (ops_a.device, ops_b.device)
        )
    report = diff(ops_a, ops_b, label_a=args.a, label_b=args.b)

    if args.json:
        print(
            json.dumps(
                {
                    "device": report.device,
                    "verdict": report.verdict,
                    "a": report.label_a,
                    "b": report.label_b,
                    "matched_ops": report.matched_ops,
                    "total_a": report.total_a,
                    "total_b": report.total_b,
                    "findings": [
                        {"verdict": f.verdict, "reason": f.reason, "detail": f.detail}
                        for f in report.findings + report.image_findings
                    ],
                },
                indent=2,
            )
        )
        return report.exit_code

    for line in report.summary_lines():
        print(line)
    print()
    every = report.findings + report.image_findings
    if not every:
        print("the two sequences are byte-identical after normalization.")
        return 0
    if args.only_real:
        every = [f for f in every if f.verdict == DIFFERENT]
        if not every:
            print("no real differences; everything was classified benign.")
            return 0
    for finding in every:
        for line in finding.render(show_bytes=not args.no_bytes):
            print(line)
    return report.exit_code


# --------------------------------------------------------------------------
# image / imgdiff
# --------------------------------------------------------------------------


def cmd_image(args) -> int:
    ops = resolve_device(load_ops(args.capture), args.device)
    index = memimage.compose(ops, args.out, source=args.capture)
    print(
        "%s: %d region(s), %d octet(s) written, %d allocation(s) -> %s"
        % (
            ops.device,
            len(index["regions"]),
            sum(r["length"] for r in index["regions"]),
            len(index["allocations"]),
            args.out,
        )
    )
    return 0


def cmd_imgdiff(args) -> int:
    report = memimage.compare(args.plan_dir, args.image_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for line in memimage.render(report):
            print(line)
    return 1 if report["verdict"] == memimage.DIFFERS else 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="knxtrace",
        description="Decode KNXnet/IP captures and diff two device downloads.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("devices", help="list the devices a capture programs")
    p.add_argument("capture")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("trace", help="chronological frame-by-frame trace")
    p.add_argument("capture")
    p.add_argument("--device", help="only frames to or from this individual address")
    p.add_argument(
        "--service",
        action="append",
        help="only this KNXnet/IP service name (repeatable)",
    )
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("ops", help="normalized per-device operation sequence")
    p.add_argument("capture", help="a .pcap/.pcapng capture or a TPDU fixture (.txt)")
    p.add_argument("--device", help="the target individual address, e.g. 1.1.5")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ops)

    p = sub.add_parser("diff", help="diff two normalized sequences for one device")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--device", help="the target individual address, e.g. 1.1.5")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--only-real",
        action="store_true",
        help="hide findings classified benign",
    )
    p.add_argument("--no-bytes", action="store_true", help="omit payload hex")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser(
        "image", help="compose the memory a download wrote (one .bin per region)"
    )
    p.add_argument("capture")
    p.add_argument("--device", help="the target individual address, e.g. 1.1.5")
    p.add_argument("--out", required=True, help="output directory")
    p.set_defaults(func=cmd_image)

    p = sub.add_parser(
        "imgdiff",
        help="diff a `bussard flash --dry-run --dump-images` dir against an `image` dir",
    )
    p.add_argument("plan_dir")
    p.add_argument("image_dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_imgdiff)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
