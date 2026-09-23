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
    BUSSARD_KEYRING_PASSWORD=... uv run tools/knxtrace/knxtrace.py \
        trace secure.pcapng --device 1.1.12 --keyring project.knxkeys --seq-check

Why no scapy: the campaign machine reads captures offline, and this repository
refuses copyleft dependencies (scapy is GPLv2, see CLAUDE.md "License Policy").
The reader is stdlib-only, which also keeps every parse failure ours to handle:
a malformed record is skipped, never fatal.

Nothing here ever prints key material. `A_Authorize` keys are hashed and
KNXnet/IP Secure frames are named and sized but never decrypted. `A_SecureData`
(Data Secure) payloads are reported as a length and a hash, unless `--keyring`
names an ETS `.knxkeys` export: then each frame's MAC is verified with the
device's tool key, its FDSK or the group key (see datasecure.py), and a frame
that verifies shows its decrypted inner APDU, decoded like a plain one. The
keyring password comes from `$BUSSARD_KEYRING_PASSWORD`, never the command line.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capture import CaptureError  # noqa: E402
import datasecure  # noqa: E402
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
KEYRING_PASSWORD_ENV = "BUSSARD_KEYRING_PASSWORD"


def load_keyring(args) -> "datasecure.Keyring | None":
    """Loads `--keyring`, if given, with the password from the environment."""
    path = getattr(args, "keyring", None)
    if not path:
        return None
    password = os.environ.get(KEYRING_PASSWORD_ENV)
    if password is None:
        raise SystemExit("--keyring needs the keyring password in $%s" % KEYRING_PASSWORD_ENV)
    try:
        return datasecure.load_keyring(path, password)
    except datasecure.KeyringError as exc:
        raise SystemExit("%s: %s" % (path, exc))
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))


def load_frames(path: str, keyring=None) -> list:
    try:
        frames = frames_from_file(path)
    except CaptureError as exc:
        raise SystemExit(str(exc))
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))
    if keyring is not None:
        datasecure.unwrap_frames(frames, keyring)
    return frames


def load_ops(path: str, keyring=None) -> dict:
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
    return normalize(load_frames(path, keyring))


# --------------------------------------------------------------------------
# devices
# --------------------------------------------------------------------------


def cmd_devices(args) -> int:
    keyring = load_keyring(args)
    frames = load_frames(args.capture, keyring) if not args.capture.endswith(TPDU_SUFFIXES) else None
    buckets = normalize(frames) if frames is not None else load_ops(args.capture)
    if not buckets:
        print("no KNX operations found in %s" % args.capture)
        return 0
    print("%-10s %6s  %s" % ("device", "ops", "operation kinds"))
    for name in sorted(buckets):
        ops = buckets[name]
        counts = ops.counts()
        kinds = ", ".join("%s x%d" % (k, v) for k, v in sorted(counts.items()))
        print("%-10s %6d  %s" % (name, len(ops.requests()), kinds))
    if keyring is not None and frames is not None:
        print()
        for line in secure_summary(frames):
            print(line)
    return 0


def secure_summary(frames) -> list:
    """Counts the Data Secure frames by outcome, skipping L_Data.con echoes.

    Prints no key material: only counts, key labels, SCF services and
    sequence numbers, which travel in the clear.
    """
    total = 0
    outcome: dict = {}
    inner: dict = {}
    seqs: dict = {}
    for frame in frames:
        cemi = frame.cemi
        if cemi is None or cemi.l4 is None or cemi.l4.apdu is None or cemi.mc == 0x2E:
            continue
        apdu = cemi.l4.apdu
        if apdu.apci != datasecure.A_SECURE_DATA:
            continue
        total += 1
        service = str(apdu.fields.get("service", "?"))
        mac = apdu.fields.get("mac")
        if mac == "ok":
            bucket = "MAC ok (%s key)" % apdu.fields.get("key")
        elif mac == "FAIL":
            bucket = "MAC FAIL (keys tried, none verified)"
        else:
            bucket = "no key (no end of the frame is in the keyring)"
        outcome.setdefault(bucket, {}).setdefault(service, 0)
        outcome[bucket][service] += 1
        if apdu.inner is not None:
            inner[apdu.inner.name] = inner.get(apdu.inner.name, 0) + 1
        if service == "S-A_Data" and "seq" in apdu.fields:
            seqs.setdefault(cemi.src, []).append(int(apdu.fields["seq"]))
    lines = ["data secure: %d A_SecureData frame(s) (L_Data.con echoes excluded)" % total]
    for bucket in sorted(outcome):
        per = outcome[bucket]
        lines.append(
            "  %-48s %4d  (%s)"
            % (bucket, sum(per.values()), ", ".join("%s x%d" % kv for kv in sorted(per.items())))
        )
    if inner:
        lines.append("  decrypted inner APDUs:")
        for name, n in sorted(inner.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append("    %-40s %4d" % (name, n))
    for src in sorted(seqs):
        values = seqs[src]
        lines.append(
            "  S-A_Data sequence from %s: %d .. %d (%d frame(s))"
            % (src, min(values), max(values), len(values))
        )
    return lines


# --------------------------------------------------------------------------
# trace
# --------------------------------------------------------------------------


def cmd_trace(args) -> int:
    keyring = load_keyring(args)
    frames = load_frames(args.capture, keyring)
    if not frames:
        print("no KNXnet/IP frames in %s" % args.capture)
        return 0
    base = frames[0].ts
    shown = []
    for frame in frames:
        if args.device and not _touches(frame, args.device):
            continue
        if args.service and frame.service_name not in args.service:
            continue
        shown.append(frame)
        print(_trace_line(frame, base))
    if keyring is not None:
        print()
        for line in secure_summary(shown):
            print(line)
    if args.seq_check:
        problems = datasecure.sequence_problems(shown)
        print()
        if problems:
            print("sequence check: %d non-increasing sequence number(s)" % len(problems))
            for line in problems:
                print("  " + line)
        else:
            print("sequence check: every Data Secure sequence increased per (sender, key)")
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
    buckets = load_ops(args.capture, load_keyring(args))
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
    keyring = load_keyring(args)
    ops_a = resolve_device(load_ops(args.a, keyring), args.device)
    ops_b = resolve_device(load_ops(args.b, keyring), args.device)
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
    ops = resolve_device(load_ops(args.capture, load_keyring(args)), args.device)
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


def _keyring_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--keyring",
        metavar="FILE.knxkeys",
        help="ETS keyring to verify and decrypt Data Secure frames "
        "(password from $%s)" % KEYRING_PASSWORD_ENV,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="knxtrace",
        description="Decode KNXnet/IP captures and diff two device downloads.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("devices", help="list the devices a capture programs")
    p.add_argument("capture")
    _keyring_arg(p)
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("trace", help="chronological frame-by-frame trace")
    p.add_argument("capture")
    p.add_argument("--device", help="only frames to or from this individual address")
    p.add_argument(
        "--service",
        action="append",
        help="only this KNXnet/IP service name (repeatable)",
    )
    _keyring_arg(p)
    p.add_argument(
        "--seq-check",
        action="store_true",
        help="report Data Secure sequence numbers that do not increase per (sender, key)",
    )
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("ops", help="normalized per-device operation sequence")
    p.add_argument("capture", help="a .pcap/.pcapng capture or a TPDU fixture (.txt)")
    p.add_argument("--device", help="the target individual address, e.g. 1.1.5")
    p.add_argument("--json", action="store_true")
    _keyring_arg(p)
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
    _keyring_arg(p)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser(
        "image", help="compose the memory a download wrote (one .bin per region)"
    )
    p.add_argument("capture")
    p.add_argument("--device", help="the target individual address, e.g. 1.1.5")
    p.add_argument("--out", required=True, help="output directory")
    _keyring_arg(p)
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
