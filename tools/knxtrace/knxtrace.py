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
    uv run tools/knxtrace/knxtrace.py statediff --base full.pcapng --ets ets-partial.pcapng \
        --bussard bussard-apply.pcapng --device 1.1.5
    BUSSARD_KEYRING_PASSWORD=... uv run tools/knxtrace/knxtrace.py \
        trace secure.pcapng --device 1.1.12 --keyring project.knxkeys --seq-check
    BUSSARD_KEYRING_PASSWORD=... uv run tools/knxtrace/knxtrace.py \
        trace rotation.pcapng --keyring before.knxkeys --keyring after.knxkeys

Why no scapy: the campaign machine reads captures offline, and this repository
refuses copyleft dependencies (scapy is GPLv2, see CLAUDE.md "License Policy").
The reader is stdlib-only, which also keeps every parse failure ours to handle:
a malformed record is skipped, never fatal.

Nothing here ever prints key material. `A_Authorize` keys are hashed and
KNXnet/IP Secure frames are named and sized but never decrypted (they cannot
be: see ipsecure.py); with a keyring, each session's device authentication is
checked against the keyring's codes. `A_SecureData`
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
import ipsecure  # noqa: E402
from knxip import KnxFrame, frames_from_file  # noqa: E402
from normalize import (  # noqa: E402
    DeviceOps,
    normalize,
    normalize_tpdu_file,
    resolve_device,
)
from opsdiff import DIFFERENT, diff  # noqa: E402
import image as memimage  # noqa: E402
import statediff  # noqa: E402

TPDU_SUFFIXES = (".txt", ".tpdu")
KEYRING_PASSWORD_ENV = "BUSSARD_KEYRING_PASSWORD"


def load_keyring(args) -> "datasecure.Keyring | None":
    """Loads `--keyring` (repeatable), with the password from the environment.

    Several keyrings are consulted in the order given: the export from before
    a key rotation decodes the frames under the old keys (and carries the
    FDSK, which ETS drops from the export once a tool key is set), the one
    after it the frames under the new keys. They share the password.
    """
    paths = getattr(args, "keyring", None)
    if not paths:
        return None
    if isinstance(paths, str):
        paths = [paths]
    password = os.environ.get(KEYRING_PASSWORD_ENV)
    if password is None:
        raise SystemExit("--keyring needs the keyring password in $%s" % KEYRING_PASSWORD_ENV)
    rings = []
    for path in paths:
        try:
            rings.append(datasecure.load_keyring(path, password))
        except datasecure.KeyringError as exc:
            raise SystemExit("%s: %s" % (path, exc))
        except OSError as exc:
            raise SystemExit("cannot read %s: %s" % (path, exc))
    first = rings[0]
    first.extra = rings[1:]
    return first


def load_frames(path: str, keyring=None) -> list:
    try:
        frames = frames_from_file(path)
    except CaptureError as exc:
        raise SystemExit(str(exc))
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))
    if keyring is not None:
        datasecure.unwrap_frames(frames, keyring)
        datasecure.annotate_credentials(frames, keyring)
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


def resolve(buckets: dict, device, path: str, keyring=None):
    """`resolve_device`, with the secure sessions named when a device is missing.

    A device ETS reached only through KNXnet/IP Secure sessions has no
    decodable operation in the capture; saying so beats "devices seen: none".
    """
    try:
        return resolve_device(buckets, device)
    except SystemExit as exc:
        if path.endswith(TPDU_SUFFIXES):
            raise
        found = ipsecure.sessions(load_frames(path), keyring)
        if device:
            found = [s for s in found if s.device in ("", device)]
        if not found:
            raise
        kinds = ", ".join("%s x%d" % kv for kv in ipsecure.connection_counts(found))
        raise SystemExit(
            "%s; the capture holds %d KNXnet/IP Secure session(s) (%s) whose content "
            "cannot be decrypted (`knxtrace trace` lists them)" % (exc, len(found), kinds)
        )


# --------------------------------------------------------------------------
# devices
# --------------------------------------------------------------------------


def cmd_devices(args) -> int:
    keyring = load_keyring(args)
    frames = load_frames(args.capture, keyring) if not args.capture.endswith(TPDU_SUFFIXES) else None
    buckets = normalize(frames) if frames is not None else load_ops(args.capture)
    if not buckets:
        print("no KNX operations found in %s" % args.capture)
        for line in ipsecure.report(ipsecure.sessions(frames or [], keyring),
                                    base=frames[0].ts if frames else 0.0):
            print(line)
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
    if frames is not None:
        lines = ipsecure.report(ipsecure.sessions(frames, keyring), base=frames[0].ts if frames else 0.0)
        if lines:
            print()
            for line in lines:
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
    found = ipsecure.sessions(frames, keyring)
    if args.device:
        found = [s for s in found if s.device in ("", args.device)]
    lines = ipsecure.report(found, shapes=args.session_shapes, base=base)
    if lines:
        print()
        for line in lines:
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
    keyring = load_keyring(args)
    buckets = load_ops(args.capture, keyring)
    ops = resolve(buckets, args.device, args.capture, keyring)
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
    ops_a = resolve(load_ops(args.a, keyring), args.device, args.a, keyring)
    ops_b = resolve(load_ops(args.b, keyring), args.device, args.b, keyring)
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
    keyring = load_keyring(args)
    ops = resolve(load_ops(args.capture, keyring), args.device, args.capture, keyring)
    index = memimage.compose(ops, args.out, source=args.capture)
    print(
        "%s: %d region(s), %d octet(s) written, %d read-confirmed, %d allocation(s), "
        "%d property write(s) -> %s"
        % (
            ops.device,
            len(index["regions"]),
            sum(r["length"] for r in index["regions"]),
            sum(r["length"] for r in index["confirmed"]),
            len(index["allocations"]),
            index["property_writes"],
            args.out,
        )
    )
    return 0


def cmd_imgdiff(args) -> int:
    report = memimage.compare(
        args.plan_dir,
        args.image_dir,
        min_coverage=args.min_coverage,
        page_size=args.page_size,
        scope=[x for x in args.scope.split(",") if x] if args.scope else None,
        phase=args.phase,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for line in memimage.render(report):
            print(line)
    return 1 if report["verdict"] == memimage.DIFFERS else 0


def cmd_statediff(args) -> int:
    keyring = load_keyring(args)

    def ops_of(path: str):
        try:
            return resolve(load_ops(path, keyring), args.device, path, keyring)
        except SystemExit:
            # No operation for the device in this capture: that side wrote nothing.
            return None

    base = [o for o in (ops_of(p) for p in args.base or []) if o is not None]
    report = statediff.compare_states(base, ops_of(args.ets), ops_of(args.bussard), args.device or "")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for line in statediff.render(report):
            print(line)
    return 1 if report["verdict"] == memimage.DIFFERS else 0


# --------------------------------------------------------------------------


def _keyring_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--keyring",
        metavar="FILE.knxkeys",
        action="append",
        help="ETS keyring to verify and decrypt Data Secure frames, to check KNXnet/IP "
        "Secure device authentication and credential writes (password from $%s; "
        "repeatable, e.g. the exports before and after a key rotation)" % KEYRING_PASSWORD_ENV,
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
        "--session-shapes",
        action="store_true",
        help="list the plain length of every wrapped frame of each KNXnet/IP Secure session",
    )
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
        "image",
        help="compose the memory a download wrote (one .bin per region) and its "
        "property writes (properties.json, key material redacted)",
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
    p.add_argument(
        "--min-coverage",
        type=float,
        default=memimage.DEFAULT_MIN_COVERAGE,
        help="percent of bussard's placed octets the capture must cover for a match to "
        "count as identical (default %(default)s)",
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=memimage.DEFAULT_PAGE_SIZE,
        help="memory page size of the per-page coverage (default %(default)s)",
    )
    p.add_argument(
        "--scope",
        help="comma-separated regions the verdict and coverage judge (addr, assoc, gobj, par, "
        "seg0x4800, ...); default: all",
    )
    p.add_argument(
        "--phase",
        choices=("fdsk", "tool"),
        help="an `interface secure` plan: compare only the writes bussard sends under this key",
    )
    p.set_defaults(func=cmd_imgdiff)

    p = sub.add_parser(
        "statediff",
        help="compare the device state after a partial download: ETS's step capture against "
        "bussard's, both on top of the base captures (issue #469)",
    )
    p.add_argument("--base", action="append", help="a capture that led to the step, in order (repeatable)")
    p.add_argument("--ets", required=True, help="ETS's capture of the step")
    p.add_argument("--bussard", required=True, help="bussard's capture of the same step")
    p.add_argument("--device", required=True, help="the target individual address, e.g. 1.1.1")
    p.add_argument("--json", action="store_true")
    _keyring_arg(p)
    p.set_defaults(func=cmd_statediff)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
