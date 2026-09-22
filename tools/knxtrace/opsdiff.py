"""Diffing two normalized operation sequences, with a benign/real classification.

The campaign's central question (issue #89, phases 1-3) is: *did bussard write
the same thing ETS did?* Two downloads of the same application are never
byte-identical as frame streams, so the useful answer is a classification rather
than a yes/no:

  IDENTICAL  the operations match exactly, byte for byte
  BENIGN     they differ only in a way the device cannot observe:
               ordering      reads or independent-object writes reshuffled
               cycling       a different number of L4 connect/disconnect cycles
               chunking      the same memory image split into different writes
               retry         an operation repeated
  DIFFERENT  anything else, reported with the bytes on both sides

`chunking` is the rule that does the heavy lifting. ETS and bussard choose
different APDU sizes (and bussard switches to `A_MemoryExtended_Write` above
64 KB where ETS may not), so the write records disagree constantly while the
resulting memory image is identical. The differ therefore compares the coalesced
image as its own, chunking-independent check, and any range where the images
disagree is reported as DIFFERENT no matter how the writes lined up.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from normalize import (
    COMMUTATIVE_KINDS,
    DeviceOps,
    LIFECYCLE_KINDS,
    MEMORY_KINDS,
    MemRegion,
    Op,
    coalesce,
)

IDENTICAL = "IDENTICAL"
BENIGN = "BENIGN"
DIFFERENT = "DIFFERENT"


@dataclass
class Finding:
    """One classified difference between the two sequences."""

    verdict: str  # BENIGN or DIFFERENT
    reason: str  # ordering / cycling / chunking / retry / missing / extra / payload
    detail: str
    a_ops: List[Op] = field(default_factory=list)
    b_ops: List[Op] = field(default_factory=list)

    def render(self, show_bytes: bool = True, limit: int = 6) -> List[str]:
        lines = ["%-9s %-9s %s" % (self.verdict, self.reason, self.detail)]
        for label, ops in (("A", self.a_ops), ("B", self.b_ops)):
            for op in ops[:limit]:
                lines.append("    %s only: %s" % (label, op.describe()))
                if show_bytes and self.verdict == DIFFERENT and op.data:
                    lines.append("        bytes: %s" % _hex_excerpt(op.data))
            if len(ops) > limit:
                lines.append("    %s only: ... %d more" % (label, len(ops) - limit))
        return lines


@dataclass
class DiffReport:
    """The whole comparison: a verdict, the findings, and the counts behind it."""

    device: str
    label_a: str
    label_b: str
    findings: List[Finding] = field(default_factory=list)
    matched_ops: int = 0
    total_a: int = 0
    total_b: int = 0
    image_a: List[MemRegion] = field(default_factory=list)
    image_b: List[MemRegion] = field(default_factory=list)
    image_findings: List[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        every = self.findings + self.image_findings
        if any(f.verdict == DIFFERENT for f in every):
            return DIFFERENT
        if every:
            return BENIGN
        return IDENTICAL

    @property
    def exit_code(self) -> int:
        return 1 if self.verdict == DIFFERENT else 0

    def summary_lines(self) -> List[str]:
        by_reason: Dict[Tuple[str, str], int] = {}
        for f in self.findings + self.image_findings:
            key = (f.verdict, f.reason)
            by_reason[key] = by_reason.get(key, 0) + 1
        lines = [
            "verdict: %s" % self.verdict,
            "device %s: %d ops in A (%s), %d ops in B (%s), %d matched"
            % (
                self.device,
                self.total_a,
                self.label_a,
                self.total_b,
                self.label_b,
                self.matched_ops,
            ),
        ]
        if by_reason:
            for (verdict, reason), n in sorted(by_reason.items()):
                lines.append("  %-9s %-9s x%d" % (verdict, reason, n))
        else:
            lines.append("  no differences")
        lines.append(
            "  memory image: A %d region(s) / %d octets, B %d region(s) / %d octets"
            % (
                len(self.image_a),
                sum(len(r.data) for r in self.image_a),
                len(self.image_b),
                sum(len(r.data) for r in self.image_b),
            )
        )
        return lines


def diff(
    a: DeviceOps,
    b: DeviceOps,
    label_a: str = "A",
    label_b: str = "B",
) -> DiffReport:
    """Compares two normalized sequences for the same device."""
    ops_a, ops_b = a.requests(), b.requests()
    report = DiffReport(
        device=a.device,
        label_a=label_a,
        label_b=label_b,
        total_a=len(ops_a),
        total_b=len(ops_b),
        image_a=a.memory_image(),
        image_b=b.memory_image(),
    )

    sig_a = [op.signature for op in ops_a]
    sig_b = [op.signature for op in ops_b]
    matcher = difflib.SequenceMatcher(a=sig_a, b=sig_b, autojunk=False)

    blocks: List[Tuple[List[Op], List[Op]]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            report.matched_ops += i2 - i1
            continue
        blocks.append((ops_a[i1:i2], ops_b[j1:j2]))

    # A move shows up as a deletion here and an insertion there. Pair those back
    # up before classifying, or a reordering would be reported twice, as one
    # "missing" and one "extra".
    findings, blocks = _pair_moves(blocks)
    report.findings.extend(findings)

    context = _Context(set(sig_a), set(sig_b))
    for block_a, block_b in blocks:
        report.findings.extend(_classify(block_a, block_b, context))

    report.image_findings = _diff_images(report.image_a, report.image_b)
    return report


@dataclass
class _Context:
    """What each whole sequence contains, for judging a one-sided block."""

    sigs_a: set
    sigs_b: set


def _pair_moves(blocks):
    """Matches one-sided blocks that hold the same operations, as a move."""
    findings: List[Finding] = []
    only_a = [i for i, (a, b) in enumerate(blocks) if a and not b]
    only_b = [i for i, (a, b) in enumerate(blocks) if b and not a]
    used = set()
    for i in only_a:
        for j in only_b:
            if j in used:
                continue
            if _same_multiset(blocks[i][0], blocks[j][1]):
                used.add(i)
                used.add(j)
                findings.extend(_classify_ordering(blocks[i][0], blocks[j][1]))
                break
    remaining = [blk for n, blk in enumerate(blocks) if n not in used]
    return findings, remaining


def _classify_ordering(block_a: Sequence[Op], block_b: Sequence[Op]) -> List[Finding]:
    kinds = {op.kind for op in block_a}
    if kinds <= COMMUTATIVE_KINDS or _distinct_keys(block_a):
        return [
            Finding(
                BENIGN,
                "ordering",
                "%d operation(s) reordered (%s)"
                % (len(block_a), ", ".join(sorted(kinds))),
            )
        ]
    return [
        Finding(
            DIFFERENT,
            "ordering",
            "%d operation(s) reordered on the same object (%s)"
            % (len(block_a), ", ".join(sorted(kinds))),
            list(block_a),
            list(block_b),
        )
    ]


def _classify(
    block_a: Sequence[Op], block_b: Sequence[Op], context: "_Context"
) -> List[Finding]:
    """Classifies one divergent block of operations."""
    if not block_a and not block_b:
        return []

    # Ordering: the same multiset of operations, shuffled. Benign only when the
    # kinds involved commute (reads, descriptors) or address different objects.
    if _same_multiset(block_a, block_b):
        return _classify_ordering(block_a, block_b)

    # Connection cycling: one side opened or closed the L4 connection more often.
    if _all_kinds(block_a + list(block_b), LIFECYCLE_KINDS):
        return [
            Finding(
                BENIGN,
                "cycling",
                "L4 connection cycled differently (A %d, B %d)"
                % (len(block_a), len(block_b)),
            )
        ]

    # Retry: one side simply repeated an operation the other side sent once.
    extra = _retry_only(block_a, block_b, context)
    if extra is not None:
        side, ops = extra
        return [
            Finding(
                BENIGN,
                "retry",
                "%s repeated %d operation(s) already present"
                % (side, len(ops)),
            )
        ]

    # Chunking: only memory writes on both sides, and their coalesced images
    # agree over the range they cover.
    if _all_kinds(list(block_a) + list(block_b), MEMORY_KINDS):
        img_a = coalesce(
            [(op.detail["addr_int"], op.data) for op in block_a if op.detail.get("addr_int") is not None]
        )
        img_b = coalesce(
            [(op.detail["addr_int"], op.data) for op in block_b if op.detail.get("addr_int") is not None]
        )
        if _regions_equal(img_a, img_b):
            return [
                Finding(
                    BENIGN,
                    "chunking",
                    "same %d octet(s) written as %d vs %d write(s)"
                    % (sum(len(r.data) for r in img_a), len(block_a), len(block_b)),
                )
            ]
        # Fall through: a real memory difference is reported by the image diff
        # with exact ranges, so here we only note that the writes diverged.
        return [
            Finding(
                DIFFERENT,
                "payload",
                "memory writes differ (see the memory-image section for ranges)",
                list(block_a),
                list(block_b),
            )
        ]

    findings: List[Finding] = []
    # Same operation, different payload: the most interesting finding there is.
    paired, rest_a, rest_b = _pair_by_identity(block_a, block_b)
    for op_a, op_b in paired:
        findings.append(
            Finding(
                DIFFERENT,
                "payload",
                "%s %s: payload differs" % (op_a.kind, op_a.key),
                [op_a],
                [op_b],
            )
        )
    if rest_a:
        findings.append(
            Finding(DIFFERENT, "missing", "%d operation(s) only in A" % len(rest_a), list(rest_a), [])
        )
    if rest_b:
        findings.append(
            Finding(DIFFERENT, "extra", "%d operation(s) only in B" % len(rest_b), [], list(rest_b))
        )
    return findings


def _same_multiset(a: Sequence[Op], b: Sequence[Op]) -> bool:
    return sorted(op.signature for op in a) == sorted(op.signature for op in b)


def _distinct_keys(ops: Sequence[Op]) -> bool:
    """True when every op in the block addresses a different object.

    Writes to different interface objects have no ordering constraint between
    them; two writes to the *same* object do, so reshuffling those is a real
    difference.
    """
    keys = [(op.kind, op.key) for op in ops]
    return len(set(keys)) == len(keys)


def _all_kinds(ops: Sequence[Op], kinds) -> bool:
    return bool(ops) and all(op.kind in kinds for op in ops)


def _retry_only(
    a: Sequence[Op], b: Sequence[Op], context: "_Context"
) -> Optional[Tuple[str, List[Op]]]:
    """Detects one side repeating an operation the other side also performed.

    The membership check is what keeps this honest: extra operations that the
    other sequence never contains at all are a real difference, not a retry.
    """
    if a and not b and set(op.signature for op in a) <= context.sigs_b:
        if len(set(op.signature for op in a)) == 1:
            return ("A", list(a))
    if b and not a and set(op.signature for op in b) <= context.sigs_a:
        if len(set(op.signature for op in b)) == 1:
            return ("B", list(b))
    return None


def _pair_by_identity(a: Sequence[Op], b: Sequence[Op]):
    """Pairs ops that are the same operation with a different payload."""
    remaining_b = list(b)
    paired = []
    rest_a = []
    for op in a:
        match = None
        for cand in remaining_b:
            if cand.kind == op.kind and cand.key == op.key:
                match = cand
                break
        if match is None:
            rest_a.append(op)
        else:
            remaining_b.remove(match)
            paired.append((op, match))
    return paired, rest_a, remaining_b


def _regions_equal(a: Sequence[MemRegion], b: Sequence[MemRegion]) -> bool:
    if len(a) != len(b):
        return False
    return all(
        ra.start == rb.start and bytes(ra.data) == bytes(rb.data) for ra, rb in zip(a, b)
    )


def _diff_images(a: Sequence[MemRegion], b: Sequence[MemRegion]) -> List[Finding]:
    """Compares the coalesced memory images octet by octet.

    This is the chunking-independent check: whatever the write records looked
    like, these are the octets the device ends up holding.
    """
    flat_a = _flatten(a)
    flat_b = _flatten(b)
    if not flat_a and not flat_b:
        return []
    findings: List[Finding] = []

    only_a = sorted(set(flat_a) - set(flat_b))
    only_b = sorted(set(flat_b) - set(flat_a))
    for label, addrs, side in (("A", only_a, "only in A"), ("B", only_b, "only in B")):
        for start, end in _ranges(addrs):
            findings.append(
                Finding(
                    DIFFERENT,
                    "coverage",
                    "0x%06x..0x%06x (%d octets) written %s"
                    % (start, end, end - start, side),
                )
            )

    both = sorted(set(flat_a) & set(flat_b))
    mismatched = [addr for addr in both if flat_a[addr] != flat_b[addr]]
    for start, end in _ranges(mismatched):
        a_bytes = bytes(flat_a[x] for x in range(start, end))
        b_bytes = bytes(flat_b[x] for x in range(start, end))
        findings.append(
            Finding(
                DIFFERENT,
                "content",
                "0x%06x..0x%06x (%d octets) differ: A %s / B %s"
                % (start, end, end - start, _hex_excerpt(a_bytes), _hex_excerpt(b_bytes)),
            )
        )
    return findings


def _flatten(regions: Sequence[MemRegion]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for region in regions:
        for i, b in enumerate(region.data):
            out[region.start + i] = b
    return out


def _ranges(addrs: Sequence[int]) -> List[Tuple[int, int]]:
    """Turns a sorted address list into (start, end-exclusive) runs."""
    out: List[Tuple[int, int]] = []
    start = prev = None
    for addr in addrs:
        if start is None:
            start = prev = addr
            continue
        if addr == prev + 1:
            prev = addr
            continue
        out.append((start, prev + 1))
        start = prev = addr
    if start is not None:
        out.append((start, prev + 1))
    return out


def _hex_excerpt(data: bytes, limit: int = 24) -> str:
    if len(data) <= limit:
        return data.hex()
    return "%s...(%d octets)" % (data[:limit].hex(), len(data))
