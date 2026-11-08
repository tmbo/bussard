"""Which catalog rows belong to the product file the sweep imported (bussard
issue #881).

ETS's catalog search by order number also lists products of earlier imports
and of the online catalog that share the order number: a rebranded clone of a
TAPKO product (German names, another manufacturer group) was added instead of
the file's own product three times on 2026-11-08, and ETS then refused the
sim as "another manufacturer's" device. The rows carry the manufacturer group
header they sit under; these rules keep the file's manufacturer.

Pure functions, no Windows imports: the driver (`ets_driver.py`, inside the
VM) imports this file from its own directory (`vm.py install` uploads both),
and the Mac-side tests import it from here.
"""
from __future__ import annotations

import re

# Words a manufacturer's name carries beside the brand ("TAPKO Technologies
# GmbH"); they do not tell two manufacturers apart.
_NOISE = {"gmbh", "co", "kg", "ag", "sa", "spa", "srl", "ltd", "inc", "bv", "nv", "sas", "the", "und", "and"}


def _canon(t: str) -> str:
    """Case-folded letters and digits, OCR's I/l/1/| and O/0 unified."""
    t = t.lower().translate(str.maketrans({"l": "i", "1": "i", "|": "i", "!": "i", "0": "o"}))
    return re.sub(r"[^0-9a-z]", "", t)


def _brand(name: str) -> str:
    """The first word of a manufacturer name that is not a legal-form word,
    canonical ("TAPKO Technologies" -> "tapko")."""
    for word in re.split(r"[\s&.,/-]+", name):
        c = _canon(word)
        if len(c) >= 2 and c not in _NOISE:
            return c
    return _canon(name)


def manufacturer_matches(header: str, manufacturer: str) -> bool | None:
    """Whether a row's manufacturer group header names `manufacturer` (the
    product file's knx_master name); None when the header is unknown."""
    if not header.strip():
        return None
    h, m = _canon(header), _canon(manufacturer)
    if not h or not m:
        return None
    return h.startswith(m) or m.startswith(h) or h.startswith(_brand(manufacturer))


def application_matches(cell: str, application: str) -> bool:
    """Whether a row's application cell (often cut with '...' or '.') is the
    start of `application`, the file's application program name."""
    c = _canon(re.sub(r"(\.\.\.|…|\.)\s*$", "", cell.strip()))
    a = _canon(application)
    return len(c) >= 4 and bool(a) and (a.startswith(c) or c.startswith(a))


class ManufacturerMismatch(RuntimeError):
    """No catalog row of the search is the file's manufacturer's."""


def file_rows(hits: list[dict], manufacturer: str, application: str = "") -> list[dict]:
    """The rows of `hits` that can be the product file's: those under the
    file's manufacturer, and among them those whose application matches when
    any does. A row whose manufacturer header was not read stays (it is no
    evidence of a stranger). Raises ManufacturerMismatch, naming the rows
    seen, when every row sits under another manufacturer. Without a
    `manufacturer` the hits are returned as they are."""
    if not manufacturer or not hits:
        return hits
    verdicts = [(r, manufacturer_matches(str(r.get("manufacturer") or ""), manufacturer)) for r in hits]
    own = [r for r, v in verdicts if v]
    unknown = [r for r, v in verdicts if v is None]
    if not own and not unknown:
        seen = [(r.get("manufacturer"), r.get("name"), r.get("order"), r.get("application")) for r in hits][:8]
        raise ManufacturerMismatch(f"catalog manufacturer mismatch: wanted {manufacturer!r}, rows {seen}")
    rows = [r for r, v in verdicts if v is not False]
    if application:
        same_app = [r for r in rows if application_matches(str(r.get("application") or ""), application)]
        if same_app:
            return same_app
    return rows
