# /// script
# requires-python = ">=3.10"
# ///
"""Clone the KNX Virtual DA.tp into a renamed synthetic product under M-00FA (epic #596).

    uv run tools/ets-sweep/synthetic/clone_datp.py [<KNX_Virtual_M-00FA.knxprod>] [<out.knxprod>]

The clone is the DA.tp application program unchanged except for its identity:
application number 0x2600 (id A-2600-10-0001), hardware serial 00FA00260000,
order number SYN.da, its own catalogue section. The KliX (A-2504) hardware, its
catalogue item and the translations of both are dropped. The `Hash` and
`RegistrationSignature` attributes are left as the original had them, so the
output is stale until `sign.py` rehashes it; that signer also replaces the
`0001` placeholder in the ids with the fingerprint of the program's hash.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
DEFAULT_SRC = REPO / "knx-sim" / "tests" / "fixtures" / "KNX_Virtual_M-00FA.knxprod"
DEFAULT_DST = REPO / "tools" / "ets-sweep" / "synthetic" / "out" / "KNX_Synthetic_DA_M-00FA.knxprod"
NS = "http://knx.org/xml/project/23"
SRC_APP = "M-00FA/M-00FA_A-2500-10-51CB.xml"
DST_APP = "M-00FA/M-00FA_A-2600-10-0001.xml"

# Plain text replacements, in this order, over the three manufacturer files.
RENAMES = [
    ("A-2500-10-51CB", "A-2600-10-0001"),
    ('ApplicationNumber="9472"', 'ApplicationNumber="9728"'),
    ("00FA00250000", "00FA00260000"),
    ("HP-2500-10-51CB", "HP-2600-10-0001"),
    ("P-DA.2Etp", "P-SYN.2Eda"),
    ('OrderNumber="DA.tp"', 'OrderNumber="SYN.da"'),
    ("CI-DA.2Etp-1", "CI-SYN.2Eda-1"),
    ('Text="DA.tp (D0)"', 'Text="SYN.da (synthetic D0 clone)"'),
    ('Name="Dimming"', 'Name="Dimming (synthetic clone)"'),
    ('Name="Dimming Actuator (D0)"', 'Name="Synthetic Dimming Actuator"'),
    ('Name="D0"', 'Name="S0"'),
    ("M-00FA_CS-25", "M-00FA_CS-26"),
    ('Name="KNX Virtual"', 'Name="bussard synthetic"'),
]


def q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def drop(xml: str, tag: str, pred) -> str:
    """Remove every element `tag` for which `pred(element)` holds."""
    root = ET.fromstring(xml)
    for parent in root.iter():
        for child in list(parent):
            if child.tag == q(tag) and pred(child):
                parent.remove(child)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode")


def rename(text: str) -> str:
    for old, new in RENAMES:
        text = text.replace(old, new)
    return text


def clone(src: Path, dst: Path) -> None:
    ET.register_namespace("", NS)
    ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
    ET.register_namespace("xsd", "http://www.w3.org/2001/XMLSchema")
    with zipfile.ZipFile(src) as z:
        app = z.read(SRC_APP).decode("utf-8-sig")
        hw = z.read("M-00FA/Hardware.xml").decode("utf-8-sig")
        cat = z.read("M-00FA/Catalog.xml").decode("utf-8-sig")
        master = z.read("knx_master.xml")
    klix = lambda e: "2504" in e.get("Id", "")  # noqa: E731
    hw = drop(drop(hw, "Hardware", klix), "Language", lambda e: True)
    cat = drop(drop(cat, "CatalogItem", klix), "Language", lambda e: True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("knx_master.xml", master)
        out.writestr("M-00FA/Catalog.xml", rename(cat).encode())
        out.writestr("M-00FA/Hardware.xml", rename(hw).encode())
        out.writestr(DST_APP, rename(app).encode())


def main(argv: list[str]) -> int:
    src = Path(argv[0]) if argv else DEFAULT_SRC
    dst = Path(argv[1]) if len(argv) > 1 else DEFAULT_DST
    clone(src, dst)
    print("wrote", dst, dst.stat().st_size, "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
