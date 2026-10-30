# /// script
# requires-python = ">=3.11"
# ///
"""Render the synthetic product specs into product XML (epic #596).

    uv run tests-support/synthetic-products/generate.py [<name>...]          # render xml/ (all by default)
    uv run tests-support/synthetic-products/generate.py --check [<name>...]  # fail if xml/ is stale
    uv run tests-support/synthetic-products/generate.py --zip [<name>...]    # also build/<name>.knxprod
    uv run tests-support/synthetic-products/generate.py --catalogue          # README catalogue table
    uv run tests-support/synthetic-products/generate.py <name> --signed-id <id | signed.knxprod>

Each `<name>/product.toml` renders, byte for byte the same on every run, into
`<name>/xml/M-00FA/Catalog.xml`, `Hardware.xml` and
`M-00FA_A-<nnnn>-<vv>-0000.xml`. `--zip` packs those with the stub
`knx_master.xml` (`<KNX/>`) into `<name>/build/<name>.knxprod` (gitignored),
the input of `tools/ets-sweep/synthetic/sign.py`. The signer replaces the
`0000` at the end of the application id with the fingerprint of the program
hash; `--signed-id` records that id, with the hash of the XML it was signed
from, in `<name>/signed.toml` for the consumers written after signing (sim
config, oracle row).

The spec schema is in README.md. The generator implements what the products in
this directory use; a known construct no product uses yet stops with an error
that names it, an unknown key stops with an error that names the key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
import tomllib
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

HERE = Path(__file__).resolve().parent
NS = "http://knx.org/xml/project/23"
MANUFACTURER = "M-00FA"
# Application numbers of the synthetic catalogue (#604): 0x27xx System B, 0x28xx
# System 7, 0x29xx Secure, 0x2Axx RF and IP. KNX Virtual uses 0x25xx, the
# DA.tp clone 0x2600.
APP_NUMBERS = range(0x2700, 0x2B00)
# Catalogue section shared by every synthetic product (the clone used CS-26).
CATALOG_SECTION = (f"{MANUFACTURER}_CS-27", "The buzzard's nest", "27")
STUB_MASTER = b"<KNX/>"
README_BEGIN = "<!-- catalogue:begin (generate.py --catalogue) -->"
README_END = "<!-- catalogue:end -->"


class SpecError(Exception):
    """A spec the generator cannot render; the message names the product and the key."""


def not_yet(where: str, what: str) -> SpecError:
    return SpecError(f"{where}: {what} is part of the schema but no product uses it yet; "
                     "implement it in generate.py together with the product that needs it")


# ---------------------------------------------------------------- spec checks

def check_keys(where: str, table: dict, required: set[str], optional: set[str] = frozenset(),
               later: set[str] = frozenset()) -> None:
    """Every required key present, no key outside required | optional | later,
    and none of `later` (schema keys not implemented yet) used."""
    for k in sorted(required - table.keys()):
        raise SpecError(f"{where}: missing key `{k}`")
    for k in table:
        if k in later:
            raise not_yet(where, f"`{k}`")
        if k not in required and k not in optional:
            raise SpecError(f"{where}: unknown key `{k}`")


def ets_escape(text: str) -> str:
    """The id encoding of ETS: letters and digits stay, every other octet is `.XX`.

    `-` separates the parts of an id, so ETS escapes it too: Enertex order
    number `1176-08` is product `M-00A6_H-00000030-0_P-1176.2D08`. Left
    unescaped, `NEST-LIGHT` made ETS 6.4.1's catalogue refresh fail with a
    KeyNotFoundException after the import (2026-10-30)."""
    return "".join(c if c.isascii() and c.isalnum() else
                   "".join(f".{b:02X}" for b in c.encode()) for c in text)


def flag(on: bool) -> str:
    return "Enabled" if on else "Disabled"


def attrs(pairs: list[tuple[str, object]]) -> str:
    out = []
    for k, v in pairs:
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        out.append(f"{k}={quoteattr(str(v))}")
    return " ".join(out)


class Xml:
    """A line-based writer: two-space indent, attributes in the order given."""

    def __init__(self) -> None:
        self.lines = ['<?xml version="1.0" encoding="utf-8"?>']
        self.depth = 0

    def open(self, tag: str, pairs: list[tuple[str, object]] = ()) -> None:
        a = attrs(list(pairs))
        self.lines.append("  " * self.depth + f"<{tag}{' ' + a if a else ''}>")
        self.depth += 1

    def close(self, tag: str) -> None:
        self.depth -= 1
        self.lines.append("  " * self.depth + f"</{tag}>")

    def empty(self, tag: str, pairs: list[tuple[str, object]] = ()) -> None:
        a = attrs(list(pairs))
        self.lines.append("  " * self.depth + f"<{tag}{' ' + a if a else ''} />")

    def text(self, tag: str, body: str) -> None:
        self.lines.append("  " * self.depth + f"<{tag}>{body}</{tag}>")

    def render(self) -> bytes:
        return ("\n".join(self.lines) + "\n").encode("utf-8")


def knx_root(x: Xml, ns: str = NS) -> None:
    x.open("KNX", [("xmlns", ns)])
    x.open("ManufacturerData")
    x.open("Manufacturer", [("RefId", MANUFACTURER)])


def knx_close(x: Xml) -> None:
    x.close("Manufacturer")
    x.close("ManufacturerData")
    x.close("KNX")


# ------------------------------------------------------------------ the model

class Product:
    """A checked spec with the ids every file refers to."""

    def __init__(self, name: str, spec: dict) -> None:
        self.name = name
        w = name
        check_keys(w, spec, {"doc", "product", "application", "segment", "parameter_type",
                             "parameter", "com_object", "dynamic", "load_procedure"},
                   {"union", "parameter_calculation", "parameter_ref"})
        self.doc = spec["doc"]
        check_keys(f"{w} [doc]", self.doc, {"purpose", "construct", "issues"})
        self.product = p = spec["product"]
        check_keys(f"{w} [product]", p, {"text", "order_number", "hardware_name", "hardware_serial",
                                         "bus_current"}, {"hardware_version", "rail_mounted"})
        if not re.fullmatch(r"00FA[0-9A-F]{8}", p["hardware_serial"]):
            raise SpecError(f"{w} [product]: hardware_serial must be 00FA followed by 8 hex digits")
        self.app = a = spec["application"]
        check_keys(f"{w} [application]", a,
                   {"number", "version", "name", "mask", "load_procedure_style",
                    "address_table_max_entries", "association_table_max_entries"},
                   {"options", "translations", "schema"} | SYS7_APP_KEYS)
        if a["number"] not in APP_NUMBERS:
            raise SpecError(f"{w} [application]: number {a['number']:#06x} is outside the synthetic "
                            f"range {APP_NUMBERS.start:#06x}..{APP_NUMBERS.stop - 1:#06x}")
        if not 0 <= a["version"] <= 0xFF:
            raise SpecError(f"{w} [application]: version must be one octet")
        if a["load_procedure_style"] not in ("MergedProcedure", "ProductProcedure"):
            raise SpecError(f"{w} [application]: load_procedure_style is MergedProcedure or ProductProcedure")
        self.system7 = a["mask"] in SYS7_MASKS
        if self.system7:
            check_system7_application(w, a)
        else:
            if a["mask"] != "07B0":
                raise not_yet(f"{w} [application]", f"mask {a['mask']} (System 7 and others)")
            if a["load_procedure_style"] == "ProductProcedure":
                raise not_yet(f"{w} [application]", "LoadProcedureStyle ProductProcedure on 07B0")
            for k in sorted(SYS7_APP_KEYS & a.keys()):
                raise SpecError(f"{w} [application]: `{k}` belongs to a System 7 mask ({', '.join(SYS7_MASKS)})")
        for k in a.get("options", {}):
            if k not in OPTIONS:
                raise SpecError(f"{w} [application.options]: unknown option `{k}`")
        self.schema = check_schema(w, a)
        self.app_id = f"{MANUFACTURER}_A-{a['number']:04X}-{a['version']:02X}-0000"
        self.hw_id = f"{MANUFACTURER}_H-{p['hardware_serial']}-{p.get('hardware_version', 1)}"
        self.product_id = f"{self.hw_id}_P-{ets_escape(p['order_number'])}"
        self.h2p_id = f"{self.hw_id}_HP-{a['number']:04X}-{a['version']:02X}-0000"
        self.item_id = f"{self.h2p_id}_CI-{ets_escape(p['order_number'])}-1"

        self.segments = {}
        for i, s in enumerate(spec["segment"]):
            sw = f"{w} [[segment]] #{i + 1}"
            if s.get("kind") == "absolute":
                if not self.system7:
                    raise not_yet(sw, "an absolute segment on a System B mask")
                self.segments[s["name"]] = check_absolute_segment(sw, s, self.app_id)
                continue
            check_keys(sw, s, {"name", "kind", "lsm", "size"}, {"fill"}, {"address"})
            if s["kind"] != "relative":
                raise SpecError(f"{sw}: kind is relative or absolute")
            if self.system7:
                raise SpecError(f"{sw}: a System 7 mask has absolute segments only")
            s = dict(s, id=f"{self.app_id}_RS-{s['lsm']:02d}-{len(self.segments):05d}")
            self.segments[s["name"]] = s

        self.types = {}
        for i, t in enumerate(spec["parameter_type"]):
            tw = f"{w} [[parameter_type]] #{i + 1}"
            kind = t.get("kind")
            if kind == "enum":
                check_keys(tw, t, {"name", "kind", "size_bits", "values"})
                for v in t["values"]:
                    check_keys(f"{tw} values", v, {"value", "text"}, set(), {"translations"})
            elif kind == "number":
                check_keys(tw, t, {"name", "kind", "size_bits", "signed", "min", "max"}, set(), {"ui_hint"})
            elif kind == "float":
                check_keys(tw, t, {"name", "kind", "encoding", "min", "max"})
                if t["encoding"] not in FLOAT_BITS:
                    raise SpecError(f"{tw}: encoding is one of {', '.join(FLOAT_BITS)}")
                t = dict(t, size_bits=FLOAT_BITS[t["encoding"]])
            elif kind == "text":
                check_keys(tw, t, {"name", "kind", "size_octets"})
                t = dict(t, size_bits=8 * t["size_octets"])
            elif kind in ("time", "ip_address", "raw"):
                raise not_yet(tw, f"parameter type kind `{kind}`")
            else:
                raise SpecError(f"{tw}: kind is one of enum, number, text, float, time, ip_address, raw")
            self.types[t["name"]] = dict(t, id=f"{self.app_id}_PT-{ets_escape(t['name'])}")

        # Unions (#405): one <Union> with its <Memory>; its members are
        # parameters with `union = { name, offset, bit_offset }`.
        self.unions = {}
        for i, u in enumerate(spec.get("union", [])):
            uw = f"{w} [[union]] #{i + 1}"
            check_keys(uw, u, {"name", "size_bits", "memory"}, {"default"})
            self.check_memory(uw, u["memory"], u["size_bits"])
            self.unions[u["name"]] = dict(u, members=[])

        self.params = {}
        for i, prm in enumerate(spec["parameter"]):
            pw = f"{w} [[parameter]] #{i + 1}"
            check_keys(pw, prm, {"name", "type", "text", "default"},
                       {"memory", "union", "access", "virtual", "legacy_patch_always"}, {"translations"})
            if prm["type"] not in self.types:
                raise SpecError(f"{pw}: unknown parameter type `{prm['type']}`")
            if prm.get("access", "ReadWrite") not in ("None", "Read", "ReadWrite"):
                raise SpecError(f"{pw}: access is None, Read or ReadWrite")
            bits = self.types[prm["type"]]["size_bits"]
            n = i + 1
            # syn-choose-never-shown (#604 row 14, #474): `virtual = true` is a
            # parameter with no <Memory>, which only steers the Dynamic tree.
            if prm.get("virtual"):
                if "memory" in prm or "union" in prm:
                    raise SpecError(f"{pw}: a virtual parameter has no `memory` and no `union`")
                self.params[prm["name"]] = dict(prm, id=f"{self.app_id}_P-{n}", ref=f"{self.app_id}_P-{n}_R-{n}")
                continue
            if ("memory" in prm) == ("union" in prm):
                raise SpecError(f"{pw}: needs exactly one of `memory` and `union`")
            if "memory" in prm:
                self.check_memory(pw, prm["memory"], bits)
                self.params[prm["name"]] = dict(prm, id=f"{self.app_id}_P-{n}", ref=f"{self.app_id}_P-{n}_R-{n}")
                continue
            m = prm["union"]
            check_keys(f"{pw} union", m, {"name", "offset", "bit_offset"})
            un = self.unions.get(m["name"])
            if un is None:
                raise SpecError(f"{pw}: unknown union `{m['name']}`")
            if m["offset"] * 8 + m["bit_offset"] + bits > un["size_bits"]:
                raise SpecError(f"{pw}: does not fit union `{m['name']}`")
            un["members"].append(prm["name"])
            self.params[prm["name"]] = dict(prm, id=f"{self.app_id}_UP-{n}", ref=f"{self.app_id}_UP-{n}_R-{n}")
        for un in self.unions.values():
            if len(un["members"]) < 2:
                raise SpecError(f"{w} [[union]] `{un['name']}`: a union needs at least two members")
            if "default" in un and un["default"] not in un["members"]:
                raise SpecError(f"{w} [[union]] `{un['name']}`: default `{un['default']}` is not a member")

        # syn-choose-per-ref (#604 row 25, #563): further `ParameterRef`s of a
        # parameter, `_P-<n>_R-<k>` numbered after every parameter's own ref.
        self.extra_refs = {}
        for i, r in enumerate(spec.get("parameter_ref", [])):
            rw = f"{w} [[parameter_ref]] #{i + 1}"
            check_keys(rw, r, {"name", "parameter"})
            if r["parameter"] not in self.params:
                raise SpecError(f"{rw}: unknown parameter `{r['parameter']}`")
            if r["name"] in self.params or r["name"] in self.extra_refs:
                raise SpecError(f"{rw}: name `{r['name']}` is already a parameter or a ref")
            prm = self.params[r["parameter"]]
            self.extra_refs[r["name"]] = dict(r, ref=f"{prm['id']}_R-{len(self.params) + i + 1}")

        # syn-param-calculation (#604 row 11, #427): <ParameterCalculation>s.
        self.calculations = [self.check_calculation(f"{w} [[parameter_calculation]] #{i + 1}", c, i + 1)
                             for i, c in enumerate(spec.get("parameter_calculation", []))]

        self.objects = {}
        for i, o in enumerate(spec["com_object"]):
            ow = f"{w} [[com_object]] #{i + 1}"
            check_keys(ow, o, {"number", "name", "text", "function_text", "size", "dpt", "flags", "priority"},
                       set(), {"ref", "translations"})
            bad = set(o["flags"]) - set(FLAGS)
            if bad:
                raise SpecError(f"{ow}: unknown flags {sorted(bad)}; use {list(FLAGS)}")
            if o["priority"] not in ("Low", "High", "Alert"):
                raise SpecError(f"{ow}: priority is Low, High or Alert")
            oid = f"{self.app_id}_O-{o['number']}"
            self.objects[o["number"]] = dict(o, id=oid, ref=f"{oid}_R-{i + 1}")

        dyn = spec["dynamic"]
        check_keys(f"{w} [dynamic]", dyn, {"block"}, {"choose"}, {"channel"})
        self.blocks = []
        for i, b in enumerate(dyn["block"]):
            bw = f"{w} [[dynamic.block]] #{i + 1}"
            check_keys(bw, b, {"name", "text", "parameters", "com_objects"}, set(), {"choose", "inline"})
            for pn in b["parameters"]:
                if pn not in self.params and pn not in self.extra_refs:
                    raise SpecError(f"{bw}: unknown parameter `{pn}`")
            for on in b["com_objects"]:
                if on not in self.objects:
                    raise SpecError(f"{bw}: unknown com object {on}")
            self.blocks.append(dict(b, id=f"{self.app_id}_PB-{i + 1}"))
        self.dynamic_chooses = [self.check_dynamic_choose(f"{w} [[dynamic.choose]] #{i + 1}", c)
                                for i, c in enumerate(dyn.get("choose", []))]

        self.load_procedures = []
        for i, lp in enumerate(spec["load_procedure"]):
            lw = f"{w} [[load_procedure]] #{i + 1}"
            if a["load_procedure_style"] == "ProductProcedure":
                check_keys(lw, lp, {"ops"})
                if len(spec["load_procedure"]) != 1:
                    raise SpecError(f"{w}: a ProductProcedure has exactly one [[load_procedure]]")
            else:
                check_keys(lw, lp, {"merge_id", "ops"})
            self.check_load_ops(lw, lp["ops"])
            self.load_procedures.append(lp)
        if self.system7:
            check_system7_tables(w, self)

    def check_block(self, bw: str, b: dict, number: int) -> dict:
        """A parameter block of the Dynamic tree, given its `_PB-<number>`."""
        check_keys(bw, b, {"name", "text", "parameters", "com_objects"}, set(), {"choose", "inline"})
        for pn in b["parameters"]:
            if pn not in self.params and pn not in self.extra_refs:
                raise SpecError(f"{bw}: unknown parameter `{pn}`")
        for on in b["com_objects"]:
            if on not in self.objects:
                raise SpecError(f"{bw}: unknown com object {on}")
        return dict(b, id=f"{self.app_id}_PB-{number}")

    def check_dynamic_choose(self, cw: str, c: dict) -> dict:
        """syn-choose-never-shown (#604 row 14, #474): a `<choose ParamRefId>`
        in the ChannelIndependentBlock, after the blocks, whose `<when
        default="true">` holds parameter blocks (numbered after every block
        before it). syn-choose-per-ref (#604 row 25, #563): a `<when test>`
        branch, and a choose on a further ref of a parameter (`parameter`
        names a `[[parameter_ref]]`)."""
        check_keys(cw, c, {"parameter", "when"})
        if c["parameter"] not in self.params and c["parameter"] not in self.extra_refs:
            raise SpecError(f"{cw}: unknown parameter `{c['parameter']}`")
        if not c["when"]:
            raise SpecError(f"{cw}: a choose needs at least one `when`")
        whens = []
        for k, branch in enumerate(c["when"]):
            bw = f"{cw} when #{k + 1}"
            check_keys(bw, branch, {"block"}, {"default", "test"})
            if ("test" in branch) == (branch.get("default") is True) or branch.get("default") is False:
                raise SpecError(f"{bw}: give either `test` or `default = true`")
            blocks = []
            for j, b in enumerate(branch["block"]):
                self.choose_blocks = getattr(self, "choose_blocks", 0) + 1
                blocks.append(self.check_block(f"{bw} block #{j + 1}", b, len(self.blocks) + self.choose_blocks))
            whens.append({"test": branch["test"], "block": blocks} if "test" in branch
                         else {"default": True, "block": blocks})
        return {"parameter": c["parameter"], "when": whens}

    def check_calculation(self, cw: str, c: dict, n: int) -> dict:
        """A `<ParameterCalculation>` in the inline form (`<RLTransformation>`,
        `<LRTransformation>`, then `<LParameters>` and `<RParameters>`, each
        ref with its `AliasName`), the corpus's most common one (#427).
        VBScript and the `LRTransformationFunc` form with a `<Script>` are
        part of the schema but unused yet."""
        check_keys(cw, c, {"name", "language", "inputs", "outputs", "lr_script", "rl_script"})
        if c["language"] != "JavaScript":
            raise not_yet(cw, f"language `{c['language']}`")
        for side in ("inputs", "outputs"):
            if not c[side]:
                raise SpecError(f"{cw}: `{side}` needs at least one parameter")
            for k, ref in enumerate(c[side]):
                check_keys(f"{cw} {side} #{k + 1}", ref, {"parameter", "alias"})
                if ref["parameter"] not in self.params:
                    raise SpecError(f"{cw} {side} #{k + 1}: unknown parameter `{ref['parameter']}`")
        return dict(c, id=f"{self.app_id}_PC-{n}")

    def check_memory(self, where: str, m: dict, bits: int) -> None:
        """A `memory = { segment, offset, bit_offset }` that fits its segment."""
        check_keys(f"{where} memory", m, {"segment", "offset", "bit_offset"})
        seg = self.segments.get(m["segment"])
        if seg is None:
            raise SpecError(f"{where}: unknown segment `{m['segment']}`")
        if m["offset"] * 8 + m["bit_offset"] + bits > seg["size"] * 8:
            raise SpecError(f"{where}: does not fit segment `{m['segment']}`")

    def check_load_ops(self, lw: str, ops: list[dict]) -> None:
        """The ops of a load procedure, and of the `when` branches of a
        `choose` among them (recursively)."""
        for j, op in enumerate(ops):
            ow = f"{lw} op #{j + 1}"
            name = op.get("op")
            if name == "choose":
                self.check_load_choose(ow, op)
                continue
            table = LOAD_OPS | SYS7_LOAD_OPS if self.system7 else LOAD_OPS
            if name not in table:
                if name in LOAD_OPS_LATER or name in SYS7_LOAD_OPS:
                    raise not_yet(ow, f"`{name}`")
                raise SpecError(f"{ow}: unknown op `{name}`")
            check_keys(ow, op, {"op"} | set(table[name]))

    def check_load_choose(self, ow: str, op: dict) -> None:
        """syn-choose-partial-segment (#604 row 8, #411): `<choose ParamRefId>`
        inside a `LoadProcedure`, its branches `{ test, ops }` or
        `{ default = true, ops }`."""
        check_keys(ow, op, {"op", "parameter", "when"})
        if op["parameter"] not in self.params:
            raise SpecError(f"{ow}: unknown parameter `{op['parameter']}`")
        if not op["when"]:
            raise SpecError(f"{ow}: a choose needs at least one `when`")
        for k, branch in enumerate(op["when"]):
            bw = f"{ow} when #{k + 1}"
            check_keys(bw, branch, {"ops"}, {"test", "default"})
            if ("test" in branch) == bool(branch.get("default")):
                raise SpecError(f"{bw}: give either `test` or `default = true`")
            self.check_load_ops(bw, branch["ops"])

    def ref_id(self, name: str) -> str:
        """The `ParameterRef` id a block or a choose names: a parameter's own
        ref, or a `[[parameter_ref]]` (#563)."""
        return self.params[name]["ref"] if name in self.params else self.extra_refs[name]["ref"]

    @property
    def app_file(self) -> str:
        return f"{self.app_id}.xml"


FLAGS = {"C": "CommunicationFlag", "R": "ReadFlag", "W": "WriteFlag", "T": "TransmitFlag",
         "U": "UpdateFlag", "I": "ReadOnInitFlag"}
# <Options> attributes the KNX schema defines that a spec may set.
OPTIONS = ("PreferPartialDownloadIfApplicationLoaded", "EasyCtrlModeModeStyleEmptyGroupComTables",
           "SetObjectTableLengthAlwaysToMax", "TextParameterEncoding", "SupportsExtendedMemoryServices",
           "SupportsExtendedPropertyServices", "SupportsIpSystemBroadcast", "MaxRoutingApduLength",
           "Comparable", "Reconstructable", "DownloadInvisibleParameters", "ParameterByteOrder")
# `<TypeFloat Encoding>` values and their width in bits (the KNX 2-octet float
# of DPT 9 and the IEEE-754 formats).
FLOAT_BITS = {"DPT 9": 16, "IEEE-754 Single": 32, "IEEE-754 Double": 64}
# Implemented load ops: spec key -> XML attribute, in XML order.
LOAD_OPS = {
    "LdCtrlRelSegment": {"lsm": "LsmIdx", "size": "Size", "mode": "Mode", "fill": "Fill"},
    "LdCtrlWriteRelMem": {"object": "ObjIdx", "offset": "Offset", "size": "Size", "verify": "Verify"},
    # syn-master-reset (#604 row 10, #546, #611): a Master Reset in the
    # application's procedure, as KNX Virtual's DA.tp has it.
    "LdCtrlMasterReset": {"erase_code": "EraseCode", "channel": "ChannelNumber"},
}
LOAD_OPS_LATER = {"LdCtrlLoadImageProp", "LdCtrlWriteProp", "LdCtrlCompareProp",
                  "LdCtrlAbsSegment", "LdCtrlConnect", "LdCtrlDisconnect", "LdCtrlRestart",
                  "LdCtrlUnload", "LdCtrlLoad", "LdCtrlLoadCompleted", "LdCtrlTaskSegment"}


# ------------------------------------------------- System 7 (masks 0705, 0701)
# A System 7 product (#604 rows 2 and 3) carries its whole download as one
# ProductProcedure over absolute segments (dev/system7-spec.md sections 2.3
# and 4); the tables live in named absolute segments.

SYS7_MASKS = ("0705", "0701")
# [application] keys of a System 7 product: the PEI type, and the absolute
# segment each table lives in (offset 0).
SYS7_APP_KEYS = {"pei_type", "address_table_segment", "association_table_segment",
                 "com_object_table_segment"}
# The ops of a System 7 product procedure: spec key -> XML attribute, in XML order.
SYS7_LOAD_OPS = {
    "LdCtrlConnect": {},
    "LdCtrlDisconnect": {},
    "LdCtrlRestart": {},
    "LdCtrlUnload": {"lsm": "LsmIdx"},
    "LdCtrlLoad": {"lsm": "LsmIdx"},
    "LdCtrlLoadCompleted": {"lsm": "LsmIdx"},
    "LdCtrlAbsSegment": {"lsm": "LsmIdx", "seg_type": "SegType", "address": "Address", "size": "Size",
                         "access": "Access", "mem_type": "MemType", "seg_flags": "SegFlags"},
    "LdCtrlTaskSegment": {"lsm": "LsmIdx", "address": "Address"},
    "LdCtrlTaskCtrl1": {"lsm": "LsmIdx", "address": "Address", "count": "Count"},
    # syn-s7-taskptr (#604 row 17, #527): the Task Pointer Record and Task
    # Control Record 2, with the attribute names of the corpus (0020/0021).
    "LdCtrlTaskPtr": {"lsm": "LsmIdx", "init_ptr": "InitPtr", "save_ptr": "SavePtr", "serial_ptr": "SerialPtr"},
    "LdCtrlTaskCtrl2": {"lsm": "LsmIdx", "callback": "Callback", "address": "Address", "seg0": "Seg0",
                        "seg1": "Seg1"},
}
MEMORY_TYPES = ("EEPROM", "RAM")


def check_system7_application(w: str, a: dict) -> None:
    if a["load_procedure_style"] != "ProductProcedure":
        raise not_yet(f"{w} [application]", f"LoadProcedureStyle {a['load_procedure_style']} on mask {a['mask']}")
    for k in ("address_table_segment", "association_table_segment", "com_object_table_segment"):
        if k not in a:
            raise SpecError(f"{w} [application]: a System 7 mask needs `{k}`")
    if not 0 <= a.get("pei_type", 0) <= 0xFF:
        raise SpecError(f"{w} [application]: pei_type must be one octet")


def check_absolute_segment(sw: str, s: dict, app_id: str) -> dict:
    """An absolute segment: `address`, `size`, `memory_type`; `data` (hex, from
    offset 0, the rest `fill`) or `allocate_only` (no <Data>, e.g. RAM)."""
    check_keys(sw, s, {"name", "kind", "address", "size", "memory_type"}, {"fill", "data", "allocate_only"})
    if s["memory_type"] not in MEMORY_TYPES:
        raise SpecError(f"{sw}: memory_type is one of {list(MEMORY_TYPES)}")
    if not (0 <= s["address"] and s["size"] > 0 and s["address"] + s["size"] <= 0x10000):
        raise SpecError(f"{sw}: address and size must lie in the 16-bit address space")
    data = bytes.fromhex(s.get("data", ""))
    if s.get("allocate_only") and (data or "fill" in s):
        raise SpecError(f"{sw}: an allocate_only segment has no data and no fill")
    if len(data) > s["size"]:
        raise SpecError(f"{sw}: data is longer than the segment")
    return dict(s, id=f"{app_id}_AS-{s['address']:04X}", data_bytes=data)


def check_system7_tables(w: str, p: "Product") -> None:
    for k in ("address_table_segment", "association_table_segment", "com_object_table_segment"):
        if p.app[k] not in p.segments:
            raise SpecError(f"{w} [application]: {k} names unknown segment `{p.app[k]}`")


def render_absolute_segment(x: "Xml", s: dict) -> None:
    pairs = [("Id", s["id"]), ("Name", s["name"]), ("MemoryType", s["memory_type"]),
             ("Address", s["address"]), ("Size", s["size"])]
    if s.get("allocate_only"):
        x.empty("AbsoluteSegment", pairs)
        return
    data = s["data_bytes"] + bytes([s.get("fill", 0)]) * (s["size"] - len(s["data_bytes"]))
    x.open("AbsoluteSegment", pairs)
    x.text("Data", base64.b64encode(data).decode())
    x.close("AbsoluteSegment")


def table_location(p: "Product", key: str) -> list[tuple[str, object]]:
    """`CodeSegment`/`Offset` of a System 7 table element; nothing on System B."""
    if not p.system7:
        return []
    return [("CodeSegment", p.segments[p.app[key]]["id"]), ("Offset", 0)]


# ------------------------------------------- the schema version (#448, #604)
# `[application] schema` picks the namespace of all three files. 23 is the
# default; 11 is the schema of the System 7 vendor applications of #448
# (Steinel, ekinex, B.E.G., all project/11 with MinEtsVersion 4.0 or none).
# Every element and attribute the generator writes also occurs in those
# project/11 files, so the schema changes only the namespace and
# MinEtsVersion ("6.0" names an ETS newer than the schema).

SCHEMAS = {
    23: {"ns": NS, "min_ets": "6.0"},
    11: {"ns": "http://knx.org/xml/project/11", "min_ets": "4.0"},
}


def check_schema(w: str, a: dict) -> int:
    schema = a.get("schema", 23)
    if schema not in SCHEMAS:
        raise SpecError(f"{w} [application]: schema is one of {sorted(SCHEMAS)}")
    return schema


# ------------------------------------------------------------------ rendering

def render_catalog(p: Product) -> bytes:
    x = Xml()
    knx_root(x, SCHEMAS[p.schema]["ns"])
    x.open("Catalog")
    cs_id, cs_name, cs_number = CATALOG_SECTION
    x.open("CatalogSection", [("Id", cs_id), ("Name", cs_name), ("Number", cs_number),
                              ("DefaultLanguage", "en-US"), ("NonRegRelevantDataVersion", 0)])
    x.empty("CatalogItem", [("Id", p.item_id), ("Name", p.product["text"]), ("Number", 1),
                            ("VisibleDescription", p.product["text"]), ("ProductRefId", p.product_id),
                            ("Hardware2ProgramRefId", p.h2p_id), ("DefaultLanguage", "en-US"),
                            ("NonRegRelevantDataVersion", 0)])
    x.close("CatalogSection")
    x.close("Catalog")
    knx_close(x)
    return x.render()


def render_hardware(p: Product) -> bytes:
    pr = p.product
    x = Xml()
    knx_root(x, SCHEMAS[p.schema]["ns"])
    x.open("Hardware")
    x.open("Hardware", [("Id", p.hw_id), ("Name", pr["hardware_name"]), ("SerialNumber", pr["hardware_serial"]),
                        ("VersionNumber", pr.get("hardware_version", 1)), ("BusCurrent", pr["bus_current"]),
                        ("HasIndividualAddress", True), ("HasApplicationProgram", True),
                        ("NonRegRelevantDataVersion", 0)])
    x.open("Products")
    x.open("Product", [("Id", p.product_id), ("Text", pr["text"]), ("OrderNumber", pr["order_number"]),
                       ("IsRailMounted", pr.get("rail_mounted", False)), ("DefaultLanguage", "en-US"),
                       ("NonRegRelevantDataVersion", 0)])
    x.empty("RegistrationInfo", [("RegistrationStatus", "Registered")])
    x.close("Product")
    x.close("Products")
    x.open("Hardware2Programs")
    x.open("Hardware2Program", [("Id", p.h2p_id), ("MediumTypes", "MT-0")])
    x.empty("ApplicationProgramRef", [("RefId", p.app_id)])
    x.empty("RegistrationInfo", [("RegistrationStatus", "Registered")])
    x.close("Hardware2Program")
    x.close("Hardware2Programs")
    x.close("Hardware")
    x.close("Hardware")
    knx_close(x)
    return x.render()


def render_type(x: Xml, t: dict) -> None:
    x.open("ParameterType", [("Id", t["id"]), ("Name", t["name"])])
    if t["kind"] == "enum":
        x.open("TypeRestriction", [("Base", "Value"), ("SizeInBit", t["size_bits"])])
        for v in t["values"]:
            x.empty("Enumeration", [("Text", v["text"]), ("Value", v["value"]),
                                    ("Id", f"{t['id']}_EN-{v['value']}")])
        x.close("TypeRestriction")
    elif t["kind"] == "text":
        x.empty("TypeText", [("SizeInBit", t["size_bits"])])
    elif t["kind"] == "float":
        x.empty("TypeFloat", [("Encoding", t["encoding"]), ("minInclusive", t["min"]),
                              ("maxInclusive", t["max"])])
    else:  # number
        x.empty("TypeNumber", [("SizeInBit", t["size_bits"]),
                               ("Type", "signedInt" if t["signed"] else "unsignedInt"),
                               ("minInclusive", t["min"]), ("maxInclusive", t["max"])])
    x.close("ParameterType")


def render_union(x: Xml, p: Product, un: dict) -> None:
    """`<Union>`: its `<Memory>`, then each member at its offset in the union."""
    m = un["memory"]
    x.open("Union", [("SizeInBit", un["size_bits"])])
    x.empty("Memory", [("CodeSegment", p.segments[m["segment"]]["id"]), ("Offset", m["offset"]),
                       ("BitOffset", m["bit_offset"])])
    for name in un["members"]:
        prm = p.params[name]
        x.empty("Parameter", [("Id", prm["id"]), ("Name", prm["name"]), ("ParameterType", p.types[prm["type"]]["id"]),
                              ("Offset", prm["union"]["offset"]), ("BitOffset", prm["union"]["bit_offset"]),
                              ("Text", prm["text"]), ("Access", prm.get("access")), ("Value", prm["default"]),
                              ("DefaultUnionParameter", True if un.get("default") == name else None)])
    x.close("Union")


def render_load_ops(x: Xml, p: Product, ops: list[dict]) -> None:
    """Load ops in spec order; a `choose` becomes `<choose ParamRefId>` with
    its `<when test>` / `<when default="true">` branches (#411)."""
    for op in ops:
        if op["op"] == "choose":
            x.open("choose", [("ParamRefId", p.params[op["parameter"]]["ref"])])
            for branch in op["when"]:
                x.open("when", [("test", branch["test"])] if "test" in branch else [("default", True)])
                render_load_ops(x, p, branch["ops"])
                x.close("when")
            x.close("choose")
        else:
            x.empty(op["op"], [(attr, op[key]) for key, attr in (LOAD_OPS | SYS7_LOAD_OPS)[op["op"]].items()])


def render_dynamic_choose(x: Xml, p: Product, c: dict) -> None:
    """`<choose ParamRefId>` in the Dynamic tree, its `<when default="true">`
    holding parameter blocks (#474)."""
    x.open("choose", [("ParamRefId", p.ref_id(c["parameter"]))])
    for branch in c["when"]:
        x.open("when", [("test", branch["test"])] if "test" in branch else [("default", True)])
        for b in branch["block"]:
            x.open("ParameterBlock", [("Id", b["id"]), ("Name", b["name"]), ("Text", b["text"])])
            for pn in b["parameters"]:
                x.empty("ParameterRefRef", [("RefId", p.ref_id(pn))])
            for on in b["com_objects"]:
                x.empty("ComObjectRefRef", [("RefId", p.objects[on]["ref"])])
            x.close("ParameterBlock")
        x.close("when")
    x.close("choose")


def render_calculations(x: Xml, p: Product) -> None:
    """`<ParameterCalculations>` after the `ParameterRefs` (#427)."""
    if not p.calculations:
        return
    x.open("ParameterCalculations")
    for c in p.calculations:
        x.open("ParameterCalculation", [("Id", c["id"]), ("Name", c["name"]), ("Language", c["language"])])
        x.text("RLTransformation", escape(c["rl_script"]))
        x.text("LRTransformation", escape(c["lr_script"]))
        for tag, side in (("LParameters", "inputs"), ("RParameters", "outputs")):
            x.open(tag)
            for ref in c[side]:
                x.empty("ParameterRefRef", [("RefId", p.params[ref["parameter"]]["ref"]), ("AliasName", ref["alias"])])
            x.close(tag)
        x.close("ParameterCalculation")
    x.close("ParameterCalculations")


def render_application(p: Product) -> bytes:
    a = p.app
    x = Xml()
    knx_root(x, SCHEMAS[p.schema]["ns"])
    x.open("ApplicationPrograms")
    x.open("ApplicationProgram", [
        ("Id", p.app_id), ("ApplicationNumber", a["number"]), ("ApplicationVersion", a["version"]),
        ("ProgramType", "ApplicationProgram"), ("MaskVersion", f"MV-{a['mask']}"), ("Name", a["name"]),
        ("LoadProcedureStyle", a["load_procedure_style"]), ("PeiType", a.get("pei_type", 0)), ("DefaultLanguage", "en-US"),
        ("DynamicTableManagement", False), ("Linkable", False), ("MinEtsVersion", SCHEMAS[p.schema]["min_ets"]),
        ("NonRegRelevantDataVersion", 0)])
    x.open("Static")
    x.open("Code")
    for s in p.segments.values():
        if s["kind"] == "absolute":
            render_absolute_segment(x, s)
            continue
        x.open("RelativeSegment", [("Id", s["id"]), ("Name", s["name"]), ("Size", s["size"]),
                                   ("LoadStateMachine", s["lsm"]), ("Offset", 0)])
        x.text("Data", base64.b64encode(bytes([s.get("fill", 0)]) * s["size"]).decode())
        x.close("RelativeSegment")
    x.close("Code")
    x.open("ParameterTypes")
    for t in p.types.values():
        render_type(x, t)
    x.close("ParameterTypes")
    x.open("Parameters")
    for prm in p.params.values():
        if "union" in prm:
            continue
        if prm.get("virtual"):  # no <Memory> (#474)
            x.empty("Parameter", [("Id", prm["id"]), ("Name", prm["name"]),
                                  ("ParameterType", p.types[prm["type"]]["id"]), ("Text", prm["text"]),
                                  ("Access", prm.get("access")), ("Value", prm["default"])])
            continue
        x.open("Parameter", [("Id", prm["id"]), ("Name", prm["name"]), ("ParameterType", p.types[prm["type"]]["id"]),
                             ("Text", prm["text"]), ("Access", prm.get("access")), ("Value", prm["default"]),
                             ("LegacyPatchAlways", True if prm.get("legacy_patch_always") else None)])
        m = prm["memory"]
        x.empty("Memory", [("CodeSegment", p.segments[m["segment"]]["id"]), ("Offset", m["offset"]),
                           ("BitOffset", m["bit_offset"])])
        x.close("Parameter")
    for un in p.unions.values():
        render_union(x, p, un)
    x.close("Parameters")
    x.open("ParameterRefs")
    for prm in p.params.values():
        x.empty("ParameterRef", [("Id", prm["ref"]), ("RefId", prm["id"])])
    for r in p.extra_refs.values():  # #563
        x.empty("ParameterRef", [("Id", r["ref"]), ("RefId", p.params[r["parameter"]]["id"])])
    x.close("ParameterRefs")
    render_calculations(x, p)
    x.open("ComObjectTable", table_location(p, "com_object_table_segment"))
    for o in p.objects.values():
        x.empty("ComObject", [("Id", o["id"]), ("Name", o["name"]), ("Text", o["text"]), ("Number", o["number"]),
                              ("FunctionText", o["function_text"]), ("ObjectSize", o["size"])]
                + [(FLAGS[f], flag(f in o["flags"])) for f in ("R", "W", "C", "T", "U", "I")]
                + [("DatapointType", o["dpt"]), ("Priority", o["priority"])])
    x.close("ComObjectTable")
    x.open("ComObjectRefs")
    for o in p.objects.values():
        x.empty("ComObjectRef", [("Id", o["ref"]), ("RefId", o["id"])])
    x.close("ComObjectRefs")
    x.empty("AddressTable", table_location(p, "address_table_segment")
            + [("MaxEntries", a["address_table_max_entries"])])
    x.empty("AssociationTable", table_location(p, "association_table_segment")
            + [("MaxEntries", a["association_table_max_entries"])])
    x.open("LoadProcedures")
    for lp in p.load_procedures:
        x.open("LoadProcedure", [("MergeId", lp["merge_id"])] if "merge_id" in lp else [])
        render_load_ops(x, p, lp["ops"])
        x.close("LoadProcedure")
    x.close("LoadProcedures")
    x.empty("Options", [(k, v) for k, v in a.get("options", {}).items()])
    x.close("Static")
    x.open("Dynamic")
    x.open("ChannelIndependentBlock")
    for b in p.blocks:
        x.open("ParameterBlock", [("Id", b["id"]), ("Name", b["name"]), ("Text", b["text"])])
        for pn in b["parameters"]:
            x.empty("ParameterRefRef", [("RefId", p.ref_id(pn))])
        for on in b["com_objects"]:
            x.empty("ComObjectRefRef", [("RefId", p.objects[on]["ref"])])
        x.close("ParameterBlock")
    for c in p.dynamic_chooses:
        render_dynamic_choose(x, p, c)
    x.close("ChannelIndependentBlock")
    x.close("Dynamic")
    x.close("ApplicationProgram")
    x.close("ApplicationPrograms")
    translations = a.get("translations", {})
    if translations:
        x.open("Languages")
        for lang, text in sorted(translations.items()):
            x.open("Language", [("Identifier", lang)])
            x.open("TranslationUnit", [("RefId", p.app_id), ("Version", 0)])
            x.open("TranslationElement", [("RefId", p.app_id)])
            x.empty("Translation", [("AttributeName", "Name"), ("Text", text)])
            x.close("TranslationElement")
            x.close("TranslationUnit")
            x.close("Language")
        x.close("Languages")
    knx_close(x)
    return x.render()


def render(p: Product) -> dict[str, bytes]:
    """The product XML, keyed by its path inside the .knxprod."""
    return {
        f"{MANUFACTURER}/Catalog.xml": render_catalog(p),
        f"{MANUFACTURER}/Hardware.xml": render_hardware(p),
        f"{MANUFACTURER}/{p.app_file}": render_application(p),
    }


# ------------------------------------------------------------------- commands

def load(name: str) -> Product:
    path = HERE / name / "product.toml"
    try:
        spec = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SpecError(f"{name}: {exc}") from exc
    return Product(name, spec)


def all_names() -> list[str]:
    return sorted(d.name for d in HERE.iterdir() if (d / "product.toml").is_file())


def xml_digest(files: dict[str, bytes]) -> str:
    """sha256 over the rendered files, in path order, path and content each."""
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(path.encode() + b"\0" + files[path] + b"\0")
    return h.hexdigest()


def committed(name: str) -> dict[str, bytes]:
    root = HERE / name / "xml"
    return {f.relative_to(root).as_posix(): f.read_bytes() for f in sorted(root.rglob("*.xml"))}


def write_xml(p: Product, files: dict[str, bytes]) -> None:
    root = HERE / p.name / "xml"
    for old in root.rglob("*.xml") if root.exists() else []:
        if old.relative_to(root).as_posix() not in files:
            old.unlink()
    for path, data in files.items():
        out = root / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)


def write_zip(p: Product, files: dict[str, bytes]) -> Path:
    """Deterministic .knxprod: fixed timestamps, stub master first, then path order."""
    out = HERE / p.name / "build" / f"{p.name}.knxprod"
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data in [("knx_master.xml", STUB_MASTER)] + sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return out


def signed_id_from(arg: str) -> str:
    if arg.endswith(".knxprod"):
        with zipfile.ZipFile(arg) as z:
            ids = sorted(Path(n).stem for n in z.namelist() if re.search(r"_A-[0-9A-F]{4}-", n))
        if len(ids) != 1:
            raise SpecError(f"{arg}: expected one application program, found {ids}")
        return ids[0]
    return arg


def record_signed(p: Product, files: dict[str, bytes], arg: str) -> Path:
    sid = signed_id_from(arg)
    prefix = p.app_id[:-4]
    if not (sid.startswith(prefix) and re.fullmatch(r"[0-9A-F]{4}", sid[len(prefix):])):
        raise SpecError(f"{p.name}: signed id {sid} does not belong to {p.app_id}")
    out = HERE / p.name / "signed.toml"
    out.write_text(
        "# Written by generate.py --signed-id after tools/ets-sweep/synthetic/sign.py.\n"
        "# Stale when xml_sha256 differs from the committed xml/ (generate.py --check says so).\n"
        f'application_id = "{sid}"\n'
        f'hardware2program_id = "{p.h2p_id[:-4]}{sid[-4:]}"\n'
        f'xml_sha256 = "{xml_digest(files)}"\n', encoding="utf-8")
    return out


def catalogue_table(products: list[Product]) -> str:
    rows = ["| product | order number | mask | construct | issues |", "| --- | --- | --- | --- | --- |"]
    for p in products:
        issues = ", ".join(f"#{n}" for n in p.doc["issues"])
        rows.append(f"| [`{p.name}`]({p.name}/product.toml) | `{p.product['order_number']}` | "
                    f"{p.app['mask']} | {p.doc['construct']} | {issues} |")
    return "\n".join(rows)


def write_catalogue(products: list[Product]) -> None:
    readme = HERE / "README.md"
    text = readme.read_text(encoding="utf-8")
    i, j = text.find(README_BEGIN), text.find(README_END)
    if i < 0 or j < i:
        raise SpecError(f"README.md: markers {README_BEGIN!r} and {README_END!r} not found")
    body = f"{README_BEGIN}\n{catalogue_table(products)}\n"
    readme.write_text(text[:i] + body + text[j:], encoding="utf-8")


def check_unique(products: list[Product]) -> None:
    for key in ("app_id", "hw_id"):
        seen: dict[str, str] = {}
        for p in products:
            v = getattr(p, key)
            if v in seen:
                raise SpecError(f"{p.name}: {key} {v} already used by {seen[v]}")
            seen[v] = p.name
    orders: dict[str, str] = {}
    for p in products:
        o = p.product["order_number"]
        if o in orders:
            raise SpecError(f"{p.name}: order number {o} already used by {orders[o]}")
        orders[o] = p.name


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="products (directory names); all when omitted")
    ap.add_argument("--check", action="store_true", help="compare with the committed xml/, write nothing")
    ap.add_argument("--zip", action="store_true", help="also write <name>/build/<name>.knxprod")
    ap.add_argument("--catalogue", action="store_true", help="rewrite the catalogue table in README.md")
    ap.add_argument("--signed-id", metavar="ID|FILE", help="record the signed application id of one product")
    args = ap.parse_args(argv)
    try:
        everything = [load(n) for n in all_names()]
        check_unique(everything)
        chosen = everything if not args.names else [load(n) for n in args.names]
        if args.signed_id and len(chosen) != 1:
            raise SpecError("--signed-id takes exactly one product name")
        stale = []
        for p in chosen:
            files = render(p)
            if args.check:
                if committed(p.name) != files:
                    stale.append(p.name)
                    continue
                signed = HERE / p.name / "signed.toml"
                if signed.exists():
                    rec = tomllib.loads(signed.read_text(encoding="utf-8"))
                    if rec.get("xml_sha256") != xml_digest(files):
                        stale.append(f"{p.name} (signed.toml)")
                continue
            write_xml(p, files)
            print(f"{p.name}: {p.app_id} ({len(files)} files)")
            if args.zip:
                print(f"  {write_zip(p, files).relative_to(HERE)}")
            if args.signed_id:
                print(f"  {record_signed(p, files, args.signed_id).relative_to(HERE)}")
        if args.catalogue:
            write_catalogue(everything)
            print("README.md catalogue:", len(everything), "products")
        if stale:
            print("stale, re-render or re-sign:", ", ".join(stale), file=sys.stderr)
            return 1
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
