# /// script
# requires-python = ">=3.11"
# ///
"""Unit tests of generate.py's rendering paths (epic #596, step 4).

    uv run tests-support/synthetic-products/test_generate.py

Each test renders a small spec in memory, so the tests need no product
directory and write nothing. One test class per construct a catalogue product
added to the generator.
"""
from __future__ import annotations

import copy
import sys
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate  # noqa: E402

BASE = tomllib.loads((HERE / "syn-minimal" / "product.toml").read_text(encoding="utf-8"))


def spec(**changes) -> dict:
    """syn-minimal's spec with the top-level tables in `changes` replaced."""
    s = copy.deepcopy(BASE)
    s.update(changes)
    return s


def app_xml(s: dict) -> str:
    p = generate.Product("test", s)
    return generate.render(p)[f"M-00FA/{p.app_file}"].decode("utf-8")


class ByteOrderAndFloat(unittest.TestCase):
    """syn-le-order (#403): ParameterByteOrder and the float type kind."""

    def test_render_float_types_and_byte_order(self) -> None:
        s = spec()
        s["application"]["options"]["ParameterByteOrder"] = "LittleEndian"
        s["parameter_type"] = s["parameter_type"] + [
            {"name": "F9", "kind": "float", "encoding": "DPT 9", "min": -671088.64, "max": 670433.28},
            {"name": "F32", "kind": "float", "encoding": "IEEE-754 Single", "min": -100, "max": 100}]
        s["parameter"] = s["parameter"] + [
            {"name": "a", "type": "F9", "text": "A", "default": 21.5,
             "memory": {"segment": "main", "offset": 3, "bit_offset": 0}},
            {"name": "b", "type": "F32", "text": "B", "default": 21.5,
             "memory": {"segment": "main", "offset": 5, "bit_offset": 0}}]
        xml = app_xml(s)
        self.assertIn('<TypeFloat Encoding="DPT 9" minInclusive="-671088.64" maxInclusive="670433.28" />', xml)
        self.assertIn('<TypeFloat Encoding="IEEE-754 Single" minInclusive="-100" maxInclusive="100" />', xml)
        self.assertIn('ParameterByteOrder="LittleEndian"', xml)
        self.assertIn('Value="21.5"', xml)

    def test_float_width_checked_against_segment(self) -> None:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [
            {"name": "F64", "kind": "float", "encoding": "IEEE-754 Double", "min": 0, "max": 1}]
        s["parameter"] = s["parameter"] + [
            {"name": "a", "type": "F64", "text": "A", "default": 0.5,
             "memory": {"segment": "main", "offset": 250, "bit_offset": 0}}]
        with self.assertRaisesRegex(generate.SpecError, "does not fit"):
            generate.Product("test", s)

    def test_float_unknown_encoding_refused(self) -> None:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [
            {"name": "F", "kind": "float", "encoding": "DPT 14", "min": 0, "max": 1}]
        with self.assertRaisesRegex(generate.SpecError, "encoding is one of"):
            generate.Product("test", s)


class Text(unittest.TestCase):
    """syn-text-undeclared (#416): the text type kind, sized in octets."""

    def test_render_text_type_non_ascii_default(self) -> None:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [{"name": "T", "kind": "text", "size_octets": 14}]
        s["parameter"] = s["parameter"] + [
            {"name": "t", "type": "T", "text": "T", "default": "Störung",
             "memory": {"segment": "main", "offset": 3, "bit_offset": 0}}]
        xml = app_xml(s)
        self.assertIn('<TypeText SizeInBit="112" />', xml)
        self.assertIn('Value="Störung"', xml)
        self.assertNotIn("TextParameterEncoding", xml)

    def test_text_width_checked_against_segment(self) -> None:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [{"name": "T", "kind": "text", "size_octets": 20}]
        s["parameter"] = s["parameter"] + [
            {"name": "t", "type": "T", "text": "T", "default": "x",
             "memory": {"segment": "main", "offset": 240, "bit_offset": 0}}]
        with self.assertRaisesRegex(generate.SpecError, "does not fit"):
            generate.Product("test", s)


class Union(unittest.TestCase):
    """syn-union-default-range (#405): `[[union]]`, union members and `access`."""

    def union_spec(self) -> dict:
        s = spec()
        s["union"] = [{"name": "u", "size_bits": 8, "default": "a",
                       "memory": {"segment": "main", "offset": 3, "bit_offset": 0}}]
        s["parameter"] = s["parameter"] + [
            {"name": "a", "type": "Mode", "text": "A", "access": "None", "default": 1,
             "union": {"name": "u", "offset": 0, "bit_offset": 0}},
            {"name": "b", "type": "Mode", "text": "B", "default": 0,
             "union": {"name": "u", "offset": 0, "bit_offset": 0}}]
        return s

    def test_render_union_members_and_access(self) -> None:
        xml = app_xml(self.union_spec())
        self.assertIn('<Union SizeInBit="8">', xml)
        self.assertIn('<Memory CodeSegment="M-00FA_A-2700-10-0000_RS-04-00000" Offset="3" BitOffset="0" />', xml)
        self.assertIn('Id="M-00FA_A-2700-10-0000_UP-3" Name="a" ParameterType="M-00FA_A-2700-10-0000_PT-Mode" '
                      'Offset="0" BitOffset="0" Text="A" Access="None" Value="1" DefaultUnionParameter="true" />', xml)
        self.assertIn('<ParameterRef Id="M-00FA_A-2700-10-0000_UP-4_R-4" RefId="M-00FA_A-2700-10-0000_UP-4" />', xml)

    def test_union_member_must_fit(self) -> None:
        s = self.union_spec()
        s["parameter"][-1]["union"]["offset"] = 1
        with self.assertRaisesRegex(generate.SpecError, "does not fit union"):
            generate.Product("test", s)

    def test_parameter_needs_memory_or_union(self) -> None:
        s = self.union_spec()
        s["parameter"][-1]["memory"] = {"segment": "main", "offset": 4, "bit_offset": 0}
        with self.assertRaisesRegex(generate.SpecError, "exactly one of"):
            generate.Product("test", s)


class HiddenParameter(unittest.TestCase):
    """syn-hidden-default (#448): a parameter no block references, over a filled segment."""

    def test_render_parameter_without_block(self) -> None:
        s = spec()
        s["parameter"] = s["parameter"] + [
            {"name": "h", "type": "Delay", "text": "H", "default": 4660,
             "memory": {"segment": "main", "offset": 3, "bit_offset": 0}}]
        xml = app_xml(s)
        self.assertIn('<ParameterRef Id="M-00FA_A-2700-10-0000_P-3_R-3" RefId="M-00FA_A-2700-10-0000_P-3" />', xml)
        self.assertNotIn('<ParameterRefRef RefId="M-00FA_A-2700-10-0000_P-3_R-3" />', xml)
        self.assertNotIn("DownloadInvisibleParameters", xml)
        # syn-minimal's segment template is fill 0xFF, unlike the default's octets.
        self.assertIn("<Data>////", xml)


if __name__ == "__main__":
    unittest.main()
