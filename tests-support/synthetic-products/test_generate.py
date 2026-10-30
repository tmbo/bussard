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


def product_spec(name: str) -> dict:
    """The committed spec of a catalogue product."""
    return tomllib.loads((HERE / name / "product.toml").read_text(encoding="utf-8"))


class System7(unittest.TestCase):
    """The System 7 rendering path (#604 rows 2 and 3)."""

    def setUp(self) -> None:
        self.s = product_spec("syn-s7-0705")

    def test_render_application_absolute_segments_and_table_locations(self) -> None:
        x = app_xml(self.s)
        app = "M-00FA_A-2800-10-0000"
        self.assertIn('MaskVersion="MV-0705"', x)
        self.assertIn('LoadProcedureStyle="ProductProcedure" PeiType="0"', x)
        self.assertIn(f'<AbsoluteSegment Id="{app}_AS-0700" Name="ram" MemoryType="RAM" Address="1792" '
                      'Size="16" />', x)
        self.assertIn(f'<AddressTable CodeSegment="{app}_AS-4000" Offset="0" MaxEntries="255" />', x)
        self.assertIn(f'<AssociationTable CodeSegment="{app}_AS-4201" Offset="0" MaxEntries="255" />', x)
        self.assertIn(f'<ComObjectTable CodeSegment="{app}_AS-4400" Offset="0">', x)
        self.assertIn(f'<Memory CodeSegment="{app}_AS-4440" Offset="1" BitOffset="0" />', x)
        self.assertIn("<LoadProcedure>\n", x)
        self.assertIn('<LdCtrlAbsSegment LsmIdx="3" SegType="1" Address="1808" Size="48" Access="0" '
                      'MemType="2" SegFlags="0" />', x)
        self.assertIn('<LdCtrlTaskCtrl1 LsmIdx="3" Address="17456" Count="1" />', x)

    def test_render_absolute_segment_data_then_fill(self) -> None:
        import base64
        import re
        x = app_xml(self.s)
        m = re.search(r'Name="application"[^>]*>\s*<Data>([^<]*)</Data>', x)
        self.assertIsNotNone(m)
        data = base64.b64decode(m.group(1))
        self.assertEqual(len(data), 64)
        self.assertEqual(data[:11].hex(), "0207000702170007034f00")
        self.assertEqual(set(data[11:]), {0xFF})

    def test_render_is_deterministic(self) -> None:
        self.assertEqual(app_xml(self.s), app_xml(copy.deepcopy(self.s)))

    def test_product_refuses_merge_id_in_a_product_procedure(self) -> None:
        self.s["load_procedure"][0]["merge_id"] = 1
        with self.assertRaisesRegex(generate.SpecError, "unknown key `merge_id`"):
            generate.Product("t", self.s)

    def test_product_refuses_a_relative_segment_on_system_7(self) -> None:
        self.s["segment"].append({"name": "r", "kind": "relative", "lsm": 4, "size": 8})
        with self.assertRaisesRegex(generate.SpecError, "absolute segments only"):
            generate.Product("t", self.s)

    def test_product_refuses_an_unknown_table_segment(self) -> None:
        self.s["application"]["address_table_segment"] = "nowhere"
        with self.assertRaisesRegex(generate.SpecError, "unknown segment `nowhere`"):
            generate.Product("t", self.s)

    def test_product_refuses_data_on_an_allocate_only_segment(self) -> None:
        self.s["segment"][0]["data"] = "00"
        with self.assertRaisesRegex(generate.SpecError, "allocate_only"):
            generate.Product("t", self.s)

    def test_product_refuses_system_7_ops_on_system_b(self) -> None:
        b = product_spec("syn-minimal")
        b["load_procedure"][0]["ops"].append({"op": "LdCtrlTaskSegment", "lsm": 1, "address": 0})
        with self.assertRaisesRegex(generate.SpecError, "no product uses it yet"):
            generate.Product("t", b)

    def test_product_refuses_system_7_keys_on_system_b(self) -> None:
        b = product_spec("syn-minimal")
        b["application"]["pei_type"] = 0
        with self.assertRaisesRegex(generate.SpecError, "belongs to a System 7 mask"):
            generate.Product("t", b)

    def test_product_refuses_merged_procedure_on_system_7(self) -> None:
        self.s["application"]["load_procedure_style"] = "MergedProcedure"
        with self.assertRaisesRegex(generate.SpecError, "no product uses it yet"):
            generate.Product("t", self.s)


class Schema(unittest.TestCase):
    """syn-s7-hidden-default-p11 (#448): `[application] schema = 11`."""

    def test_render_schema_11_namespace_and_min_ets_version(self) -> None:
        s = spec()
        s["application"]["schema"] = 11
        p = generate.Product("test", s)
        files = generate.render(p)
        for f in files.values():
            self.assertIn(b'<KNX xmlns="http://knx.org/xml/project/11">', f)
        self.assertIn('MinEtsVersion="4.0"', files[f"M-00FA/{p.app_file}"].decode("utf-8"))

    def test_render_schema_default_is_23(self) -> None:
        xml = app_xml(spec())
        self.assertIn('<KNX xmlns="http://knx.org/xml/project/23">', xml)
        self.assertIn('MinEtsVersion="6.0"', xml)

    def test_product_refuses_unknown_schema(self) -> None:
        s = spec()
        s["application"]["schema"] = 20
        with self.assertRaisesRegex(generate.SpecError, "schema is one of"):
            generate.Product("t", s)


class MasterReset(unittest.TestCase):
    """syn-master-reset (#546, #611): LdCtrlMasterReset in the application's procedure."""

    def test_render_master_reset_after_rel_segment(self) -> None:
        s = spec()
        s["load_procedure"][0]["ops"].append({"op": "LdCtrlMasterReset", "erase_code": 4, "channel": 0})
        self.assertIn('<LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0" Fill="0" />\n'
                      '                <LdCtrlMasterReset EraseCode="4" ChannelNumber="0" />', app_xml(s))

    def test_master_reset_missing_channel_refused(self) -> None:
        s = spec()
        s["load_procedure"][0]["ops"].append({"op": "LdCtrlMasterReset", "erase_code": 1})
        with self.assertRaisesRegex(generate.SpecError, "missing key `channel`"):
            generate.Product("test", s)


class LoadProcedureChoose(unittest.TestCase):
    """syn-choose-partial-segment (#411): `<choose>` inside a LoadProcedure."""

    HALF = {"op": "LdCtrlWriteRelMem", "object": 4, "offset": 0, "size": 128, "verify": False}

    def choose(self, parameter: str, when: list) -> dict:
        s = spec()
        s["load_procedure"][1]["ops"] = [{"op": "choose", "parameter": parameter, "when": when}]
        return s

    def test_render_choose_with_test_and_default(self) -> None:
        s = self.choose("mode", [{"test": "1", "ops": [self.HALF]},
                                 {"default": True, "ops": [dict(self.HALF, size=256)]}])
        xml = app_xml(s)
        self.assertIn('<choose ParamRefId="M-00FA_A-2700-10-0000_P-1_R-1">', xml)
        self.assertIn('<when test="1">\n'
                      '                    <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="128" Verify="false" />\n'
                      '                  </when>\n'
                      '                  <when default="true">', xml)

    def test_choose_branch_needs_test_or_default(self) -> None:
        with self.assertRaisesRegex(generate.SpecError, "either `test` or `default = true`"):
            generate.Product("test", self.choose("mode", [{"ops": []}]))

    def test_choose_unknown_parameter_refused(self) -> None:
        with self.assertRaisesRegex(generate.SpecError, "unknown parameter `nope`"):
            generate.Product("test", self.choose("nope", [{"test": "1", "ops": []}]))


class DynamicChoose(unittest.TestCase):
    """syn-choose-never-shown (#474): a virtual parameter and a `<choose>` in
    the Dynamic tree whose default branch shows a block."""

    def choose_spec(self) -> dict:
        s = spec()
        s["parameter"] = s["parameter"] + [
            {"name": "steer", "type": "Mode", "text": "Steer", "default": 0, "virtual": True}]
        s["dynamic"] = dict(s["dynamic"], choose=[{"parameter": "steer", "when": [
            {"default": True, "block": [{"name": "b", "text": "B", "parameters": ["delay"],
                                         "com_objects": [1]}]}]}])
        return s

    def test_render_virtual_parameter_and_dynamic_choose(self) -> None:
        xml = app_xml(self.choose_spec())
        self.assertIn('<Parameter Id="M-00FA_A-2700-10-0000_P-3" Name="steer" '
                      'ParameterType="M-00FA_A-2700-10-0000_PT-Mode" Text="Steer" Value="0" />', xml)
        self.assertIn('              </ParameterBlock>\n'
                      '              <choose ParamRefId="M-00FA_A-2700-10-0000_P-3_R-3">\n'
                      '                <when default="true">\n'
                      '                  <ParameterBlock Id="M-00FA_A-2700-10-0000_PB-2" Name="b" Text="B">\n'
                      '                    <ParameterRefRef RefId="M-00FA_A-2700-10-0000_P-2_R-2" />\n'
                      '                    <ComObjectRefRef RefId="M-00FA_A-2700-10-0000_O-1_R-2" />\n'
                      '                  </ParameterBlock>\n'
                      '                </when>\n'
                      '              </choose>\n'
                      '            </ChannelIndependentBlock>', xml)

    def test_virtual_parameter_with_memory_refused(self) -> None:
        s = self.choose_spec()
        s["parameter"][-1]["memory"] = {"segment": "main", "offset": 4, "bit_offset": 0}
        with self.assertRaisesRegex(generate.SpecError, "virtual parameter has no `memory`"):
            generate.Product("test", s)

    def test_dynamic_choose_branch_needs_test_or_default(self) -> None:
        s = self.choose_spec()
        s["dynamic"]["choose"][0]["when"][0]["test"] = "1"
        with self.assertRaisesRegex(generate.SpecError, "either `test` or `default = true`"):
            generate.Product("test", s)

    def test_dynamic_choose_unknown_parameter_refused(self) -> None:
        s = self.choose_spec()
        s["dynamic"]["choose"][0]["parameter"] = "nope"
        with self.assertRaisesRegex(generate.SpecError, "unknown parameter `nope`"):
            generate.Product("test", s)


class ParameterCalculation(unittest.TestCase):
    """syn-param-calculation (#427, #450): an inline JavaScript calculation and
    a LegacyPatchAlways parameter."""

    def calc_spec(self, **calc) -> dict:
        s = spec()
        s["parameter"] = s["parameter"] + [
            {"name": "out", "type": "Delay", "text": "Out", "default": 0, "legacy_patch_always": True,
             "memory": {"segment": "main", "offset": 3, "bit_offset": 0}}]
        c = {"name": "c", "language": "JavaScript", "inputs": [{"parameter": "delay", "alias": "d"}],
             "outputs": [{"parameter": "out", "alias": "o"}], "lr_script": "o = d < 2 && d > 0;",
             "rl_script": "1"}
        c.update(calc)
        s["parameter_calculation"] = [c]
        return s

    def test_render_calculation_after_parameter_refs(self) -> None:
        xml = app_xml(self.calc_spec())
        self.assertIn('Value="0" LegacyPatchAlways="true">', xml)
        self.assertIn('            </ParameterRefs>\n'
                      '            <ParameterCalculations>\n'
                      '              <ParameterCalculation Id="M-00FA_A-2700-10-0000_PC-1" Name="c" Language="JavaScript">\n'
                      '                <RLTransformation>1</RLTransformation>\n'
                      '                <LRTransformation>o = d &lt; 2 &amp;&amp; d &gt; 0;</LRTransformation>\n'
                      '                <LParameters>\n'
                      '                  <ParameterRefRef RefId="M-00FA_A-2700-10-0000_P-2_R-2" AliasName="d" />\n'
                      '                </LParameters>\n'
                      '                <RParameters>\n'
                      '                  <ParameterRefRef RefId="M-00FA_A-2700-10-0000_P-3_R-3" AliasName="o" />\n'
                      '                </RParameters>\n'
                      '              </ParameterCalculation>\n'
                      '            </ParameterCalculations>\n'
                      '            <ComObjectTable>', xml)

    def test_no_calculation_renders_nothing(self) -> None:
        self.assertNotIn("ParameterCalculations", app_xml(spec()))

    def test_calculation_vbscript_not_yet(self) -> None:
        with self.assertRaisesRegex(generate.SpecError, "no product uses it yet"):
            generate.Product("test", self.calc_spec(language="VBScript"))

    def test_calculation_unknown_parameter_refused(self) -> None:
        with self.assertRaisesRegex(generate.SpecError, "unknown parameter `nope`"):
            generate.Product("test", self.calc_spec(outputs=[{"parameter": "nope", "alias": "o"}]))


class System7Choose(unittest.TestCase):
    """syn-s7-choose-split (#411, #413): a `choose` of AbsSegments in a product procedure."""

    def test_render_choose_with_abs_segments_on_system_7(self) -> None:
        x = app_xml(product_spec("syn-s7-choose-split"))
        self.assertIn('<choose ParamRefId="M-00FA_A-2809-10-0000_P-1_R-1">\n'
                      '                  <when test="1">\n'
                      '                    <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="17472" Size="1" '
                      'Access="51" MemType="3" SegFlags="128" />\n'
                      '                    <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="17475" Size="61" ', x)
        self.assertIn('<when default="true">\n'
                      '                    <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="17472" Size="64" ', x)


class TaskPtrAndTaskCtrl2(unittest.TestCase):
    """syn-s7-taskptr (#527): LdCtrlTaskPtr and LdCtrlTaskCtrl2 on System 7."""

    def test_render_task_ptr_and_task_ctrl2(self) -> None:
        s = product_spec("syn-s7-0705")
        s["load_procedure"][0]["ops"][-3:-3] = [
            {"op": "LdCtrlTaskPtr", "lsm": 3, "init_ptr": 0x4410, "save_ptr": 0x4414, "serial_ptr": 0x4418},
            {"op": "LdCtrlTaskCtrl2", "lsm": 3, "callback": 0x441C, "address": 0x4400, "seg0": 0x0700,
             "seg1": 0x4440}]
        x = app_xml(s)
        self.assertIn('<LdCtrlTaskPtr LsmIdx="3" InitPtr="17424" SavePtr="17428" SerialPtr="17432" />', x)
        self.assertIn('<LdCtrlTaskCtrl2 LsmIdx="3" Callback="17436" Address="17408" Seg0="1792" Seg1="17472" />', x)

    def test_task_ptr_refused_on_system_b(self) -> None:
        b = product_spec("syn-minimal")
        b["load_procedure"][0]["ops"].append(
            {"op": "LdCtrlTaskPtr", "lsm": 3, "init_ptr": 0, "save_ptr": 0, "serial_ptr": 0})
        with self.assertRaisesRegex(generate.SpecError, "no product uses it yet"):
            generate.Product("t", b)

    def test_task_ctrl2_missing_key_refused(self) -> None:
        s = product_spec("syn-s7-0705")
        s["load_procedure"][0]["ops"].append({"op": "LdCtrlTaskCtrl2", "lsm": 3, "callback": 0, "address": 0,
                                              "seg0": 0})
        with self.assertRaisesRegex(generate.SpecError, "missing key `seg1`"):
            generate.Product("t", s)


class BitFields(unittest.TestCase):
    """syn-union-bitfields (#604 row 29): a union of two member types and
    sub-octet parameters packed into one octet by BitOffset."""

    def bits_spec(self) -> dict:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [
            {"name": "Three", "kind": "number", "size_bits": 3, "signed": False, "min": 0, "max": 7},
            {"name": "Nibble", "kind": "number", "size_bits": 4, "signed": False, "min": 0, "max": 15}]
        s["union"] = [{"name": "u", "size_bits": 16, "default": "wide",
                       "memory": {"segment": "main", "offset": 3, "bit_offset": 0}}]
        s["parameter"] = s["parameter"] + [
            {"name": "wide", "type": "Delay", "text": "W", "default": 2571,
             "union": {"name": "u", "offset": 0, "bit_offset": 0}},
            {"name": "narrow", "type": "Nibble", "text": "N", "default": 6,
             "union": {"name": "u", "offset": 1, "bit_offset": 4}},
            {"name": "three", "type": "Three", "text": "T", "default": 5,
             "memory": {"segment": "main", "offset": 5, "bit_offset": 1}},
            {"name": "nibble", "type": "Nibble", "text": "Q", "default": 6,
             "memory": {"segment": "main", "offset": 5, "bit_offset": 4}}]
        return s

    def test_render_union_of_two_types_and_bit_fields(self) -> None:
        xml = app_xml(self.bits_spec())
        self.assertIn('<Union SizeInBit="16">', xml)
        self.assertIn('ParameterType="M-00FA_A-2700-10-0000_PT-Delay" Offset="0" BitOffset="0" Text="W" '
                      'Value="2571" DefaultUnionParameter="true" />', xml)
        self.assertIn('ParameterType="M-00FA_A-2700-10-0000_PT-Nibble" Offset="1" BitOffset="4" Text="N" '
                      'Value="6" />', xml)
        self.assertIn('<TypeNumber SizeInBit="3" Type="unsignedInt" minInclusive="0" maxInclusive="7" />', xml)
        self.assertIn('<Memory CodeSegment="M-00FA_A-2700-10-0000_RS-04-00000" Offset="5" BitOffset="1" />', xml)
        self.assertIn('<Memory CodeSegment="M-00FA_A-2700-10-0000_RS-04-00000" Offset="5" BitOffset="4" />', xml)

    def test_bit_offset_beyond_the_octet_refused(self) -> None:
        s = self.bits_spec()
        s["parameter"][-1]["memory"] = {"segment": "main", "offset": 5, "bit_offset": 8}
        with self.assertRaisesRegex(generate.SpecError, "bit_offset is 0 to 7"):
            generate.Product("test", s)

    def test_union_member_bit_offset_beyond_the_octet_refused(self) -> None:
        s = self.bits_spec()
        s["parameter"][3]["union"] = {"name": "u", "offset": 0, "bit_offset": 9}
        with self.assertRaisesRegex(generate.SpecError, "bit_offset is 0 to 7"):
            generate.Product("test", s)


class IpAddress(unittest.TestCase):
    """syn-ip-address-param (#457): the `ip_address` type kind, 32 bits in memory."""

    def ip_spec(self, offset: int = 3) -> dict:
        s = spec()
        s["parameter_type"] = s["parameter_type"] + [
            {"name": "Ip", "kind": "ip_address", "address_type": "HostAddress"}]
        s["parameter"] = s["parameter"] + [
            {"name": "ip", "type": "Ip", "text": "IP", "default": "192.168.27.21",
             "memory": {"segment": "main", "offset": offset, "bit_offset": 0}}]
        return s

    def test_render_ip_address_type(self) -> None:
        xml = app_xml(self.ip_spec())
        self.assertIn('<TypeIPAddress AddressType="HostAddress" />', xml)
        self.assertIn('Text="IP" Value="192.168.27.21">', xml)

    def test_ip_address_width_checked_against_segment(self) -> None:
        with self.assertRaisesRegex(generate.SpecError, "does not fit"):
            generate.Product("test", self.ip_spec(offset=253))

    def test_ip_address_unknown_address_type_refused(self) -> None:
        s = self.ip_spec()
        s["parameter_type"][-1]["address_type"] = "Gateway"
        with self.assertRaisesRegex(generate.SpecError, "address_type is one of"):
            generate.Product("test", s)


class ParameterRefPerChoose(unittest.TestCase):
    """syn-choose-per-ref (#563): a second ParameterRef of a parameter, a
    `<when test>` branch, and a choose on the second ref."""

    def per_ref_spec(self) -> dict:
        s = spec(parameter_ref=[{"name": "mode_twin", "parameter": "mode"}])
        s["dynamic"] = dict(s["dynamic"], choose=[
            {"parameter": "mode", "when": [
                {"test": "0", "block": [{"name": "t", "text": "T", "parameters": ["mode_twin"], "com_objects": []}]}]},
            {"parameter": "mode_twin", "when": [
                {"default": True, "block": [{"name": "d", "text": "D", "parameters": [], "com_objects": [1]}]}]}])
        return s

    def test_render_second_ref_and_test_branch(self) -> None:
        xml = app_xml(self.per_ref_spec())
        self.assertIn('<ParameterRef Id="M-00FA_A-2700-10-0000_P-2_R-2" RefId="M-00FA_A-2700-10-0000_P-2" />\n'
                      '              <ParameterRef Id="M-00FA_A-2700-10-0000_P-1_R-3" '
                      'RefId="M-00FA_A-2700-10-0000_P-1" />\n            </ParameterRefs>', xml)
        self.assertIn('<choose ParamRefId="M-00FA_A-2700-10-0000_P-1_R-1">\n'
                      '                <when test="0">\n'
                      '                  <ParameterBlock Id="M-00FA_A-2700-10-0000_PB-2" Name="t" Text="T">\n'
                      '                    <ParameterRefRef RefId="M-00FA_A-2700-10-0000_P-1_R-3" />', xml)
        self.assertIn('<choose ParamRefId="M-00FA_A-2700-10-0000_P-1_R-3">\n'
                      '                <when default="true">', xml)

    def test_parameter_ref_unknown_parameter_refused(self) -> None:
        s = self.per_ref_spec()
        s["parameter_ref"][0]["parameter"] = "nope"
        with self.assertRaisesRegex(generate.SpecError, "unknown parameter `nope`"):
            generate.Product("test", s)

    def test_parameter_ref_name_clash_refused(self) -> None:
        s = self.per_ref_spec()
        s["parameter_ref"][0]["name"] = "delay"
        with self.assertRaisesRegex(generate.SpecError, "already a parameter or a ref"):
            generate.Product("test", s)


if __name__ == "__main__":
    unittest.main()
