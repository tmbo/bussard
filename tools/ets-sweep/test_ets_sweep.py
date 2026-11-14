# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Offline tests of the ETS sweep's Mac-side tooling (no VM, no ETS, no bus).

    uv run tools/ets-sweep/test_ets_sweep.py [-v]
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_rows  # noqa: E402
import defaults  # noqa: E402
import followups  # noqa: E402
import links_subset  # noqa: E402
import secure_subset  # noqa: E402
import nightly  # noqa: E402
import oracle  # noqa: E402
import oracle_model  # noqa: E402
import params  # noqa: E402
import params_subset  # noqa: E402
import secure  # noqa: E402
import series  # noqa: E402
import summary  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent / "synthetic"))
import calibrate  # noqa: E402
import distil  # noqa: E402
import importlib.util  # noqa: E402

# `capture` by path: another module of that name can sit earlier on sys.path.
_spec = importlib.util.spec_from_file_location(
    "synthetic_capture", Path(__file__).resolve().parent / "synthetic" / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


class TestParams(unittest.TestCase):
    MODEL = {"parameters": {
        "P-2": {"kind": {"Int": {"min": 0, "max": 255, "signed": False}}, "default": "1", "text": "Zyklus"},
        "P-3": {"kind": {"Float": {"min": 13917383856470496379, "max": 4694006190116186358}}, "text": "Wert"},
        "P-6": {"kind": {"Int": {"min": 1, "max": 10}}, "default": "1", "text": "Zyklus"},
        "P-7": {"kind": {"Enum": {"values": [0, 1]}}, "text": "Raumtemperaturregler Funktion"},
        "P-8": {"kind": {"Enum": {"values": [0, 1]}}, "text": "Ausgangskontakt"},
        "P-10": {"kind": {"Int": {"min": 0, "max": 1}}, "text": "Zwangssteuerung"},
        "P-11": {"kind": {"Int": {"min": 0, "max": 1}}, "text": "Szene"},
        "P-12": {"kind": {"Text": {"len": 14}}, "text": "Name"},
        "P-13": {"kind": {"Int": {"min": 0, "max": 1}}, "text": "Priorität"},
        # A number field whose label only an enumeration has: no change.
        "P-14": {"kind": {"Enum": {"values": [0, 1]}}, "text": "Unbekannt"},
    }}
    MODEL["parameter_refs"] = {f"{pid}_R-1": {"parameter": pid} for pid in MODEL["parameters"]}
    DEVICE = {"blocks": [
        {"text": "Kühlung", "inactive": {"enable": [{"reference": "P-95_R-138", "text": "Raumtemperaturregler Funktion",
                                                      "set_to": "Kühlung", "default": "Heizung"}]}},
        {"text": "Lüftung", "inactive": {"enable": [{"reference": "P-9_R-9", "text": "VentilationEnabled",
                                                      "set_to": ">0", "default": "0"}]}},
        {"text": "- A1: Zwangssteuerung", "inactive": {"enable": [{"reference": "P-27_R-36", "text": "Zwangssteuerung",
                                                                    "set_to": "1", "default": "0"}]}},
        {"text": "Allgemein", "active": True},
    ]}
    # A survey as the driver's param_pages flow returns it (rows=True).
    SURVEY = [
        {"crumb": "Allgemein", "page": "Allgemein", "rows": [
            {"label": "Raumtemperaturregler Funktion", "n": 0, "kind": "dropdown", "value": "Heizung"},
            {"label": "Zyklus", "n": 0, "kind": "number", "value": "5"},
            {"label": "Hinweis", "n": 0, "kind": "none", "value": "Bitte beachten"},
            {"label": "Name", "n": 0, "kind": "text", "value": ""},
        ]},
        {"crumb": "Ausgang 1 > Ausgang 1: Funktionsfreigabe", "page": "Ausgang 1: Funktionsfreigabe", "rows": [
            {"label": "Ausgangskontakt", "n": 0, "kind": "radio", "value": "Schließer",
             "options": [{"text": "Schließer"}, {"text": "Öffner"}]},
            {"label": "Zwangssteuerung", "n": 0, "kind": "checkbox", "value": "0"},
            {"label": "Szene", "n": 0, "kind": "checkbox", "value": "0"},
            {"label": "Einzig", "n": 0, "kind": "radio", "value": "a", "options": [{"text": "a"}]},
            {"label": "Unbekannt", "n": 0, "kind": "number", "value": "3"},
        ]},
    ]

    def test_visible_enablers_skip_conditions(self):
        self.assertEqual([(e["text"], e["value"]) for e in params.visible_enablers(self.DEVICE)],
                         [("Raumtemperaturregler Funktion", "Kühlung"), ("Zwangssteuerung", "1")])

    def test_fits_model_skips_rows_no_parameter_type_shows(self):
        kinds = params.label_kinds({"parameters": {
            "a": {"kind": {"Int": {"min": 0, "max": 255}}, "text": "volle Bandbreite Dimmzeit"},
            "b": {"kind": "None", "text": "Herunterladen"},
            "c": {"kind": {"Text": {"len": 14}}, "text": "Name"},
            "d": {"kind": {"Enum": {"values": [0, 1]}}, "text": "Sperrobjekt"}},
            "parameter_refs": {"a_R": {"parameter": "a"}, "b_R": {"parameter": "b"}, "c_R": {"parameter": "c"},
                               # The reference's own wording is what ETS shows.
                               "d_R": {"parameter": "d", "text": "Sperrobjekt Kanal A"}}})
        row = lambda label, kind: {"label": label, "kind": kind}
        self.assertFalse(params.fits_model(row("volle Bandbreite Dimmzeit", "text"), kinds))
        self.assertTrue(params.fits_model(row("volle Bandbreite Dimmzeit", "number"), kinds))
        self.assertFalse(params.fits_model(row("Herunterladen", "dropdown"), kinds))
        self.assertTrue(params.fits_model(row("Name", "text"), kinds))
        self.assertFalse(params.fits_model(row("Unbekannt", "checkbox"), kinds))
        self.assertTrue(params.fits_model(row("Sperrobjekt Kanal A", "dropdown"), kinds))
        # An OCR slip in the label still finds it.
        self.assertTrue(params.fits_model(row("Sperrobjekt Kanal Ä", "dropdown"), kinds))

    def test_number_ranges_shared_range_and_no_encoded_floats(self):
        ranges = params.number_ranges(self.MODEL)
        self.assertEqual(ranges["zyklus"], (1, 10, "Int"))
        self.assertNotIn("wert", ranges)

    def test_survey_rows_settable_with_options(self):
        labels = [r["label"] for r in params.survey_rows(self.SURVEY)]
        self.assertEqual(labels, ["Raumtemperaturregler Funktion", "Zyklus", "Name", "Ausgangskontakt",
                                  "Zwangssteuerung", "Szene", "Unbekannt"])

    def test_generate_deterministic_switches_first_values_off_default(self):
        enablers = params.visible_enablers(self.DEVICE)
        a = params.generate(self.SURVEY, seed=7, index=0, changes=6, model=self.MODEL, enablers=enablers)
        self.assertEqual(a, params.generate(self.SURVEY, seed=7, index=0, changes=6, model=self.MODEL,
                                            enablers=enablers))
        self.assertNotEqual(a, params.generate(self.SURVEY, seed=7, index=1, changes=6, model=self.MODEL,
                                               enablers=enablers))
        changes = a["changes"]
        switches = [c for c in changes if c.get("switch")]
        self.assertEqual(len(switches), 2)
        self.assertEqual(changes[:2], switches)
        self.assertEqual({(c["label"], c["value"]) for c in switches},
                         {("Raumtemperaturregler Funktion", "Kühlung"), ("Zwangssteuerung", "1")})
        by_label = {c["label"]: c for c in changes}
        # 'Unbekannt' is a number field the model has no number for: never chosen.
        self.assertNotIn("Unbekannt", by_label)
        if "Zyklus" in by_label:
            self.assertIn(int(by_label["Zyklus"]["value"]), range(1, 11))
            self.assertNotEqual(by_label["Zyklus"]["value"], "5")
        if "Szene" in by_label:
            self.assertEqual(by_label["Szene"]["value"], "1")
        if "Ausgangskontakt" in by_label:
            self.assertTrue(0 <= by_label["Ausgangskontakt"]["pick"] < 1)
        self.assertEqual(params.variant_name(7, 2), "params-7-2")

    def test_dependent_changes_only_on_new_pages(self):
        after = self.SURVEY + [{"crumb": "Ausgang 1 > - A1: Zwangssteuerung", "page": "- A1: Zwangssteuerung",
                                "rows": [{"label": "Priorität", "n": 0, "kind": "checkbox", "value": "0"}]}]
        more = params.dependent_changes(self.SURVEY, after, 1, 0, self.MODEL)
        self.assertEqual([(c["label"], c["value"], c["dependent"]) for c in more], [("Priorität", "1", True)])

    def test_partial_change_skips_switches(self):
        enablers = params.visible_enablers(self.DEVICE)
        c = params.partial_change(self.SURVEY, enablers)
        self.assertEqual((c["label"], c["value"]), ("Zyklus", "6"))

    def test_apply_hook_records_set_unreachable_failed(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        calls = []

        def flow(name, **body):
            calls.append(name)
            if name == "param_pages":
                return {"pages": self.SURVEY}
            if name == "ensure_layout":
                return {}
            if body["label"] == "Szene":
                raise RuntimeError("set_param: the dropdown opened no list")
            if body["label"] == "Zwangssteuerung":
                return {"set": False, "unreachable": "no row 'Zwangssteuerung' on the page"}
            return {"set": True, "value": body.get("value"), "row": {"value": body.get("value")}}

        with unittest.mock.patch.object(params, "SURVEYS", tmp / "surveys"):
            summary_ = params.apply_hook("M-X", 3, 0, 6, self.MODEL, params.visible_enablers(self.DEVICE))(flow, tmp)
        saved = json.loads((tmp / "params.json").read_text())
        results = {c["label"]: c["result"] for c in saved["changes"]}
        self.assertEqual(results["Zwangssteuerung"], "unreachable")
        self.assertEqual(results.get("Szene", "failed"), "failed")
        self.assertEqual(summary_["unreachable"], 1)
        self.assertEqual(sum(summary_.values()), len(saved["changes"]))
        self.assertEqual(calls[-1], "ensure_layout")
        self.assertTrue((tmp / "surveys" / "M-X.json").exists())


class TestParamsModel(unittest.TestCase):
    """The model a parameter-set row is compared with, from what ETS showed
    (#424): a label on a page and channel names one reference."""
    MODEL = {
        "parameters": {
            "P-1": {"kind": {"Int": {"min": 0, "max": 23}}, "text": "      Sendeverzögerung\r\n      nach Buswiederkehr"},
            "P-2": {"kind": {"Int": {"min": 0, "max": 59}}, "text": "Sendeverzögerung nach Buswiederkehr"},
            "P-3": {"kind": {"Enum": {"values": [0, 1, 2]}}, "text": "Preset",
                    "labels": [[0, "Inaktiv"], [1, "1 Presetobjekt"], [2, "2 Presetobjekten"]]},
            "P-4": {"kind": {"Int": {"min": 0, "max": 1}}, "text": "Zwangssteuerung"},
        },
        "parameter_refs": {"P-1_R-1": {"parameter": "P-1"}, "P-2_R-2": {"parameter": "P-2"},
                           "P-3_R-31": {"parameter": "P-3"}, "P-3_R-39": {"parameter": "P-3"},
                           "P-4_R-41": {"parameter": "P-4"}, "P-4_R-49": {"parameter": "P-4"}},
        "dynamic": [
            {"block": {"text": "Ausgänge 1-16: Allgemein", "nodes": [
                {"block": {"text": "- A1-16: Statusanzeigen schalten", "nodes": [
                    {"choose": {"ref": "x", "when": [{"nodes": [{"p": "P-1_R-1"}, {"p": "P-2_R-2"}]}]}}]}}]}},
            {"channel": {"text": "Ausgang 1", "nodes": [{"block": {"text": "Ausgang 1: Funktionsfreigabe", "nodes": [
                {"p": "P-3_R-31"}, {"p": "P-4_R-41"}]}}]}},
            {"channel": {"text": "Ausgang 9", "nodes": [{"block": {"text": "Ausgang 9: Funktionsfreigabe", "nodes": [
                {"p": "P-3_R-39"}, {"p": "P-4_R-49"}]}}]}},
        ],
    }
    FINAL = [
        {"crumb": "- Al-16: Statusanzeigen schalten", "page": "- Al-16: Statusanzeigen sch...", "rows": [
            {"label": "Sendeverzögerung nach Buswiederkehr", "kind": "number", "value": "1"},
            {"label": "Sendeverzögerung nach Buswiederkehr", "kind": "number", "value": "0"}]},
        {"crumb": "Ausgang 9 > Ausgang 9: Funktionsfreigabe", "page": "Ausgang 9: Funktionsfreigabe", "rows": [
            {"label": "Preset", "kind": "dropdown", "value": "2 Presetobjekten"},
            {"label": "Zwangssteuerung", "kind": "checkbox", "value": "1"}]},
    ]

    def change(self, crumb, label, kind, shown, n=0):
        return {"page": {"crumb": crumb, "page": crumb.rsplit(">", 1)[-1].strip()}, "label": label, "n": n,
                "kind": kind, "result": "set", "shown": shown, "set_to": shown}

    def test_model_changes_maps_channel_page_and_occurrence(self):
        done = [self.change("- Al-16: Statusanzeigen schalten", "Sendeverzögerung nach Buswiederkehr", "number", "1"),
                self.change("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Preset", "dropdown", "2 Presetobjekten"),
                self.change("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Zwangssteuerung", "checkbox", "1"),
                {**self.change("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Szene", "checkbox", "1"),
                 "result": "unreachable"}]
        values, problems = params.model_changes(self.MODEL, self.FINAL, done)
        self.assertEqual(problems, [])
        self.assertEqual(values, {"param@P-1_R-1": "1", "param@P-3_R-39": "2", "param@P-4_R-49": "1"})
        self.assertIn('"param@P-3_R-39" = "2"', params.device_toml_with(values))

    def test_model_changes_refuses_a_label_the_tree_lists_more_often(self):
        final = [{"crumb": "- Al-16: Statusanzeigen schalten", "rows": [
            {"label": "Sendeverzögerung nach Buswiederkehr", "kind": "number", "value": "1"}]}]
        done = [self.change("- Al-16: Statusanzeigen schalten", "Sendeverzögerung nach Buswiederkehr", "number", "1")]
        values, problems = params.model_changes(self.MODEL, final, done)
        self.assertEqual(values, {})
        self.assertIn("2 references", problems[0])

    def test_model_changes_asks_the_evaluator_between_branches(self):
        # Two references of one label on the page (a choose's branches), ETS
        # shows one row: the evaluator's shown reference is taken; at the
        # default nothing is stored.
        final = [{"crumb": "- Al-16: Statusanzeigen schalten", "rows": [
            {"label": "Sendeverzögerung nach Buswiederkehr", "kind": "number", "value": "7"}]}]
        done = [self.change("- Al-16: Statusanzeigen schalten", "Sendeverzögerung nach Buswiederkehr", "number", "7")]
        asked = []

        def shown(values):
            asked.append(dict(values))
            return {"P-2_R-2"}
        values, problems = params.model_changes(self.MODEL, final, done, shown)
        self.assertEqual((values, problems), ({"param@P-2_R-2": "7"}, []))
        self.assertEqual(asked, [{"param@P-1_R-1": "7", "param@P-2_R-2": "7"}])
        model = json.loads(json.dumps(self.MODEL))
        model["parameters"]["P-1"]["default"] = model["parameters"]["P-2"]["default"] = "7"
        self.assertEqual(params.model_changes(model, final, done, shown), ({}, []))

    def test_float_values_in_the_locale_ets_shows(self):
        model = {"parameters": {"P-9": {"kind": {"Float": {"min": 0.5, "max": 2.5}}, "text": "Faktor"}},
                 "parameter_refs": {"P-9_R-9": {"parameter": "P-9"}}}
        row = {"page": {"crumb": "A", "page": "A"}, "label": "Faktor", "n": 0, "kind": "number", "before": "1,5"}
        import random
        for seed in range(20):
            c = params.change_for(row, random.Random(seed), params.number_ranges(model), "t")
            self.assertNotIn(".", c["value"], c)
            self.assertNotEqual(c["value"], "1,5")
        self.assertEqual(params.value_of(model, "P-9_R-9", {"kind": "number", "shown": "2,5"}), "2.5")

    MODULE_MODEL = {
        "parameters": {"MD-2_P-32": {"kind": {"Enum": {"values": [0, 1, 2]}}, "text": "    Wert Kontakt geöffnet",
                                     "labels": [[0, "Aus"], [1, "Ein"], [2, "nicht aktiv"]], "is_virtual": True}},
        "parameter_refs": {"MD-2_P-32_R-50": {"parameter": "MD-2_P-32"}},
        "dynamic": [{"channel": {"text": "Eingänge A-P", "nodes": [
            {"module": {"id": "MD-2_M-2", "def": "MD-2"}}, {"module": {"id": "MD-2_M-3", "def": "MD-2"}}]}}],
        "module_dynamics": {"MD-2": [{"block": {"text": "Eingang {{ChNo}}: {{0}}", "nodes": [{"p": "MD-2_P-32_R-50"}]}}]},
    }

    def test_ref_places_walk_module_instances_in_device_form(self):
        places = params.ref_places(self.MODULE_MODEL)
        self.assertEqual([(p["ref"], p["instance"], p["channel"]) for p in places],
                         [("MD-2_M-2_MI-1_P-32_R-50", "MD-2_M-2_MI-1", "Eingänge A-P"),
                          ("MD-2_M-3_MI-1_P-32_R-50", "MD-2_M-3_MI-1", "Eingänge A-P")])
        self.assertEqual(params.model_ref("MD-2_M-3_P-32_R-50"), "MD-2_P-32_R-50")
        self.assertEqual(params.device_ref("MD-2_M-3", "MD-2_P-32_R-50"), "MD-2_M-3_P-32_R-50")
        self.assertTrue(params.page_matches("Eingang {{ChNo}}: {{0}}", "Eingang B:"))
        self.assertFalse(params.page_matches("Eingang {{ChNo}}: {{0}}", "Ausgang B:"))

    def test_model_changes_picks_the_module_instance_by_page_order(self):
        # Two instances show the label; the change is on the second
        # instance's page ('Eingang B:'), so the second instance's ref is
        # stored, with the virtual parameter's value (it feeds calculations).
        order = [{"crumb": "Eingänge A-P > Eingang A:", "page": "Eingang A:"},
                 {"crumb": "Eingänge A-P > Eingang B:", "page": "Eingang B:"}]
        done = [{"page": order[1], "label": "Wert Kontakt geöffnet", "n": 0, "kind": "dropdown", "result": "set",
                 "shown": "nicht aktiv", "set_to": "nicht aktiv", "rows_with_label": 1}]
        values, problems = params.model_changes(self.MODULE_MODEL, [], done,
                                                lambda v: {r.split("@")[1] for r in v}, [[], order])
        self.assertEqual((values, problems), ({"param@MD-2_M-3_MI-1_P-32_R-50": "2"}, []))

    def test_summary_verdict_reads_the_table_line_not_the_heading(self):
        out = ("1.1.1  (ETS partial download after Sendeverzögerung set to 1)\n"
               "  knx-sim on 127.0.0.1:5\n"
               "device    system verdict ...\n"
               "1.1.1     apply  not-comparable  0.0% (100)  -  props=ok(2935)  loadctl=ok(4)\n")
        self.assertEqual(params.summary_verdict(out, "1.1.1")["verdict"], "not-comparable")
        self.assertEqual(params.summary_verdict("1.1.1  (note)", "1.1.1")["verdict"], "oracle-error")

    def test_checked_verdict_follows_the_exit_code(self):
        found = {"verdict": "identical", "summary": "1.1.1 apply identical ... props=ok(2935)"}
        self.assertEqual(params.checked_verdict(found, 0, "r")["verdict"], "identical")
        self.assertEqual(params.checked_verdict(found, 1, "r")["verdict"], "differs")
        self.assertEqual(params.checked_verdict({"verdict": "not-comparable"}, 1, "r")["verdict"], "not-comparable")

    def test_partial_oracle_on_an_empty_work_dir_writes_the_same_row_twice(self):
        # Issue #1074: the first run on an empty --work wrote a property-only
        # row without its pins, because the pins were decided from a product
        # model only the run itself imports. The row no longer depends on it:
        # the first and the second run write the same row, without pins.
        app = "M-0009_A-E802-13-7620"
        out = "1.1.1     apply  identical  0.0% (0)  -  props=ok(4118)  loadctl=ok(4)\n"
        with tempfile.TemporaryDirectory() as tmp:
            work, captures = Path(tmp) / "work", Path(tmp) / "captures"
            step = captures / app / "params-partial" / "b-partial-param"
            step.mkdir(parents=True)
            (step / "params.json").write_text(json.dumps({"changes": [{"label": "Delay", "shown": "2"}]}))

            def model(job, work_, out_, recorded):
                out_.mkdir(parents=True, exist_ok=True)
                return out_, []

            run = mock.Mock(return_value=mock.Mock(returncode=0, stdout=out, stderr=""))
            import sweep

            with mock.patch.object(sweep, "CAPTURES", captures), \
                    mock.patch.object(params, "change_model", side_effect=model), \
                    mock.patch.object(params.subprocess, "run", run), \
                    mock.patch.object(defaults, "product_path", return_value=Path("/p/E802.knxprod")):
                job = {"id": app, "mask": "07B0", "file": "E802.knxprod"}
                first = params.partial_oracle(job, work)
                rows = Path(first["rows"])
                first_row = rows.read_text()
                second = params.partial_oracle(job, work)
                second_row = rows.read_text()
        self.assertEqual(first_row, second_row)
        self.assertEqual((first["verdict"], second["verdict"]), ("identical", "identical"))
        fields = first_row.strip().split("|")
        self.assertEqual(fields[5], "")
        self.assertFalse({"expect", "props", "loadctl"} & {o.split("=", 1)[0] for o in fields[6].split()})
        self.assertTrue(fields[6].startswith("run=params base="))

    def test_best_pages_exact_over_close(self):
        places = [{"page": "FS: Ampel"}, {"page": "LS: Ampel"}]
        self.assertEqual(params.best_pages(places, "FS: Ampel"), {"FS: Ampel"})

    def test_page_matches_anchored_sibling_and_placeholder_only(self):
        main, sibling = "Eingang {{ChNo}}: {{0}}", "Eingang {{ChNo}}: Sperre"
        self.assertTrue(params.page_matches(main, "Eingang A:"))
        self.assertTrue(params.page_matches(sibling, "Eingang A: Sperre"))
        self.assertFalse(params.page_matches(sibling, "Eingang A:"))
        self.assertFalse(params.page_matches(main, "Eingang"))
        self.assertFalse(params.page_matches(main, "Ausgang A:"))
        self.assertFalse(params.page_matches("{{0}}", "Eingang A:"))
        places = [{"page": main}, {"page": sibling}]
        self.assertEqual(params.best_pages(places, "Eingang A: Sperre"), {sibling})
        self.assertEqual(params.best_pages(places, "Eingang A:"), {main})

    THREE = {
        "parameters": {"MD-2_P-23": {"kind": {"Text": {}}, "text": "Beschreibung"},
                       "MD-2_P-32": {"kind": {"Enum": {"values": [0, 1, 2]}}, "text": "Wert Kontakt geöffnet",
                                     "labels": [[0, "Aus"], [1, "Ein"], [2, "nicht aktiv"]]}},
        "parameter_refs": {"MD-2_P-23_R-1": {"parameter": "MD-2_P-23"}, "MD-2_P-32_R-50": {"parameter": "MD-2_P-32"}},
        "dynamic": [{"channel": {"text": "Eingänge", "nodes": [
            {"module": {"id": f"MD-2_M-{i}", "def": "MD-2"}} for i in (2, 3, 4)]}}],
        "module_dynamics": {"MD-2": [{"block": {"text": "Eingang {{ChNo}}: {{0}}", "nodes": [
            {"p": "MD-2_P-23_R-1"}, {"p": "MD-2_P-32_R-50"}]}}]},
    }
    ORDER = [{"crumb": f"Eingänge > Eingang {c}:", "page": f"Eingang {c}:"} for c in "ABC"]

    def three(self, page_index):
        # M-2's page is shown but hides the label; M-3 and M-4 show it.
        def shown(values):
            return {"MD-2_M-2_MI-1_P-23_R-1", "MD-2_M-3_MI-1_P-23_R-1", "MD-2_M-4_MI-1_P-23_R-1",
                    "MD-2_M-3_MI-1_P-32_R-50", "MD-2_M-4_MI-1_P-32_R-50"}
        done = [{"page": self.ORDER[page_index], "label": "Wert Kontakt geöffnet", "n": 0, "kind": "dropdown",
                 "result": "set", "shown": "Ein", "set_to": "Ein", "rows_with_label": 1}]
        return params.model_changes(self.THREE, [], done, shown, [self.ORDER])

    def test_model_changes_counts_instances_whose_page_is_shown(self):
        # The change on the second page (M-3's) is M-3's, though M-2 hides
        # the label: the instance comes from the shown pages, not the
        # instances showing the label.
        self.assertEqual(self.three(1), ({"param@MD-2_M-3_MI-1_P-32_R-50": "1"}, []))
        self.assertEqual(self.three(2), ({"param@MD-2_M-4_MI-1_P-32_R-50": "1"}, []))

    def test_model_changes_module_label_in_a_nested_block(self):
        # The label sits in a block 'Verhalten' nested in the module page,
        # which ETS shows as a section of that page: the instance comes from
        # the page the change was matched on.
        model = json.loads(json.dumps(self.THREE))
        model["module_dynamics"]["MD-2"] = [{"block": {"text": "Eingang {{ChNo}}: {{0}}", "nodes": [
            {"p": "MD-2_P-23_R-1"}, {"block": {"text": "Verhalten", "nodes": [{"p": "MD-2_P-32_R-50"}]}}]}}]
        done = [{"page": self.ORDER[1], "label": "Wert Kontakt geöffnet", "n": 0, "kind": "dropdown",
                 "result": "set", "shown": "Ein", "set_to": "Ein", "rows_with_label": 1}]
        values, problems = params.model_changes(model, [], done, lambda v: {r.split("@")[1] for r in v},
                                                [self.ORDER])
        self.assertEqual((values, problems), ({"param@MD-2_M-3_MI-1_P-32_R-50": "1"}, []))

    def test_ref_places_selector_keys_for_repeated_and_nested_instances(self):
        # bussard keys a module value by the instance selector
        # (`ActiveModule::selector`): `_MI-1` for a single instance, `_MI-<n>`
        # for the n-th of a `<Repeat>`, a submodule after its parent's.
        model = {
            "parameters": {"P-1": {"kind": {"Int": {"min": 1, "max": 3}}, "text": "Number of feeders"},
                           "MD-1_P-1": {"kind": {"Int": {"min": 0, "max": 9}}, "text": "Portion size"},
                           "MD-1_SM-1_P-1": {"kind": {"Int": {"min": 0, "max": 9}}, "text": "Lid"}},
            "parameter_refs": {"P-1_R-1": {"parameter": "P-1"}, "MD-1_P-1_R-1": {"parameter": "MD-1_P-1"},
                               "MD-1_SM-1_P-1_R-1": {"parameter": "MD-1_SM-1_P-1"}},
            "dynamic": [{"block": {"text": "General", "nodes": [
                {"p": "P-1_R-1"}, {"repeat": {"id": "X-1", "ref": "P-1_R-1", "nodes": [
                    {"module": {"id": "MD-1_M-1", "def": "MD-1"}}]}}]}}],
            "module_dynamics": {"MD-1": [{"block": {"text": "Feeder", "nodes": [
                {"p": "MD-1_P-1_R-1"}, {"module": {"id": "MD-1_SM-1_M-1", "def": "MD-1_SM-1"}}]}}],
                "MD-1_SM-1": [{"p": "MD-1_SM-1_P-1_R-1"}]},
        }
        refs = [p["ref"] for p in params.ref_places(model)]
        self.assertEqual(refs[:3], ["P-1_R-1", "MD-1_M-1_MI-1_P-1_R-1", "MD-1_M-1_MI-1_SM-1_M-1_MI-1_P-1_R-1"])
        self.assertEqual(refs[3:5], ["MD-1_M-1_MI-2_P-1_R-1", "MD-1_M-1_MI-2_SM-1_M-1_MI-1_P-1_R-1"])
        self.assertEqual(len(refs), 7)
        self.assertEqual(params.model_ref("MD-1_M-1_MI-2_P-1_R-1"), "MD-1_P-1_R-1")
        self.assertEqual(params.model_ref("MD-1_M-1_MI-1_SM-1_M-1_MI-3_P-1_R-1"), "MD-1_SM-1_P-1_R-1")
        self.assertEqual(params.ref_label(model, "MD-1_M-1_MI-2_P-1_R-1"), "Portion size")
        self.assertEqual(params.device_ref("MD-2_M-13_MI-1", "MD-2_P-31_R-43"), "MD-2_M-13_MI-1_P-31_R-43")
        self.assertEqual(params.device_ref("MD-2_M-13_MI-1", "MD-20_P-31_R-43"), "MD-20_P-31_R-43")
        self.assertIn('"param@MD-1_M-1_MI-2_P-1_R-1" = "5"',
                      params.device_toml_with({"param@MD-1_M-1_MI-2_P-1_R-1": "5"}))

    def test_model_changes_page_l_is_not_page_i_read_as_l(self):
        # The MDT 00B1 run of #1050 (params-1-0): OCR read input I's page as
        # 'Eingang l:' and L's tree entry as 'Eingang L•'. Folding the case
        # made 'l' the first page matching L's breadcrumb, and the change on
        # L landed in I's instance (one instance off in the oracle).
        model = json.loads(json.dumps(self.THREE))
        model["dynamic"][0]["channel"]["nodes"] = [{"module": {"id": f"MD-2_M-{i}", "def": "MD-2"}}
                                                   for i in (13, 14, 16, 17)]
        order = [{"crumb": f"Eingänge > Eingang {c}", "page": p}
                 for c, p in (("l:", "Eingang l:"), ("J:", "Eingang J:"), ("K:", "Eingang K:"), ("L:", "Eingang L•"))]
        done = [{"page": {"crumb": "Eingänge > Eingang L:", "page": "Eingang L•"}, "label": "Wert Kontakt geöffnet",
                 "n": 0, "kind": "dropdown", "result": "set", "shown": "Ein", "set_to": "Ein", "rows_with_label": 1}]
        values, problems = params.model_changes(model, [], done, lambda v: {r.split("@")[1] for r in v}, [order])
        self.assertEqual((values, problems), ({"param@MD-2_M-17_MI-1_P-32_R-50": "1"}, []))
        self.assertNotEqual(params.page_key("Eingang l:"), params.page_key("Eingang L:"))
        self.assertEqual(params.page_key("Eingang L•"), params.page_key("Eingang L:"))

    def test_model_changes_second_page_of_one_name(self):
        # Two pages 'Feeder' (a `<Repeat>`, syn-module-repeat): the driver
        # lists the second with page_n 1; the change on it is MI-2's.
        model = json.loads(json.dumps(self.THREE))
        model["dynamic"] = [{"channel": {"text": "Eingänge", "nodes": [{"repeat": {"id": "X", "count": 2, "nodes": [
            {"module": {"id": "MD-2_M-2", "def": "MD-2"}}]}}]}}]
        order = [{"crumb": "Eingänge > Eingang A:", "page": "Eingang A:"},
                 {"crumb": "Eingänge > Eingang A:", "page": "Eingang A:", "page_n": 1}]
        done = [{"page": {"crumb": "Eingänge > Eingang A:", "page": "Eingang A:", "page_n": 1},
                 "label": "Wert Kontakt geöffnet", "n": 0, "kind": "dropdown", "result": "set", "shown": "Ein",
                 "set_to": "Ein", "rows_with_label": 1}]
        values, problems = params.model_changes(model, [], done, lambda v: {r.split("@")[1] for r in v}, [order])
        self.assertEqual((values, problems), ({"param@MD-2_M-2_MI-2_P-32_R-50": "1"}, []))
        self.assertEqual(params.survey_rows([{**order[1], "rows": [
            {"label": "Wert Kontakt geöffnet", "kind": "dropdown", "value": "Aus"}]}])[0]["page"]["page_n"], 1)

    def test_model_changes_unmapped_when_the_instance_hides_the_label(self):
        values, problems = self.three(0)
        self.assertEqual(values, {})
        self.assertIn("0 shown, ETS shows 1", problems[0])

    def test_read_back_records_shown_and_loses_what_does_not_read_back(self):
        done = [{**self.change("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Preset", "dropdown", ""),
                 "set_to": "2 Presetobjekten"},
                {**self.change("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Zwangssteuerung", "checkbox", ""),
                 "set_to": "0"},
                {**self.change("- Al-16: Statusanzeigen schalten", "Sendeverzögerung nach Buswiederkehr", "number", ""),
                 "set_to": "1"},
                {**self.change("Ausgang 1 > Ausgang 1: Funktionsfreigabe", "Preset", "dropdown", ""), "set_to": "x"}]

        shows = {("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Preset"): "2 Presetobjekten",
                 ("Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Zwangssteuerung"): "1",
                 ("- Al-16: Statusanzeigen schalten", "Sendeverzögerung nach Buswiederkehr"): "1"}

        def flow(name, **body):
            self.assertEqual(name, "read_param")
            value = shows.get((body["page"]["crumb"], body["label"]))
            if value is None:
                return {"shown": False, "why": "no row 'Preset' on the page"}
            return {"shown": True, "row": {"value": value}, "rows_with_label": 1}

        params.read_back(flow, "1.1.1", self.FINAL, done)
        self.assertEqual([(d["result"], d.get("shown")) for d in done],
                         [("set", "2 Presetobjekten"), ("lost", "1"), ("set", "1"), ("lost", "")])
        self.assertEqual(done[0]["rows_with_label"], 1)


class TestVmDriver(unittest.TestCase):
    def test_driver_down_raises_instead_of_an_empty_answer(self):
        from unittest import mock
        import vm

        ch = mock.MagicMock()
        ch.recv.return_value = b""
        c = mock.MagicMock()
        c.get_transport.return_value.open_channel.return_value = ch
        with self.assertRaises(RuntimeError) as err:
            vm.driver(c, "POST", "/ets/devices", {})
        self.assertIn("does not answer", str(err.exception))
        ch.recv.side_effect = [b"HTTP/1.0 500 x\r\n\r\n<html>", b""]
        r = vm.driver(c, "POST", "/ets/devices", {})
        self.assertFalse(r["ok"])


class TestVmInstall(unittest.TestCase):
    def test_wait_restarted_waits_for_another_pid(self):
        from unittest import mock
        import vm

        # The old driver (pid 7) answers while a flow runs, then nothing
        # answers, then the replacement (pid 9).
        answers = iter([7, 7, None, 9])
        with mock.patch.object(vm, "health_pid", side_effect=lambda c: next(answers)):
            self.assertTrue(vm.wait_restarted(None, 7, timeout=5, pause=0))
        with mock.patch.object(vm, "health_pid", return_value=7):
            self.assertFalse(vm.wait_restarted(None, 7, timeout=0.05, pause=0))
        with mock.patch.object(vm, "health_pid", return_value=None):
            self.assertFalse(vm.wait_restarted(None, None, timeout=0.05, pause=0))


class TestParamsSubset(unittest.TestCase):
    def test_features_placement_types_dynamic(self):
        model = {"mask_version": "07B0",
                 "parameters": {"a": {"memory": None, "property": {"object_index": 10, "property_id": 52}},
                                "b": {"memory": {"offset": 3}}},
                 "parameter_types": {"t1": {"kind": {"Enum": {}}}, "t2": {"kind": {"Text": {}}}, "t3": {"kind": "None"}},
                 "unions": [{"id": "u"}], "module_instances": [], "calculations": [],
                 "dynamic": [{"channel": {"nodes": [{"choose": {"when": [{"nodes": [{"choose": {}}]}]}}]}}]}
        self.assertEqual(params_subset.features(model, {"differs"}),
                         {"mask:07B0", "placement:07B0/both", "type:Enum", "type:Text", "unions:07B0",
                          "channels:07B0", "switches:07B0/few <=20", "oracle:07B0/differs"})

    def test_committed_subset_pins_the_property_only_program(self):
        apps = [r["app"] for r in params_subset.load()]
        self.assertEqual(apps[0], "M-0009_A-E804-10-98AD")
        self.assertLessEqual(len(apps), 15)
        self.assertTrue(all(r["why"] for r in params_subset.load()))


class TestSecure(unittest.TestCase):
    def test_crc4_check_value(self):
        # Plain CRC-4 (x^4 + x + 1, not reflected): 0xE over "123456789";
        # the reflected CRC-4/ITU would give 0x7.
        self.assertEqual(secure.crc4(b"123456789"), 0xE)

    def test_certificate_text_matches_the_enroll_vectors(self):
        root = Path(__file__).resolve().parents[2]
        vectors = json.loads((root / "dev" / "enroll" / "vectors-v2.json").read_text())
        for v in vectors["certificates"]["valid"]:
            text = secure.certificate_text(bytes.fromhex(v["serial"]), bytes.fromhex(v["fdsk"]))
            self.assertEqual(text, v["text"])
        for text in vectors["certificates"]["bad_check"]:
            self.assertFalse(secure.parse_certificate(text)["check_ok"])

    def test_certificate_round_trip_and_groups(self):
        serial, fdsk = bytes.fromhex("00FA12345678"), bytes(range(16))
        text = secure.certificate_text(serial, fdsk)
        self.assertRegex(text, r"^([A-Z2-7]{6}-){5}[A-Z2-7]{6}$")
        info = secure.parse_certificate(text.lower().replace("-", " "))
        self.assertEqual((info["serial"], info["fdsk"]), (serial, fdsk))
        self.assertTrue(info["check_ok"])

    def test_parse_certificate_rejects_other_text(self):
        with self.assertRaises(ValueError):
            secure.parse_certificate("ABC-018")

    def test_synthetic_identity_is_stable_and_names_the_manufacturer(self):
        a = secure.synthetic_identity("M-0083_A-000E-23-2274")
        self.assertEqual(a, secure.synthetic_identity("M-0083_A-000E-23-2274"))
        self.assertEqual(a[0][:2], b"\x00\x83")
        self.assertNotEqual(a, secure.synthetic_identity("M-0083_A-000F-23-2274"))
        block, props = secure.sim_security("M-0083_A-000E-23-2274")
        self.assertEqual((block["status"], len(block["tool_key"])), ("factory", 32))
        self.assertEqual(props, [{"object": 0, "pid": 11, "value": a[0].hex()}])

    def test_decode_verdict(self):
        text = ("data secure: 12 A_SecureData frame(s) (L_Data.con echoes excluded)\n"
                "  MAC ok (tool key)                                   10  (S-A_Data x10)\n"
                "  MAC ok (FDSK key)                                    2  (S-A_Data x2)\n")
        self.assertEqual(secure.decode_verdict(text), {"verdict": "decoded", "frames": 12, "verified": 12})
        text += "  MAC FAIL (keys tried, none verified)                 3  (S-A_Data x3)\n"
        self.assertEqual(secure.decode_verdict(text.replace("12 A_Secure", "15 A_Secure"))["verdict"], "partial")
        self.assertEqual(secure.decode_verdict("no KNX operations")["verdict"], "plain")


class TestNightly(unittest.TestCase):
    def test_commands_shards_in_order_then_links(self):
        cmds = [c[3:] for c in nightly.commands("sweep", 3, False)]
        self.assertEqual([c[1:] for c in cmds],
                         [["--redo-failed", "--shard", "0/3"], ["--redo-failed", "--shard", "1/3"],
                          ["--redo-failed", "--shard", "2/3"], ["--variant", "links", "--representative"]])
        self.assertEqual(nightly.commands("followups", 1, False)[0][-1][-12:], "followups.py")
        self.assertEqual(nightly.commands("followups", 1, True)[0][-1], "--create")
        self.assertIn("--redo", nightly.commands("oracle", 1, False)[0])

    def test_preflight_ok_needs_ets_window(self):
        self.assertIsNone(nightly.preflight_ok('{"ok": true, "windows": [{"title": "ETS6 - ets-sweep"}]}'))
        self.assertIn("not among", nightly.preflight_ok('{"ok": true, "windows": [{"title": "Explorer"}]}'))
        self.assertIn("did not answer", nightly.preflight_ok("ssh: connect timed out"))

    def test_lock_refuses_a_second_run(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        with nightly.Lock(tmp / "lock"):
            with self.assertRaises(SystemExit):
                with nightly.Lock(tmp / "lock"):
                    pass
        self.assertFalse((tmp / "lock").exists())


class TestRepair(unittest.TestCase):
    def test_save_repair_keeps_screen_trees_trace_and_version(self):
        import base64
        from unittest import mock

        import sweep

        def driver(c, method, path, body=None, timeout=600):
            if path == "/screenshot":
                return {"png_base64": base64.b64encode(b"PNG").decode()}
            if path == "/popups":
                return {"tree": "Menu - 'Löschen'"}
            raise OSError("channel closed")

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        sweep._ETS_VERSION.clear()
        with mock.patch.object(sweep.vm, "driver", driver), \
                mock.patch.object(sweep.vm, "run", lambda c, cmd, t=60: (0, "6.4.8718.0\r\n")):
            saved = sweep.save_repair(None, tmp, "catalog_add: text 'OK' not on screen",
                                      {"ok": False, "trace": "Traceback ... RuntimeError"})
        repair = tmp / "repair"
        self.assertEqual((repair / "screen.png").read_bytes(), b"PNG")
        self.assertEqual((repair / "popups.txt").read_text(), "Menu - 'Löschen'")
        self.assertIn("Traceback", (repair / "error.txt").read_text())
        self.assertEqual(saved["ets_version"], "6.4.8718.0")
        self.assertTrue(saved["tree.txt"].startswith("failed:"))
        self.assertEqual(json.loads((repair / "repair.json").read_text())["screen.png"], "ok")


class TestEtsHistoryAndLog(unittest.TestCase):
    """What a run keeps of ETS's history pane and of its log (2026-11-04
    evaluation: defaults.json held only '1.1.1' lines for A-4945, and a run
    that ended 'ets logged a failure' did not say which message)."""

    def test_newest_history_entry_ocr_split_address_column(self):
        import sweep

        hist = ["Historie löschen", "1.1.1", "1.1.1", "1.1.1", "1.1.1", "KNX IP interface secure",
                "Programmieren(Appl.): Abgeschlossen", "Keine Details verfügbar", "Verbindung:", "Start:",
                "Ende:", "Modul für Büroräume", "1.1.254 knx-sim (127.0.0.1)",
                "Programmieren(Appl.): Abgeschlossen"]
        self.assertEqual(sweep.newest_history_entry(hist),
                         ["1.1.1", "KNX IP interface secure", "Programmieren(Appl.): Abgeschlossen",
                          "Keine Details verfügbar"])

    def test_newest_history_entry_failure_keeps_the_message(self):
        import sweep

        hist = ["Historie löschen", "1.1.1 6108/06-500 Tasterankopplung 2-fach, UP",
                "Programmieren(Appl.): fehlgeschlagen", "Die Programmierung kann nicht fortgesetzt werden",
                "aufgrund inkompatibler Produktdaten.", "1.1.1", "Verbindung:", "Start:", "Ende:",
                "1.1.254 knx-sim (127.0.0.1)", "1.1.1 HeatingBOX 230V", "Programmieren(Appl.): Abgeschlossen"]
        entry = sweep.newest_history_entry(hist)
        self.assertEqual(entry[:2], ["1.1.1 6108/06-500 Tasterankopplung 2-fach, UP",
                                     "Programmieren(Appl.): fehlgeschlagen"])
        self.assertEqual(entry[2:], ["Die Programmierung kann nicht fortgesetzt werden",
                                     "aufgrund inkompatibler Produktdaten."])
        self.assertEqual(sweep.ets_status(entry), "failed")

    def test_newest_history_entry_without_status_and_empty(self):
        import sweep

        self.assertEqual(sweep.newest_history_entry(["Historie löschen", "a", "b", "c", "d", "e"]),
                         ["a", "b", "c", "d"])
        self.assertEqual(sweep.newest_history_entry(None), [])
        # An entry from an older defaults.json (first four lines) reads the same.
        self.assertEqual(sweep.newest_history_entry(["Historie löschen", "1.1.1 X",
                                                     "Programmieren(Appl.): Abgeschlossen",
                                                     "Keine Details verfügbar"]),
                         ["1.1.1 X", "Programmieren(Appl.): Abgeschlossen", "Keine Details verfügbar"])

    def test_ets_failure_lines_since_warn_and_error_once(self):
        import sweep

        log = ("2026-11-04 10:00:01,1 WARN  LoadDeviceTask - old\r\n"
               "2026-11-04 10:05:00,2 INFO  LoadDeviceTask - started\r\n"
               "2026-11-04 10:05:03,3 WARN  LoadDeviceTask - LoadImageProp mismatch obj 4\r\n"
               "2026-11-04 10:05:03,3 WARN  LoadDeviceTask - LoadImageProp mismatch obj 4\r\n"
               "2026-11-04 10:05:04,4 ERROR LoadDeviceTask - download failed\r\n")
        self.assertEqual(sweep.ets_failure_lines(log, "2026-11-04 10:05:00"),
                         ["2026-11-04 10:05:03,3 WARN  LoadDeviceTask - LoadImageProp mismatch obj 4",
                          "2026-11-04 10:05:04,4 ERROR LoadDeviceTask - download failed"])
        self.assertEqual(sweep.ets_failure_lines("", "2026-11-04 10:05:00"), [])

    def test_ets_failed_since_returns_the_lines(self):
        from unittest import mock

        import sweep

        out = "2026-11-04 10:05:03,3 WARN  LoadDeviceTask - x\r\n"
        with mock.patch.object(sweep.vm, "run", lambda c, cmd, t=60: (0, out)):
            self.assertEqual(sweep.ets_failed_since(None, "2026-11-04 10:05:00"),
                             ["2026-11-04 10:05:03,3 WARN  LoadDeviceTask - x"])
            self.assertEqual(sweep.ets_failed_since(None, "2026-11-04 10:06:00"), [])


class TestEtsLogFailed(unittest.TestCase):
    def test_ets_log_failed_exception_and_error_only(self):
        import sweep

        warn = ("2026-11-04 21:00:00,000 [37] WARN  Knx.Ets.Hawk.LoadDeviceTask - Determining "
                "AssignedIPAddress from IP discovery has failed")
        exc = ("2026-11-04 22:26:44,439 [37] WARN  Knx.Ets.Hawk.LoadDeviceTask - Knx.Ets.Hawk."
               "DeviceManagementException: Das Gerät ist mit einem in diesem Projekt nicht bekannten Schlüssel gesichert.")
        err = "2026-11-04 22:26:44,445 [1] ERROR Knx.Ets.ViewModel.OnlineOperations.Download.HawkPendingOperation - x"
        self.assertFalse(sweep.ets_log_failed(None))
        self.assertFalse(sweep.ets_log_failed([warn]))
        self.assertTrue(sweep.ets_log_failed([warn, exc]))
        self.assertTrue(sweep.ets_log_failed([err]))


class TestFollowups(unittest.TestCase):
    def test_draft_names_app_capture_and_diff(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        app = "M-0083_A-0003-10-0000"
        oracle_dir = tmp / app / "plain-defaults" / "oracle" / "1.1.1"
        oracle_dir.mkdir(parents=True)
        (oracle_dir / "diff.txt").write_text("\n".join(f"line {i}" for i in range(40)))
        d = followups.draft({"app": app, "before": "identical", "after": "differs", "mask": "07B0",
                             "file": "mdt.knxprod", "regression": True},
                            {app: {"summary": "1.1.1 B differs par=1/10@+0x3"}}, tmp, None,
                            {"id": "20261030T013000Z", "ets_version": "6.4.8718"})
        self.assertEqual(d["title"], f"ETS sweep: {app} went from identical to differs (07B0)")
        self.assertIn(str(tmp / app / "plain-defaults" / "ets.pcapng"), d["body"])
        self.assertIn("line 29\n... 10 more lines", d["body"])
        self.assertIn("ETS 6.4.8718", d["body"])

    def test_draft_reads_the_diff_under_the_rows_address(self):
        # A coupler row's oracle output lives under 1.1.0 (#876).
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        app = "M-0006_A-E001-10-AE55-O0009"
        oracle_dir = tmp / app / "plain-defaults" / "oracle" / "1.1.0"
        oracle_dir.mkdir(parents=True)
        (oracle_dir / "diff.txt").write_text("coupler diff")
        d = followups.draft({"app": app, "before": "identical", "after": "differs", "mask": "0701",
                             "file": "s.knxprod", "regression": True},
                            {app: {"summary": "1.1.0 7 differs", "ia": "1.1.0"}}, tmp, None, {})
        self.assertIn("coupler diff", d["body"])


class TestSeries(unittest.TestCase):
    # The EK-E72's object table at defaults, as the driver reads it.
    E72 = [{"number": 1, "gas": [], "flags": "KLÜ"}, {"number": 20, "gas": [], "flags": "KLÜ"},
           {"number": 22, "gas": [], "flags": "KS"}, {"number": 24, "gas": [], "flags": "KLÜ"},
           {"number": 27, "gas": [], "flags": "KLÜ"}, {"number": 29, "gas": [], "flags": "KLSÜA"},
           {"number": 31, "gas": [], "flags": "KLSÜA"}]

    def test_plan_links_senders_first_then_free_and_second(self):
        plan = series.plan_links(self.E72)
        self.assertEqual(plan["initial"], [(1, "1/0/1"), (20, "1/0/2"), (24, "1/0/3"), (27, "1/0/4")])
        self.assertEqual(plan["add"], (22, "1/0/9"))
        # No initial object can be written: the second address goes on the first.
        self.assertEqual(plan["second"], (1, "1/0/2"))

    def test_plan_links_second_prefers_writable(self):
        plan = series.plan_links(self.E72[4:] + self.E72[:1], n=2)
        self.assertEqual(plan["initial"], [(27, "1/0/1"), (29, "1/0/2")])
        self.assertEqual(plan["second"], (29, "1/0/1"))
        self.assertEqual(plan["add"], (31, "1/0/9"))

    # The ise KNX Sonos as the links run of 2026-11-10 read it: three free
    # senders of two sizes, none writable (#478).
    SONOS = [{"number": 12, "gas": [], "size": "1 bit", "flags": "KLÜ"},
             {"number": 16, "gas": [], "size": "1 byte", "flags": "KLÜ"},
             {"number": 20, "gas": [], "size": "1 bit", "flags": "KLÜ"},
             {"number": 21, "gas": [], "size": "1 bit", "flags": "KS"}]

    def test_plan_links_second_same_size(self):
        plan = series.plan_links(self.SONOS, n=3)
        self.assertEqual(plan["initial"], [(12, "1/0/1"), (16, "1/0/2"), (20, "1/0/3")])
        # Not 1/0/2 (the 1-byte object's) on object 12: ETS refuses it.
        self.assertEqual(plan["second"], (12, "1/0/3"))

    def test_plan_links_second_none_without_a_same_size_pair(self):
        rows = [dict(self.SONOS[0]), dict(self.SONOS[1])]
        self.assertIsNone(series.plan_links(rows, n=2)["second"])
        # An unread size does not rule the pair out.
        rows[1]["size"] = None
        self.assertEqual(series.plan_links(rows, n=2)["second"], (12, "1/0/2"))

    def test_links_hook_records_a_refused_link_and_goes_on(self):
        calls = []

        def flow(name, **kw):
            calls.append((name, kw))
            if name == "objects":
                return {"objects": self.SONOS}
            out = [{"number": n, "ga": g, "linked": True} for n, g in kw["links"]]
            out[1] = {"number": 16, "ga": "1/0/2", "linked": False, "refused": "ETS refused 1/0/2 for object 16: ..."}
            return {"links": out, "objects": [{"number": 12, "gas": ["1/0/1", "1/0/3"]}]}
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        out = series.links_hook(3)(flow, tmp)
        self.assertEqual(out["links"], [[12, "1/0/1"], [20, "1/0/3"], [12, "1/0/3"]])
        self.assertEqual(out["refused"], [{"number": 16, "ga": "1/0/2", "reason": "ETS refused 1/0/2 for object 16: ..."}])
        # Two driver calls: the table read (it selects the device and opens
        # the table) and every link on that same table; no last read.
        self.assertEqual([c[0] for c in calls], ["objects", "links"])
        self.assertEqual(calls[1][1], {"ia": "1.1.1", "open": False,
                                       "links": [[12, "1/0/1"], [16, "1/0/2"], [20, "1/0/3"], [12, "1/0/3"]]})
        self.assertEqual(json.loads((tmp / "objects.json").read_text()), [{"number": 12, "gas": ["1/0/1", "1/0/3"]}])

    def test_links_hook_without_candidates_makes_no_links_call(self):
        calls = []
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        out = series.links_hook(3)(lambda name, **kw: calls.append(name) or {"objects": []}, tmp)
        self.assertEqual((calls, out), (["objects"], {"links": [], "refused": []}))

    def test_link_steps_initial_then_second(self):
        plan = series.plan_links(self.SONOS, n=3)
        self.assertEqual(series.link_steps(plan), [[12, "1/0/1"], [16, "1/0/2"], [20, "1/0/3"], [12, "1/0/3"]])
        self.assertEqual(series.link_steps({"initial": [(1, "1/0/1")], "add": None, "second": None}), [[1, "1/0/1"]])

    def test_plan_links_empty_table(self):
        self.assertEqual(series.plan_links([]), {"initial": [], "add": None, "second": None})

    def test_pcap_slice_from_offset_drops_cut_record(self):
        head = b"\xd4\xc3\xb2\xa1" + bytes(20)
        rec = lambda body: bytes(8) + len(body).to_bytes(4, "little") * 2 + body  # noqa: E731
        data = head + rec(b"aa") + rec(b"bbb") + rec(b"cccc")[:-1]
        out, n = series.pcap_slice(data, 24 + len(rec(b"aa")))
        self.assertEqual((out, n), (head + rec(b"bbb"), 1))


class TestApplyRows(unittest.TestCase):
    def test_links_from_objects_send_first_listen_rest(self):
        objects = [
            {"number": 1, "gas": ["1/0/1", "1/0/4"], "flags": "KLÜ"},
            {"number": 22, "gas": [], "flags": "KS"},
            {"number": 29, "gas": ["1/0/7"], "flags": "KS"},
            {"number": None, "gas": ["1/0/8"], "flags": "KLÜ"},
            {"number": 31, "gas": ["1/0/9", "noise"], "flags": "KLSÜA"},
        ]
        self.assertEqual(apply_rows.links_from_objects(objects), {
            "1": {"send": "1/0/1", "listen": ["1/0/4"]},
            "29": {"send": None, "listen": ["1/0/7"]},
            "31": {"send": "1/0/9", "listen": []},
        })

    def test_rows_one_apply_row_per_partial_step(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        product = tmp / "p.knxprod"
        product.write_bytes(b"x")
        shared = tmp / "shared"
        (shared / "products").mkdir(parents=True)
        for name in oracle_model.SHARED_CACHES:
            (shared / ".bussard" / name).mkdir(parents=True)
        (shared / "bussard.lock").write_text("version = 3\n")
        series = tmp / "M-00B6_A-4537-03-DE59"
        for step, objs in (("a-full-links", []), ("b-partial-add", [{"number": 31, "gas": ["1/0/9"], "flags": "KLSÜA"}])):
            (series / step).mkdir(parents=True)
            (series / step / "ets.pcapng").write_bytes(b"")
            (series / step / "objects.json").write_text(json.dumps(objs))
            (series / step / "sim.yaml").write_text("devices:\n- lsm_access: property\n")
        lines = apply_rows.rows(series, product, "M-00B6_A-4537-03-DE59", tmp / "work", shared=shared)
        row = [l for l in lines if not l.startswith("#")]
        self.assertEqual(len(row), 1)
        self.assertIn(f"run=apply base={series / 'a-full-links' / 'ets.pcapng'} dir=", row[0])
        self.assertTrue(row[0].endswith("lsm=property"))
        self.assertIn(f"#@ --dir {shared}", lines)
        model = tmp / "work" / "b-partial-add" / "model"
        self.assertIn('31.send = "1/0/9"', (model / "devices" / "1.1.1.toml").read_text())


class TestRowVersion(unittest.TestCase):
    def test_shown_version_noise_and_suffix(self):
        self.assertEqual(defaults.shown_version(". 11.1"), (11, 1))
        self.assertEqual(defaults.shown_version("...1.13"), (1, 13))
        self.assertEqual(defaults.shown_version("1.0a"), (1, 0))
        self.assertIsNone(defaults.shown_version(""))
        self.assertIsNone(defaults.shown_version("Ver"))

    def test_row_version_mismatch_wrong_row_refused(self):
        # Busch-Jaeger A-6109-50 ran against the catalog row of version 1.1.
        why = defaults.row_version_mismatch("M-0007_A-6109-50-71A0", {"version": "1.1"})
        self.assertEqual(why, "catalog row shows version 1.1, the job is 5.0")

    def test_row_version_mismatch_decimal_minor_passes(self):
        # ETS prints the nibbles in decimal: 0x1C is 1.12, 0xB1 is 11.1.
        self.assertIsNone(defaults.row_version_mismatch("M-0071_A-45C1-1C-7989", {"version": "1.12"}))
        self.assertIsNone(defaults.row_version_mismatch("M-0002_A-0806-B1-C2E4-O0007", {"version": ". 11.1"}))
        self.assertIsNone(defaults.row_version_mismatch("M-0071_A-4B51-1D-B865", {"version": "...1.13"}))

    def test_row_version_mismatch_ocr_digit_in_front_passes(self):
        self.assertIsNone(defaults.row_version_mismatch("M-0071_A-4821-12-2859", {"version": "21.2"}))

    def test_row_version_mismatch_unreadable_passes(self):
        self.assertIsNone(defaults.row_version_mismatch("M-0007_A-6109-50-71A0", {"version": ""}))
        self.assertIsNone(defaults.row_version_mismatch("M-0007_A-6109-50-71A0", None))

    def test_relabel_wrong_rows_captured_and_failed(self):
        results = {
            "M-0007_A-6109-50-71A0": {"outcome": "captured", "row": {"version": "1.1"}},
            "M-0002_A-6109-50-8FF2-O0007": {"outcome": "captured", "row": {"version": "5.0"}},
            # The Theben MIX 2 secure (2.2) ran its 0701 sibling's row (1.12):
            # ETS refused the mask, a failure of the other application.
            "M-0048_A-493B-22-1E4D": {"outcome": "ets-failed", "row": {"version": "1.12"}},
            # A failure on the job's own row stays.
            "M-0001_A-9A01-03-E6C8": {"outcome": "ets-failed", "row": {"version": ". 0.3"}},
            "M-0007_A-6109-40-0000": {"outcome": "bus-failed", "row": {"version": "1.1"}},
        }
        self.assertEqual(defaults.relabel_wrong_rows(results),
                         ["M-0007_A-6109-50-71A0", "M-0048_A-493B-22-1E4D"])
        self.assertEqual(results["M-0007_A-6109-50-71A0"]["outcome"], "skipped-catalog-version")
        self.assertEqual(results["M-0048_A-493B-22-1E4D"]["outcome"], "skipped-catalog-version")
        self.assertEqual(results["M-0002_A-6109-50-8FF2-O0007"]["outcome"], "captured")
        self.assertEqual(results["M-0001_A-9A01-03-E6C8"]["outcome"], "ets-failed")
        self.assertEqual(results["M-0007_A-6109-40-0000"]["outcome"], "bus-failed")


LOCK = """# @generated
version = 3

[[product]]
sha256 = "SHA"
file = "products/p.knxprod"
applications = ["M-00FA_A-0001-10-0000"]

[[device]]
address = "1.1.1"
application = "M-00FA_A-0001-10-0000"
product_sha256 = "SHA"
"""


class TestOracleModel(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.product = self.tmp / "p.knxprod"
        self.product.write_bytes(b"not a zip, only hashed")

    def shared(self) -> Path:
        """A fake shared import (what `bussard import-product` leaves)."""
        sha = oracle_model.product_sha(self.product)
        d = self.tmp / "shared"
        (d / "products").mkdir(parents=True)
        for name in oracle_model.SHARED_CACHES:
            (d / ".bussard" / name).mkdir(parents=True)
        (d / "bussard.lock").write_text(LOCK.replace("SHA", sha))
        return d

    def test_strip_devices_keeps_products(self):
        out = oracle_model.strip_devices(LOCK)
        self.assertIn("[[product]]", out)
        self.assertNotIn("[[device]]", out)
        self.assertNotIn('address = "1.1.1"', out)

    def test_build_shared_links_caches_and_pins_one_device(self):
        shared = self.shared()
        model = oracle_model.build(self.tmp / "row" / "model", self.product, "M-00FA_A-0001-10-0000",
                                   mask="07B0", shared=shared)
        self.assertTrue((model / "products").is_symlink())
        for name in oracle_model.SHARED_CACHES:
            self.assertTrue((model / ".bussard" / name).is_symlink())
        lock = (model / "bussard.lock").read_text()
        self.assertEqual(lock.count("[[device]]"), 1)
        self.assertIn('mask = "07B0"', lock)
        self.assertIn(oracle_model.product_sha(self.product), lock)
        # A rebuild replaces the links and still pins exactly one device.
        oracle_model.build(model, self.product, "M-00FA_A-0001-10-0000", shared=shared)
        self.assertEqual((model / "bussard.lock").read_text().count("[[device]]"), 1)

    def test_build_links_writes_send_listen_and_groups(self):
        model = oracle_model.build(self.tmp / "m", self.product, "M-00FA_A-0001-10-0000", shared=self.shared(),
                                   links={"31": {"send": "1/0/9", "listen": []},
                                          "1": {"send": "1/0/1", "listen": ["1/0/4"]}})
        dev = (model / "devices" / "1.1.1.toml").read_text()
        self.assertIn('1.send = "1/0/1"\n1.listen = ["1/0/4"]\n31.send = "1/0/9"\n', dev)
        groups = (model / "groups.toml").read_text()
        self.assertLess(groups.index('"1/0/1"'), groups.index('"1/0/4"'))
        self.assertLess(groups.index('"1/0/4"'), groups.index('"1/0/9"'))

    def test_additional_addresses_bus_interfaces_order(self):
        """ETS assigns the tunnels of an application with <BusInterfaces>
        descending from .255, of one with only AdditionalAddressesCount
        ascending (#840, sweep captures)."""
        import zipfile

        def product(name: str, body: str) -> Path:
            path = self.tmp / f"{name}.knxprod"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(f"M-00FA/{name}.xml", '<ApplicationProgram Id="x" AdditionalAddressesCount="3">' + body)
            return path

        legacy = product("M-00FA_A-0001-10-0000", "</ApplicationProgram>")
        modern = product("M-00FA_A-0002-10-0000", '<BusInterfaces><BusInterface AddressIndex="1" '
                         'AccessType="Tunneling"/></BusInterfaces></ApplicationProgram>')
        self.assertEqual(oracle_model.additional_addresses(legacy, "M-00FA_A-0001-10-0000"), (3, False))
        self.assertEqual(oracle_model.additional_addresses(modern, "M-00FA_A-0002-10-0000"), (3, True))
        self.assertIn('tunnels = ["1.1.253", "1.1.254", "1.1.255"]', oracle_model.knxnet_table("1.1.1", 3, None))
        self.assertIn('tunnels = ["1.1.255", "1.1.254", "1.1.253"]',
                      oracle_model.knxnet_table("1.1.1", 3, None, bus_interfaces=True))

    def test_ip_enabled_hardware_without_tunnels(self):
        """IsIPEnabled hardware without tunnelling addresses gets a [knxnet]
        table with no tunnels, named by the product text in the project
        language, trimmed and cut to 30 characters (#1023, ise smart connect
        captures)."""
        import zipfile

        app = "M-007C_A-0001-10-2A85"
        path = self.tmp / "ise.knxprod"
        hw = ('<KNX><ManufacturerData><Manufacturer RefId="M-007C"><Hardware>'
              '<Hardware Id="H-1" Name="KIM" IsIPEnabled="true"><Products>'
              '<Product Id="H-1_P-1" Text="x" OrderNumber="1-0004-005" /></Products>'
              f'<Hardware2Programs><Hardware2Program Id="H-1_HP-1"><ApplicationProgramRef RefId="{app}" />'
              '</Hardware2Program></Hardware2Programs></Hardware></Hardware>'
              '<Languages><Language Identifier="de-DE"><TranslationUnit RefId="H-1_P-1">'
              '<TranslationElement RefId="H-1_P-1"><Translation AttributeName="Text" '
              'Text=" ise smart connect KNX Programmable" /></TranslationElement></TranslationUnit>'
              '</Language></Languages></Manufacturer></ManufacturerData></KNX>')
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("M-007C/Hardware.xml", hw)
            z.writestr(f"M-007C/{app}.xml", f'<ApplicationProgram Id="{app}"></ApplicationProgram>')
        self.assertEqual(oracle_model.hardware_of(path, app)[0], True)
        self.assertEqual(oracle_model.hardware_of(path, "M-007C_A-0009-10-0000"), (False, []))
        self.assertEqual(oracle_model.project_device_name(path, app, "1-0004-005"), "ise smart connect KNX Programm")
        self.assertEqual(oracle_model.knxnet_table("1.1.1", 0, "ise"),
                         '\n[knxnet]\nassignment = "dhcp"\nfriendly_name = "ise"\n')
        devices = self.tmp / "m" / "devices"
        devices.mkdir(parents=True)
        (devices / "1.1.1.toml").write_text('address = "1.1.1"\n')
        oracle_model.ensure_knxnet(self.tmp / "m", path, app, friendly_name="ise")
        self.assertIn("[knxnet]", (devices / "1.1.1.toml").read_text())
        self.assertNotIn("tunnels", (devices / "1.1.1.toml").read_text())

    def test_shared_import_seed_copies_without_devices(self):
        seed = self.shared()
        (seed / "devices").mkdir()
        out = oracle_model.shared_import(self.tmp / "root", self.product, seed=seed)
        self.assertEqual(out, oracle_model.shared_dir(self.tmp / "root", self.product))
        self.assertNotIn("[[device]]", (out / "bussard.lock").read_text())
        # A second call finds the import and returns it as is.
        (out / "marker").write_text("x")
        self.assertTrue((oracle_model.shared_import(self.tmp / "root", self.product) / "marker").exists())


class TestSummary(unittest.TestCase):
    DEFAULTS = {
        "M-0002_A-0001-10-0000": {"outcome": "captured", "when": "t1", "mask": "07B0", "file": "abb.knxprod"},
        "M-0002_A-0002-10-0000": {"outcome": "captured", "when": "t1", "mask": "0701", "file": "abb.knxprod"},
        "M-0083_A-0003-10-0000": {"outcome": "captured", "when": "t2", "mask": "07B0", "file": "mdt.knxprod"},
        "M-0083_A-0004-10-0000": {"outcome": "ets-failed", "when": "t1", "mask": "07B0", "file": "mdt.knxprod"},
        "M-0083_A-0005-10-0000": {"outcome": "captured", "when": "t3", "mask": "07B0", "file": "mdt.knxprod"},
    }
    ORACLE = {
        "M-0002_A-0001-10-0000": {"verdict": "identical", "capture_when": "t1", "loadctl": {"verdict": "identical"}},
        "M-0002_A-0002-10-0000": {"verdict": "differs", "capture_when": "t1"},
        "M-0083_A-0003-10-0000": {"verdict": "differs", "capture_when": "t2"},
        # Compared against an older capture: pending.
        "M-0083_A-0005-10-0000": {"verdict": "identical", "capture_when": "t0"},
    }

    def manifest(self, oracle=None, benign=None):
        return summary.build_manifest(self.DEFAULTS, oracle or self.ORACLE, benign or {}, {"ets_version": "6.4.1"}, "now")

    def test_verdict_of_pending_benign_and_outcome(self):
        m = self.manifest(benign={"M-0002_A-0002-10-0000": "known template tail"})["apps"]
        self.assertEqual(m["M-0002_A-0001-10-0000"]["verdict"], "identical")
        self.assertEqual(m["M-0002_A-0002-10-0000"]["verdict"], "benign")
        self.assertEqual(m["M-0083_A-0003-10-0000"]["verdict"], "differs")
        self.assertEqual(m["M-0083_A-0004-10-0000"]["verdict"], "ets-failed")
        self.assertEqual(m["M-0083_A-0005-10-0000"]["verdict"], "pending")
        self.assertEqual(m["M-0083_A-0003-10-0000"]["manufacturer"], "M-0083")

    def test_changes_flags_identical_to_differs(self):
        before = self.manifest()
        oracle = json.loads(json.dumps(self.ORACLE))
        oracle["M-0002_A-0001-10-0000"]["verdict"] = "differs"
        oracle["M-0083_A-0003-10-0000"]["verdict"] = "identical"
        delta = summary.changes(before, self.manifest(oracle))
        self.assertEqual([(d["app"], d["before"], d["after"], d["regression"]) for d in delta],
                         [("M-0002_A-0001-10-0000", "identical", "differs", True),
                          ("M-0083_A-0003-10-0000", "differs", "identical", False)])
        self.assertEqual(summary.changes(None, before), [])

    def test_render_links_and_series_sections(self):
        m = self.manifest()
        m["links"] = {"M-0002_A-0001-10-0000": {"mask": "07B0", "verdict": "differs"}}
        m["series"] = {"M-00B6_A-4537-03-DE59": {"why": "own GO segment", "steps": {"a-full-links": {"ets": "ok"}}}}
        text = summary.render(m, [])
        self.assertIn("## Links variant parity per mask family (#478)", text)
        self.assertIn("| M-00B6_A-4537-03-DE59 | own GO segment | a-full-links: ok |", text)

    def test_render_description_reads_apart_from_the_verdict(self):
        # Issue #1014: a description read difference is shown per mask and
        # leaves the row's verdict alone.
        oracle = json.loads(json.dumps(self.ORACLE))
        oracle["M-0002_A-0001-10-0000"]["desc"] = {"verdict": "differs", "ets_only": 2}
        m = self.manifest(oracle)
        self.assertEqual(m["apps"]["M-0002_A-0001-10-0000"]["verdict"], "identical")
        self.assertEqual(m["apps"]["M-0002_A-0001-10-0000"]["desc"], "differs")
        text = summary.render(m, [])
        self.assertIn("## Property description reads per mask family (#1014, not part of the verdict)", text)

    def test_description_summary_and_progress_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "diff.json"
            self.assertEqual(oracle.description_summary(diff), {"verdict": "missing"})
            diff.write_text(json.dumps({"verdict": "identical", "property_descriptions": {
                "verdict": "differs", "bussard_reads": 1, "ets_reads": 2,
                "bussard_only": [{"step": 3}], "ets_only": [{"ets_seq": 1}, {"ets_seq": 2}],
                "not_compared": [{"ets_seq": 0}]}}))
            desc = oracle.description_summary(diff)
        self.assertEqual(desc, {"verdict": "differs", "bussard_reads": 1, "ets_reads": 2,
                                "bussard_only": 1, "ets_only": 2, "not_compared": 1})
        self.assertEqual(oracle.desc_text(desc), "desc=differs(+1/-2)")
        self.assertEqual(oracle.desc_text({"verdict": "identical"}), "desc=ok")
        self.assertEqual(oracle.desc_text(None), "desc=-")

    def test_render_tables(self):
        text = summary.render(self.manifest(), [])
        self.assertIn("ETS 6.4.1", text)
        self.assertIn("| 07B0 | 1 | 1 |", text.replace("|  |", "|"))
        self.assertIn("| M-0083 | mdt.knxprod |", text)
        self.assertIn("None.", text)


def _pcap(datagrams: list[bytes]) -> bytes:
    """A classic pcap with raw-IPv4 linktype (101) holding each datagram as UDP."""
    import struct

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    for i, payload in enumerate(datagrams):
        udp = struct.pack("!HHHH", 3671, 3672, 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1])) + udp
        out += struct.pack("<IIII", i, 0, len(ip), len(ip)) + ip
    return out


def _tunnel(seq: int, cemi: bytes, channel: int = 1) -> bytes:
    body = bytes([4, channel, seq, 0]) + cemi
    return bytes([0x06, 0x10, 0x04, 0x20]) + (6 + len(body)).to_bytes(2, "big") + body


class TestDistil(unittest.TestCase):
    def test_requests_keeps_requests_once(self) -> None:
        req = bytes([0x11, 0, 0xB0, 0x60, 0, 0, 0x11, 0x01, 0]) + bytes([0x80])
        con = bytes([0x2E]) + req[1:]
        conn = bytes([0x06, 0x10, 0x02, 0x05, 0, 6])
        datagrams = [_tunnel(0, req), _tunnel(0, req), _tunnel(1, con), conn, _tunnel(0, req)]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.pcap"
            path.write_bytes(_pcap(datagrams))
            reqs = distil.requests(path)
        # The retransmission is dropped, the confirmation is not a request, and
        # a CONNECT_REQUEST lets the same sequence number count again.
        self.assertEqual(reqs, [(0, 0x1101, b"\x80"), (0, 0x1101, b"\x80")])
        self.assertIn("0000 1101 80", distil.render(reqs, "c.pcap"))

    def test_app_number_from_id(self) -> None:
        self.assertEqual(calibrate.app_number("M-00FA_A-2600-10-731A"), bytes([0x26, 0x00]))
        self.assertEqual(calibrate.app_number("nonsense"), b"")


class TestCaptureRows(unittest.TestCase):
    def test_row_options_identical_writes_only_loadctl(self):
        self.assertEqual(capture.row_options({"verdict": "identical", "loadctl": "identical"}), "loadctl=identical")

    def test_row_options_differs_records_the_verdicts(self):
        self.assertEqual(capture.row_options({"verdict": "identical", "loadctl": "differs"}), "loadctl=differs")
        self.assertEqual(capture.row_options({"verdict": "differs", "loadctl": None}), "expect=differs")
        self.assertEqual(capture.row_options({"verdict": "not-comparable", "loadctl": "not-comparable"}),
                         "expect=not-comparable")


    def test_oracle_row_marks_a_system_7_product_fresh(self):
        # The sim starts unloaded; ETS reads no System 7 load state (#488).
        self.assertTrue(capture.oracle_row("syn-s7-0705", "A", "100.0", "loadctl=identical")
                        .endswith("|100.0|loadctl=identical state=fresh"))
        self.assertTrue(capture.oracle_row("syn-minimal", "A", "100.0", "loadctl=identical")
                        .endswith("|100.0|loadctl=identical"))
    def test_oracle_row_variant_state_replaces_fresh(self):
        # A run variant into a programmed System 7 device names its state (#488).
        row = capture.oracle_row("syn-s7-0705", "A", "100.0", "loadctl=differs", variant="reload",
                                 extra=capture.variant_options("syn-s7-0705", "reload"))
        self.assertIn("/syn-s7-0705/reload/ets.pcapng|", row)
        self.assertTrue(row.endswith("|100.0|loadctl=differs state=loaded"))

    def test_row_options_records_the_confirmed_verdict(self):
        self.assertEqual(capture.row_options({"verdict": "not-comparable", "confirmed": "identical",
                                              "loadctl": "differs"}),
                         "expect=not-comparable confirmed=identical loadctl=differs")


class TestIpEnabled(unittest.TestCase):
    """sweep.ip_enabled reads IsIPEnabled as an xs:boolean (#422)."""

    def _product(self, tmp: Path, attrs: str) -> Path:
        import zipfile

        path = tmp / "p.knxprod"
        hw = (f'<Hardware Id="M-0004_H-JUSOCOKX01-1-O007C" Name="KIM Sonos" {attrs}>'
              '<Hardware2Programs><Hardware2Program Id="M-0004_H-JUSOCOKX01-1-O007C_HP-B015-21-F7AD-O007C">'
              '<ApplicationProgramRef RefId="M-0004_A-B015-21-F7AD-O007C" /></Hardware2Program>'
              '</Hardware2Programs></Hardware>')
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("M-0004/Hardware.xml", f"<KNX><Hardwares>{hw}</Hardwares></KNX>")
        return path

    def test_ip_enabled_true_or_one(self):
        import sweep

        app = "M-0004_A-B015-21-F7AD-O007C"
        # The Jung Sonos gateway's start tag: older schema, "1", past 600 characters.
        long_attrs = " ".join(f'Is{i}="0"' for i in range(60)) + ' IsIPEnabled="1"'
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sweep.ip_enabled(self._product(Path(tmp), long_attrs), app))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(sweep.ip_enabled(self._product(Path(tmp), 'IsIPEnabled="true"'), app))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(sweep.ip_enabled(self._product(Path(tmp), 'IsIPEnabled="0"'), app))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(sweep.ip_enabled(self._product(Path(tmp), 'IsIPEnabled="false"'), app))


class TestStaleCompatPrompt(unittest.TestCase):
    """A compatibility prompt before one of the sweep's own flows belongs to
    the previous product (#422)."""

    def test_stale_compat_prompt_before_any_flow(self):
        import sweep

        for flow in ("project_tab", "catalog_import", "devices"):
            self.assertTrue(sweep.stale_compat_prompt(
                f"CompatModeRequired('ETS asked for compatibility mode before {flow}: Herunterladen')"))
        # The product's own download prompt is a skip, not a stale prompt.
        self.assertFalse(sweep.stale_compat_prompt(
            "download: CompatModeRequired('ETS asked for compatibility mode on download: Herunterladen')"))
        self.assertFalse(sweep.stale_compat_prompt(""))


class TestProductProperties(unittest.TestCase):
    """sweep.product_properties leaves a device property a parameter names by
    type (ObjectType="0") to the product's CompareProp, which knx-sim serves
    (#422)."""

    def _product(self, tmp: Path, app: str, prop: str, binary: str) -> Path:
        import zipfile

        xml = f"""<KNX><ApplicationProgram Id="{app}"><Static>
          <ParameterTypes><ParameterType Id="{app}_PT-HardwareType" Name="HardwareType">
            <TypeRestriction Base="BinaryValue" SizeInBit="48">
              <Enumeration Text="hw" Value="0" Id="{app}_PT-HardwareType_EN-0" BinaryValue="{binary}" />
            </TypeRestriction></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="{app}_P-2" Name="HardwareType" ParameterType="{app}_PT-HardwareType" Value="0">
            {prop}
          </Parameter></Parameters></Static></ApplicationProgram></KNX>"""
        path = tmp / "p.knxprod"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(f"M-0009/{app}.xml", xml)
        return path

    def test_product_properties_skips_object_type_zero(self):
        import sweep

        app = "M-0009_A-7209-10-6610"
        with tempfile.TemporaryDirectory() as tmp:
            # The Schneider STJAS471 shape: by type, not seeded.
            path = self._product(Path(tmp), app, '<Property ObjectType="0" PropertyId="78" Offset="0" BitOffset="0" />',
                                 "Cf//////")
            self.assertEqual(sweep.product_properties(path, app), [])
        with tempfile.TemporaryDirectory() as tmp:
            # By index it still is.
            path = self._product(Path(tmp), app, '<Property ObjectIndex="0" PropertyId="78" Offset="0" BitOffset="0" />',
                                 "Cf//////")
            self.assertEqual(sweep.product_properties(path, app),
                             [{"object": 0, "pid": 78, "value": "09ffffffffff"}])


class TestCompareProperties(unittest.TestCase):
    """A device-object property the load procedure only compares is seeded
    (#966, Jung F50 Secure room controller, obj 0 PID 201)."""

    APP = "M-0004_A-D162-22-D781-O000A"

    def setUp(self):
        defaults._product_seeds.cache_clear()

    def _product(self, tmp: Path, compares: str) -> Path:
        import zipfile

        xml = f"""<KNX><ApplicationProgram Id="{self.APP}"><Static><LoadProcedures>
          <LoadProcedure MergeId="1">{compares}</LoadProcedure>
          </LoadProcedures></Static></ApplicationProgram></KNX>"""
        path = tmp / "p.knxprod"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr(f"M-0004/{self.APP}.xml", xml)
        return path

    def test_seed_properties_seeds_a_range_compare(self):
        from unittest import mock

        import sweep

        # This product's op shape: a lower bound only, 0x1_0004_0000_0000.
        compare = """<LdCtrlCompareProp Range="[281492156579840,]" ObjIdx="0" PropId="201">
                       <OnError Cause="CompareMismatch" MessageRef="M-1" /></LdCtrlCompareProp>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._product(Path(tmp), compare)
            want = {"object": 0, "pid": 201, "value": "01000400000000"}
            self.assertEqual(sweep.compare_properties(path, self.APP), [want])
            with mock.patch.object(sweep, "product_properties", return_value=[]):
                self.assertEqual(defaults.seed_properties(path, self.APP, None), [want])
                # A seed is not learned.
                self.assertEqual(defaults.learned_from_ets(path, self.APP, {"learned_properties": [want]}), [])
        # An InlineData compare is knx-sim's (it honours the choose blocks).
        inline = '<LdCtrlCompareProp InlineData="000A8000011D" ObjIdx="0" PropId="78" />'
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(sweep.compare_properties(self._product(Path(tmp), inline), self.APP), [])
        with tempfile.TemporaryDirectory() as tmp:
            path = self._product(Path(tmp), compare)
            # A parameter or ETS's log names the property: that value stays.
            param = {"object": 0, "pid": 201, "value": "02000000000000"}
            with mock.patch.object(sweep, "product_properties", return_value=[param]):
                self.assertEqual(defaults.seed_properties(path, self.APP, None), [param])

    def test_compare_value_shapes(self):
        import sweep

        tag = '<LdCtrlCompareProp ObjIdx="0" PropId="201" {}>'
        cases = {
            'InlineData="00000000014A"': "00000000014a",
            # Seven octets for Count 6: the last six, as knx-sim reads it.
            'InlineData="00000000200003" Count="6"': "000000200003",
            'Range="[,513]"': "0201",
            'Range="[0,65535]"': "0000",
            'Range="(255,]"': "0100",
            'Range="[5,1]"': None,
            'Range="[,]"': None,
            'InlineData="01" StartElement="2"': None,
        }
        for attrs, want in cases.items():
            got = sweep.compare_value(tag.format(attrs))
            self.assertEqual(got.hex() if got is not None else None, want, attrs)


class TestModuleParameters(unittest.TestCase):
    """A module definition's parameters are relative to the module instance,
    not device-object properties (#422, Schneider STXF121)."""

    def test_product_properties_skips_module_defs(self):
        import zipfile

        import sweep

        app = "M-0009_A-E0EE-10-ADF8"
        xml = f"""<KNX><ApplicationProgram Id="{app}"><Static>
          <ParameterTypes><ParameterType Id="{app}_PT-1" Name="b"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="{app}_P-1" Name="top" ParameterType="{app}_PT-1" Value="7"><Property ObjectIndex="0" PropertyId="25" Offset="0" BitOffset="0" /></Parameter></Parameters>
          </Static><ModuleDefs><ModuleDef Id="{app}_MD-1" Name="MeteringSensor"><Static>
          <Parameters><Parameter Id="{app}_MD-1_P-1" Name="m" ParameterType="{app}_PT-1" Value="0"><Property ObjectIndex="0" PropertyId="208" Offset="0" BitOffset="0" /></Parameter></Parameters>
          </Static></ModuleDef></ModuleDefs></ApplicationProgram></KNX>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.knxprod"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(f"M-0009/{app}.xml", xml)
            self.assertEqual(sweep.product_properties(path, app), [{"object": 0, "pid": 25, "value": "07"}])


class TestLearnedProperties(unittest.TestCase):
    """Only what ETS's log required is learned; a seed is not (#422)."""

    def test_run_learning_keeps_only_ets_requirements(self):
        from unittest import mock

        import sweep

        seed = [{"object": 0, "pid": 78, "value": "09ffffffffff"}]
        required = {"object": 0, "pid": 78, "value": "000009720900"}
        runs = iter([{"outcome": "ets-failed", "ets_required": [required]},
                     {"outcome": "captured", "ets_required": []}])
        with mock.patch.object(sweep, "run_one", side_effect=lambda *a, **k: next(runs)):
            r = sweep.run_learning(None, Path("p.knxprod"), "M-0009_A-7209-10-6610", "TJAS471", properties=seed)
        self.assertEqual(r["learned_properties"], [required])
        # A clean first run learns nothing, whatever was seeded.
        with mock.patch.object(sweep, "run_one", return_value={"outcome": "captured"}):
            r = sweep.run_learning(None, Path("p.knxprod"), "M-0009_A-7209-10-6610", "TJAS471", properties=seed)
        self.assertEqual(r["learned_properties"], [])
        # Earlier learning is carried.
        with mock.patch.object(sweep, "run_one", return_value={"outcome": "captured"}):
            r = sweep.run_learning(None, Path("p.knxprod"), "M-0009_A-7209-10-6610", "TJAS471",
                                   properties=seed, learned=[required])
        self.assertEqual(r["learned_properties"], [required])

    def test_learned_from_ets_drops_seeded_entries(self):
        from unittest import mock

        import sweep

        seeded = {"object": 0, "pid": 78, "value": "000009720900"}
        real = {"object": 0, "pid": 15, "value": "0102"}
        with mock.patch.object(sweep, "product_properties", return_value=[seeded]):
            self.assertEqual(defaults.learned_from_ets(Path("p.knxprod"), "M-0009_A-7209-10-6610",
                                                       {"learned_properties": [seeded, real]}), [real])


class TestCaptureIpEnabled(unittest.TestCase):
    """An IP-enabled TP product (syn-ip-enabled-tp, #455): the sim gets the
    KNXnet/IP object, the row plans with the sweep project's [knxnet] table."""

    def test_knxnet_sim_only_for_an_ip_enabled_product(self):
        self.assertEqual(capture.knxnet_sim("syn-ip-enabled-tp"), "  knxnet:\n    tunnel_slots: 16\n")
        self.assertEqual(capture.knxnet_sim("syn-minimal"), "")
        self.assertIn("  knxnet:\n", capture.sim_yaml("syn-ip-enabled-tp", "A"))

    def test_knxnet_model_writes_the_device_file(self):
        with tempfile.TemporaryDirectory(dir=capture.OUT) as tmp:
            dst = Path(tmp)
            self.assertEqual(capture.knxnet_model("syn-minimal", dst), "")
            opt = capture.knxnet_model("syn-ip-enabled-tp", dst)
            self.assertTrue(opt.startswith("dir=captures/synthetic/") and opt.endswith("/model"))
            text = (dst / "model" / "devices" / "1.1.1.toml").read_text()
            self.assertIn('friendly_name = "Treetop uplink"', text)
            self.assertIn('tunnels = ["1.1.254", "1.1.255"]', text)


class TestCaptureSecure(unittest.TestCase):
    """A secure-capable product (syn-secure, #423): the sim device starts in
    factory state with secure.py's synthetic FDSK and serial number, the
    download goes through the secure project with the certificate."""

    APP = "M-00FA_A-2900-10-0000"

    def test_secure_sim_only_for_a_secure_product(self):
        self.assertEqual(capture.secure_sim("syn-minimal", "A"), "")
        # The pair knx-sim/tests/synthetic_products.rs builds the device with.
        self.assertEqual(capture.secure_sim("syn-secure", self.APP),
                         "  security:\n    status: factory\n    tool_key: 5e2c820a4e1b264302afda130b69c915\n"
                         "  properties:\n  - object: 0\n    pid: 11\n    value: 00fad4730c98\n")
        self.assertIn("    status: factory\n", capture.sim_yaml("syn-secure", self.APP))

    def test_secure_run_passes_the_secure_flow(self):
        self.assertEqual(capture.secure_run("syn-minimal", self.APP), {})
        old = os.environ.get(secure.PASSWORD_ENV)
        os.environ[secure.PASSWORD_ENV] = "Synthetic1234!"
        try:
            kw = capture.secure_run("syn-secure", self.APP)
        finally:
            if old is None:
                del os.environ[secure.PASSWORD_ENV]
            else:
                os.environ[secure.PASSWORD_ENV] = old
        self.assertEqual(kw["project"], secure.PROJECT)
        self.assertEqual(kw["secure"], {"status": "factory", "tool_key": "5e2c820a4e1b264302afda130b69c915"})
        self.assertEqual(kw["properties"], [{"object": 0, "pid": 11, "value": "00fad4730c98"}])
        self.assertEqual(kw["flow_extra"], {"project_password": "Synthetic1234!",
                                            "certificate": "AD5NI4-YMTBPC-ZAQKJY-NSMQYC-V7NBGC-3JZEKR"})
        self.assertTrue(callable(kw["after_download"]))

    def test_secure_run_exports_the_keyring_under_the_synthetic_password(self):
        # The project password stays private; the keyring is committed next
        # to the capture, so it is exported under the public one (#423).
        old = os.environ.get(secure.PASSWORD_ENV)
        os.environ[secure.PASSWORD_ENV] = "Synthetic1234!"
        try:
            kw = capture.secure_run("syn-secure", self.APP)
        finally:
            if old is None:
                del os.environ[secure.PASSWORD_ENV]
            else:
                os.environ[secure.PASSWORD_ENV] = old
        calls = []
        kw["after_download"](lambda name, **body: calls.append((name, body)), Path("/tmp/run/out"))
        self.assertEqual(calls[0][0], "export_keyring")
        self.assertEqual(calls[0][1]["password"], capture.SYNTHETIC_KEYRING_PASSWORD)
        self.assertNotEqual(capture.SYNTHETIC_KEYRING_PASSWORD, "Synthetic1234!")
        # ETS's rule for the password the driver types.
        os.environ[secure.PASSWORD_ENV] = capture.SYNTHETIC_KEYRING_PASSWORD
        try:
            self.assertEqual(secure.password(), capture.SYNTHETIC_KEYRING_PASSWORD)
        finally:
            if old is None:
                del os.environ[secure.PASSWORD_ENV]
            else:
                os.environ[secure.PASSWORD_ENV] = old

    def test_oracle_row_names_the_keyring_of_a_secure_capture(self):
        row = capture.oracle_row("syn-secure", self.APP, "100.0", "loadctl=identical")
        self.assertIn("keyring=captures/synthetic/syn-secure/defaults/project.knxkeys", row)
        # A secure product plans with the key store of its model template (#858).
        self.assertTrue(row.endswith("dir=captures/synthetic/syn-secure/defaults/model"), row)
        self.assertNotIn("keyring=", capture.oracle_row("syn-minimal", "M-00FA_A-2700-10-0000"))
        # Derived on every capture, so a re-capture does not carry an old one.
        self.assertEqual(capture.carried_options("loadctl=identical", "keyring=old.knxkeys scope=par"),
                         "loadctl=identical scope=par")

    def test_keyring_args_decode_with_the_committed_keyring(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = Path(tmp)
            self.assertEqual(capture.keyring_args(dst)[0], [])
            (dst / capture.KEYRING_FILE).write_text("<Keyring/>")
            args, env = capture.keyring_args(dst)
            self.assertEqual(args, ["--keyring", str(dst / capture.KEYRING_FILE)])
            self.assertEqual(env["BUSSARD_KEYRING_PASSWORD"], capture.SYNTHETIC_KEYRING_PASSWORD)

    def test_portable_driver_commits_no_local_path(self):
        src = Path("/Users/someone/bussard/captures/ets-sweep/M-00FA_A-2900-10-14FD/plain-defaults")
        text = json.dumps({"keyring": str(src / "project.knxkeys"),
                           "keyring_remote": "C:\\Users\\vmuser\\ets-sweep\\keyrings\\x.knxkeys"})
        out = json.loads(capture.portable_driver(text, src, "captures/synthetic/syn-secure/defaults"))
        self.assertEqual(out, {"keyring": "captures/synthetic/syn-secure/defaults/project.knxkeys",
                               "keyring_remote": "<vm>\\keyrings\\x.knxkeys"})

    def test_write_driver_scrubs_a_variant_run(self):
        # copy_variant copied driver.json as it was; the connection list of a
        # run variant named the owner's gateway (#1054).
        with tempfile.TemporaryDirectory() as tmp:
            run, dst = Path(tmp) / "run", Path(tmp) / "dst"
            run.mkdir(); dst.mkdir()
            (run / "driver.json").write_text(json.dumps(
                {"connections": ["KNX IP (198.51.100.74:3671 - 1.1.200)", "knx-sim (127.0.0.1:3672)"],
                 "keyring": str(run / "project.knxkeys")}))
            capture.write_driver(run, dst, "captures/synthetic/syn-secure/apply")
            out = json.loads((dst / "driver.json").read_text())
        self.assertEqual(out["connections"], ["KNX IP (192.0.2.74:3671 - 1.1.200)", "knx-sim (127.0.0.1:3672)"])
        self.assertEqual(out["keyring"], "captures/synthetic/syn-secure/apply/project.knxkeys")

    def test_portable_driver_commits_no_lan_endpoint(self):
        text = json.dumps({"entries": ["KNX IP (10.20.30.74:3671 - 1.1.200)", "knx-sim (127.0.0.1:3672 Udp)"],
                           "value": "192.168.27.21"})
        out = json.loads(capture.portable_driver(text, Path("/nowhere"), "captures/synthetic/x/defaults"))
        self.assertEqual(out, {"entries": ["KNX IP (192.0.2.74:3671 - 1.1.200)", "knx-sim (127.0.0.1:3672 Udp)"],
                               "value": "192.168.27.21"})

    def test_synthetic_keyring_password_matches_the_oracle_test(self):
        # crates/bussard-cli/tests/it/offline_oracle.rs runs the synthetic
        # rows with the same password.
        rs = (Path(__file__).resolve().parents[2] / "crates" / "bussard-cli" / "tests" / "it"
              / "offline_oracle.rs").read_text()
        self.assertIn(f'const SYNTHETIC_KEYRING_PASSWORD: &str = "{capture.SYNTHETIC_KEYRING_PASSWORD}";', rs)

    def test_secure_run_needs_the_password(self):
        old = os.environ.pop(secure.PASSWORD_ENV, None)
        try:
            with self.assertRaises(SystemExit):
                capture.secure_run("syn-secure", self.APP)
        finally:
            if old is not None:
                os.environ[secure.PASSWORD_ENV] = old


class TestCaptureVariants(unittest.TestCase):
    def test_variant_steps_name_the_base_and_the_capture(self):
        steps = capture.variant_steps("syn-s7-0705", "other-app")
        self.assertEqual([(s["name"], s["product"]) for s in steps],
                         [("base", "syn-s7-hidden-default"), ("capture", "syn-s7-0705")])
        # A programmed System B device (#1056): another 07B0 application first.
        self.assertEqual([s["product"] for s in capture.variant_steps("syn-minimal", "other-app")],
                         ["syn-hidden-default", "syn-minimal"])
        self.assertEqual([s["mode"] for s in capture.variant_steps("syn-minimal", "partial")],
                         ["application", "partial"])

    def test_variant_steps_refuse_a_product_the_variant_does_not_run_on(self):
        with self.assertRaises(SystemExit):
            capture.variant_steps("syn-relseg-fill", "reload")

    def test_variant_options(self):
        self.assertEqual(capture.variant_options("syn-minimal", "links"),
                         "dir=captures/synthetic/syn-minimal/links/model")
        self.assertEqual(capture.variant_options("syn-minimal", "partial"),
                         "run=params base=captures/synthetic/syn-minimal/partial/base.pcapng "
                         "dir=captures/synthetic/syn-minimal/partial/model lsm=property")

    def test_model_template_links_and_parameters(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-minimal", "links", Path(tmp))
            device = (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text()
            # The switch object listens to both addresses, the status object sends.
            self.assertIn('0.listen = ["1/0/1", "1/0/2"]', device)
            self.assertIn('1.send = "1/0/3"', device)
            self.assertIn('"1/0/3"', (Path(tmp) / "model" / "groups.toml").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-param-calculation", "calc-input", Path(tmp))
            self.assertIn("delay-s = 500", (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-s7-0705", "reload", Path(tmp))
            self.assertFalse((Path(tmp) / "model").exists())

    def test_model_template_quotes_a_ref_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-module-repeat", "params", Path(tmp))
            device = (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text()
            self.assertIn('"portion-size@MD-1_M-1_MI-2_P-1_R-1" = 1000', device)
            self.assertIn("number-of-feeders = 2", device)

    def test_variant_options_of_the_1054_variants(self):
        self.assertEqual(capture.variant_options("syn-secure", "apply"),
                         "run=apply base=captures/synthetic/syn-secure/apply/base.pcapng "
                         "dir=captures/synthetic/syn-secure/apply/model lsm=property")
        self.assertEqual(capture.variant_options("syn-module-choose", "params"),
                         "dir=captures/synthetic/syn-module-choose/params/model")
        self.assertEqual(capture.variant_options("syn-param-calculation", "calc-overflow"),
                         "dir=captures/synthetic/syn-param-calculation/calc-overflow/model")
        # A System 7 parameter set into a fresh device keeps state=fresh.
        row = capture.oracle_row("syn-s7-0705", "A", variant="params",
                                 extra=capture.variant_options("syn-s7-0705", "params"))
        self.assertTrue(row.endswith("|dir=captures/synthetic/syn-s7-0705/params/model state=fresh"), row)
        # The secure partial plans with its own model and decodes with its keyring.
        row = capture.oracle_row("syn-secure", "A", variant="partial",
                                 extra=capture.variant_options("syn-secure", "partial"))
        self.assertIn("keyring=captures/synthetic/syn-secure/partial/project.knxkeys", row)
        self.assertEqual(row.count("dir="), 1)

    def test_apply_steps_link_then_partial(self):
        steps = capture.variant_steps("syn-minimal", "apply")
        self.assertEqual([(s["name"], s["mode"], s["links"]) for s in steps],
                         [("base", "application", [(0, "1/0/1"), (1, "1/0/3")]),
                          ("capture", "partial", [(0, "1/0/2")])])
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-minimal", "apply", Path(tmp))
            device = (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text()
            # The model holds the links after the change: both steps'.
            self.assertIn('0.listen = ["1/0/1", "1/0/2"]', device)
            self.assertIn('1.send = "1/0/3"', device)

    def test_partial_twice_splits_the_changes_by_step(self):
        # #1091: one change before each partial download, the base is the
        # defaults download and the first partial one.
        steps = capture.variant_steps("syn-property-param", "partial-twice")
        self.assertEqual([(s["name"], s["mode"], [c["label"] for c in s["params"]]) for s in steps],
                         [("base-1", "application", []), ("base-2", "partial", ["Delay (s)"]),
                          ("capture", "partial", ["Territory mark"])])
        self.assertTrue(capture.variant_options("syn-property-param", "partial-twice").startswith(
            "run=params base=captures/synthetic/syn-property-param/partial-twice/base.pcapng "))
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-property-param", "partial-twice", Path(tmp))
            device = (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text()
            # The model holds both changes: the state after the capture.
            self.assertIn("delay-s = 500\n", device)
            self.assertIn("territory-mark = 7\n", device)
        minimal = capture.variant_steps("syn-minimal", "partial-twice")
        self.assertEqual([c["label"] for c in minimal[-1]["params"]], ["Operating mode"])

    def test_apply_params_links_and_a_parameter_in_one_partial(self):
        # #1095: the third link and the parameter change before one partial.
        for product in ("syn-minimal", "syn-secure"):
            steps = capture.variant_steps(product, "apply-params")
            self.assertEqual([(s["mode"], s["links"], [c["label"] for c in s["params"]]) for s in steps],
                             [("application", [(0, "1/0/1"), (1, "1/0/3")], []),
                              ("partial", [(0, "1/0/2")], ["Delay (s)"])])
            self.assertIn("run=apply ", capture.variant_options(product, "apply-params"))
        with tempfile.TemporaryDirectory() as tmp:
            capture.model_template("syn-minimal", "apply-params", Path(tmp))
            device = (Path(tmp) / "model" / "devices" / "1.1.1.toml").read_text()
            self.assertIn("delay-s = 500\n", device)
            self.assertIn('0.listen = ["1/0/1", "1/0/2"]', device)

    def test_secure_fill_reset_variants(self):
        # #1081: another secure application first, unload then download,
        # assign then download, each on the secure-capable fill product.
        self.assertEqual([s["product"] for s in capture.variant_steps("syn-secure-fill", "other-app")],
                         ["syn-secure", "syn-secure-fill"])
        self.assertEqual([(s["name"], s["mode"]) for s in capture.variant_steps("syn-secure-fill", "unload-reload")],
                         [("base-1", "application"), ("base-2", "unload"), ("capture", "application")])
        self.assertEqual([s["mode"] for s in capture.variant_steps("syn-secure-fill", "assign")],
                         ["address", "application"])
        app = "M-00FA_A-2902-10-0000"
        # The assignment leaves the secure device in factory state; an
        # unload leaves it activated.
        self.assertIn("    status: factory\n", capture.sim_yaml("syn-secure-fill", app, variant="assign", base=True))
        self.assertIn("    status: activated\n",
                      capture.sim_yaml("syn-secure-fill", app, variant="unload-reload", base=True))

    def test_param_changes_refuse_a_bad_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "changes.toml"
            bad.write_text('[syn-minimal]\npartial = [{ page = "General", label = "Delay (s)", kind = "number", '
                           'value = "500", step = 0 }]\n')
            with mock.patch.object(capture, "CHANGES", bad), self.assertRaises(SystemExit):
                capture.param_changes("syn-minimal", "partial")

    def test_every_parameter_variant_has_its_changes(self):
        for variant in ("partial", "calc-input", "calc-overflow", "params"):
            for product in capture.VARIANTS[variant]["products"]:
                changes = capture.param_changes(product, variant)
                self.assertTrue(changes, f"{product} {variant}: no change in changes.toml")
                steps = capture.variant_steps(product, variant)
                self.assertEqual(steps[-1]["params"], changes)

    def test_changes_name_the_products_labels_and_pages(self):
        # Offline: each change's label is a parameter's text and its page a
        # block's text (a module page with its text argument filled in).
        import tomllib

        table = tomllib.loads(capture.CHANGES.read_text())
        for product, variants in table.items():
            spec = capture.generate_spec(product)
            labels = {p["text"] for p in spec["parameter"]}
            pages = {b["text"] for b in spec["dynamic"]["block"]}
            for md in spec.get("module_def", []):
                labels |= {p["text"] for p in md["parameter"]}
                pages |= {b["text"].split(" {{")[0] for b in md["block"]}
            for choose in spec["dynamic"].get("choose", []):
                for when in choose["when"]:
                    pages |= {b["text"] for b in when.get("block", [])}
                    pages |= {f"Perch {m['args']['ch']}" for m in when.get("module", []) if "ch" in m["args"]}
            for variant, changes in variants.items():
                for ch in changes:
                    self.assertIn(ch["label"], labels, f"{product} {variant}")
                    self.assertIn(ch["page"], pages, f"{product} {variant}")

    def test_param_changes_refuse_an_incomplete_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "changes.toml"
            bad.write_text('[syn-minimal]\npartial = [{ page = "General", label = "Delay (s)", kind = "number", '
                           'value = "5", expect = "maybe" }]\n')
            with mock.patch.object(capture, "CHANGES", bad), self.assertRaises(SystemExit):
                capture.param_changes("syn-minimal", "partial")

    def test_find_page_by_name_and_occurrence(self):
        pages = [{"crumb": "General", "page": "General"}, {"crumb": "Feeder", "page": "Feeder"},
                 {"crumb": "Feeder", "page": "Feeder"}, {"crumb": "Perch B", "page": "Perch B"}]
        self.assertEqual(capture.find_page(pages, {"page": "Feeder", "page_n": 1}), {**pages[2], "page_n": 1})
        # The driver's own count (`param_pages`) is what `go_to_page` takes.
        listed = [{**p, "page_n": 1 if i == 2 else 0} for i, p in enumerate(pages)]
        self.assertEqual(capture.find_page(listed, {"page": "Feeder", "page_n": 1})["page_n"], 1)
        self.assertNotIn("page_n", capture.find_page(listed, {"page": "Feeder"}))
        self.assertIsNone(capture.find_page(pages, {"page": "Feeder", "page_n": 2}))
        self.assertEqual(capture.find_page(pages, {"page": "perch b"}), pages[3])

    @staticmethod
    def fake_flow(pages_seq, set_answers, read_answers):
        """A driver whose `param_pages` answers come from `pages_seq` in turn,
        `set_param` and `read_param` by label; records every call."""
        calls = []

        def flow(name, **body):
            calls.append((name, body))
            if name == "param_pages":
                return {"pages": pages_seq.pop(0) if len(pages_seq) > 1 else pages_seq[0]}
            if name == "set_param":
                return set_answers[body["label"]]
            if name == "read_param":
                return read_answers[body["label"]]
            raise AssertionError(name)

        return flow, calls

    def test_set_params_lists_pages_again_and_reads_back(self):
        general = {"crumb": "General", "page": "General"}
        perch_b = {"crumb": "Perch B", "page": "Perch B"}
        flow, calls = self.fake_flow(
            [[general], [general, perch_b]],
            {"Roost layout": {"set": True, "value": "two perches"},
             "Perch height": {"set": True, "value": "1000"}},
            {"Roost layout": {"shown": True, "row": {"value": "two perches"}},
             "Perch height": {"shown": True, "row": {"value": "1000"}}})
        done = capture.set_params(flow, "1.1.1", capture.param_changes("syn-module-choose", "params"))
        self.assertEqual([d["result"] for d in done], ["set", "set"])
        self.assertEqual([c[0] for c in calls],
                         ["param_pages", "set_param", "param_pages", "set_param", "read_param", "read_param"])
        # A choice goes by its text, a field with its kind.
        self.assertNotIn("kind", calls[1][1])
        self.assertEqual(calls[3][1]["kind"], "number")
        self.assertEqual(calls[3][1]["page"], perch_b)
        self.assertIsNone(capture.params_problem(done))

    def test_params_problem_accepts_the_expected_rewrite_and_hide(self):
        general = {"crumb": "General", "page": "General"}
        flow, _ = self.fake_flow(
            [[general]],
            {"Chore interval": {"set": True, "value": "1000"}, "Nap length": {"set": True, "value": "7"},
             "Operating mode": {"set": True, "value": "automatic"}},
            {"Chore interval": {"shown": True, "row": {"value": "300"}},
             "Nap length": {"shown": False, "why": "no row 'Nap length' on the page"},
             "Operating mode": {"shown": True, "row": {"value": "automatic"}}})
        done = capture.set_params(flow, "1.1.1", capture.param_changes("syn-assign-rewrite", "params"))
        self.assertEqual([d["result"] for d in done], ["lost", "lost", "set"])
        self.assertEqual(done[0]["shown"], "300")
        self.assertIsNone(capture.params_problem(done))
        # The same loss on a change that should stay shown stops the run.
        done[2].update({"result": "lost", "why": "ETS shows 'on'"})
        self.assertIn("lost after the last change", capture.params_problem(done))

    def test_params_problem_refusal_is_the_answer(self):
        general = {"crumb": "General", "page": "General"}
        flow, _ = self.fake_flow([[general]], {"Delay (s)": {"set": False, "unreachable": "value refused"}}, {})
        done = capture.set_params(flow, "1.1.1", capture.param_changes("syn-param-calculation", "calc-overflow"))
        self.assertEqual(done[0]["result"], "unreachable")
        self.assertIn("nothing downloaded", capture.params_problem(done))
        flow, _ = self.fake_flow([[general]], {"Delay (s)": {"set": False, "unreachable": "no row"}}, {})
        done = capture.set_params(flow, "1.1.1", capture.param_changes("syn-minimal", "partial"))
        self.assertIn("did not set", capture.params_problem(done))

    def test_secure_variant_sim_starts_activated_from_the_keyring(self):
        app = "M-00FA_A-2900-10-0000"
        yaml = capture.sim_yaml("syn-secure", app, variant="reload", base=True)
        self.assertIn("    status: activated\n", yaml)
        self.assertIn(f'keyring: {{ file: project.knxkeys, password: "{capture.SYNTHETIC_KEYRING_PASSWORD}" }}',
                      yaml)
        self.assertIn("replay:\n- base.pcapng\n", yaml)
        self.assertNotIn("tool_key", yaml)
        # A variant without earlier downloads starts in factory state.
        self.assertIn("    status: factory\n", capture.sim_yaml("syn-secure", app, variant="links"))


class TestOracleDeviceState(unittest.TestCase):
    """One function names the device state of the sweep's rows and of the
    synthetic captures' rows (#640, #488)."""

    def test_device_state_system_7_fresh_and_loaded(self):
        self.assertEqual(oracle.device_state("0701", "plain-defaults"), "state=fresh")
        self.assertEqual(oracle.device_state("0705", "defaults"), "state=fresh")
        self.assertEqual(oracle.device_state("0700", "reload"), "state=loaded")
        self.assertEqual(oracle.device_state("0705", "other-app"), "state=loaded")
        self.assertEqual(oracle.device_state("07B0", "plain-defaults"), "")
        self.assertEqual(oracle.device_state("", "plain-defaults"), "")

    def test_row_writes_state_fresh_on_a_system_7_defaults_capture(self):
        cap, prod = Path("/c/ets.pcapng"), Path("/p/x.knxprod")
        self.assertEqual(oracle.row("M-1_A-1", cap, prod, "0701"),
                         "1.1.1|/c/ets.pcapng|/p/x.knxprod|M-1_A-1|||state=fresh")
        self.assertEqual(oracle.row("M-1_A-1", cap, prod, "07B0"), "1.1.1|/c/ets.pcapng|/p/x.knxprod|M-1_A-1")

    def test_capture_device_state_is_the_oracle_one(self):
        self.assertEqual(capture.device_state("syn-s7-0705"), "state=fresh")
        self.assertEqual(capture.device_state("syn-s7-0705", "reload"), "state=loaded")
        self.assertEqual(capture.variant_options("syn-s7-0701", "other-app"), "state=loaded")
        self.assertEqual(capture.device_state("syn-minimal"), "")


class TestCaptureRecapture(unittest.TestCase):
    """A re-capture after an XML change needs a version bump; a capture must
    carry the spec's program version; hand-set row options survive (#650)."""

    ENTRY = {"product": "syn-x", "variant": "defaults", "signed_id": "M-00FA_A-2800-10-E9F3", "xml_sha256": "old"}

    def test_app_version_reads_the_version_octet(self):
        self.assertEqual(capture.app_version("M-00FA_A-280F-11-48D6"), 0x11)
        self.assertIsNone(capture.app_version(""))

    def test_recapture_refusal_first_capture_and_same_xml_pass(self):
        self.assertIsNone(capture.recapture_refusal("syn-x", "new", 0x10, []))
        self.assertIsNone(capture.recapture_refusal("syn-x", "old", 0x10, [self.ENTRY]))
        self.assertIsNone(capture.recapture_refusal("syn-y", "new", 0x10, [self.ENTRY]))

    def test_recapture_refusal_changed_xml_without_bump_names_the_bump(self):
        why = capture.recapture_refusal("syn-x", "new", 0x10, [self.ENTRY])
        self.assertIsNotNone(why)
        self.assertIn("to 0x11", why)
        self.assertIn("syn-x/product.toml", why)
        self.assertIn("defaults (M-00FA_A-2800-10-E9F3)", why)

    def test_recapture_refusal_changed_xml_with_bump_passes(self):
        self.assertIsNone(capture.recapture_refusal("syn-x", "new", 0x11, [self.ENTRY]))
        # A variant still on the old XML and version does not block the bumped capture.
        variant = {**self.ENTRY, "variant": "reload"}
        self.assertIsNone(capture.recapture_refusal("syn-x", "new", 0x11, [self.ENTRY, variant]))

    def test_recapture_refusal_committed_catalogue_passes(self):
        # Every committed capture matches its product's xml/ today.
        entries = capture.load_manifest()
        for e in entries:
            version = int(capture.generate_spec(e["product"])["application"]["version"])
            self.assertIsNone(capture.recapture_refusal(e["product"], capture.xml_sha256(e["product"]),
                                                        version, entries), e["product"])

    def test_version_mismatch_property_write(self):
        sha = "162dae9b"  # sha256 of 00fa270010, as knxtrace prints it
        self.assertIsNone(capture.version_mismatch([("sha", sha)], "00fa270010"))
        self.assertIn("sha=162dae9b", capture.version_mismatch([("sha", sha)], "00fa270011"))

    def test_version_mismatch_task_segment_and_none(self):
        self.assertIsNone(capture.version_mismatch([("app_id", "00fa280f11")] * 3, "00fa280f11"))
        self.assertIn("app_id=00fa280f10", capture.version_mismatch([("app_id", "00fa280f10")], "00fa280f11"))
        self.assertIn("no program version", capture.version_mismatch([], "00fa280f11"))

    def test_downloaded_versions_of_committed_captures(self):
        # Property form (07B0), LdCtrlTaskSegment in ops.txt (0705), the
        # memory-mapped records in the pcap (0701).
        for product, kind in (("syn-minimal", "sha"), ("syn-s7-0705", "app_id"), ("syn-s7-lsm5", "app_id")):
            found = capture.downloaded_versions(capture.OUT / product / "defaults")
            self.assertTrue(found and all(k == kind for k, _ in found), product)
            self.assertIsNone(capture.version_mismatch(found, capture.expected_program_version(product)), product)

    def test_memory_verdict_drops_a_property_only_difference(self):
        self.assertEqual(capture.memory_verdict(
            "differs", "par=ok(1) props=differs(bussard-only 1, ets-only 0, value 0)  (property writes differ)"),
            "identical")
        self.assertEqual(capture.memory_verdict("differs", "par=1/2@+0x0 props=ok(1)"), "differs")
        self.assertEqual(capture.memory_verdict("identical", "par=ok(1)"), "identical")

    def test_props_verdict_from_regions(self):
        self.assertEqual(capture.props_verdict("par=ok(256) props=ok(1)"), "identical")
        self.assertEqual(capture.props_verdict("props=differs(bussard-only 1, ets-only 0, value 0)"), "differs")
        self.assertEqual(capture.props_verdict("props=n/c(bussard 1, ETS ran no procedure write)"), "not-comparable")
        self.assertIsNone(capture.props_verdict("par=ok(256)"))

    def test_carried_options_recomputes_derived_and_keeps_hand_set(self):
        self.assertEqual(capture.carried_options("", "props=differs"), "")
        self.assertEqual(capture.carried_options("dir=a/model", "dir=b/model scope=memory phase=2"),
                         "dir=a/model scope=memory phase=2")
        self.assertEqual(capture.carried_options("state=loaded", "state=loaded expect=differs"), "state=loaded")

    def test_row_options_of_a_property_only_difference(self):
        # A headline the property writes alone turned `differs` (#669) is
        # recorded as the memory verdict, identical, with `props=differs`:
        # the script judges a row that pins props= on its memory (#683).
        regions = "par=ok(1) props=differs(bussard-only 1, ets-only 0, value 0)  (property writes differ)"
        verdicts = {"verdict": capture.memory_verdict("differs", regions), "coverage": "100.0%",
                    "loadctl": "identical", "props": capture.props_verdict(regions)}
        self.assertEqual(capture.row_options(verdicts), "loadctl=identical props=differs")

    def test_write_rows_reproduces_the_committed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "rows.txt"
            saved = capture.ROWS
            capture.ROWS = out
            try:
                capture.write_rows(capture.load_manifest())
            finally:
                capture.ROWS = saved
            self.assertEqual(out.read_text(), saved.read_text())

    def test_seq_verdict_from_regions(self):
        self.assertEqual(capture.seq_verdict("par=ok(3)  loadctl=ok(17)  seq=ok(23)"), "identical")
        self.assertEqual(capture.seq_verdict(
            "seq=differs(first: bussard-only mem-write obj4 (after load-control obj2 rel-segment))"), "differs")
        self.assertEqual(capture.seq_verdict("loadctl=n/c  seq=n/c"), "not-comparable")
        # bussard refused the product: nothing compared, nothing to pin.
        self.assertIsNone(capture.seq_verdict("neither side wrote memory  loadctl=n/c  seq=ok(0)"))
        self.assertIsNone(capture.seq_verdict("par=ok(256)"))

    def test_row_options_pins_seq_and_a_property_only_parity(self):
        self.assertEqual(capture.row_options({"verdict": "identical", "loadctl": "identical", "seq": "identical"}),
                         "loadctl=identical seq=identical")
        self.assertEqual(capture.row_options({"verdict": "identical", "loadctl": "identical", "seq": "differs"}),
                         "loadctl=identical seq=differs")
        self.assertEqual(capture.row_options({"verdict": "identical", "loadctl": "identical", "seq": "not-comparable"}),
                         "loadctl=identical")
        # A not-comparable headline with identical property writes (#1052).
        self.assertEqual(capture.row_options({"verdict": "not-comparable", "loadctl": "identical",
                                              "props": "identical", "seq": "identical"}),
                         "expect=not-comparable loadctl=identical props=identical seq=identical")

    def test_write_rows_keeps_options_the_manifest_does_not_hold(self):
        # #1054: capture.py rewrote rows.txt without the hand-set seq=identical
        # of 43 rows. A regeneration keeps every option of the committed row it
        # does not write, except a verdict the entry records.
        entry = {"product": "syn-minimal", "variant": "defaults", "application": "M-00FA_A-2700-10-0000",
                 "oracle": {"verdict": "identical", "coverage": "100.0%", "loadctl": "identical"}}
        recorded = {**entry, "variant": "no-ga", "oracle": {**entry["oracle"], "seq": "differs"}}
        with tempfile.TemporaryDirectory() as tmp:
            rows = Path(tmp) / "rows.txt"
            rows.write_text(
                "# head\n"
                "1.1.1|captures/synthetic/syn-minimal/defaults/ets.pcapng|x|a|n|100.0|loadctl=identical "
                "seq=identical scope=par\n"
                "1.1.1|captures/synthetic/syn-minimal/no-ga/ets.pcapng|x|a|n|100.0|loadctl=identical seq=identical\n")
            saved = capture.ROWS
            capture.ROWS = rows
            try:
                capture.write_rows([entry, recorded])
            finally:
                capture.ROWS = saved
            lines = [l for l in rows.read_text().splitlines() if not l.startswith("#")]
        self.assertTrue(lines[0].endswith("|loadctl=identical seq=identical scope=par"), lines[0])
        self.assertTrue(lines[1].endswith("|loadctl=identical seq=differs"), lines[1])

    def test_check_downloaded_version_accepts_a_partial_step_without_version(self):
        # syn-s7-0705/partial, syn-minimal/apply (#1054): the partial step
        # writes no version; the base step's full download carries it.
        expected = capture.expected_program_version("syn-s7-0705")
        steps = {Path("base"): [("app_id", expected)], Path("capture"): []}
        with mock.patch.object(capture, "downloaded_versions", side_effect=lambda d: steps[d]):
            capture.check_downloaded_version("syn-s7-0705", [Path("base"), Path("capture")])
            with self.assertRaises(SystemExit):
                capture.check_downloaded_version("syn-s7-0705", [Path("capture")])
            steps[Path("capture")] = [("app_id", "00fa280011")]
            with self.assertRaises(SystemExit):
                capture.check_downloaded_version("syn-s7-0705", [Path("base"), Path("capture")])

    def test_ops_header_names_the_committed_capture(self):
        # A run kept in the main checkout, finished with --no-ets in a worktree.
        text = "normalized operation sequence for 1.1.1 (/x/captures/ets-sweep/S/apply/capture/ets.pcapng)\nrest\n"
        got = capture.OPS_HEADER.sub(r"\g<1>captures/synthetic/syn-minimal/apply/ets.pcapng)", text, count=1)
        self.assertEqual(got.splitlines()[0],
                         "normalized operation sequence for 1.1.1 (captures/synthetic/syn-minimal/apply/ets.pcapng)")

    def test_save_row_shots_writes_the_png_and_keeps_its_name(self):
        import base64

        done = [{"label": "a", "result": "set"},
                {"label": "b", "result": "unreachable", "row_png": base64.b64encode(b"\x89PNG").decode()}]
        with tempfile.TemporaryDirectory() as tmp:
            capture.save_row_shots(done, Path(tmp))
            self.assertEqual((Path(tmp) / "row-2.png").read_bytes(), b"\x89PNG")
        self.assertEqual(done[1]["row_png"], "row-2.png")
        self.assertNotIn("row_png", done[0])



class TestCouplerAddress(unittest.TestCase):
    """A coupler product gets the line's coupler address 1.1.0 from ETS, and
    the sweep follows it (#876, M-0006 S85050100 and M-0009 STR131)."""

    def test_added_address_takes_the_address_ets_gave(self):
        import sweep

        # The catalog_add result of M-0006_A-E001-10-AE55-O0009, 2026-11-05.
        add = {"devices": [{"ia": "1.1.0", "y": 287}], "added": [{"ia": "1.1.0", "y": 287}],
               "row": {"name": "Funk/KNX Gateway AP"}, "ok": True}
        self.assertEqual(sweep.added_address(add, "1.1.1"), "1.1.0")
        # The usual case, nothing added, or an ambiguous add keep the address.
        self.assertEqual(sweep.added_address({"added": [{"ia": "1.1.1"}]}, "1.1.1"), "1.1.1")
        self.assertEqual(sweep.added_address({"added": []}, "1.1.1"), "1.1.1")
        self.assertEqual(sweep.added_address({"added": [{"ia": "1.1.0"}, {"ia": "1.1.2"}]}, "1.1.1"), "1.1.1")

    def run_one(self, added: str, refuse_restart: bool = False, catalog_add: dict | None = None,
                leftover: list | None = None, delete: dict | None = None):
        """sweep.run_one against a fake driver and sim: ETS adds the device
        at `added`; returns the result, the sims started and the flows."""
        from unittest import mock

        import sweep

        sims, flows = [], []

        class FakeSim:
            def __init__(self, c, knxprod, app, ia, *a, **kw):
                if sims and refuse_restart:
                    raise RuntimeError("knx-sim.exe exited at once: bad address")
                self.ia, self.stopped, self.fetched = ia, False, False
                sims.append(self)

            def lines(self):
                return ['load-state changed object=1 state=Loaded', 'device restarted master_reset=false']

            def stop(self):
                self.stopped = True

            def fetch_pcap(self, local):
                self.fetched = True
                Path(local).write_bytes(b"pcap")

            def loaded_objects(self):
                return {"1"}

            def last_telegram_age(self):
                return 0.0

        def driver(c, method, path, body, timeout=0):
            name = path.rsplit("/", 1)[1]
            flows.append((name, body.get("ia")))
            return {"devices": {"devices": leftover or []},
                    "delete_device": delete or {"deleted": True},
                    "catalog_add": catalog_add or {"added": [{"ia": added}], "row": {"name": "x"}},
                    "history": {"lines": ["Programmieren(Appl.): Abgeschlossen"]}}.get(name, {})

        hook_ia = []
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        with mock.patch.object(sweep, "RemoteSim", FakeSim), mock.patch.object(sweep.vm, "driver", driver), \
                mock.patch.object(sweep, "vm_now", return_value="2026-11-08 00:00:00"), \
                mock.patch.object(sweep, "ets_failed_since", return_value=[]), \
                mock.patch.object(sweep, "secure_enabled", return_value=False), \
                mock.patch.object(sweep, "save_repair", return_value={}), \
                mock.patch.object(sweep, "write_ops", return_value=3), \
                mock.patch.object(sweep, "CAPTURES", tmp), mock.patch.object(sweep.time, "sleep"):
            r = sweep.run_one(None, Path("p.knxprod"), "M-0006_A-E001-10-AE55-O0009", "85050100",
                              before_download=lambda flow, out, ia: hook_ia.append(ia) or {})
        return r, sims, flows, hook_ia

    def test_run_one_restarts_the_sim_at_the_coupler_address(self):
        r, sims, flows, hook_ia = self.run_one("1.1.0")
        self.assertEqual(r["outcome"], "captured", r)
        self.assertEqual((r["ia"], r["ia_requested"]), ("1.1.0", "1.1.1"))
        self.assertEqual([s.ia for s in sims], ["1.1.1", "1.1.0"])
        # The first sim stopped at the restart; the finally stopped and
        # fetched the second one.
        self.assertTrue(sims[0].stopped and not sims[0].fetched)
        self.assertTrue(sims[1].stopped and sims[1].fetched)
        self.assertIn(("download", "1.1.0"), flows)
        self.assertEqual(hook_ia, ["1.1.0"])

    def test_run_one_other_address_is_a_cleanup_failure(self):
        r, sims, flows, _ = self.run_one("1.1.2")
        self.assertEqual(r["outcome"], "driver-error-address", r)
        self.assertEqual(len(sims), 1)
        self.assertNotIn("download", [f for f, _ in flows])

    def test_run_one_leftover_device_not_deleted_is_a_cleanup_failure(self):
        r, _, flows, _ = self.run_one("1.1.1", leftover=[{"ia": "1.1.1"}], delete={"deleted": False})
        self.assertEqual(r["outcome"], "driver-error-cleanup", r)
        self.assertNotIn("catalog_add", [f for f, _ in flows])

    def test_run_one_refused_delete_is_a_cleanup_failure(self):
        # The flow error of 2026-11-08 (#997), met by the delete before the add.
        r, _, flows, _ = self.run_one("1.1.1", leftover=[{"ia": "1.1.1"}], delete={
            "ok": False, "error": "RuntimeError(\"button 'Ja' not on screen in (1300, 1380, 2800, 1580)\")"})
        self.assertEqual(r["outcome"], "driver-error-cleanup", r)
        self.assertNotIn("catalog_add", [f for f, _ in flows])

    def test_run_one_driver_cleanup_failure_in_catalog_add(self):
        r, _, _, _ = self.run_one("1.1.1", catalog_add={
            "ok": False, "error": "RuntimeError('clean-up failed: device 1.1.1 left in the project before the add')"})
        self.assertEqual(r["outcome"], "driver-error-cleanup", r)

    def test_run_one_refused_restart_is_sim_refused(self):
        r, sims, _, _ = self.run_one("1.1.0", refuse_restart=True)
        self.assertEqual(r["outcome"], "sim-refused", r)
        self.assertIn("exited at once", r["sim_refused"])

    def test_oracle_row_uses_the_recorded_address(self):
        self.assertEqual(oracle.entry_ia({"ia": "1.1.0"}), "1.1.0")
        self.assertEqual(oracle.entry_ia({"ia": None}), "1.1.1")
        self.assertEqual(oracle.entry_ia({}), "1.1.1")
        row = oracle.row("M-0006_A-E001-10-AE55-O0009", Path("c/ets.pcapng"), Path("p.knxprod"), "0701", ia="1.1.0")
        self.assertTrue(row.startswith("1.1.0|c/ets.pcapng|p.knxprod|M-0006_A-E001-10-AE55-O0009"))
        self.assertTrue(row.endswith("state=fresh"))


def load_driver():
    """The VM-side driver module, with pywinauto stubbed: only its pure
    helpers and flows with every screen access mocked run on the Mac."""
    import types
    from unittest import mock

    pw = types.ModuleType("pywinauto")
    pw.Desktop, pw.keyboard, pw.mouse = mock.MagicMock(), mock.MagicMock(), mock.MagicMock()
    app = types.ModuleType("pywinauto.application")
    app.Application = mock.MagicMock()
    with mock.patch.dict(sys.modules, {"pywinauto": pw, "pywinauto.application": app}):
        spec = importlib.util.spec_from_file_location(
            "ets_driver_under_test", Path(__file__).resolve().parent / "driver" / "ets_driver.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class TestDriverParamEditor(unittest.TestCase):
    """The parameter editor's pure helpers (#424): rows told apart by their
    pixels as measured on ETS 6.4.1 (Hager TYMS616D, 2026-11-10)."""

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    WHITE, GREY, BORDER, BLUE = (255, 255, 255), (242, 242, 242), (204, 204, 204), (219, 234, 255)

    def px_of(self, shapes):
        """A pixel function from shapes: (kind, x0, y0, x1, y1, colour);
        'fill' paints the box, 'frame' its 1 px border, 'ring' a circle of
        radius 16 centred at (x0, y0) (x1 the colour of its centre)."""
        def px(x, y):
            colour = self.WHITE
            for kind, x0, y0, x1, y1, c in shapes:
                if kind == "fill" and x0 <= x <= x1 and y0 <= y <= y1:
                    colour = c
                elif kind == "frame" and x0 <= x <= x1 and y0 <= y <= y1 and (x in (x0, x1) or y in (y0, y1)):
                    colour = c
                elif kind == "ring":
                    r2 = (x - x0) ** 2 + (y - y0) ** 2
                    if 14 ** 2 <= r2 <= 16 ** 2:
                        colour = c
                    elif x1 and r2 <= 8 ** 2:
                        colour = (195, 208, 221)
            return colour
        return px

    def test_classify_dropdown_by_grey_fill(self):
        px = self.px_of([("fill", 1625, 320, 2204, 366, self.GREY)])
        cells = [{"text": "Inaktiv", "x": 1637, "y": 334, "w": 68, "h": 18}]
        got = self.d.classify_control(px, 343, cells)
        self.assertEqual((got["kind"], got["value"]), ("dropdown", "Inaktiv"))

    def test_classify_checkbox_checked_and_clear(self):
        clear = self.px_of([("frame", 1625, 529, 1657, 561, self.BORDER)])
        self.assertEqual(self.d.classify_control(clear, 545, [])["value"], "0")
        checked = self.px_of([("fill", 1625, 387, 1657, 419, self.BLUE), ("fill", 1636, 400, 1646, 404, (113, 152, 204))])
        got = self.d.classify_control(checked, 403, [])
        self.assertEqual((got["kind"], got["value"]), ("checkbox", "1"))

    def test_classify_fixed_value_text_is_no_checkbox(self):
        # Hager TXB692F 'Ausgangskontakt  Schließer': a fixed setting shown
        # as text in the control column; its glyphs are dark near CONTROL_X.
        px = self.px_of([("fill", 1627, 380, 1631, 396, (60, 60, 60)), ("fill", 1640, 383, 1700, 393, (60, 60, 60))])
        got = self.d.classify_control(px, 389, [{"text": "Schließer", "x": 1626, "y": 377, "w": 95, "h": 18}])
        self.assertEqual((got["kind"], got["value"]), ("none", "Schließer"))

    def test_classify_number_field_with_spinner(self):
        px = self.px_of([("frame", 1625, 383, 2182, 427, self.BORDER), ("fill", 2165, 395, 2172, 399, (80, 80, 80)),
                         ("fill", 2165, 411, 2172, 415, (80, 80, 80))])
        got = self.d.classify_control(px, 405, [])
        self.assertEqual((got["kind"], got["box"][1]), ("number", 2182))

    def test_classify_radio_options_from_one_ocr_line(self):
        # OCR joined both options and read the second circle as an 'O'.
        px = self.px_of([("ring", 1641, 803, 1, 0, self.BORDER), ("ring", 1798, 803, 0, 0, self.BORDER)])
        cells = [{"text": "O", "x": 1625, "y": 787, "w": 32, "h": 32},
                 {"text": "Schalten O Rollladen und Jalousie", "x": 1668, "y": 793, "w": 385, "h": 20}]
        got = self.d.classify_control(px, 803, cells)
        self.assertEqual(got["kind"], "radio")
        self.assertEqual([o["text"] for o in got["options"]], ["Schalten", "Rollladen und Jalousie"])
        self.assertEqual(got["value"], "Schalten")

    def two_options(self, cy, dy=-5, selected=2):
        """The #1054 rows (row-1.png of syn-choose-partial-segment and
        syn-module-choose): two radio circles side by side whose centre sits
        `dy` px off the label's OCR centre `cy`, the `selected`-th filled."""
        rings = [("ring", 1640, cy + dy, int(selected == 1), 0, self.BORDER),
                 ("ring", 1801, cy + dy, int(selected == 2), 0, self.BORDER)]
        # OCR read the row as one line, the first circle as an 'O' (x 1625
        # to 1878 on the saved row).
        cells = [{"text": "O overwrite keep", "x": 1625, "y": cy - 12, "w": 253, "h": 20}]
        return rings, cells

    def test_classify_control_radio_circles_above_the_label_centre(self):
        # Measured on the saved rows: the ring runs y-20..y+11 at x 1640, its
        # centre 4 to 5 px above the row's y, where no ring was found.
        for dy in (-5, -4, 0, 4):
            rings, cells = self.two_options(1000, dy)
            got = self.d.classify_control(self.px_of(rings), 1000, cells)
            self.assertEqual(got["kind"], "radio", dy)
            self.assertEqual([(abs(o["x"] - x) <= 1, o["text"]) for o, x in zip(got["options"], (1640, 1801))],
                             [(True, "overwrite"), (True, "keep")], dy)
            self.assertEqual(got["value"], "keep", dy)
            self.assertTrue(all(abs(o["y"] - (1000 + dy)) <= 1 for o in got["options"]), got)
        rings, cells = self.two_options(1000, -5, selected=1)
        self.assertEqual(self.d.classify_control(self.px_of(rings), 1000, cells)["value"], "overwrite")

    def test_set_row_clicks_the_radio_circle_centre(self):
        rings, cells = self.two_options(1000, -5)
        row = {"label": "Keep the warming log on download", "y": 1000,
               **self.d.classify_control(self.px_of(rings), 1000, cells)}
        with mock.patch.object(self.d, "click") as click:
            self.assertEqual(self.d.set_row(row, {"value": "overwrite"}), ("overwrite", "overwrite"))
        (x, y), _ = click.call_args
        self.assertLessEqual(abs(x - 1640), 1)
        self.assertLessEqual(abs(y - 995), 1)

    def test_radio_row_leaves_a_neighbour_rows_circles(self):
        # A note between two radio rows ~58 px away: the window (RING_DY)
        # reaches neither row's circles.
        rings = self.two_options(942, -5)[0] + self.two_options(1058, -5)[0]
        cells = [{"text": "a note", "x": 1625, "y": 990, "w": 60, "h": 20}]
        self.assertEqual(self.d.radio_row(self.px_of(rings), 1000, cells)[0], [])
        self.assertEqual(self.d.classify_control(self.px_of(rings), 1000, cells)["kind"], "none")

    def e802_logic_row(self, first_cell):
        """Hager E802 'Art der logischen Funktion' (#1049, driver.json of
        params-1-0, 2026-11-13): circles at 1640 and 1753 on the row at 345
        (centre 341), the second selected; `first_cell` what OCR made of the
        first option."""
        px = self.px_of([("ring", 1640, 341, 0, 0, self.BORDER), ("ring", 1753, 341, 1, 0, self.BORDER)])
        cells = ([first_cell] if first_cell else []) + [{"text": "ODER", "x": 1773, "y": 335, "w": 52, "h": 18}]
        return px, cells

    def test_classify_control_radio_option_glued_to_its_circle(self):
        # OCR read the first circle and the short word after it as one word
        # starting left of the circle's centre: the option read ''.
        px, cells = self.e802_logic_row({"text": "OUND", "x": 1624, "y": 335, "w": 78, "h": 18})
        got = self.d.classify_control(px, 345, cells)
        self.assertEqual([o["text"] for o in got["options"]], ["UND", "ODER"])
        self.assertEqual(got["value"], "ODER")

    def test_fill_option_texts_reads_a_dropped_option_on_its_own(self):
        px, cells = self.e802_logic_row(None)
        row = {"label": "Art der logischen Funktion", "y": 345, **self.d.classify_control(px, 345, cells)}
        self.assertEqual([o["text"] for o in row["options"]], ["", "ODER"])
        boxes = []

        def read(bbox):
            boxes.append(bbox)
            return [{"text": "UND", "x": 1662, "y": 333, "w": 40, "h": 18}]
        self.d.fill_option_texts(row, read)
        self.assertEqual([o["text"] for o in row["options"]], ["UND", "ODER"])
        self.assertEqual(row["value"], "ODER")
        # Only the unread option's span, right of its circle to the next one.
        self.assertEqual(len(boxes), 1)
        self.assertTrue(1640 < boxes[0][0] and boxes[0][2] < 1753, boxes)

    def test_set_row_never_sets_an_unread_radio_option(self):
        # The #1049 record: pick chose the option read '' and stored ''.
        px, cells = self.e802_logic_row(None)
        row = {"label": "Art der logischen Funktion", "y": 345, **self.d.classify_control(px, 345, cells)}
        with mock.patch.object(self.d, "click") as click:
            with self.assertRaises(LookupError):
                self.d.set_row(row, {"pick": 0.909})
            with self.assertRaises(LookupError):
                self.d.set_row(row, {"value": ""})
        click.assert_not_called()

    def test_classify_control_checkbox_a_few_px_above_the_label_centre(self):
        px = self.px_of([("frame", 1625, 979, 1657, 1011, self.BORDER)])
        self.assertEqual(self.d.classify_control(px, 1000, [])["kind"], "checkbox")

    def test_next_page_moves_to_a_second_page_of_the_same_name(self):
        # syn-module-repeat (#1054): two child pages 'Feeder' under
        # 'General'; Down moves the highlight 40 px, the tree does not scroll.
        top = ("- General", 300)
        first = {"crumb": "General > Feeder", "page": "Feeder", "y": 340, "top": top}
        second = {**first, "y": 380}
        with mock.patch.object(self.d, "keys"), mock.patch.object(self.d, "selected_page", return_value=second):
            self.assertEqual(self.d.next_page(first), second)
        self.assertTrue(self.d.other_entry(first, second))
        # Scrolled by one entry: the same y is not another entry by y alone.
        self.assertFalse(self.d.other_entry(first, {**second, "y": 340, "top": ("Feeder", 300)}))
        self.assertFalse(self.d.channel_node_of(first, second))
        self.assertEqual(self.d.page_occurrence([{"crumb": "General", "page": "- General"}, first], second), 1)

    def test_go_to_page_clicks_the_nth_entry_of_a_name(self):
        lines = [{"text": "- General", "x": 700, "y": 300, "w": 90, "h": 20},
                 {"text": "Feeder", "x": 720, "y": 340, "w": 60, "h": 20},
                 {"text": "Feeder", "x": 720, "y": 380, "w": 60, "h": 20}]
        target = {"crumb": "General > Feeder", "page": "Feeder", "page_n": 1}
        with mock.patch.object(self.d, "scroll_tree", return_value=False), \
                mock.patch.object(self.d, "tree_entries", return_value=lines), \
                mock.patch.object(self.d, "selected_page", return_value={**target, "y": 380}), \
                mock.patch.object(self.d, "click") as click:
            got = self.d.go_to_page(target)
        click.assert_called_once_with(750, 390)
        self.assertEqual(got["page_n"], 1)

    def test_split_at_circles_leading_circle_letter(self):
        cells = [{"text": "Schalten", "x": 1668, "y": 795, "w": 87, "h": 18},
                 {"text": "O Rollladen und Jalousie", "x": 1783, "y": 793, "w": 270, "h": 20}]
        got = self.d.split_at_circles(cells, [1640, 1792])
        self.assertEqual([(c["text"], c["x"] > 1792) for c in got], [("Schalten", False), ("Rollladen und Jalousie", True)])

    def test_merge_labels_wrapped_lines(self):
        lines = [{"text": "Umschalten, Dauer/Zeitbetrieb", "x": 1146, "y": 439, "w": 322, "h": 21},
                 {"text": "für Schaltobjekt", "x": 1144, "y": 471, "w": 166, "h": 24},
                 {"text": "Zusätzliches Schaltobjekt", "x": 1144, "y": 573, "w": 264, "h": 24},
                 {"text": "Inaktiv", "x": 1637, "y": 331, "w": 68, "h": 18}]
        got = self.d.merge_labels(lines)
        self.assertEqual([l["text"] for l in got], ["Umschalten, Dauer/Zeitbetrieb für Schaltobjekt",
                                                     "Zusätzliches Schaltobjekt"])

    def test_alike_digits_must_agree(self):
        self.assertTrue(self.d._alike("Ausqanq 11: Funktionsfreiqabe", "Ausgang 11: Funktionsfreigabe"))
        self.assertTrue(self.d._alike("- Al-16: Handbetrieb schalten", "- A1-16: Handbetrieb schalten"))
        self.assertFalse(self.d._alike("Ausgang 1: Funktionsfreigabe", "Ausgang 2: Funktionsfreigabe"))

    def test_alike_standalone_letters_must_agree(self):
        # Issue #1050: MDT inputs are named by letter; the walk stopped at
        # 'Eingang B:', taken for 'Eingang A:'.
        alike = self.d._alike
        self.assertFalse(alike("Eingang A:", "Eingang B:"))
        self.assertFalse(alike("Eingänge A-P > Eingang A:", "Eingänge A-P > Eingang B:", 0.9))
        self.assertFalse(alike("Eingang C:", "Eingang D:"))
        self.assertFalse(alike("Eingänge gruppiert A / B:", "Eingänge gruppiert C / D:"))
        self.assertTrue(alike("Eingänge gruppiert A / B:", "Eingänge gruppiert A / B:"))
        self.assertTrue(alike("Eingänge A-P > Eingang A:", "Eingänge A-P > Einqang A:", 0.9))
        # A capital inside a word, or OCR's 'Al' for 'A1', is no letter name.
        self.assertTrue(alike("- Al-16: Handbetrieb schalten", "- A1-16: Handbetrieb schalten"))
        self.assertTrue(alike("Ausqanq 11: Funktionsfreiqabe", "Ausgang 11: Funktionsfreigabe"))

    def test_same_page_tells_letter_named_inputs_apart(self):
        a = {"crumb": "Eingänge A-P > Eingang A:", "page": "Eingang A:"}
        b = {"crumb": "Eingänge A-P > Eingang B:", "page": "Eingang B:"}
        self.assertFalse(self.d.same_page(a, b))
        self.assertTrue(self.d.same_page(a, dict(a)))

    def test_page_consistent_channel_and_lagging_highlight(self):
        ok = self.d.page_consistent
        self.assertTrue(ok({"crumb": "Ausgang 2 > Ausgang 2: Funktionsfreigabe", "page": "Ausgang 2: Funktionsfreigabe"}))
        # A channel node selected highlights its first page.
        self.assertTrue(ok({"crumb": "Ausgang 2", "page": "Ausgang 2: Funktionsfreigabe"}))
        self.assertTrue(ok({"crumb": "Ausgang 5 > ...", "page": "Ausgang 4: Funktionsfreigabe"}))
        # The breadcrumb moved on, the highlight not yet.
        self.assertFalse(ok({"crumb": "Ausgang 1 > - A1: Zeiten für Schaltobjekt", "page": "Ausgang 1: Funktionsfreigabe"}))

    def walk(self, last, pages, stuck_at=None):
        """walk_pages over `pages`, End selecting `last`; Down from
        `stuck_at` moves nothing the first time."""
        from unittest import mock

        seq = [{"crumb": c, "page": c.rsplit(">", 1)[-1].strip()} for c in pages]
        state = {"i": 0, "stuck": stuck_at}

        def next_page(current):
            if state["stuck"] is not None and current["crumb"] == state["stuck"]:
                state["stuck"] = None
                return None
            state["i"] += 1
            return seq[state["i"]] if state["i"] < len(seq) else None
        first = {**seq[0], "last": {"crumb": last, "page": last.rsplit(">", 1)[-1].strip()}}
        with mock.patch.object(self.d, "first_page", return_value=first), \
                mock.patch.object(self.d, "next_page", side_effect=next_page), \
                mock.patch.object(self.d, "log"):
            got = [p["crumb"] for _, p in self.d.walk_pages()]
        return got, self.d.WALK["short"]

    def test_walk_pages_goes_past_a_collapsed_last_channel(self):
        # End selects the node of 'Ausgang 9', collapsed; its pages appear
        # once the walk expands it and are walked too.
        pages = ["Allgemein", "Ausgang 9", "Ausgang 9 > Ausgang 9: Funktionsfreigabe", "Ausgang 9 > - A9: Zeiten"]
        self.assertEqual(self.walk("Ausgang 9", pages), (pages, False))

    def test_walk_pages_retries_a_slow_down_before_the_last_entry(self):
        pages = ["Allgemein", "Ausgang 1 > Ausgang 1: Funktionsfreigabe", "Information > Versionen"]
        self.assertEqual(self.walk("Information > Versionen", pages, stuck_at="Allgemein"), (pages, False))

    def test_walk_pages_short_when_down_moves_nothing_twice(self):
        from unittest import mock

        first = {"crumb": "Allgemein", "page": "Allgemein", "last": {"crumb": "Information > Versionen", "page": "Versionen"}}
        with mock.patch.object(self.d, "first_page", return_value=first), \
                mock.patch.object(self.d, "next_page", return_value=None), mock.patch.object(self.d, "log"):
            got = [p["crumb"] for _, p in self.d.walk_pages()]
        self.assertEqual((got, self.d.WALK["short"]), (["Allgemein"], True))

    def test_channel_node_of_keeps_two_channels_pages_of_one_name(self):
        node = {"crumb": "Ausgang 5 > ...", "page": "Ausgang 5: Funktionsfreigabe"}
        page = {"crumb": "Ausgang 5 > Ausgang 5: Funktionsfreigabe", "page": "Ausgang 5: Funktionsfreigabe"}
        self.assertTrue(self.d.channel_node_of(node, page))
        self.assertTrue(self.d.channel_node_of({"crumb": "Ausgang 5", "page": page["page"]}, page))
        k1 = {"crumb": "K1 > Allgemein", "page": "Allgemein"}
        k2 = {"crumb": "K2 > Allgemein", "page": "Allgemein"}
        self.assertFalse(self.d.channel_node_of(k1, k2))

    def test_choose_value_pick_among_others(self):
        row = {"label": "Preset", "value": "Inaktiv"}
        opts = ["Inaktiv", "1 Presetobjekt", "2 Presetobjekten"]
        self.assertEqual(self.d.choose_value(row, {"pick": 0.7}, opts), "2 Presetobjekten")
        self.assertEqual(self.d.choose_value(row, {"pick": 0.0}, opts), "1 Presetobjekt")
        self.assertEqual(self.d.choose_value(row, {"value": "Inaktiv"}, opts), "Inaktiv")
        with self.assertRaises(LookupError):
            self.d.choose_value(row, {"pick": 0.5}, ["Inaktiv"])


class TestDriverSession1054(unittest.TestCase):
    """Driver failures of the #1054 capture session (2026-11-12)."""

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    def test_popup_lists_open_tolerates_a_vanished_popup(self):
        # pick_option's "dropdown closed" wait queried a popup that had closed
        # (InvalidWindowHandle), twice on the MDT 00B1 rerun of #1050.
        gone = mock.MagicMock()
        gone.descendants.side_effect = RuntimeError("InvalidWindowHandle")
        empty = mock.MagicMock()
        empty.descendants.return_value = []
        with mock.patch.object(self.d, "ets_popups", return_value=[gone, empty]):
            self.assertFalse(self.d.popup_lists_open())
        listing = mock.MagicMock()
        listing.descendants.return_value = [object()]
        with mock.patch.object(self.d, "ets_popups", return_value=[gone, listing]):
            self.assertTrue(self.d.popup_lists_open())

    def test_pick_option_waits_on_a_closing_popup_without_raising(self):
        text = mock.MagicMock()
        text.window_text.return_value = "overwrite"
        item = mock.MagicMock()
        item.descendants.return_value = [text]
        pop = mock.MagicMock()
        calls = {"n": 0}

        def descendants(control_type=None):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("InvalidWindowHandle")  # closed after the click
            return [item]
        pop.descendants.side_effect = descendants
        with mock.patch.object(self.d, "ets_popups", return_value=[pop]), mock.patch.object(self.d, "log"):
            self.assertTrue(self.d.pick_option("overwrite"))
        item.click_input.assert_called_once()

    def test_catalog_layout_retries_ensure_layout_until_the_panel_is_back(self):
        # After the parameter editor the Katalog panel stayed collapsed and the
        # next catalog_search read no rows; ensure_layout failed once right
        # after a download.
        buttons = iter([{"y": 2387}, {"y": 2387}, {"y": 1356}])
        ensure = mock.MagicMock(return_value={"did": ["katalog"]})
        with mock.patch.object(self.d, "catalog_import_button", side_effect=lambda: next(buttons)), \
                mock.patch.object(self.d, "ensure_layout", ensure), \
                mock.patch.object(self.d, "wait_busy"), mock.patch.object(self.d.time, "sleep"):
            got = self.d.catalog_layout()
        self.assertEqual((got["ok"], got["tries"], ensure.call_count), (True, 2, 2))
        with mock.patch.object(self.d, "catalog_import_button", return_value={"y": 1354}), \
                mock.patch.object(self.d, "ensure_layout") as untouched:
            self.assertTrue(self.d.catalog_layout()["ok"])
        untouched.assert_not_called()

    def test_catalog_search_restores_the_layout_first(self):
        with mock.patch.object(self.d, "catalog_layout") as layout, \
                mock.patch.object(self.d, "catalog_dy", return_value=0), \
                mock.patch.object(self.d, "type_search"), mock.patch.object(self.d, "click"), \
                mock.patch.object(self.d, "ocr", return_value=[]), mock.patch.object(self.d.time, "sleep"):
            self.d.flow_catalog_search({"term": "NEST-MOSS"})
        layout.assert_called_once()

    def test_walk_pages_expands_a_collapsed_entry(self):
        # syn-module-repeat: after 'Number of feeders' = 2 the tree showed
        # only '+ General'; its Feeder pages appear once it is expanded.
        general = {"crumb": "General", "page": "+ General"}
        feeder = {"crumb": "General > Feeder", "page": "Feeder"}
        selected = iter([{"crumb": "General", "page": "General"}])
        expanded = {"done": False}

        def keys(k):
            if k == "{RIGHT}":
                expanded["done"] = True

        def nxt(page):
            return feeder if expanded["done"] and page["page"] == "+ General" else None
        with mock.patch.object(self.d, "first_page", return_value={**general, "last": None}), \
                mock.patch.object(self.d, "next_page", side_effect=nxt), \
                mock.patch.object(self.d, "keys", side_effect=keys), \
                mock.patch.object(self.d, "selected_page", side_effect=lambda: next(selected)), \
                mock.patch.object(self.d, "log"):
            pages = [p["page"] for _, p in self.d.walk_pages(5)]
        self.assertEqual(pages, ["+ General", "Feeder"])


class TestDriverProjectNames(unittest.TestCase):
    """OCR splits 'ets-sweep-secure' into 'ets-sweep' and '-secure' (start
    page tiles, 2026-11-10, #423): neither project may pass for the other."""

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    # The start page's tile names as OCR read them (2026-11-10): the secure
    # tile's second fragment sits 5 px lower.
    TILES = [
        {"text": "ets-sweep", "x": 171, "y": 1246, "w": 162, "h": 31},
        {"text": "Demohouse / Alpha", "x": 731, "y": 1246, "w": 280, "h": 31},
        {"text": "ets-sweep", "x": 1291, "y": 1246, "w": 162, "h": 31},
        {"text": "-secure", "x": 1457, "y": 1251, "w": 116, "h": 18},
    ]

    def test_whole_name_hits_tiles(self):
        self.assertEqual([h["x"] for h in self.d.whole_name_hits(self.TILES, "ets-sweep")], [171])
        self.assertEqual([h["x"] for h in self.d.whole_name_hits(self.TILES, "ets-sweep-secure")], [1291])

    def test_project_tile_reads_split_names(self):
        with mock.patch.object(self.d, "ocr", return_value=self.TILES):
            self.assertEqual(self.d.project_tile("ets-sweep")["x"], 171)
            self.assertEqual(self.d.project_tile("ets-sweep-secure")["x"], 1291)

    def test_project_tab_hit_never_takes_the_secure_tab_for_ets_sweep(self):
        tabs = [{"text": "ets-sweep", "x": 1291, "y": 30, "w": 162, "h": 31},
                {"text": "-secure", "x": 1457, "y": 35, "w": 116, "h": 18}]
        with mock.patch.object(self.d, "ocr", return_value=tabs):
            self.assertIsNone(self.d.project_tab_hit("ets-sweep"))
            self.assertEqual(self.d.project_tab_hit("ets-sweep-secure")["x"], 1291)


class TestDriverDeleteDialog(unittest.TestCase):
    """The delete confirmation's buttons carry an icon OCR reads in front of
    the word, and a dialog left open must not stop the run (#997)."""

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    # PR #878's strip (1300, 1380, 2800, 1580): a catalog row shares it, the
    # check mark glued to Ja, the dialog grown by a two-line device name.
    ROWS_878 = [
        {"text": "Secure, Schalter/Jalousie 8-fach", "x": 1310, "y": 1400, "w": 520, "h": 30},
        {"text": "√Ja", "x": 2340, "y": 1462, "w": 66, "h": 30},
        {"text": "X Nein", "x": 2480, "y": 1462, "w": 120, "h": 30},
    ]
    # 2026-11-08 (#997): the dialog of BE-BZS86.01, Ja at about x 2380.
    ROWS_997 = [
        {"text": "Löschen", "x": 1260, "y": 1010, "w": 120, "h": 30},
        {"text": "Möchten Sie die markierten Objekte wirklich löschen?", "x": 1400, "y": 1250, "w": 900, "h": 30},
        {"text": "v Ja", "x": 2340, "y": 1400, "w": 80, "h": 32},
        {"text": "X Nein", "x": 2480, "y": 1400, "w": 120, "h": 32},
    ]

    def assert_inside_word(self, hit, row, word):
        # The word is the line's last characters: the click lies in them.
        cw = row["w"] / len(row["text"])
        start = row["x"] + (len(row["text"]) - len(word)) * cw
        self.assertGreaterEqual(hit["click_x"], start, hit)
        self.assertLessEqual(hit["click_x"], row["x"] + row["w"], hit)
        self.assertEqual(hit["click_y"], row["y"] + row["h"] // 2)

    def test_button_hit_ja_followed_by_nein_on_one_line(self):
        # OCR joined both buttons of the delete confirmation (2026-11-09):
        # 'Ja' is matched as a whole word and the click lands on it, not on
        # 'Nein'; the same line also yields 'Nein'.
        line = {"text": "√ Ja X Nein", "x": 2340, "y": 1405, "w": 220, "h": 24}
        ja = self.d.button_hit([line], "Ja")
        nein = self.d.button_hit([line], "Nein")
        self.assertIsNotNone(ja)
        self.assertIsNotNone(nein)
        self.assertLess(ja["click_x"], nein["click_x"])
        cw = 220 / len("√ Ja X Nein")
        self.assertEqual(ja["click_x"], 2340 + int((2 + 1) * cw))
        self.assertIsNone(self.d.button_hit([{"text": "Secure, Schalter/Jalousie 8-fach", "x": 0, "y": 0, "w": 300, "h": 20}], "Ja"))

    def test_ja_beside_nein_from_the_nein_hit(self):
        # OCR of 2026-11-09 read the delete confirmation's 'Nein' at x 2584
        # and no 'Ja' at all; the click lands in the word left of it.
        nein = {"text": "Nein", "x": 2584, "y": 1468, "w": 60, "h": 24, "click_x": 2614, "click_y": 1480}
        hit = self.d.ja_beside_nein(nein)
        self.assertEqual((hit["click_x"], hit["click_y"]), (2456, 1480))
        self.assertIsNone(self.d.ja_beside_nein(None))

    def test_ja_on_the_line_of_nein_skips_a_catalog_cell(self):
        # A catalog row's "SL Ready" cell reads 'Ja' inside the search region;
        # the button is the 'Ja' on Nein's line (2026-11-09).
        cell = {"text": "Ja", "x": 2300, "y": 1499, "w": 24, "h": 20, "click_x": 2312, "click_y": 1509}
        btn = {"text": "√ Ja", "x": 2440, "y": 1468, "w": 60, "h": 24, "click_x": 2480, "click_y": 1480}
        nein = {"text": "X Nein", "x": 2538, "y": 1468, "w": 100, "h": 24, "click_x": 2600, "click_y": 1480}
        self.assertIs(self.d.ja_on_the_line_of([cell, btn], nein), btn)
        self.assertIsNone(self.d.ja_on_the_line_of([cell], nein))
        self.assertIs(self.d.ja_on_the_line_of([cell], None), cell)

    def test_result_ok_finds_the_button_or_falls_back(self):
        # The import result panel's OK by OCR (2026-11-09: at 2416, 1486),
        # else the position of 2026-10-27.
        line = {"text": "OK", "x": 2404, "y": 1476, "w": 28, "h": 20}
        hit = self.d.result_ok([line])
        self.assertEqual(hit["click_y"], 1486)
        self.assertTrue(2404 <= hit["click_x"] <= 2432, hit)
        self.assertEqual(self.d.result_ok([]), {"click_x": 2488, "click_y": 1528})

    def test_button_hit_ja_with_icon_prefix(self):
        for prefix in ("√ ", "v ", "V ", "✓ ", ""):
            rows = [*self.ROWS_997[:2], {**self.ROWS_997[2], "text": prefix + "Ja"}, self.ROWS_997[3]]
            hit = self.d.button_hit(rows, "Ja")
            self.assertIsNotNone(hit, prefix)
            self.assertEqual(hit["y"], 1400)
            self.assert_inside_word(hit, rows[2], "Ja")

    def test_button_hit_pr_878_region(self):
        hit = self.d.button_hit(self.ROWS_878, "Ja")
        self.assertEqual(hit["text"], "√Ja")
        self.assert_inside_word(hit, self.ROWS_878[1], "Ja")
        nein = self.d.button_hit(self.ROWS_878, "Nein")
        self.assert_inside_word(nein, self.ROWS_878[2], "Nein")

    def test_button_hit_rejects_other_text(self):
        rows = [{"text": "Secure, Schalter/Jalousie 8-fach", "x": 0, "y": 0, "w": 500, "h": 30},
                {"text": "Gerät 1.1.1 Ja", "x": 0, "y": 40, "w": 200, "h": 30},
                {"text": "Jalousie", "x": 0, "y": 80, "w": 100, "h": 30},
                {"text": "X Nein", "x": 0, "y": 120, "w": 100, "h": 30}]
        self.assertIsNone(self.d.button_hit(rows, "Ja"))

    def test_click_button_clicks_inside_the_word(self):
        from unittest import mock

        with mock.patch.object(self.d, "ocr", return_value=self.ROWS_997), \
                mock.patch.object(self.d, "click") as click:
            self.d.click_button("Ja", self.d.LAYOUT["delete_yes"])
        (x, y), _ = click.call_args
        self.assertTrue(2340 + 2 * 80 / 4 <= x <= 2420, x)
        self.assertEqual(y, 1416)

    def test_click_button_missing_raises(self):
        from unittest import mock

        with mock.patch.object(self.d, "ocr", return_value=self.ROWS_997[:2]), \
                mock.patch.object(self.d, "click") as click:
            with self.assertRaisesRegex(RuntimeError, "button 'Ja' not on screen"):
                self.d.click_button("Ja", self.d.LAYOUT["delete_yes"])
        click.assert_not_called()

    def test_leftover_delete_dialog_found_by_title_and_nein(self):
        hit = self.d.leftover_delete_dialog(self.ROWS_997)
        self.assertIsNotNone(hit)
        self.assert_inside_word(hit, self.ROWS_997[3], "Nein")
        # A context menu holds 'Löschen' but no 'Nein'; a dialog without the
        # title is not the delete confirmation.
        self.assertIsNone(self.d.leftover_delete_dialog([self.ROWS_997[0], {"text": "Gerät neu starten", "x": 0, "y": 0, "w": 9, "h": 9}]))
        self.assertIsNone(self.d.leftover_delete_dialog(self.ROWS_997[1:]))
        self.assertIsNone(self.d.leftover_delete_dialog([]))

    def test_close_delete_dialog_clicks_nein(self):
        from unittest import mock

        with mock.patch.object(self.d, "ocr", return_value=self.ROWS_997), \
                mock.patch.object(self.d, "click") as click, mock.patch.object(self.d.time, "sleep"), \
                mock.patch.object(self.d, "keys"), mock.patch.object(self.d, "log"):
            self.assertTrue(self.d.close_delete_dialog())
        (x, _), _ = click.call_args
        self.assertTrue(2480 + 2 * 120 / 6 <= x <= 2600, x)
        with mock.patch.object(self.d, "ocr", return_value=[]), mock.patch.object(self.d, "click") as click:
            self.assertFalse(self.d.close_delete_dialog())
        click.assert_not_called()

    def confirm(self, screens: list):
        """confirm_delete with OCR answering `screens` in turn; returns the
        error (or None) and the clicked points."""
        from unittest import mock

        shots = iter(screens)
        with mock.patch.object(self.d, "ocr", side_effect=lambda *a, **k: next(shots)), \
                mock.patch.object(self.d, "click") as click, mock.patch.object(self.d.time, "sleep"), \
                mock.patch.object(self.d, "keys"), mock.patch.object(self.d, "log"):
            try:
                self.d.confirm_delete()
                err = None
            except RuntimeError as exc:
                err = exc
        return err, [c.args for c in click.call_args_list]

    def test_confirm_delete_clicks_ja_and_checks_the_dialog_closed(self):
        err, clicks = self.confirm([self.ROWS_997, []])
        self.assertIsNone(err)
        self.assertEqual(len(clicks), 1)
        self.assertTrue(2340 + 2 * 80 / 4 <= clicks[0][0] <= 2420, clicks)

    def test_confirm_delete_closes_a_dialog_still_open_with_nein(self):
        # The click on Ja missed: the dialog is there after it.
        # The first look, DELETE_POLLS looks after the click, one after Enter, the close.
        err, clicks = self.confirm([self.ROWS_997] * (self.d.DELETE_POLLS + 3))
        self.assertIn("still open", str(err))
        self.assertIn("closed with Nein", str(err))
        self.assertEqual(len(clicks), 2)
        self.assertTrue(2480 + 2 * 120 / 6 <= clicks[1][0] <= 2600, clicks)

    def test_confirm_delete_without_ja_clicks_beside_nein_then_closes(self):
        # OCR reads 'Nein' but no 'Ja' (2026-11-09): the Ja is clicked at its
        # place beside Nein; the dialog still open afterwards is closed with
        # Nein and the error says so.
        no_ja = [r for r in self.ROWS_997 if "Ja" not in r["text"]]
        err, clicks = self.confirm([no_ja] * (self.d.DELETE_POLLS + 3))
        self.assertIn("still open after 'Ja'", str(err))
        self.assertIn("closed with Nein", str(err))
        self.assertEqual(len(clicks), 2)
        nein = self.d.button_hit(no_ja, "Nein")
        self.assertEqual(clicks[0][0], nein["x"] - 128)

    def test_confirm_delete_waits_for_a_slow_delete(self):
        # A Data Secure device's confirmation stays a few looks (#423).
        err, clicks = self.confirm([self.ROWS_997, self.ROWS_997, self.ROWS_997, []])
        self.assertIsNone(err)
        self.assertEqual(len(clicks), 1)

    def test_confirm_delete_without_ja_or_nein_reports_what_ocr_read(self):
        other = [r for r in self.ROWS_997 if "Ja" not in r["text"] and "Nein" not in r["text"]]
        err, clicks = self.confirm([other, other])
        self.assertIn("button 'Ja' not on screen", str(err))
        self.assertIn("OCR read", str(err))
        self.assertEqual(len(clicks), 0)

    def catalog_add(self, devices: list, delete):
        """flow_catalog_add up to its catalog search, with the screen mocked:
        `devices` are the device lists it reads in turn, `delete` stands in
        for flow_delete_device. Returns the exception and the deletes."""
        from unittest import mock

        class Reached(Exception):
            pass

        lists = iter(devices)
        deletes = []

        def fake_delete(req):
            deletes.append(req["ia"])
            return delete(req)

        d = self.d
        with mock.patch.multiple(d, require_project=mock.DEFAULT, dismiss_password_dialog=mock.DEFAULT,
                                 wait_busy=mock.DEFAULT, restore_tree_splitter=mock.DEFAULT,
                                 catalog_layout=mock.DEFAULT, close_delete_dialog=mock.DEFAULT), \
                mock.patch.object(d, "flow_devices", side_effect=lambda req: {"devices": next(lists)}), \
                mock.patch.object(d, "flow_delete_device", side_effect=fake_delete), \
                mock.patch.object(d, "catalog_dy", side_effect=Reached):
            try:
                d.flow_catalog_add({"project": "ets-sweep", "search": "X"})
            except Exception as exc:  # noqa: BLE001 - the test looks at which one
                return exc, deletes
        return None, deletes

    def test_catalog_add_deletes_a_leftover_device_first(self):
        exc, deletes = self.catalog_add([[{"ia": "1.1.1", "y": 287}], []], lambda req: {"deleted": True})
        self.assertEqual(type(exc).__name__, "Reached", exc)
        self.assertEqual(deletes, ["1.1.1"])

    def test_catalog_add_failed_cleanup_stops_before_the_add(self):
        exc, deletes = self.catalog_add([[{"ia": "1.1.1", "y": 287}]], lambda req: {"deleted": False})
        self.assertRegex(str(exc), "clean-up failed: device 1.1.1")
        self.assertEqual(deletes, ["1.1.1"])

        def refused(req):
            raise RuntimeError("button 'Ja' not on screen in (1300, 1380, 2800, 1580)")

        exc, _ = self.catalog_add([[{"ia": "1.1.1", "y": 287}]], refused)
        self.assertRegex(str(exc), "clean-up failed: device 1.1.1 .*'Ja' not on screen")

    def test_catalog_add_empty_project_deletes_nothing(self):
        exc, deletes = self.catalog_add([[]], lambda req: {"deleted": True})
        self.assertEqual(type(exc).__name__, "Reached", exc)
        self.assertEqual(deletes, [])


class FakeImage:
    """The few PIL image calls the driver's pixel checks make."""

    def __init__(self, w: int, h: int, fill=(255, 255, 255)):
        self.width, self.height = w, h
        self.px = [[fill] * w for _ in range(h)]

    def put(self, x0: int, y0: int, x1: int, y1: int, rgb) -> "FakeImage":
        for y in range(y0, y1):
            for x in range(x0, x1):
                self.px[y][x] = rgb
        return self

    def convert(self, mode: str):
        if mode == "RGB":
            return self
        grey = FakeImage(self.width, self.height)
        grey.px = [[sum(p) // 3 for p in row] for row in self.px]
        return grey

    def getpixel(self, xy):
        return self.px[xy[1]][xy[0]]

    def getdata(self):
        return [p for row in self.px for p in row]


class TestDriverLinkDialog(unittest.TestCase):
    """ETS refuses an address of another size than the object's, and the
    dialog it leaves open must not stop the run (#478)."""

    RED = (220, 30, 40)
    TITLE = {"text": "Mit Gruppenadresse verbinden", "x": 1560, "y": 600, "w": 500, "h": 40}
    BUTTONS = [{"text": "00 Verbinden", "x": 2070, "y": 1866, "w": 200, "h": 40},
               {"text": "X Abbrechen", "x": 2310, "y": 1866, "w": 200, "h": 40}]

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    def field(self, framed: bool) -> FakeImage:
        img = FakeImage(60, 24).put(4, 8, 10, 16, self.RED)  # the red address icon
        if framed:
            img.put(0, 0, 60, 1, self.RED).put(0, 23, 60, 24, self.RED)
            img.put(0, 0, 1, 24, self.RED).put(59, 0, 60, 24, self.RED)
        return img

    def test_object_size_normalised(self):
        self.assertEqual(self.d.object_size("1 bit"), "1 bit")
        self.assertEqual(self.d.object_size("1/0/2 1 byte"), "1 byte")
        self.assertEqual(self.d.object_size("14 Bytes"), "14 bytes")
        self.assertEqual(self.d.object_size("4 bit"), "4 bit")
        self.assertIsNone(self.d.object_size("Gruppe 1 - Zeigt an"))

    def test_red_frame_needs_the_frame_not_the_icon(self):
        self.assertTrue(self.d.red_frame(self.field(True)))
        self.assertFalse(self.d.red_frame(self.field(False)))

    def test_greyed_out_by_ink(self):
        self.assertTrue(self.d.greyed_out(FakeImage(40, 10).put(5, 3, 30, 7, (150, 150, 150))))
        self.assertFalse(self.d.greyed_out(FakeImage(40, 10).put(5, 3, 30, 7, (40, 40, 40))))

    def screen(self, open_states: list[bool], framed: bool = True, list_lines=None):
        """Mocks for the link dialog: `open_states`, what successive title
        checks see."""
        from unittest import mock

        states = iter(open_states)
        d = self.d

        def ocr(bbox=None, **_):
            if bbox == d.LINK_BUTTONS:
                return self.BUTTONS
            if bbox == d.LINK_VERBINDEN:
                return self.BUTTONS[:1]
            if bbox == d.LINK_LIST:
                return list_lines or [{"text": "1/0/1 On/Off", "x": 1700, "y": 1000, "w": 300, "h": 30},
                                      {"text": "1/0/3 On/Off status", "x": 1700, "y": 1040, "w": 300, "h": 30}]
            return []

        def grab(bbox=None):
            if bbox == d.LINK_FIELD:
                return self.field(framed)
            return FakeImage(40, 10).put(5, 3, 30, 7, (150, 150, 150))
        return [mock.patch.object(d, "link_dialog_open", side_effect=lambda: next(states)),
                mock.patch.object(d, "find_text", side_effect=lambda p, *a, **k: self.TITLE if "verbinden" in p else None),
                mock.patch.object(d, "ocr", side_effect=ocr), mock.patch.object(d, "grab", side_effect=grab),
                mock.patch.object(d, "click"), mock.patch.object(d, "keys"), mock.patch.object(d.time, "sleep"),
                mock.patch.object(d, "log")]

    def run_patched(self, patches, fn):
        import contextlib

        with contextlib.ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in patches]
            return fn(), mocks

    def test_close_link_dialog_clicks_abbrechen(self):
        out, mocks = self.run_patched(self.screen([True, False, False]), self.d.close_link_dialog)
        self.assertTrue(out)
        (x, y), _ = mocks[4].call_args
        self.assertTrue(2310 + 200 * 2 / 11 <= x <= 2510, x)
        self.assertEqual(y, 1886)
        mocks[5].assert_not_called()

    def test_close_link_dialog_none_open(self):
        out, mocks = self.run_patched(self.screen([False]), self.d.close_link_dialog)
        self.assertFalse(out)
        mocks[4].assert_not_called()

    def test_flow_link_closes_a_leftover_dialog_first(self):
        from unittest import mock

        with mock.patch.object(self.d, "close_link_dialog", side_effect=RuntimeError("stop")) as close, \
                mock.patch.object(self.d, "close_link_question", return_value=False), \
                mock.patch.object(self.d, "require_project"):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                self.d.flow_link({"project": "ets-sweep", "ia": "1.1.1", "number": 12, "ga": "1/0/2"})
        close.assert_called_once()


class TestDriverCatalogColumns(unittest.TestCase):
    """The catalog's columns come from its header row: ETS showed 'Sic' and
    'Hersteller' before 'Name' on 2026-11-10 and every cell moved (#478)."""

    HEADER = [{"text": "Sic Hersteller", "x": 1090, "y": 1409, "w": 147, "h": 18},
              {"text": "Name", "x": 1469, "y": 1410, "w": 62, "h": 17},
              {"text": "Bestellnummer", "x": 2302, "y": 1409, "w": 162, "h": 18},
              {"text": "Medie Applikation", "x": 2559, "y": 1409, "w": 203, "h": 24},
              {"text": "Version", "x": 2897, "y": 1409, "w": 79, "h": 18}]

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    def test_catalog_columns_from_the_header(self):
        cols = self.d.catalog_columns(self.HEADER)
        self.assertEqual(cols["name"], (1449, 2282))
        self.assertEqual(cols["order"], (2282, 2539))
        self.assertEqual(cols["application"], (2610, 2877))
        self.assertEqual(cols["version"][0], 2877)
        # The cells of the Hager TXB601B row land in their columns.
        for key, x in (("order", 2292), ("application", 2630), ("version", 2891), ("name", 1460)):
            self.assertTrue(cols[key][0] <= x < cols[key][1], (key, x, cols[key]))
        self.assertFalse(cols["name"][0] <= 1125 < cols["name"][1])

    def test_catalog_columns_fall_back_without_a_header(self):
        self.assertEqual(self.d.catalog_columns([]), self.d.CATALOG_COLS)


class FakeEts:
    """The screen of ETS's object table and its link dialog, for the link
    flow: menus open the dialog, Abbrechen closes it, Verbinden closes it
    unless the address is refused (`refuse`: those ETS frames red and greys
    out), and the table rows show what was linked."""

    BUTTONS = TestDriverLinkDialog.BUTTONS
    TITLE = TestDriverLinkDialog.TITLE

    def __init__(self, d, rows, refuse=(), leftover=False, stuck=False, late_menus=0, blind_menus=0,
                 size_prompt=(), leftover_prompt=False):
        self.d, self.rows, self.refuse, self.stuck = d, [dict(r, gas=list(r["gas"])) for r in rows], set(refuse), stuck
        # Right-clicks whose menu comes too late for menu_click (it then
        # stays open as a popup until Escape).
        self.late_menus = late_menus
        # Right-clicks whose menu shows but has no MenuItem for UI
        # Automation: OCR finds the entry.
        self.blind_menus = blind_menus
        self.menu_open = False
        # Addresses for which ETS asks about another object size after
        # Verbinden (its question is a dialog of its own; OK links).
        self.size_prompt = set(size_prompt)
        self.prompt = leftover_prompt
        self.pending = None
        # The mouse over the table shows ETS's tooltip of addresses over the
        # last row: a read then sees them there (DALI Basic 1f, 2026-11-10).
        self.parked = True
        self.dialog = leftover
        self.typed = ""
        self.row = None
        self.now = 0.0
        self.events: list[tuple] = []
        self.opened = 0
        self.reads = 0

    def link_dialog_open(self):
        return self.dialog

    def menu_click(self, title, timeout=5.0, settle=0.5):
        if self.blind_menus:
            self.blind_menus -= 1
            raise RuntimeError(f"menu item {title!r} not in any popup; popups: []")
        self.menu_open = False
        self.events.append(("menu", title))
        self.dialog = True
        self.typed = ""

    def right_click(self, coords):
        self.parked = False
        self.events.append(("right", coords[1]))
        if self.late_menus:
            self.late_menus -= 1
        else:
            self.menu_open = True
        self.row = next(r for r in self.rows if r["y"] == coords[1])

    def find_text(self, pattern, bbox=None, min_ratio=0.8):
        if self.prompt and pattern == "Mit Gruppenadresse verbinden" and bbox == self.d.QUESTION_TITLE:
            return {"text": pattern, "x": 1640, "y": 1058, "w": 400, "h": 30}
        if pattern == "Verbinden mit" and self.menu_open:
            return {"text": "Verbinden mit...", "x": 1050, "y": 900, "w": 200, "h": 30, "ratio": 1.0}
        return None

    def click(self, x, y, *a, **k):
        if 260 <= y <= 1240:
            self.parked = False
        if self.prompt:
            self.prompt = False
            if x < 2500:
                self.events.append(("ok",))
                if self.pending:
                    self.pending["gas"].append(self.typed)
            else:
                self.events.append(("prompt-abbrechen",))
            self.pending = None
            return
        if self.menu_open and not self.dialog:
            self.events.append(("menu-ocr",))
            self.menu_open = False
            self.dialog = True
            self.typed = ""
            return
        if not self.dialog:
            self.events.append(("click", x, y))
            return
        if x > 2300:
            self.events.append(("abbrechen",))
            self.dialog = False
        elif y > 1830:
            self.events.append(("verbinden", self.typed))
            if self.typed not in self.refuse and not self.stuck:
                self.dialog = False
                if self.typed in self.size_prompt:
                    self.prompt, self.pending = True, self.row
                else:
                    self.row["gas"].append(self.typed)
        else:
            self.events.append(("field",))

    def click_text(self, pattern, bbox=None, *a, **k):
        hit = self.find_text(pattern, bbox)
        if not hit:
            raise RuntimeError(f"text {pattern!r} not on screen in {bbox}")
        self.click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
        return hit

    def ets_popups(self):
        return ["menu"] if self.menu_open else []

    def keys(self, seq, pause=0.05):
        if seq == "{ESC}":
            self.events.append(("esc",))
            self.menu_open = False
            return
        if seq != "^a":
            self.typed = seq

    def ocr(self, bbox=None, zoom=1, **_):
        d = self.d
        if bbox == d.QUESTION_BUTTONS:
            # The Hue's question: OK at x ~2432, Abbrechen at ~2580.
            return [{"text": "OK", "x": 2420, "y": 1445, "w": 24, "h": 22},
                    {"text": "Abbrechen", "x": 2540, "y": 1445, "w": 80, "h": 22}] if self.prompt else []
        if bbox == d.LINK_BUTTONS:
            return self.BUTTONS
        if bbox == d.LINK_VERBINDEN:
            return self.BUTTONS[:1]
        if bbox == d.LINK_LIST:
            return [{"text": "1/0/1", "x": 1700, "y": 1000, "w": 300, "h": 30}]
        if bbox == d.LINK_FIELD:
            return [{"text": self.typed, "x": 1610, "y": 1700, "w": 100, "h": 30}]
        if bbox and bbox[0] == d.GO_COLS["ga"][0] - 400:
            hit = [r for r in self.rows if abs(r["y"] - (bbox[1] + 18)) < 3]
            return [{"text": ", ".join(hit[0]["gas"]), "x": 1840, "y": bbox[1], "w": 100, "h": 30}] if hit and hit[0]["gas"] else []
        return []

    def grab(self, bbox=None):
        if bbox == self.d.LINK_FIELD:
            return TestDriverLinkDialog().field(self.typed in self.refuse)
        return FakeImage(40, 10).put(5, 3, 30, 7, (150, 150, 150) if self.typed in self.refuse or self.stuck else (30, 30, 30))

    def read_objects(self, numbers=None):
        self.reads += 1
        rows = [dict(r, gas=list(r["gas"])) for r in self.rows]
        if not self.parked:
            rows[-1]["gas"].append("1/0/3")
        return rows

    def table_numbers(self):
        return {r["y"]: r["number"] for r in self.rows}

    def open_device_objects(self, ia):
        self.opened += 1

    def sleep(self, s):
        self.now += s

    def time(self):
        self.now += 0.01
        return self.now

    def patches(self):
        import types
        from unittest import mock

        d = self.d
        pw = types.ModuleType("pywinauto")
        pw.mouse = mock.MagicMock()
        pw.mouse.right_click.side_effect = self.right_click
        pw.mouse.move.side_effect = lambda coords: setattr(self, "parked", True)
        return [mock.patch.dict(sys.modules, {"pywinauto": pw}),
                mock.patch.multiple(d, require_project=mock.DEFAULT, scale=mock.Mock(return_value=1.0),
                                    link_dialog_open=self.link_dialog_open, menu_click=self.menu_click,
                                    click=self.click, keys=self.keys, ocr=self.ocr, grab=self.grab,
                                    read_objects=self.read_objects, table_numbers=self.table_numbers,
                                    open_device_objects=self.open_device_objects, log=mock.DEFAULT,
                                    ets_popups=self.ets_popups,
                                    find_text=self.find_text),
                mock.patch.object(d, "click_text", side_effect=self.click_text),
                mock.patch.object(d.time, "sleep", side_effect=self.sleep),
                mock.patch.object(d.time, "time", side_effect=self.time)]

    def run(self, fn):
        import contextlib

        with contextlib.ExitStack() as stack:
            for p in self.patches():
                stack.enter_context(p)
            return fn()


class TestDriverUnloadAndGaSecurity(unittest.TestCase):
    """The pure helpers of the `unload` and `ga_security` flows (#1056,
    #1054), from the OCR lines read on ETS 6.4.1 on 2026-11-13."""

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    @staticmethod
    def line(text, x, y, w=200, h=24):
        return {"text": text, "x": x, "y": y, "w": w, "h": h}

    def test_unload_entry_picks_the_submenu_line(self):
        sub = [self.line("Applikationsprogramm", 1604, 445),
               self.line("Physikalische Adresse und Applikationsprogramm Strg + U", 1606, 509)]
        self.assertEqual(self.d.unload_entry(sub, "application")["y"], 445)
        self.assertEqual(self.d.unload_entry(sub, "full")["y"], 509)
        self.assertIsNone(self.d.unload_entry(sub[1:], "application"))
        self.assertIsNone(self.d.unload_entry(sub[:1], "full"))

    def test_ga_panel_header_is_the_topmost_left_line(self):
        lines = [self.line("Elemente", 24, 1653), self.line("Gruppenadressen", 67, 1741),
                 self.line("Suchordner", 57, 1797), self.line("Gruppenadressen", 57, 1941),
                 self.line("1 Neue Hauptgruppe", 82, 1990)]
        self.assertEqual(self.d.ga_panel_header(lines)["y"], 1741)
        self.assertIsNone(self.d.ga_panel_header([self.line("Katalog", 68, 1354)]))

    def test_ga_tree_entry_main_and_middle_group(self):
        lines = [self.line("Gruppenadressen", 67, 1741), self.line("3 Addresses not assigned", 89, 1844),
                 self.line("1 Neue Hauptgruppe", 82, 1990), self.line("88 1/0 Neue Mittelgruppe", 52, 2031)]
        self.assertEqual(self.d.ga_tree_entry(lines, "1", 1741)["y"], 1990)
        self.assertEqual(self.d.ga_tree_entry(lines, "1/0", 1741)["y"], 2031)
        self.assertIsNone(self.d.ga_tree_entry(lines, "1/1", 1741))
        self.assertIsNone(self.d.ga_tree_entry(lines, "2", 1741))

    def test_ga_security_value_reads_below_the_label(self):
        lines = [self.line("Gruppenadress-Einstellungen", 3436, 755), self.line("Zentralfunktion", 3471, 790),
                 self.line("Sicherheit", 3436, 845), self.line("Automatisch", 3452, 888),
                 self.line("Datentyp", 3436, 952), self.line("1.001 Schalten", 3452, 995)]
        self.assertEqual(self.d.ga_security_value(lines), "Automatisch")
        self.assertIsNone(self.d.ga_security_value(lines[:2]))
        self.assertEqual(set(self.d.GA_SECURITY_TEXT.values()), {"Automatisch", "Erzwungen an", "Erzwungen aus"})


class TestDriverLinksFlow(unittest.TestCase):
    """All links of a device from one opened object table, each a few
    clicks with polls in between (#478)."""

    # The ise KNX Sonos as the links run of 2026-11-10 read it.
    ROWS = [{"number": 12, "y": 707, "gas": [], "size": "1 bit", "flags": "KLÜ"},
            {"number": 16, "y": 787, "gas": [], "size": "1 byte", "flags": "KLÜ"},
            {"number": 20, "y": 867, "gas": [], "size": "1 bit", "flags": "KLÜ"}]

    @classmethod
    def setUpClass(cls):
        cls.d = load_driver()

    def links(self, ets, **req):
        return ets.run(lambda: self.d.flow_links({"project": "ets-sweep", "ia": "1.1.1", **req}))

    def test_flow_links_opens_the_table_once_for_every_link(self):
        ets = FakeEts(self.d, self.ROWS)
        out = self.links(ets, links=[[12, "1/0/1"], [16, "1/0/2"], [20, "1/0/3"], [12, "1/0/3"]])
        self.assertEqual(ets.opened, 1)
        self.assertEqual([r["linked"] for r in out["links"]], [True] * 4)
        self.assertEqual(out["links"][3]["row"]["gas"], ["1/0/1", "1/0/3"])
        self.assertEqual(out["objects"][0]["gas"], ["1/0/1", "1/0/3"])
        # The step list of one link: the row's menu, the dialog's field, Verbinden.
        self.assertEqual([e[0] for e in ets.events],
                         ["right", "menu", "field", "verbinden"] * 4)
        # The table is read whole twice (before and after), never per link:
        # the view did not move.
        self.assertEqual(ets.reads, 2)

    def test_flow_links_uses_the_open_table(self):
        ets = FakeEts(self.d, self.ROWS)
        out = self.links(ets, links=[[20, "1/0/1"]], open=False, final=False)
        self.assertEqual(ets.opened, 0)
        self.assertFalse(out["opened"])
        self.assertNotIn("objects", out)

    def test_flow_links_opens_when_the_table_shows_none_of_the_objects(self):
        ets = FakeEts(self.d, self.ROWS)
        with self.assertRaisesRegex(RuntimeError, "object 99 not in the table"):
            ets.run(lambda: self.d.flow_links({"project": "ets-sweep", "ia": "1.1.1", "links": [[99, "1/0/1"]],
                                               "open": False, "final": False}))
        self.assertEqual(ets.opened, 1)

    def test_flow_links_refused_address_cancels_and_goes_on(self):
        ets = FakeEts(self.d, self.ROWS, refuse={"1/0/2"})
        out = self.links(ets, links=[[12, "1/0/1"], [12, "1/0/2"], [20, "1/0/3"]])
        self.assertEqual([r["linked"] for r in out["links"]], [True, False, True])
        self.assertRegex(out["links"][1]["refused"], r"ETS refused 1/0/2 for object 12: the address field shows an error "
                                                     r"and 'Verbinden' is disabled \(the dialog offers 1/0/1")
        # The refused link never clicks Verbinden: its dialog ends with Abbrechen.
        self.assertEqual([e[0] for e in ets.events[4:8]], ["right", "menu", "field", "abbrechen"])
        self.assertFalse(ets.dialog)

    def test_flow_links_dialog_that_stays_open_is_cancelled(self):
        # Not framed, Verbinden clicked three times, the dialog stays: the
        # greyed button names the refusal, Abbrechen closes it.
        ets = FakeEts(self.d, self.ROWS, stuck=True)
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertFalse(out["links"][0]["linked"])
        self.assertIn("'Verbinden' is disabled", out["links"][0]["refused"])
        self.assertEqual([e[0] for e in ets.events].count("verbinden"), 3)
        self.assertFalse(ets.dialog)

    def test_flow_links_right_clicks_again_after_a_late_menu(self):
        ets = FakeEts(self.d, self.ROWS, late_menus=1)
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["links"][0]["linked"])
        self.assertEqual([e[0] for e in ets.events], ["right", "right", "menu", "field", "verbinden"])

    def test_flow_links_takes_the_menu_entry_by_ocr(self):
        ets = FakeEts(self.d, self.ROWS, blind_menus=1)
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["links"][0]["linked"])
        self.assertEqual([e[0] for e in ets.events], ["right", "menu-ocr", "field", "verbinden"])

    def test_flow_links_leaves_no_menu_when_it_fails(self):
        ets = FakeEts(self.d, self.ROWS, late_menus=3)
        with self.assertRaisesRegex(RuntimeError, "no context menu"):
            self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertFalse(ets.menu_open)
        self.assertEqual([e[0] for e in ets.events].count("right"), 3)

    def test_flow_links_closes_a_leftover_dialog_first(self):
        ets = FakeEts(self.d, self.ROWS, leftover=True)
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["closed_link_dialog"])
        self.assertEqual(ets.events[0], ("abbrechen",))

    def test_flow_links_reads_the_table_again_when_the_view_moved(self):
        ets = FakeEts(self.d, self.ROWS)
        moved = iter([{707 + 80: 12}])
        ets.table_numbers = lambda: next(moved, {r["y"]: r["number"] for r in ets.rows})
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["links"][0]["linked"])
        self.assertEqual(ets.reads, 2)

    def test_flow_link_is_one_link_of_flow_links(self):
        ets = FakeEts(self.d, self.ROWS)
        out = ets.run(lambda: self.d.flow_link({"project": "ets-sweep", "ia": "1.1.1", "number": 16, "ga": "1/0/2"}))
        self.assertTrue(out["linked"])
        self.assertEqual(out["row"]["gas"], ["1/0/2"])
        self.assertEqual(ets.opened, 1)

    def test_flow_links_answers_the_question_after_a_link_with_ok(self):
        ets = FakeEts(self.d, self.ROWS, size_prompt={"1/0/2"})
        out = self.links(ets, links=[[12, "1/0/2"]], final=False)
        self.assertTrue(out["links"][0]["linked"])
        self.assertEqual([e[0] for e in ets.events], ["right", "menu", "field", "verbinden", "ok"])

    def test_flow_links_cancels_a_leftover_question_first(self):
        ets = FakeEts(self.d, self.ROWS, leftover_prompt=True)
        out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["closed_link_dialog"])
        self.assertEqual(ets.events[0], ("prompt-abbrechen",))

    def test_flow_links_keeps_a_linked_row_the_last_read_missed(self):
        ets = FakeEts(self.d, self.ROWS)
        read = ets.read_objects
        calls = {"n": 0}

        def read_objects(numbers=None):
            calls["n"] += 1
            rows = read(numbers)
            return rows if calls["n"] == 1 else [r for r in rows if r["number"] != 12]
        ets.read_objects = read_objects
        out = self.links(ets, links=[[12, "1/0/1"]])
        self.assertEqual([(r["number"], r["gas"]) for r in out["objects"]], [(12, ["1/0/1"]), (16, []), (20, [])])

    def test_with_linked_rows_the_links_number_stands_at_its_place(self):
        from unittest import mock

        final = [{"number": 0, "y": 290, "gas": ["1/0/1"]}, {"number": 3, "y": 370, "gas": ["1/0/2"]}]
        links = [{"number": 1, "ga": "1/0/1", "linked": True, "row": {"number": 1, "y": 290, "gas": ["1/0/1"]}},
                 {"number": 3, "ga": "1/0/2", "linked": True, "row": {"number": 3, "y": 370, "gas": ["1/0/2"]}},
                 {"number": 1, "ga": "1/0/2", "linked": False, "row": {"number": 1, "y": 290, "gas": []}}]
        with mock.patch.object(self.d, "log"):
            out = self.d.with_linked_rows(final, links)
        self.assertEqual([(r["number"], r["y"]) for r in out], [(1, 290), (3, 370)])

    def test_flow_links_waits_for_an_address_shown_late(self):
        ets = FakeEts(self.d, self.ROWS)
        gas_at = self.d.gas_at
        calls = {"n": 0}
        from unittest import mock

        def slow(y):
            calls["n"] += 1
            return gas_at(y) if calls["n"] > 15 else []
        with mock.patch.object(self.d, "gas_at", side_effect=slow):
            read = ets.read_objects

            def blank_gas(numbers=None):
                return [dict(r, gas=[]) for r in read(numbers)]
            ets.read_objects = blank_gas
            out = self.links(ets, links=[[12, "1/0/1"]], final=False)
        self.assertTrue(out["links"][0]["linked"])
        self.assertEqual(out["links"][0]["row"]["gas"], ["1/0/1"])

    def test_flow_links_reads_the_table_with_the_mouse_off_it(self):
        ets = FakeEts(self.d, self.ROWS)
        out = self.links(ets, links=[[12, "1/0/1"], [16, "1/0/2"]])
        self.assertEqual([(r["number"], r["gas"]) for r in out["objects"]],
                         [(12, ["1/0/1"]), (16, ["1/0/2"]), (20, [])])

    def test_view_changed(self):
        rows = self.ROWS
        self.assertFalse(self.d.view_changed(rows, {707: 12, 867: 20}))
        self.assertTrue(self.d.view_changed(rows, {}))
        self.assertTrue(self.d.view_changed(rows, {707: 16}))
        self.assertTrue(self.d.view_changed(rows, {947: 24}))

    def test_wait_for_polls_until_true_or_timeout(self):
        from unittest import mock

        clock = {"t": 0.0}
        answers = iter([None, None, "ok"])
        with mock.patch.object(self.d.time, "time", side_effect=lambda: clock["t"]), \
                mock.patch.object(self.d.time, "sleep", side_effect=lambda s: clock.__setitem__("t", clock["t"] + s)), \
                mock.patch.object(self.d, "log") as log:
            self.assertEqual(self.d.wait_for("x", lambda: next(answers), 5, 0.5), "ok")
            self.assertEqual(clock["t"], 1.0)
            self.assertIn("wait x 1.00s ok", log.call_args.args[0])
            self.assertFalse(self.d.wait_for("y", lambda: False, 1, 0.5))
            self.assertIn("timeout", log.call_args.args[0])

    def test_tree_node_of(self):
        self.assertTrue(self.d.tree_node_of("> 1.1.1 ise KNX Sonos", "1.1.1"))
        self.assertTrue(self.d.tree_node_of("m 1.1.1 KCI 4 S0", "1.1.1"))
        self.assertFalse(self.d.tree_node_of("1.1 TP Linie", "1.1.1"))
        self.assertFalse(self.d.tree_node_of("> 1.1.10 Dimmer", "1.1.1"))
        self.assertFalse(self.d.tree_node_of("> 1.1.1.5", "1.1.1"))

    def test_cell_digit_checks_ocr_against_the_ink(self):
        black = (20, 20, 20)
        one = FakeImage(108, 32).put(50, 5, 56, 22, black).convert("L")
        zero = FakeImage(108, 32).put(48, 5, 58, 22, black).put(51, 8, 55, 19, (255, 255, 255)).convert("L")
        seven = FakeImage(108, 32).put(48, 5, 58, 8, black).put(54, 8, 57, 22, black).convert("L")
        d = self.d
        self.assertTrue(d.lone_one(one))
        self.assertFalse(d.lone_one(zero))
        self.assertFalse(d.lone_one(seven))
        self.assertTrue(d.has_hole(zero))
        self.assertFalse(d.has_hole(seven))
        # The Vaillant's selected lone 1 that OCR read as 0.
        self.assertEqual(d.cell_digit(one, 0), 1)
        self.assertEqual(d.cell_digit(one, 4), 1)
        self.assertEqual(d.cell_digit(one, None), 1)
        self.assertEqual(d.cell_digit(one, 1), 1)
        self.assertEqual(d.cell_digit(zero, 0), 0)
        self.assertIsNone(d.cell_digit(zero, 1))
        self.assertIsNone(d.cell_digit(zero, None))
        self.assertEqual(d.cell_digit(seven, 7), 7)
        self.assertIsNone(d.cell_digit(seven, 1))
        self.assertIsNone(d.cell_digit(FakeImage(108, 32).convert("L"), None))

    def test_repeated_number(self):
        self.assertEqual(self.d.repeated_number("7 7 7"), 7)
        self.assertEqual(self.d.repeated_number("12 12 12"), 12)
        self.assertEqual(self.d.repeated_number("lll"), 1)
        self.assertEqual(self.d.repeated_number("O O O"), 0)
        self.assertIsNone(self.d.repeated_number("7 1 7"))
        self.assertIsNone(self.d.repeated_number("77"))
        self.assertIsNone(self.d.repeated_number(""))

    def test_field_text_normalised(self):
        self.assertEqual(self.d._ga_text("l/O/ 3"), "1/0/3")


class TestLinksSubset(unittest.TestCase):
    """The representative subset of the links variant (#478)."""

    # A 0705 product as the model import writes it, cut to what `features` reads.
    MDT = {"id": "M-0083_A-000E-23-2274", "mask_version": "0705", "is_secure_enabled": False,
           "ets_download_plugin": False, "com_object_table": {"code_segment": "AS-4400", "offset": 0},
           "com_objects": {"O-1": {"object_size": "1 Bit"}, "M-0083_A-000E-23-2274_MD-1_O-2": {"object_size": "2 Bytes"}},
           "com_object_refs": {"R-1": {"ref_id": "O-1", "object_size": "14 Bytes"}, "R-2": {"ref_id": "O-1", "object_size": None}},
           "module_instances": [{"x": 1}], "module_dynamics": {},
           "load_procedures": [{"ops": ["Connect", {"AbsSegment": {"lsm_idx": 1, "size": 513}},
                                        {"AbsSegment": {"lsm_idx": 2, "size": 511}}]}]}
    SECURE_07B0 = {"id": "M-0008_A-0004", "mask_version": "07B0", "is_secure_enabled": True, "ets_download_plugin": True,
                   "com_object_table": None, "com_objects": {f"O-{i}": {"object_size": "1 Byte"} for i in range(60)},
                   "com_object_refs": {}, "module_instances": [], "module_dynamics": {},
                   "load_procedures": [{"ops": [{"LoadImageProp": {"obj_idx": 1, "prop_id": 27}}]}]}

    def test_features_of_a_0705_in_memory(self):
        self.assertEqual(links_subset.features(self.MDT, {"differs"}), {
            "mask:0705", "tables:0705/abs-segment", "go-table:0705/own-segment", "assoc:0705/standard 448-511 B",
            "objects:0705/few <=10", "size:0705/1 Bit", "size:0705/14 Bytes", "size:0705/2 Bytes",
            "modules:0705", "module-objects:0705", "oracle:0705/differs"})

    def test_features_of_a_secure_07b0_through_properties(self):
        f = links_subset.features(self.SECURE_07B0)
        self.assertLessEqual({"tables:07B0/prop-image", "go-table:07B0/property", "secure:07B0", "plugin:M-0008",
                              "objects:07B0/many 51-200", "size:07B0/1 Byte"}, f)
        self.assertFalse(any(x.startswith("assoc:") for x in f))

    def test_table_style_ets_default_and_relative(self):
        self.assertEqual(links_subset.table_style({"load_procedures": []}), "ets-default")
        rel = {"load_procedures": [{"ops": [{"RelSegment": {"lsm_idx": 2, "size": 600}},
                                            {"LoadImageProp": {"obj_idx": 1}}]}]}
        self.assertEqual(links_subset.table_style(rel), "rel-segment")
        self.assertEqual(links_subset.assoc_size(rel), 600)

    def test_greedy_cover_most_new_labels_then_cost(self):
        apps = {"a": {"x", "y"}, "b": {"x", "y", "z"}, "c": {"z", "w"}, "d": {"w"}, "e": {"z", "w"}}
        self.assertEqual(links_subset.greedy_cover(apps, {"c": 5, "e": 1}), [("b", ["x", "y", "z"]), ("e", ["w"])])

    def test_greedy_cover_pins_first(self):
        apps = {"a": {"x"}, "b": {"x", "y"}}
        self.assertEqual(links_subset.greedy_cover(apps, pinned=["a", "gone"]), [("a", ["x"]), ("b", ["y"])])

    def test_why_names_the_pin_or_the_labels(self):
        self.assertEqual(links_subset.why("M-1", ["mask:0705"]), "first to cover mask:0705")
        pin = next(iter(links_subset.PINNED))
        self.assertTrue(links_subset.why(pin, []).startswith("series representative"))

    def test_committed_subset_is_a_reasoned_cover(self):
        rows = links_subset.load()
        apps = [r["app"] for r in rows]
        self.assertEqual(len(apps), len(set(apps)))
        self.assertTrue(20 <= len(rows) <= 40, len(rows))
        self.assertTrue(all(r["why"] for r in rows))
        self.assertLessEqual(set(links_subset.PINNED), set(apps))
        covered = {c for r in rows for c in r["covers"]}
        for mask in ("07B0", "0705", "0701"):
            self.assertIn(f"mask:{mask}", covered)
            self.assertIn(f"size:{mask}/1 Bit", covered)
        self.assertLessEqual({"secure:07B0", "modules:07B0", "module-objects:07B0", "tables:07B0/prop-image",
                              "tables:07B0/rel-segment", "tables:0705/prop-image", "tables:0705/abs-segment"}, covered)

    def test_representative_keeps_the_subset_order(self):
        todo = [{"id": "A"}, {"id": "B"}, {"id": "C"}]
        out = defaults.representative(todo, [{"app": "C"}, {"app": "Z"}, {"app": "A"}])
        self.assertEqual([j["id"] for j in out], ["C", "A"])


class TestOemIdentity(unittest.TestCase):
    """The brand's manufacturer id of an OEM hardware is seeded as PID 12
    (#881, Gewiss GW10966 on Hugo Müller hardware)."""

    MASTER = """<KNX><MasterData><Manufacturers>
      <Manufacturer Id="M-0019" KnxManufacturerId="25" Name="GEWISS" DefaultLanguage="en-US" />
      <Manufacturer Id="M-00FC" KnxManufacturerId="252" Name="Hugo M&#252;ller GmbH &amp; Co KG" DefaultLanguage="en-US" />
      </Manufacturers></MasterData></KNX>"""
    HARDWARE = """<KNX><ManufacturerData><Manufacturer RefId="M-00FC"><Hardware>
      <Hardware Id="M-00FC_H-LP.2D579.2D401-0" Name="GS4X_knx" SerialNumber="LP-579-401" VersionNumber="0">
        <Hardware2Programs><Hardware2Program Id="H1">
          <ApplicationProgramRef RefId="M-00FC_A-000A-11-5E09" /></Hardware2Program></Hardware2Programs>
      </Hardware>
      <Hardware Id="M-00FC_H-LP.2D579.2D401.5FGEWISS-0" Name="GS4X_knx" SerialNumber="LP-579-401_GEWISS" VersionNumber="0">
        <Hardware2Programs><Hardware2Program Id="H2">
          <ApplicationProgramRef RefId="M-00FC_A-000C-11-FA2D" /></Hardware2Program></Hardware2Programs>
      </Hardware>
      </Hardware></Manufacturer></ManufacturerData></KNX>"""

    def setUp(self):
        defaults._product_seeds.cache_clear()

    def _product(self, tmp: Path) -> Path:
        import zipfile

        path = tmp / "GS4x12_v1.1.knxprod"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("knx_master.xml", self.MASTER)
            z.writestr("M-00FC/Hardware.xml", self.HARDWARE)
        return path

    def test_oem_identity_seeds_the_brand_manufacturer(self):
        from unittest import mock

        import sweep

        with tempfile.TemporaryDirectory() as tmp:
            path = self._product(Path(tmp))
            want = {"object": 0, "pid": 12, "value": "0019"}
            self.assertEqual(sweep.oem_identity(path, "M-00FC_A-000C-11-FA2D"), [want])
            # The unbranded sibling of the same file: nothing.
            self.assertEqual(sweep.oem_identity(path, "M-00FC_A-000A-11-5E09"), [])
            with mock.patch.object(sweep, "product_properties", return_value=[]), \
                    mock.patch.object(sweep, "compare_properties", return_value=[]):
                self.assertEqual(defaults.seed_properties(path, "M-00FC_A-000C-11-FA2D", None), [want])
                # A seed is not learned; a value ETS's log taught still wins.
                self.assertEqual(defaults.learned_from_ets(path, "M-00FC_A-000C-11-FA2D",
                                                           {"learned_properties": [want]}), [])
                taught = {"object": 0, "pid": 12, "value": "00fc"}
                self.assertEqual(defaults.seed_properties(path, "M-00FC_A-000C-11-FA2D",
                                                          {"learned_properties": [taught]}), [taught])



class TestCatalogManufacturer(unittest.TestCase):
    """The added catalog row's manufacturer group header is recorded against
    the product file's manufacturer, not acted on (#881)."""

    TAPKO = {"y": 1507, "name": "Spannungsversorgung IPS640", "order": "IPS 640",
             "application": "Gerät/Bus-Diagnose", "version": "1.0", "online": False,
             "manufacturer": "TAPKO Technologies GmbH"}
    OTHER = dict(TAPKO, y=1560, name="Power Supply 640", manufacturer="Other Brand AG")

    def test_manufacturer_matches_ocr_and_legal_forms(self):
        import sweep

        self.assertTrue(sweep.manufacturer_matches("TAPKO Technologies GmbH", "TAPKO Technologies"))
        self.assertTrue(sweep.manufacturer_matches("Hugo Muller GmbH & Co KG", "Hugo Müller GmbH & Co KG"))
        self.assertFalse(sweep.manufacturer_matches("GEWISS", "Hugo Müller GmbH & Co KG"))
        self.assertIsNone(sweep.manufacturer_matches("", "TAPKO Technologies"))

    def test_catalog_identity_and_verdict(self):
        import zipfile

        import sweep

        app = "M-0072_A-3001-10-A7BD"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "TAPKO_ETS4_IPS640_R1-0b_01.knxprod"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("knx_master.xml", '<KNX><Manufacturer Id="M-0071" KnxManufacturerId="113" Name="Zennio" />'
                                             '<Manufacturer Id="M-0072" KnxManufacturerId="114" Name="TAPKO Technologies" /></KNX>')
                z.writestr(f"M-0072/{app}.xml", f'<KNX><ApplicationProgram Id="{app}" Name="Device/Busline Diagnostics" '
                                                'MaskVersion="MV-0705"></ApplicationProgram></KNX>')
            identity = sweep.catalog_identity(path, app)
        self.assertEqual(identity, {"manufacturer": "TAPKO Technologies", "application": "Device/Busline Diagnostics"})
        # Two manufacturers, same order number: each row gets its verdict.
        self.assertEqual(sweep.catalog_manufacturer_verdict(self.TAPKO, identity), "same")
        self.assertEqual(sweep.catalog_manufacturer_verdict(self.OTHER, identity), "other")
        self.assertEqual(sweep.catalog_manufacturer_verdict({"name": "x"}, identity), "unknown")

    def test_run_one_records_the_rows_manufacturer_and_goes_on(self):
        from unittest import mock

        import sweep

        add = {"added": [{"ia": "1.1.1"}], "row": self.OTHER}
        with mock.patch.object(sweep, "catalog_identity", return_value={"manufacturer": "TAPKO Technologies"}):
            r, _, flows, _ = TestCouplerAddress.run_one(self, "1.1.1", catalog_add=add)
        # Recorded, not acted on: the download ran.
        self.assertEqual(r["catalog_manufacturer"], "other")
        self.assertEqual(r["catalog_row"]["manufacturer"], "Other Brand AG")
        self.assertIn(("download", "1.1.1"), flows)
        self.assertEqual(r["outcome"], "captured", r)


class TestSecureSubset(unittest.TestCase):
    """The representative subset of the Data Secure variant (#423)."""

    TP = {"id": "M-0083_A-0001-10-AAAA", "mask_version": "07B0", "is_secure_enabled": True,
          "com_objects": {f"O-{i}": {} for i in range(30)},
          "security_capacity": {"group_key_table_entries": 1500, "individual_address_entries": 100},
          "load_procedures": [{"ops": [{"WriteProp": {"obj_idx": 9, "prop_id": 51, "inline_data": [1]}}]}]}
    IFACE = {"id": "M-00B6_A-0002-10-BBBB", "mask_version": "07B0", "is_secure_enabled": True,
             "additional_addresses_count": 8, "com_objects": {}, "load_procedures": []}

    def test_features_tp_device_with_security_mode_by_index(self):
        self.assertEqual(secure_subset.features(self.TP), {
            "mask:07B0", "iface:07B0/tp", "secobj:lp-index", "tables:tp/ets-default", "objects:some 11-50",
            "group-keys:>1100", "ia-table:<=100", "maker:MDT"})

    def test_features_ip_interface(self):
        f = secure_subset.features(self.IFACE)
        self.assertTrue({"iface:07B0/tunnelling", "iface:07B0/ip-interface", "tunnels:8", "secobj:ets",
                         "objects:none", "group-keys:undeclared", "maker:Ekinex"} <= f, f)

    def test_plain_identical_needs_memory_and_load_control(self):
        self.assertTrue(secure_subset.plain_identical({"verdict": "identical", "loadctl": {"verdict": "identical"}}))
        self.assertFalse(secure_subset.plain_identical({"verdict": "identical", "loadctl": {"verdict": "missing"}}))
        self.assertFalse(secure_subset.plain_identical({"verdict": "differs", "loadctl": {"verdict": "identical"}}))
        self.assertFalse(secure_subset.plain_identical(None))

    def test_committed_subset_has_a_reason_per_row(self):
        rows = secure_subset.load()
        self.assertTrue(15 <= len(rows) <= 25, len(rows))
        self.assertTrue(all(r["why"] for r in rows))
        self.assertEqual(len({r["app"] for r in rows}), len(rows))


class TestOracleSecureVariant(unittest.TestCase):
    """The oracle's Data Secure variant (#423): the run directory, the
    results file and the row's keyring."""

    def test_variant_run_dir_and_results(self):
        self.assertEqual(oracle.variant_run_dir("secure"), "secure-defaults")
        self.assertEqual(oracle.variant_run_dir("links"), "links")
        self.assertEqual(oracle.variant_results("secure"), secure.RESULTS)
        self.assertEqual(oracle.variant_results("links"), defaults.results_path("links"))

    def test_row_names_the_keyring(self):
        cap, prod, kr = Path("/c/ets.pcapng"), Path("/p/x.knxprod"), Path("/c/project.knxkeys")
        self.assertEqual(oracle.row("M-1_A-1", cap, prod, "07B0", "secure", keyring=kr),
                         "1.1.1|/c/ets.pcapng|/p/x.knxprod|M-1_A-1|||keyring=/c/project.knxkeys")
        self.assertEqual(oracle.row("M-1_A-1", cap, prod, "0705", "secure", keyring=kr),
                         "1.1.1|/c/ets.pcapng|/p/x.knxprod|M-1_A-1|||state=fresh keyring=/c/project.knxkeys")

    def test_keyring_password_required(self):
        with mock.patch.dict(os.environ, {secure.PASSWORD_ENV: ""}):
            with self.assertRaises(RuntimeError):
                oracle.keyring_password()


if __name__ == "__main__":
    unittest.main()
