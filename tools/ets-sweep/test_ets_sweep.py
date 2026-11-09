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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_rows  # noqa: E402
import defaults  # noqa: E402
import followups  # noqa: E402
import nightly  # noqa: E402
import oracle  # noqa: E402
import oracle_model  # noqa: E402
import params  # noqa: E402
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
        "P-1": {"kind": {"Enum": {"values": [0, 1]}}, "default": "0", "text": "Lesen beim Start",
                "labels": [[0, "nein"], [1, "ja"]]},
        "P-2": {"kind": {"Int": {"min": 0, "max": 255, "signed": False}}, "default": "1", "text": "Zyklus"},
        "P-3": {"kind": "Float", "default": "4.5E1", "text": "Wert"},
        "P-4": {"kind": {"Enum": {"values": [0]}}, "default": "0", "text": "Nur einer", "labels": [[0, "x"]]},
        "P-5": {"kind": {"Enum": {"values": [0, 1]}}, "default": "0", "text": "", "labels": [[0, "a"], [1, "b"]]},
    }}
    DEVICE = {"blocks": [
        {"text": "Kühlung", "inactive": {"enable": [{"reference": "P-95_R-138", "text": "Raumtemperaturregler Funktion",
                                                      "set_to": "Kühlung", "default": "Heizung"}]}},
        {"text": "Lüftung", "inactive": {"enable": [{"reference": "P-9_R-9", "text": "VentilationEnabled",
                                                      "set_to": ">0", "default": "0"}]}},
        {"text": "Allgemein", "active": True},
    ]}

    def test_candidates_enum_and_int_with_labels_only(self):
        self.assertEqual([c["id"] for c in params.candidates(self.MODEL)], ["P-1", "P-2"])

    def test_visible_enablers_skip_conditions(self):
        self.assertEqual([(e["text"], e["shown"], e["enables"]) for e in params.visible_enablers(self.DEVICE)],
                         [("Raumtemperaturregler Funktion", "Kühlung", "Kühlung")])

    def test_generate_deterministic_enablers_first_values_off_default(self):
        visible = params.visible_enablers(self.DEVICE)
        a = params.generate(self.MODEL, seed=7, n=3, changes=3, visible=visible)
        self.assertEqual(a, params.generate(self.MODEL, seed=7, n=3, changes=3, visible=visible))
        for config in a:
            self.assertEqual(config["changes"][0]["text"], "Raumtemperaturregler Funktion")
            for ch in config["changes"][1:]:
                self.assertNotEqual(ch["shown"], {"P-1": "nein", "P-2": "1"}[ch["id"]])
        self.assertEqual(params.variant_name(7, 2), "params-7-2")

    def test_apply_hook_records_set_unreachable_failed(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        config = {"seed": 1, "index": 0, "changes": [
            {"id": "a", "text": "A", "kind": "enum", "value": "1", "shown": "ja"},
            {"id": "b", "text": "B", "kind": "int", "value": "5", "shown": "5"},
            {"id": "c", "text": "C", "kind": "enum", "value": "0", "shown": "nein"}]}

        def flow(name, **body):
            if name == "param_pages":
                return {"pages": ["Allgemein"]}
            if body["text"] == "C":
                raise RuntimeError("set_param: no control on the row")
            return {"set": body["text"] == "A", "page": "Allgemein"}

        summary_ = params.apply_hook(config)(flow, tmp)
        self.assertEqual(summary_, {"set": 1, "unreachable": 1, "failed": 1})
        saved = json.loads((tmp / "params.json").read_text())
        self.assertEqual([c["result"] for c in saved["changes"]], ["set", "unreachable", "failed"])


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
                          ["--redo-failed", "--shard", "2/3"], ["--variant", "links"]])
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
        self.assertEqual([s["mode"] for s in capture.variant_steps("syn-minimal", "partial")],
                         ["application", "partial"])

    def test_variant_steps_refuse_a_product_the_variant_does_not_run_on(self):
        with self.assertRaises(SystemExit):
            capture.variant_steps("syn-minimal", "reload")

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
        err, clicks = self.confirm([self.ROWS_997, self.ROWS_997, self.ROWS_997, self.ROWS_997])
        self.assertIn("still open", str(err))
        self.assertIn("closed with Nein", str(err))
        self.assertEqual(len(clicks), 2)
        self.assertTrue(2480 + 2 * 120 / 6 <= clicks[1][0] <= 2600, clicks)

    def test_confirm_delete_without_ja_clicks_beside_nein_then_closes(self):
        # OCR reads 'Nein' but no 'Ja' (2026-11-09): the Ja is clicked at its
        # place beside Nein; the dialog still open afterwards is closed with
        # Nein and the error says so.
        no_ja = [r for r in self.ROWS_997 if "Ja" not in r["text"]]
        err, clicks = self.confirm([no_ja, no_ja, no_ja, no_ja])
        self.assertIn("still open after 'Ja'", str(err))
        self.assertIn("closed with Nein", str(err))
        self.assertEqual(len(clicks), 2)
        nein = self.d.button_hit(no_ja, "Nein")
        self.assertEqual(clicks[0][0], nein["x"] - 128)

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
                                 restore_catalog_splitter=mock.DEFAULT, close_delete_dialog=mock.DEFAULT), \
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


if __name__ == "__main__":
    unittest.main()
