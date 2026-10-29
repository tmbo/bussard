# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Offline tests of the ETS sweep's Mac-side tooling (no VM, no ETS, no bus).

    uv run tools/ets-sweep/test_ets_sweep.py [-v]
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_rows  # noqa: E402
import defaults  # noqa: E402
import followups  # noqa: E402
import nightly  # noqa: E402
import oracle_model  # noqa: E402
import series  # noqa: E402
import summary  # noqa: E402


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

    def test_relabel_wrong_rows_only_captured(self):
        results = {
            "M-0007_A-6109-50-71A0": {"outcome": "captured", "row": {"version": "1.1"}},
            "M-0002_A-6109-50-8FF2-O0007": {"outcome": "captured", "row": {"version": "5.0"}},
            "M-0007_A-6109-40-0000": {"outcome": "ets-failed", "row": {"version": "1.1"}},
        }
        self.assertEqual(defaults.relabel_wrong_rows(results), ["M-0007_A-6109-50-71A0"])
        self.assertEqual(results["M-0007_A-6109-50-71A0"]["outcome"], "skipped-catalog-version")
        self.assertEqual(results["M-0002_A-6109-50-8FF2-O0007"]["outcome"], "captured")
        self.assertEqual(results["M-0007_A-6109-40-0000"]["outcome"], "ets-failed")


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


if __name__ == "__main__":
    unittest.main()
