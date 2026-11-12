# /// script
# requires-python = ">=3.11"
# ///
"""Offline tests of generate.py (issue #1097): `python3 tools/supported-devices/test_generate.py`."""
from __future__ import annotations

import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate  # noqa: E402


class RuleTest(unittest.TestCase):
    def test_application_id_of_a_sweep_key(self) -> None:
        self.assertEqual(generate.application_id("M-0001_A-140B-11-3036-O0048"), "0001140B11")
        self.assertEqual(generate.application_id("M-0048_A-140C-14-A512"), "0048140C14")
        self.assertIsNone(generate.application_id("nonsense"))

    def test_passes_needs_identical_loadctl_and_coverage(self) -> None:
        good = {"verdict": "identical", "loadctl": "identical", "coverage": "100.0%"}
        self.assertTrue(generate.passes(good))
        self.assertTrue(generate.passes(good | {"coverage": "97.7%"}))
        self.assertFalse(generate.passes(good | {"coverage": "94.9%"}))
        self.assertFalse(generate.passes(good | {"loadctl": "differs"}))
        self.assertFalse(generate.passes({k: v for k, v in good.items() if k != "loadctl"}))
        self.assertFalse(generate.passes(good | {"verdict": "not-comparable"}))
        self.assertFalse(generate.passes({k: v for k, v in good.items() if k != "coverage"}))

    def test_classify_holds_for_every_build(self) -> None:
        ok = {"outcome": "captured", "verdict": "identical", "loadctl": "identical",
              "coverage": "100.0%", "mask": "07B0"}
        skipped = {"outcome": "skipped-older-version", "verdict": "skipped-older-version", "mask": "07B0"}
        proven = {"07B0"}
        self.assertEqual(generate.classify([ok], proven), (100.0, 0))
        # A skipped sibling build is counted, not judged.
        self.assertEqual(generate.classify([ok, skipped], proven), (100.0, 1))
        # Every captured build must pass.
        thin = ok | {"verdict": "not-comparable"}
        self.assertIsNone(generate.classify([ok, thin], proven))
        self.assertIsNone(generate.classify([ok, ok | {"loadctl": "differs"}], proven))
        # Every mask of a build needs a proven device (00B6453201: 07B0 and 0705).
        self.assertEqual(generate.classify([ok, ok | {"mask": "0705"}], proven), ["0705"])
        self.assertEqual(generate.classify([ok, skipped | {"mask": "0701"}], proven), ["0701"])
        self.assertIsNone(generate.classify([skipped], proven))

    def test_check_hand_refuses_mask_and_differs_contradictions(self) -> None:
        row = {"outcome": "captured", "verdict": "identical", "loadctl": "identical", "mask": "07B0"}
        rows = {"0004D14221": [("M-0004_A-D142-21-8848-O000A", row)]}
        good = {"application_id": "0004D14221", "category": "proven", "mask": "07B0"}
        generate.check_hand([good], rows)
        with self.assertRaisesRegex(SystemExit, "0004D14221: hand mask 0701"):
            generate.check_hand([good | {"mask": "0701"}], rows)
        with self.assertRaisesRegex(SystemExit, "no sweep row"):
            generate.check_hand([good], {})
        generate.check_hand([good | {"mask_source": "#89"}], {})
        bad = {"0004D14221": [("k", row | {"loadctl": "differs"})]}
        with self.assertRaisesRegex(SystemExit, "0004D14221: proven, but the sweep reports differs"):
            generate.check_hand([good], bad)
        generate.check_hand([good | {"sweep_differs": "#1060"}], bad)
        # A known problem may differ.
        generate.check_hand([good | {"category": "unsupported"}], bad)

    def test_toml_str_escapes(self) -> None:
        text = 'a "b" \\ c\td'
        self.assertEqual(tomllib.loads(f"x = {generate.toml_str(text)}")["x"], text)


class OutputTest(unittest.TestCase):
    def test_compute_parses_and_keeps_the_family_rule(self) -> None:
        text, stats = generate.compute()
        data = tomllib.loads(text)
        hand_rows = tomllib.loads(generate.HAND.read_text())["device"]
        proven = {d["mask"] for d in hand_rows if d["category"] == "proven"}
        likely = [e for rule in data["rule"] for e in rule["likely"]]
        self.assertEqual(len(likely), stats["likely"])
        self.assertTrue(all(set(e["masks"]) <= proven for e in likely))
        self.assertTrue(all(e["coverage"] >= generate.COVERAGE_FLOOR for e in likely))
        hand = {d["application_id"] for d in tomllib.loads(generate.HAND.read_text())["device"]}
        ids = [e["id"] for e in likely] + [e["id"] for e in data["differs"]["entries"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertFalse(hand & set(ids), "a hand-kept application is never generated")
        self.assertFalse(any(i.startswith("00FA") for i in ids), "synthetic products are not listed")
        self.assertTrue(all(e["issue"] > 0 for e in data["differs"]["entries"]))


if __name__ == "__main__":
    unittest.main()
