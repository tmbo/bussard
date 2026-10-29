# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Generated parameter sets through ETS's parameter pages (epic #419, part 5 #424).

    uv run tools/ets-sweep/params.py plan --app <id> [--seed 1] [--n 3]      # offline: the configurations
    uv run tools/ets-sweep/params.py run [--filter ...] [--seed 1] [--n 3] [--limit N]
    uv run tools/ets-sweep/params.py oracle [--filter ...]

`plan` draws N configurations per application from the parameter types of
bussard's product model (`.bussard/model-cache/<app>.json` of the shared
product import, `oracle_model.shared_import`), seeded, so a run is
reproducible: each configuration changes `--changes` parameters away from
their default, picked among those with a label ETS shows (an enumeration
gets another of its values, an integer a value in its range). Half of them,
at least one, are page switches ETS shows at defaults (the parameter and
value that activate an inactive page, from `bussard device --json`, i.e.
bussard's shared Dynamic evaluator); they are set first. Floats,
texts and the other types stay at their defaults for now.

`run` has ETS add the device (defaults sweep identity), sets each change on
the parameter pages through the driver (`param_pages`, `set_param`: the page
list, the parameter's label by OCR, the control on its row), downloads, and
exports the project (`export_project`) next to the capture. A parameter the
editor cannot reach (a page it does not find, a label not shown with the
other values, a vendor page) is recorded as `unreachable`, not as a failure.
Run directories: `captures/ets-sweep/<app>/params-<seed>-<n>/` with
`params.json` (what was asked, what was set) and `project.knxproj`.
Outcomes: `results/params.json`.

`oracle` imports each export (`bussard import`) into a scratch model and runs
the offline-oracle row of the capture against it, the export standing in for
the product data (`1.1.1|<capture>|<export>|<app>`): the model holds exactly
the values ETS downloaded. Verdicts in `results/oracle-params.json`.

The driver flows were written without ETS at hand (2026-10-30) and are
unverified: they anchor on text read by OCR and fail with what they saw.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULTS = HERE / "results" / "params.json"
ORACLE_OUT = HERE / "results" / "oracle-params.json"
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"


def candidates(model: dict) -> list[dict]:
    """The parameters a configuration may change: an enumeration with at
    least two values or an integer with a range, with a label ETS shows."""
    out = []
    for pid, p in sorted((model.get("parameters") or {}).items()):
        text = (p.get("text") or "").strip()
        if not text:
            continue
        kind = p.get("kind")
        default = str(p.get("default") or "")
        if isinstance(kind, dict) and "Enum" in kind:
            labels = [(str(v), str(t)) for v, t in p.get("labels") or []]
            if len(labels) >= 2:
                out.append({"id": pid, "text": text, "kind": "enum", "default": default, "labels": labels})
        elif isinstance(kind, dict) and "Int" in kind:
            lo, hi = kind["Int"].get("min"), kind["Int"].get("max")
            if isinstance(lo, int) and isinstance(hi, int) and hi > lo:
                out.append({"id": pid, "text": text, "kind": "int", "default": default, "min": lo, "max": hi})
    return out


def visible_enablers(device: dict) -> list[dict]:
    """The parameters ETS shows at defaults that switch a page on, from
    `bussard device <ia> --json` (bussard's shared Dynamic evaluator, so no
    ETS semantics are re-implemented here): each inactive page names the
    parameter and the value that activate it. A condition that is not one
    value (`>0`) is left out."""
    out: dict[str, dict] = {}
    for block in device.get("blocks") or []:
        for e in (block.get("inactive") or {}).get("enable") or []:
            ref, shown = e.get("reference"), str(e.get("set_to") or "")
            if not ref or not e.get("text") or re.match(r"^[<>=!]", shown):
                continue
            out.setdefault(ref, {"id": ref, "text": e["text"], "kind": "enum", "value": shown, "shown": shown,
                                 "default": str(e.get("default") or ""), "enables": block.get("text")})
    return list(out.values())


def generate(model: dict, seed: int, n: int, changes: int = 5, visible: list[dict] | None = None) -> list[dict]:
    """N configurations (see the module doc); each a list of changes
    {id, text, kind, value, shown}. `shown` is what ETS displays for the value
    (an enumeration's label, the number). With `visible` (`visible_enablers`)
    a configuration switches pages on first, parameters ETS shows at defaults;
    the rest of its changes come from the whole model. Deterministic for
    (model, visible, seed)."""
    pool = candidates(model)
    rng = random.Random(seed)
    configs = []
    for k in range(n):
        shown_first = rng.sample(visible, min(len(visible), max(1, changes // 2))) if visible else []
        taken = {c["text"] for c in shown_first}
        rest = [c for c in pool if c["text"] not in taken]
        picked = rng.sample(rest, min(changes - len(shown_first), len(rest)))
        config = [{k2: c[k2] for k2 in ("id", "text", "kind", "value", "shown", "enables") if k2 in c}
                  for c in shown_first]
        for c in picked:
            if c["kind"] == "enum":
                others = [(v, t) for v, t in c["labels"] if v != c["default"]]
                value, shown = rng.choice(others)
            else:
                choices = [x for x in (c["min"], c["max"], rng.randint(c["min"], c["max"])) if str(x) != c["default"]]
                value = shown = str(rng.choice(choices or [c["max"]]))
            config.append({"id": c["id"], "text": c["text"], "kind": c["kind"], "value": value, "shown": shown})
        # Page switches first: the pages they open hold later changes.
        configs.append({"seed": seed, "index": k,
                        "changes": sorted(config, key=lambda x: ("enables" not in x, x["id"]))})
    return configs


def variant_name(seed: int, index: int) -> str:
    return f"params-{seed}-{index}"


def model_json(shared: Path, app: str, model_dir: Path | None = None) -> dict:
    """bussard's product model of `app` (the shared import's model cache),
    written on demand by `bussard device` when the cache lacks it."""
    path = shared / ".bussard" / "model-cache" / f"{app}.json"
    if not path.exists() and model_dir is not None:
        import oracle_model

        subprocess.run([str(oracle_model.BUSSARD), "device", "1.1.1", "--dir", str(model_dir)],
                       capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    return json.loads(path.read_text())["model"]


def device_json(model_dir: Path) -> dict:
    """`bussard device 1.1.1 --json` of a default model (empty on failure)."""
    import oracle_model

    r = subprocess.run([str(oracle_model.BUSSARD), "device", "1.1.1", "--json", "--dir", str(model_dir)],
                       capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {}


def apply_hook(config: dict):
    """`sweep.run_one(before_download=...)`: set every change on the
    parameter pages; what was set and what was unreachable go to
    params.json in the run directory."""

    def hook(flow, out: Path) -> dict:
        pages = flow("param_pages", ia="1.1.1").get("pages") or []
        done = []
        for change in config["changes"]:
            try:
                r = flow("set_param", ia="1.1.1", text=change["text"], kind=change["kind"], value=change["shown"],
                         pages=pages)
                done.append({**change, "result": "set" if r.get("set") else "unreachable",
                             "page": r.get("page"), "seen": r.get("seen")})
            except RuntimeError as exc:
                done.append({**change, "result": "failed", "error": str(exc)[:300]})
        (out / "params.json").write_text(json.dumps({"config": config, "pages": pages, "changes": done},
                                                    indent=1, ensure_ascii=False))
        return {"set": sum(1 for d in done if d["result"] == "set"),
                "unreachable": sum(1 for d in done if d["result"] == "unreachable"),
                "failed": sum(1 for d in done if d["result"] == "failed")}

    return hook


def export_hook():
    """`sweep.run_one(after_download=...)`: the project export to the VM."""
    import vm

    def hook(flow, out: Path) -> dict:
        remote = f"{vm.REMOTE_DIR}\\exports\\{out.parent.name}-{out.name}.knxproj"
        flow("export_project", path=remote)
        return {"export_remote": remote}

    return hook


def captured_jobs(wanted: list[str]) -> list[dict]:
    import defaults

    captured = json.loads(defaults.RESULTS.read_text()) if defaults.RESULTS.exists() else {}
    jobs = [{**j, "prev": captured[j["id"]]} for j in defaults.jobs()
            if (captured.get(j["id"]) or {}).get("outcome") == "captured"]
    return [j for j in jobs if not wanted or any(w in (j["id"] + " " + j["file"]).lower() for w in wanted)]


def shared_for(job: dict, work: Path) -> tuple[Path, Path]:
    """The shared product import and a per-application default model."""
    import defaults
    import oracle_model

    product = defaults.product_path(job["file"])
    shared = oracle_model.shared_import(work / ".oracle-products", product)
    model = oracle_model.build(work / job["id"] / "default-model", product, job["id"], mask=job["mask"], shared=shared)
    return shared, model


def run(args) -> int:
    import defaults
    import sweep
    import vm

    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    c = vm.connect()
    vm.run(c, f'mkdir "{vm.REMOTE_DIR}\\exports"')
    done = 0
    for job in captured_jobs([w.lower() for w in args.filter.split(",") if w]):
        shared, model_dir = shared_for(job, args.work)
        configs = generate(model_json(shared, job["id"], model_dir), args.seed, args.n, args.changes,
                           visible=visible_enablers(device_json(model_dir)))
        path = defaults.product_path(job["file"])
        for config in configs:
            name = variant_name(config["seed"], config["index"])
            key = f"{job['id']}/{name}"
            if key in results and not args.redo:
                continue
            r = sweep.run_one(c, path, job["id"], str(job["order_numbers"][0]), variant=name, mask=job["mask"],
                              properties=defaults.seed_properties(path, job["id"], job["prev"]),
                              before_download=apply_hook(config), after_download=export_hook())
            out = sweep.CAPTURES / job["id"] / name
            entry = {"file": job["file"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat(),
                     "outcome": r["outcome"], "error": r.get("error"), "params": r.get("before"),
                     "repair": (r.get("repair") or {}).get("dir")}
            remote = (r.get("after") or {}).get("export_remote")
            if remote:
                try:
                    c.open_sftp().get(remote.replace("\\", "/"), str(out / "project.knxproj"))
                    entry["export"] = True
                except OSError as exc:
                    entry["export"] = f"not fetched: {exc}"[:200]
            results[key] = entry
            RESULTS.parent.mkdir(exist_ok=True)
            RESULTS.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")
            print(f"{entry['outcome']:13} {key} {entry.get('params')}", flush=True)
            done += 1
            if args.limit and done >= args.limit:
                return 0
    return 0


def oracle(args) -> int:
    """Each captured configuration against `bussard import` of its export."""
    import oracle_model
    import sweep

    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    out = json.loads(ORACLE_OUT.read_text()) if ORACLE_OUT.exists() else {}
    wanted = [w.lower() for w in args.filter.split(",") if w]
    for key, entry in sorted(results.items()):
        if entry.get("outcome") != "captured" or entry.get("export") is not True:
            continue
        if wanted and not any(w in key.lower() for w in wanted):
            continue
        app, name = key.split("/", 1)
        run_dir = sweep.CAPTURES / app / name
        export = run_dir / "project.knxproj"
        model = args.work / app / name / "model"
        model.mkdir(parents=True, exist_ok=True)
        (model / "bussard.toml").write_text(oracle_model.model_toml())
        imp = subprocess.run([str(oracle_model.BUSSARD), "import", "--dir", str(model), str(export)],
                             capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
        if imp.returncode != 0:
            out[key] = {"verdict": "import-failed", "error": (imp.stderr or imp.stdout)[-300:]}
        else:
            row = f"1.1.1|{run_dir / 'ets.pcapng'}|{export}|{app}"
            r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--out", str(args.work / app / name / "oracle"),
                                "--row", row], capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
            text = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
            summary = next((l for l in text.splitlines() if l.startswith("1.1.1 ")), "")
            m = re.match(r"1\.1\.1\s+(\S+)\s+(\S+)\s+(\S+)", summary)
            out[key] = {"verdict": m.group(2) if m else "oracle-error", "summary": summary.strip()}
        out[key]["when"] = datetime.now(timezone.utc).isoformat()
        ORACLE_OUT.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{out[key]['verdict']:14} {key}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "run", "oracle"):
        p = sub.add_parser(name)
        p.add_argument("--filter", default="")
        p.add_argument("--seed", type=int, default=1)
        p.add_argument("--n", type=int, default=3)
        p.add_argument("--changes", type=int, default=5)
        p.add_argument("--work", type=Path, default=REPO / "captures" / "ets-sweep" / ".params-work")
        p.add_argument("--limit", type=int, default=0)
        p.add_argument("--redo", action="store_true")
        if name == "plan":
            p.add_argument("--app", required=True)
            p.add_argument("--model-json", type=Path, help="a model-cache JSON instead of the shared import")
            p.add_argument("--model-dir", type=Path, help="with --model-json: a default model for `bussard device`")
    args = ap.parse_args()
    if args.cmd == "plan":
        if args.model_json:
            model = json.loads(args.model_json.read_text())["model"]
            visible = visible_enablers(device_json(args.model_dir)) if args.model_dir else None
        else:
            job = next((j for j in captured_jobs([args.app.lower()]) if j["id"] == args.app), None)
            if job is None:
                raise SystemExit(f"{args.app}: not a captured application of the defaults sweep")
            shared, model_dir = shared_for(job, args.work)
            model = model_json(shared, args.app, model_dir)
            visible = visible_enablers(device_json(model_dir))
        print(json.dumps(generate(model, args.seed, args.n, args.changes, visible), indent=1, ensure_ascii=False))
        return 0
    if args.cmd == "run":
        return run(args)
    return oracle(args)


if __name__ == "__main__":
    sys.exit(main())
