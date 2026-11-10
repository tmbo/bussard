# /// script
# requires-python = ">=3.10"
# dependencies = ["paramiko", "pyyaml"]
# ///
"""Generated parameter sets through ETS's parameter pages (epic #419, part 5 #424).

    uv run tools/ets-sweep/params.py plan --app <id> [--survey FILE] [--seed 1] [--n 3]
    uv run tools/ets-sweep/params.py run [--filter ...|--representative] [--seed 1] [--n 3] [--limit N]
    uv run tools/ets-sweep/params.py oracle [--filter ...|--representative]
    uv run tools/ets-sweep/params.py partial --filter <app> [--page P --label L --value V]

A configuration is drawn from what ETS shows, not from the product model:
`run` adds the device (defaults sweep identity), and the driver walks its
parameter pages (`param_pages` with rows: every page of the tree, channels
expanded, each row's label, control and value, read by OCR and pixels).
That survey is kept in `results/param-surveys/<app>.json`; `plan` draws
from it offline. Seeded (`--seed`, configuration index), so a run is
reproducible while ETS shows the same pages:

- half of the changes, at least one, are page switches: rows whose label is
  a parameter that enables an inactive page at defaults (`bussard device
  --json`, bussard's shared Dynamic evaluator), set to the enabling value;
- the rest are any other rows: a checkbox toggled, a radio button or
  dropdown on another option (`pick`, the driver chooses among the options
  ETS offers), a number field to a value in the range of the model's
  parameter of that label (min, max or between), a text field to a short
  text;
- once those are set, the pages are walked again and one or two rows of the
  pages that appeared are changed as well (a dependent page shown only after
  an enabling switch).

The driver sets each change (`set_param`: the page by its tree entry and
breadcrumb, the row by label and occurrence) and reads the row back; a page
or row ETS does not show, or a control it cannot set, is recorded as
`unreachable`, not as a failure. ETS then downloads and exports the project
(`export_project`) next to the capture. Run directories:
`captures/ets-sweep/<app>/params-<seed>-<n>/` with `params.json` (what was
asked, what was set) and `project.knxproj`; outcomes `results/params.json`.

`oracle` imports each export (`bussard import`) into a scratch model and
runs the offline-oracle row of the capture against it, the export standing
in for the product data (`1.1.1|<capture>|<export>|<app>`): the model holds
exactly the values ETS downloaded. Verdicts in `results/oracle-params.json`.

`--representative` runs the applications of `params-subset.json`
(`params_subset.py select`, a cover of mask families, parameter placement,
parameter types, unions, modules and page switches) instead of a filter.

`partial` captures ETS's parameter-only download (#572 A.4, #944): in one
sim process, the application download at defaults (`a-full`), then one
changed parameter and ETS's partial download (`b-partial-param`), each
step's slice of the capture in its run directory under
`captures/ets-sweep/<app>/params-partial/`, the project exported after
step b. The parameter is `--page/--label/--value`, else the first number
field of the survey that is no page switch, else such a dropdown.
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
SURVEYS = HERE / "results" / "param-surveys"
ORACLE_OUT = HERE / "results" / "oracle-params.json"
ORACLE = REPO / "scripts" / "campaign" / "95-offline-oracle.sh"
SETTABLE = ("checkbox", "radio", "dropdown", "number", "text")


def norm(t: str) -> str:
    """A label as compared across OCR and the model: lower case, letters
    and digits only."""
    return re.sub(r"[^a-z0-9äöüß]", "", (t or "").lower())


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
            out.setdefault(ref, {"id": ref, "text": e["text"], "value": shown,
                                 "default": str(e.get("default") or ""), "enables": block.get("text")})
    return list(out.values())


def number_ranges(model: dict) -> dict[str, tuple[float, float, str]]:
    """Per label (`norm`) the range of the model's integer or float
    parameters of that text, (min, max, 'Int'|'Float'); a label whose
    parameters disagree on the range keeps the range they share."""
    out: dict[str, tuple[float, float, str]] = {}
    for p in (model.get("parameters") or {}).values():
        kind = p.get("kind")
        if not isinstance(kind, dict):
            continue
        name = next(iter(kind), None)
        spec = kind.get(name) or {}
        lo, hi = spec.get("min"), spec.get("max")
        if name not in ("Int", "Float") or not isinstance(lo, (int, float)) or not isinstance(hi, (int, float)):
            continue
        if name == "Float" and (abs(lo) > 1e12 or abs(hi) > 1e12):
            continue  # an encoded bound, not a value
        key = norm(p.get("text") or "")
        if not key or hi <= lo:
            continue
        if key in out:
            a, b, _ = out[key]
            lo, hi = max(a, lo), min(b, hi)
            if hi <= lo:
                continue
        out[key] = (lo, hi, name)
    return out


def survey_rows(survey: list[dict]) -> list[dict]:
    """The rows of a survey a configuration may change: a control the
    driver can set, with a label."""
    out = []
    for page in survey:
        for row in page.get("rows") or []:
            if row.get("kind") not in SETTABLE or not (row.get("label") or "").strip():
                continue
            if row["kind"] == "radio" and len(row.get("options") or []) < 2:
                continue
            out.append({"page": {"crumb": page.get("crumb"), "page": page.get("page")}, "label": row["label"],
                        "n": row.get("n", 0), "kind": row["kind"], "before": row.get("value", "")})
    return out


def row_key(r: dict) -> tuple:
    return (norm((r.get("page") or {}).get("crumb") or ""), norm(r["label"]), r.get("n", 0))


def change_for(row: dict, rng: random.Random, ranges: dict, tag: str) -> dict | None:
    """The change of one row (see the module doc), None for a number field
    the model gives no range for."""
    out = {k: row[k] for k in ("page", "label", "n", "kind", "before")}
    kind = row["kind"]
    if kind == "checkbox":
        out["value"] = "0" if row["before"] == "1" else "1"
    elif kind in ("radio", "dropdown"):
        out["pick"] = round(rng.random(), 3)
    elif kind == "number":
        bounds = ranges.get(norm(row["label"]))
        if bounds is None:
            return None
        lo, hi, name = bounds
        if name == "Int":
            choices = [int(lo), int(hi), rng.randint(int(lo), int(hi))]
        else:
            choices = [lo, hi, round(rng.uniform(lo, hi), 1)]
        choices = [c for c in choices if str(c) != str(row["before"])] or [hi]
        value = rng.choice(choices)
        out["value"] = str(int(value)) if name == "Int" or float(value).is_integer() else str(value)
    else:
        out["value"] = f"bussard {tag}"
    return out


def generate(survey: list[dict], seed: int, index: int, changes: int = 5, model: dict | None = None,
             enablers: list[dict] | None = None) -> dict:
    """Configuration `index` of `seed` (see the module doc): page switches
    first, then other rows of the survey. Deterministic for (survey, model,
    enablers, seed, index)."""
    rng = random.Random(f"{seed}:{index}")
    rows = survey_rows(survey)
    ranges = number_ranges(model or {})
    by_label: dict[str, dict] = {}
    for e in enablers or []:
        by_label.setdefault(norm(e["text"]), e)
    switches = []
    for r in rows:
        e = by_label.get(norm(r["label"]))
        if e is None or r["kind"] == "number" or norm(e["value"]) == norm(r["before"]):
            continue
        if r["kind"] == "checkbox" and e["value"] not in ("0", "1"):
            continue
        switches.append((r, e))
    picked = rng.sample(switches, min(len(switches), max(1, changes // 2))) if switches else []
    config = []
    for r, e in picked:
        c = {k: r[k] for k in ("page", "label", "n", "kind", "before")}
        c.update({"value": e["value"], "switch": True})
        config.append(c)
    taken = {row_key(r) for r, _ in picked}
    rest = [r for r in rows if row_key(r) not in taken]
    rng.shuffle(rest)
    for r in rest:
        if len(config) >= changes:
            break
        c = change_for(r, rng, ranges, f"{seed}-{index}")
        if c is not None:
            config.append(c)
    return {"seed": seed, "index": index, "changes": config}


def dependent_changes(before: list[dict], after: list[dict], seed: int, index: int, model: dict | None = None,
                      k: int = 2) -> list[dict]:
    """Up to `k` changes on pages the first changes made ETS show (in
    `after`, not in `before`), seeded like `generate`."""
    rng = random.Random(f"{seed}:{index}:dependent")
    seen = {norm(p.get("crumb") or "") for p in before}
    rows = survey_rows([p for p in after if norm(p.get("crumb") or "") not in seen])
    rng.shuffle(rows)
    ranges = number_ranges(model or {})
    out = []
    for r in rows:
        if len(out) >= k:
            break
        c = change_for(r, rng, ranges, f"{seed}-{index}")
        if c is not None:
            out.append({**c, "dependent": True})
    return out


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


def set_changes(flow, ia: str, changes: list[dict]) -> list[dict]:
    """Each change through the driver's `set_param`; the outcome per change:
    set (the row reads back the value), unreachable (ETS does not show it
    or offers no other value), failed (the driver raised or the row reads
    another value)."""
    done = []
    for change in changes:
        body = {k: change[k] for k in ("page", "label", "n", "kind", "value", "pick") if k in change}
        try:
            r = flow("set_param", ia=ia, **body)
        except RuntimeError as exc:
            done.append({**change, "result": "failed", "error": str(exc)[:300]})
            continue
        result = "set" if r.get("set") else "unreachable" if r.get("unreachable") else "failed"
        done.append({**change, "result": result, "set_to": r.get("value"), "why": r.get("unreachable"),
                     "after": (r.get("row") or {}).get("value")})
    return done


def counts(done: list[dict]) -> dict:
    return {k: sum(1 for d in done if d["result"] == k) for k in ("set", "unreachable", "failed")}


def save_survey(app: str, pages: list[dict]) -> Path:
    SURVEYS.mkdir(parents=True, exist_ok=True)
    path = SURVEYS / f"{app}.json"
    path.write_text(json.dumps({"app": app, "when": datetime.now(timezone.utc).isoformat(), "pages": pages},
                               indent=1, ensure_ascii=False) + "\n")
    return path


def apply_hook(app: str, seed: int, index: int, changes: int, model: dict | None, enablers: list[dict] | None):
    """`sweep.run_one(before_download=...)`: survey the pages, draw the
    configuration, set it, then the dependent changes; what was asked and
    what was set go to params.json in the run directory."""

    def hook(flow, out: Path, ia: str = "1.1.1") -> dict:
        survey = flow("param_pages", ia=ia, rows=True).get("pages") or []
        save_survey(app, survey)
        config = generate(survey, seed, index, changes, model, enablers)
        done = set_changes(flow, ia, config["changes"])
        after: list[dict] = []
        if any(d["result"] == "set" for d in done):
            after = flow("param_pages", ia=ia, rows=True).get("pages") or []
            done += set_changes(flow, ia, dependent_changes(survey, after, seed, index, model))
        # The Katalog splitter back where the next catalog flow expects it.
        flow("ensure_layout")
        (out / "params.json").write_text(json.dumps(
            {"config": config, "pages": [{"crumb": p.get("crumb"), "page": p.get("page")} for p in survey],
             "pages_after": [{"crumb": p.get("crumb"), "page": p.get("page")} for p in after],
             "changes": done}, indent=1, ensure_ascii=False))
        return counts(done)

    return hook


def export_hook():
    """`sweep.run_one(after_download=...)`: the project export to the VM."""
    import vm

    def hook(flow, out: Path) -> dict:
        remote = f"{vm.REMOTE_DIR}\\exports\\{out.parent.name}-{out.name}.knxproj"
        flow("export_project", path=remote)
        return {"export_remote": remote}

    return hook


def captured_jobs(wanted: list[str], representative: bool = False) -> list[dict]:
    import defaults

    captured = json.loads(defaults.RESULTS.read_text()) if defaults.RESULTS.exists() else {}
    jobs = [{**j, "prev": captured[j["id"]]} for j in defaults.jobs()
            if (captured.get(j["id"]) or {}).get("outcome") == "captured"]
    if representative:
        import params_subset

        order = [r["app"] for r in params_subset.load()]
        by_id = {j["id"]: j for j in jobs}
        missing = [a for a in order if a not in by_id]
        if missing:
            print(f"representative: not captured by the defaults sweep: {', '.join(missing)}", flush=True)
        return [by_id[a] for a in order if a in by_id]
    return [j for j in jobs if not wanted or any(w in (j["id"] + " " + j["file"]).lower() for w in wanted)]


def shared_for(job: dict, work: Path) -> tuple[Path, Path]:
    """The shared product import and a per-application default model."""
    import defaults
    import oracle_model

    product = defaults.product_path(job["file"])
    shared = oracle_model.shared_import(work / ".oracle-products", product)
    model = oracle_model.build(work / job["id"] / "default-model", product, job["id"], mask=job["mask"], shared=shared)
    return shared, model


def import_product(c, path: Path) -> str:
    """The product file in ETS's catalog (quick when it is there)."""
    import catalog
    import vm

    remote = catalog.upload_if_missing(c, path)
    imp = vm.driver(c, "POST", "/ets/catalog_import", {"path": remote, "timeout": 3600, "project": "ets-sweep"},
                    timeout=3700)
    return str(imp.get("outcome", imp.get("error")))


def run(args) -> int:
    import defaults
    import sweep
    import vm

    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    c = vm.connect()
    vm.run(c, f'mkdir "{vm.REMOTE_DIR}\\exports"')
    done = 0
    for job in captured_jobs([w.lower() for w in args.filter.split(",") if w], args.representative):
        shared, model_dir = shared_for(job, args.work)
        model = model_json(shared, job["id"], model_dir)
        enablers = visible_enablers(device_json(model_dir))
        path = defaults.product_path(job["file"])
        imported = None
        for index in range(args.n):
            name = variant_name(args.seed, index)
            key = f"{job['id']}/{name}"
            if key in results and not args.redo:
                continue
            if imported is None:
                imported = import_product(c, path)
                print(f"import  {imported:12} {job['file']}", flush=True)
            r = sweep.run_one(c, path, job["id"], str(job["order_numbers"][0]), variant=name, mask=job["mask"],
                              properties=defaults.seed_properties(path, job["id"], job["prev"]),
                              before_download=apply_hook(job["id"], args.seed, index, args.changes, model, enablers),
                              after_download=export_hook())
            out = sweep.CAPTURES / job["id"] / name
            entry = {"file": job["file"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat(),
                     "outcome": r["outcome"], "error": r.get("error"), "params": r.get("before"),
                     "repair": (r.get("repair") or {}).get("dir"), "ia": r.get("ia")}
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
    if args.representative:
        import params_subset

        wanted = [r["app"].lower() for r in params_subset.load()]
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
            # The address ETS gave the device (1.1.0 for a coupler, #876).
            ia = str(entry.get("ia") or "1.1.1")
            row = f"{ia}|{run_dir / 'ets.pcapng'}|{export}|{app}"
            r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--out", str(args.work / app / name / "oracle"),
                                "--row", row], capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
            text = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
            summary = next((l for l in text.splitlines() if l.startswith(ia + " ")), "")
            m = re.match(re.escape(ia) + r"\s+(\S+)\s+(\S+)\s+(\S+)", summary)
            out[key] = {"verdict": m.group(2) if m else "oracle-error", "summary": summary.strip()}
        out[key]["set"] = (entry.get("params") or {}).get("set")
        out[key]["when"] = datetime.now(timezone.utc).isoformat()
        ORACLE_OUT.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{out[key]['verdict']:14} {key}", flush=True)
    return 0


def partial_change(survey: list[dict], enablers: list[dict] | None = None) -> dict | None:
    """The parameter-only change of the `partial` series: the first number
    field of the survey whose label enables no page (one above its value),
    else such a dropdown (another option)."""
    switch = {norm(e["text"]) for e in enablers or []}
    rows = [r for r in survey_rows(survey) if norm(r["label"]) not in switch]
    for kind in ("number", "dropdown"):
        for r in rows:
            if r["kind"] != kind:
                continue
            c = {k: r[k] for k in ("page", "label", "n", "kind", "before")}
            if kind == "number":
                if not re.fullmatch(r"\d+", r["before"] or ""):
                    continue
                c["value"] = str(int(r["before"]) + 1)
            else:
                c["pick"] = 0.0
            return c
    return None


def partial(args) -> int:
    """The parameter-only download series (see the module doc)."""
    import defaults
    import series
    import sweep
    import vm

    jobs = captured_jobs([w.lower() for w in args.filter.split(",") if w])
    if not jobs or not args.filter:
        raise SystemExit(f"{args.filter!r}: name the captured applications with --filter")
    c = vm.connect()
    vm.run(c, f'mkdir "{vm.REMOTE_DIR}\\exports"')
    manifest_path = HERE / "results" / "params-partial.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    for job in jobs:
        app, path = job["id"], defaults.product_path(job["file"])
        _, model_dir = shared_for(job, args.work)
        enablers = visible_enablers(device_json(model_dir))
        base = sweep.CAPTURES / app / "params-partial"
        result: dict = {"when": datetime.now(timezone.utc).isoformat(), "file": job["file"], "steps": {}}

        def flow(name: str, /, **body) -> dict:
            r = vm.driver(c, "POST", f"/ets/{name}", {"project": "ets-sweep", **body}, timeout=900)
            if not r.get("ok", True):
                raise RuntimeError(f"{name}: {r.get('error')}")
            return r

        print(f"import  {import_product(c, path):12} {job['file']}", flush=True)
        flow("project_tab", name="ets-sweep")
        for d in flow("devices")["devices"]:
            if not flow("delete_device", ia=d["ia"]).get("deleted"):
                raise RuntimeError(f"could not delete {d['ia']}")
        add = flow("catalog_add", search=str(job["order_numbers"][0]), version=sweep.app_version(app),
                   fallback_search="", password_wait=2)
        if not add.get("added"):
            raise RuntimeError(f"catalog add added nothing: {add.get('row')}")
        first = base / "a-full"
        first.mkdir(parents=True, exist_ok=True)
        sim = sweep.RemoteSim(c, path.resolve(), app, "1.1.1", 3672, None, first / "sim.log", mask=job["mask"],
                              properties=defaults.seed_properties(path, app, job["prev"]))
        try:
            step = series.download_step(c, flow, sim, first, app, "a-full", "application")
            (first / "driver.json").write_text(json.dumps({"app": app, "variant": "a-full", **step}, indent=1,
                                                          ensure_ascii=False))
            result["steps"]["a-full"] = {k: step[k] for k in ("ets", "end", "frames")}
            if step["ets"] != "ok":
                raise RuntimeError(f"a-full: ETS {step['ets']} ({step['end']})")
            survey = flow("param_pages", ia="1.1.1", rows=True).get("pages") or []
            save_survey(app, survey)
            if args.label:
                change = {"page": {"crumb": args.page, "page": args.page.rsplit(">", 1)[-1].strip()},
                          "label": args.label, "n": args.occurrence, "value": args.value}
            else:
                change = partial_change(survey, enablers)
            if change is None:
                raise RuntimeError("the survey offers no parameter-only change (no number field or dropdown)")
            done = set_changes(flow, "1.1.1", [change])
            result["change"] = done[0]
            if done[0]["result"] != "set":
                raise RuntimeError(f"the change was not set: {done[0]}")
            flow("ensure_layout")
            second = base / "b-partial-param"
            second.mkdir(parents=True, exist_ok=True)
            step = series.download_step(c, flow, sim, second, app, "b-partial-param", "partial")
            step["change"] = done[0]
            (second / "driver.json").write_text(json.dumps({"app": app, "variant": "b-partial-param", **step},
                                                           indent=1, ensure_ascii=False))
            result["steps"]["b-partial-param"] = {k: step[k] for k in ("ets", "end", "frames", "history")}
            remote = f"{vm.REMOTE_DIR}\\exports\\{app}-params-partial.knxproj"
            flow("export_project", path=remote)
            c.open_sftp().get(remote.replace("\\", "/"), str(second / "project.knxproj"))
            result["export"] = str(second / "project.knxproj")
        except Exception as exc:  # noqa: BLE001 - recorded per application
            result["error"] = str(exc)[:600]
        finally:
            sim.stop()
        manifest[app] = result
        manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{app}: {json.dumps(result['steps'])} {result.get('error') or ''}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "run", "oracle", "partial"):
        p = sub.add_parser(name)
        p.add_argument("--filter", default="")
        p.add_argument("--representative", action="store_true",
                       help="the applications of params-subset.json (params_subset.py select)")
        p.add_argument("--seed", type=int, default=1)
        p.add_argument("--n", type=int, default=3)
        p.add_argument("--changes", type=int, default=5)
        p.add_argument("--work", type=Path, default=REPO / "captures" / "ets-sweep" / ".params-work")
        p.add_argument("--limit", type=int, default=0)
        p.add_argument("--redo", action="store_true")
        if name == "plan":
            p.add_argument("--app", required=True)
            p.add_argument("--survey", type=Path, help="a survey file (default results/param-surveys/<app>.json)")
            p.add_argument("--model-json", type=Path, help="a model-cache JSON instead of the shared import")
            p.add_argument("--model-dir", type=Path, help="with --model-json: a default model for `bussard device`")
        if name == "partial":
            p.add_argument("--page", default="", help="the page's breadcrumb as the survey records it")
            p.add_argument("--label", default="")
            p.add_argument("--occurrence", type=int, default=0)
            p.add_argument("--value", default="")
    args = ap.parse_args()
    if args.cmd == "plan":
        survey = json.loads((args.survey or SURVEYS / f"{args.app}.json").read_text())["pages"]
        if args.model_json:
            model = json.loads(args.model_json.read_text())["model"]
            enablers = visible_enablers(device_json(args.model_dir)) if args.model_dir else None
        else:
            job = next((j for j in captured_jobs([args.app.lower()]) if j["id"] == args.app), None)
            if job is None:
                raise SystemExit(f"{args.app}: not a captured application of the defaults sweep")
            shared, model_dir = shared_for(job, args.work)
            model = model_json(shared, args.app, model_dir)
            enablers = visible_enablers(device_json(model_dir))
        print(json.dumps([generate(survey, args.seed, k, args.changes, model, enablers) for k in range(args.n)],
                         indent=1, ensure_ascii=False))
        return 0
    if args.cmd == "run":
        return run(args)
    if args.cmd == "partial":
        return partial(args)
    return oracle(args)


if __name__ == "__main__":
    sys.exit(main())
