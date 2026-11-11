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
`unreachable`, not as a failure. After the last change the pages are
surveyed once more and every change is read back as ETS shows it (a number
or text field exactly, through the clipboard, `read_param`): the model the
oracle compares with is built from those values, never from what the driver
meant to set, and a change that does not read back (`failed`, `lost`) makes
the run a `driver-error-params`, never compared. ETS then downloads. Run
directories: `captures/ets-sweep/<app>/params-<seed>-<n>/` with
`params.json` (the surveys, what was asked, set and shown); outcomes
`results/params.json`.

`oracle` builds bussard's model from `params.json`: each change's label on
its page and channel names its parameter references in the product's
Dynamic tree (`ref_places`); where the tree has more of them than ETS shows
rows, bussard's shared Dynamic evaluator decides which is shown
(`bussard_shown_refs`), else the run is `unmapped`, not compared. The shown
value is the device file's value (`"param@<ref>" = ...`). The row
`1.1.1|<capture>|<product>|<app>` then compares ETS's download with
bussard's plan for that model. Verdicts in `results/oracle-params.json`.
There is no project export: ETS exports the product data of every device
the project ever held (17.5 GB for `ets-sweep`, more than 14 minutes,
2026-11-10).

`--representative` runs the applications of `params-subset.json`
(`params_subset.py select`, a cover of mask families, parameter placement,
parameter types, unions, modules and page switches) instead of a filter.

`partial` captures ETS's parameter-only download (#572 A.4, #944): in one
sim process, the application download at defaults (`a-full`), then one
changed parameter and ETS's partial download (`b-partial-param`), each
step's slice of the capture in its run directory under
`captures/ets-sweep/<app>/params-partial/`, the change read back as for
`run`. The parameter is `--page/--label/--value`, else the first number
field of the survey that is no page switch, else such a dropdown.
`--oracle` (or `--oracle-only` on a recorded series) then runs the
`run=params` row: knx-sim replays step a, `bussard flash --parameters-only`
writes the model of the read-back value, and the device states compare
(memory, property elements, load-control records).
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
# The decimal separator of the sweep's ETS (German UI, de-DE).
DECIMAL = ","


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


# The parameter types a control of each kind shows (`value_of` the same).
FITS = {"radio": ("Enum",), "dropdown": ("Enum",), "checkbox": ("Enum", "Int"),
        "number": ("Int", "Float"), "text": ("Text",)}


def label_kinds(model: dict) -> dict[str, set]:
    """Per label ETS shows (`ref_label`: the reference's own text, else its
    parameter's) the parameter types behind it ('Enum', 'Int', 'Text', ...)."""
    out: dict[str, set] = {}
    params_ = model.get("parameters") or {}
    for ref, r in (model.get("parameter_refs") or {}).items():
        p = params_.get(r.get("parameter") or "") or {}
        kind = p.get("kind")
        name = next(iter(kind), None) if isinstance(kind, dict) else kind
        label = ref_label(model, ref)
        if name and label:
            out.setdefault(label, set()).add(name)
    return out


def fits_model(row: dict, kinds: dict[str, set]) -> bool:
    """Whether a survey row can be a model parameter: a reference whose
    label is alike (OCR slips, a module page's placeholder text aside) has
    a type the row's control shows. A time field the driver read as text
    (Ekinex 'volle Bandbreite Dimmzeit') or a button read as a dropdown
    (Ekinex 'Herunterladen') is none, and no change is drawn for it
    (2026-11-11)."""
    want = set(FITS.get(row["kind"], ()))
    exact = kinds.get(" ".join((row["label"] or "").split()))
    if exact is not None:
        return bool(exact & want)
    return any(types & want for label, types in kinds.items() if alike(label, row["label"], 0.9))


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
        before = str(row["before"]).replace(",", ".")
        choices = [c for c in choices if str(c) != before] or [hi]
        value = rng.choice(choices)
        text = str(int(value)) if name == "Int" or float(value).is_integer() else str(value)
        # Typed as ETS shows numbers (the sweep's ETS is German: 12,3).
        out["value"] = text.replace(".", DECIMAL)
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
    if (model or {}).get("parameters"):
        kinds = label_kinds(model)
        rows = [r for r in rows if fits_model(r, kinds)]
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
    if (model or {}).get("parameters"):
        kinds = label_kinds(model)
        rows = [r for r in rows if fits_model(r, kinds)]
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


def alike(a: str, b: str, ratio: float = 0.85) -> bool:
    """Two texts as OCR and the product data give them: equal after `norm`
    ('Al-16' read for 'A1-16' counts as 'A1-16'), or close with the same
    digits."""
    a, b = norm(re.sub(r"(?<=A)l(?=[\d\-:\s]|$)", "1", a or "")), norm(re.sub(r"(?<=A)l(?=[\d\-:\s]|$)", "1", b or ""))
    if a == b:
        return True
    if not a or not b or re.sub(r"\D", "", a) != re.sub(r"\D", "", b):
        return False
    import difflib

    return difflib.SequenceMatcher(None, a, b).ratio() >= ratio


def ref_label(model: dict, ref: str) -> str:
    """The text ETS shows for parameter reference `ref`: the reference's
    own text, else its parameter's."""
    ref = model_ref(ref)
    r = (model.get("parameter_refs") or {}).get(ref) or {}
    p = (model.get("parameters") or {}).get(r.get("parameter") or "") or {}
    return " ".join((r.get("text") or p.get("text") or "").split())


def model_ref(ref: str) -> str:
    """The product model's reference of a device-form one: a module
    instance's `MD-2_M-3_P-32_R-44` is the module's `MD-2_P-32_R-44`."""
    m = re.match(r"^(MD-\d+)_M-\d+(?:_MI-\d+)?(_.+)$", ref)
    return m.group(1) + m.group(2) if m else ref


def device_ref(instance: str | None, ref: str) -> str:
    """The device-form reference of `ref` inside module instance `instance`
    (`MD-2_M-3` + `MD-2_P-32_R-44` -> `MD-2_M-3_P-32_R-44`), as bussard's
    device files key it (`device_view::device_ref`); the ref itself outside
    a module."""
    if not instance or "_" not in instance:
        return ref
    module_def = instance.split("_", 1)[0]
    return instance + ref[len(module_def):] if ref.startswith(module_def) else ref


def ref_places(model: dict) -> list[dict]:
    """Where each parameter reference sits in the product's Dynamic tree, in
    tree order: {ref, channel, page, pages, label, instance, group}.
    `channel` is the enclosing channel's text (None outside one; it may be
    `{{0}}`, the channel's text parameter). `pages` are the texts of every
    enclosing block, outer first, `page` the innermost: ETS shows a nested
    block as a section of its parent page at times (Theben's 'Allgemein'
    holding 'Verhalten'). A block without a text is named by its parameter
    (`param_ref`, the ABB 'Page1' block). `instance` is the module instance
    (None outside one), `group` the instance, or the channel when its text
    is a placeholder: the pages of a group's siblings look alike and are
    told apart by their order. `ref` is in device form. A plain walk of the
    tree's structure: which branch is shown is not decided here (that is
    the shared Dynamic evaluator's job), so a page may list a label more
    often than ETS shows it."""
    out: list[dict] = []
    modules = model.get("module_dynamics") or {}

    def block_text(b: dict) -> str | None:
        if b.get("text"):
            return b["text"]
        if b.get("param_ref"):
            return ref_label(model, b["param_ref"]) or None
        return None

    def walk(nodes, channel, pages, instance, group, depth=0):
        for n in nodes or []:
            if "channel" in n:
                c = n["channel"]
                text = c.get("text")
                g = group or (c.get("id") if text and "{{" in text else None)
                walk(c.get("nodes"), text, pages, instance, g, depth)
            elif "block" in n:
                b = n["block"]
                text = block_text(b)
                walk(b.get("nodes"), channel, pages + [text] if text else pages, instance, group, depth)
            elif "choose" in n:
                for w in n["choose"].get("when") or []:
                    walk(w.get("nodes"), channel, pages, instance, group, depth)
            elif "module" in n and depth < 4:
                m = n["module"]
                walk(modules.get(m.get("def")) or [], channel, pages, m.get("id"), m.get("id"), depth + 1)
            elif "p" in n:
                out.append({"ref": device_ref(instance, n["p"]), "channel": channel,
                            "page": pages[-1] if pages else None, "pages": list(pages),
                            "label": ref_label(model, n["p"]), "instance": instance, "group": group})
    walk(model.get("dynamic"), None, [], None, None)
    return out


def page_pattern(template: str) -> "re.Pattern | None":
    """The pattern of a page text with `{{...}}` placeholders, anchored at
    both ends: the literal text as it is (runs of spaces as any space, case
    folded), each placeholder non-empty text. A placeholder at the very end
    may be empty, as ETS leaves an unset text parameter out ('Eingang
    {{ChNo}}: {{0}}' shown as 'Eingang A:'). None for a page text of
    placeholders only, which could be any page."""
    t = re.sub(r"^\s*-\s*", "", template or "").strip()
    parts = re.split(r"\{\{[^}]*\}\}", t)
    if not "".join(parts).strip():
        return None

    def lit(x: str) -> str:
        return r"\s*".join(re.escape(w) for w in x.split()) if x.strip() else ""
    out = ""
    for i, part in enumerate(parts):
        out += lit(part) if part.strip() else ""
        if i < len(parts) - 1:
            last = i == len(parts) - 2 and not parts[-1].strip()
            out += r"(?:\s*.+?)?" if last else r"\s*.+?\s*"
    return re.compile("^" + out + "$", re.IGNORECASE)


def page_matches(template: str, shown: str) -> bool:
    """Whether a page ETS shows as `shown` is the tree's page `template`:
    alike, or, for a module's page text with `{{...}}` placeholders, the
    whole shown text by `page_pattern` (never a page text of placeholders
    only)."""
    t = re.sub(r"^\s*-\s*", "", template or "")
    v = re.sub(r"^\s*-\s*", "", shown or "").strip()
    if "{{" not in t:
        return alike(t, v)
    pattern = page_pattern(t)
    return pattern is not None and pattern.match(v) is not None


def literal_len(template: str) -> int:
    return len(norm(re.sub(r"\{\{[^}]*\}\}", "", template or "")))


def best_pages(places: list[dict], shown: str) -> set:
    """The tree's page texts a shown page is: of those that match, the ones
    with the most literal text ('Eingang {{ChNo}}: Sperre' over 'Eingang
    {{ChNo}}: {{0}}' for 'Eingang A: Sperre')."""
    matching = {t for p in places for t in p.get("pages") or [p["page"]] if t and page_matches(t, shown)}
    if not matching:
        return set()
    # An exact match wins over a close one ('FS: Ampel' is not 'LS: Ampel').
    exact = {t for t in matching if "{{" not in t and norm(re.sub(r"^\s*-\s*", "", t)) == norm(
        re.sub(r"^\s*-\s*", "", shown or ""))}
    if exact:
        return exact
    top = max(literal_len(t) for t in matching)
    return {t for t in matching if literal_len(t) == top}


def page_parts(page: dict) -> tuple[str | None, str]:
    """(channel, page) of a survey page: the breadcrumb 'Ausgang 9 >
    Ausgang 9: Funktionsfreigabe' names both; a page outside a channel has
    one part. A shortened last part ('...') gives way to the tree entry."""
    parts = [p.strip() for p in (page.get("crumb") or "").split(">") if p.strip()]
    last = parts[-1] if parts else ""
    if not last or last.endswith("..."):
        last = page.get("page") or last
    return (parts[0] if len(parts) > 1 else None), last.strip()


def enum_value(model: dict, ref: str, shown: str) -> str | None:
    """The value of enumeration reference `ref` whose label ETS shows as
    `shown`: the one label alike, else the one label it begins (OCR loses
    the end of a radio option's text at times: '0 = Aus' for '0 = Aus,
    1 = Ein')."""
    ref = model_ref(ref)
    r = (model.get("parameter_refs") or {}).get(ref) or {}
    p = (model.get("parameters") or {}).get(r.get("parameter") or "") or {}
    labels = [(str(v), str(t)) for v, t in p.get("labels") or []]
    hits = [v for v, t in labels if alike(t, shown, 0.9)]
    if len(hits) != 1 and len(norm(shown)) >= 3:
        hits = [v for v, t in labels if norm(t).startswith(norm(shown))]
    return hits[0] if len(hits) == 1 else None


def ref_default(model: dict, ref: str) -> str:
    """The default of reference `ref`: its own value, else its parameter's."""
    ref = model_ref(ref)
    r = (model.get("parameter_refs") or {}).get(ref) or {}
    p = (model.get("parameters") or {}).get(r.get("parameter") or "") or {}
    return str(r.get("value") if r.get("value") not in (None, "") else p.get("default", ""))


def value_of(model: dict, ref: str, change: dict) -> str | None:
    """The device file's value of reference `ref` for what ETS shows
    (`change['shown']`), None when it does not convert."""
    ref = model_ref(ref)
    shown = str(change.get("shown", ""))
    kind = change["kind"]
    r = (model.get("parameter_refs") or {}).get(ref) or {}
    p = (model.get("parameters") or {}).get(r.get("parameter") or "") or {}
    pkind = p.get("kind") if isinstance(p.get("kind"), dict) else {}
    # A control of another type than the parameter's is not its row. A
    # virtual parameter in an editable control stays: it is downloaded
    # through the calculations it feeds (MDT's module 'Wert Kontakt
    # geöffnet', MD-2_P-32).
    fits = FITS.get(kind, ())
    if not any(k in pkind for k in fits):
        return None
    if kind in ("radio", "dropdown"):
        return enum_value(model, ref, shown)
    if kind == "checkbox" and "Enum" in pkind:
        return shown if shown in [str(v) for v, _ in p.get("labels") or []] else None
    if kind in ("checkbox", "number"):
        # ETS shows a decimal in its locale (12,3); the device file takes 12.3.
        number = shown.replace(DECIMAL, ".") if kind == "number" else shown
        return number if re.fullmatch(r"-?\d+(\.\d+)?", number) else None
    return shown


def candidates_of(places: list[dict], change: dict) -> list[str]:
    """The references labelled like the change on its page and channel, in
    tree order."""
    channel, page = page_parts(change["page"])
    pages = best_pages(places, page)
    cands = [p["ref"] for p in places if alike(p["label"], change["label"], 0.9)
             and set(p.get("pages") or [p["page"]]) & pages
             and (channel is None or channel_matches(p["channel"], channel))]
    return list(dict.fromkeys(cands))


def channel_matches(template: str | None, shown: str) -> bool:
    """Whether a channel ETS shows as `shown` can be the tree's channel
    `template`: alike, or by its placeholder pattern; a channel text of a
    placeholder only (`{{0}}`, its text parameter) can be any channel, told
    apart from its siblings by order (`group_refs`)."""
    if not template:
        return False
    if "{{" not in template:
        return alike(template, shown)
    pattern = page_pattern(template)
    return pattern is None or pattern.match(shown.strip()) is not None


def model_changes(model: dict, survey_after: list[dict], done: list[dict],
                  shown_refs=None, page_orders: list[list[dict]] | None = None) -> tuple[dict, list[str]]:
    """The device file's parameter values for the changes ETS shows after
    the run, {"param@<ref>": value}, and the changes that do not map.

    A change's label on its page and channel names its candidate
    references (`candidates_of`). When the tree lists more of them than
    ETS shows rows of that label (the branches of a choose), `shown_refs`
    decides: called with every candidate stored, it returns the references
    bussard's shared Dynamic evaluator shows under those values (`bussard
    device`: a stored parameter "not shown under the current values" is
    left out), and the change's occurrence picks among those. Without it,
    or when the count still differs, the change is a problem."""
    places = ref_places(model)
    rows_of: dict[tuple, int] = {}
    for page in survey_after:
        for row in page.get("rows") or []:
            key = (norm(page.get("crumb") or ""), norm(row.get("label") or ""))
            rows_of[key] = rows_of.get(key, 0) + 1
    values: dict[str, str] = {}
    problems: list[str] = []
    open_: list[tuple[dict, list[str], int]] = []
    for d in done:
        if d.get("result") != "set":
            continue
        n_rows = d.get("rows_with_label") or rows_of.get((norm(d["page"].get("crumb") or ""), norm(d["label"])), 0)
        cands = candidates_of(places, d)
        _, page = page_parts(d["page"])
        if not cands:
            problems.append(f"no reference labelled {d['label']!r} on {page!r}")
            continue
        if len(cands) == n_rows:
            cands = [cands[d.get("n", 0)]]
        def virtual(ref: str) -> bool:
            r = (model.get("parameter_refs") or {}).get(model_ref(ref)) or {}
            return bool(((model.get("parameters") or {}).get(r.get("parameter") or "") or {}).get("is_virtual"))
        if d["kind"] == "text" and all(virtual(r) for r in cands):
            # An information text ETS never downloads: nothing to model.
            continue
        # A candidate whose values ETS's text does not name is not the row.
        converted = [(ref, v) for ref in cands if (v := value_of(model, ref, d)) is not None]
        if not converted:
            problems.append(f"{d['label']!r}: no value for {d.get('shown')!r}")
            continue
        if len(cands) > 1 and all(str(v) == ref_default(model, r) for r, v in converted):
            # ETS shows the default: whichever reference it is, the model's
            # default stands (and bussard's evaluator flags no hidden value
            # at its default, so it could not tell them apart).
            continue
        if len(cands) > 1:
            open_.append((d, converted, n_rows))
            continue
        values[f"param@{converted[0][0]}"] = str(converted[0][1])
    # Each open change on its own: its candidates stored over the mapped
    # values, so the candidates of another change switch no branch here.
    definite = dict(values)
    for d, converted, n_rows in open_:
        cands = [r for r, _ in converted]
        probes = module_probes(places, cands, matched_page(places, d, cands[0]))
        stored = {**definite, **{f"param@{r}": str(v) for r, v in converted}}
        for ref in probes.values():
            stored.setdefault(f"param@{ref}", ref_default(model, ref))
        shown = shown_refs(stored) if shown_refs else None
        visible = [r for r in cands if shown is not None and r in shown]
        _, page = page_parts(d["page"])
        if probes and shown is not None:
            picked = module_instance_refs(places, page_orders or [survey_after], d, cands, shown, probes)
            if picked is None:
                problems.append(f"{d['label']!r} on {page!r}: the page order does not tell the module instance")
                continue
            visible = picked
        if len(visible) != n_rows:
            problems.append(f"{len(cands)} references labelled {d['label']!r} on {page!r}, "
                            f"{len(visible)} shown, ETS shows {n_rows}")
            continue
        ref = visible[d.get("n", 0)]
        values[f"param@{ref}"] = str(value_of(model, ref, d))
        # Resolved in change order (page switches first): a later change's
        # page may need this one's value to be shown.
        definite[f"param@{ref}"] = values[f"param@{ref}"]
    return values, problems


def matched_page(places: list[dict], change: dict, ref: str) -> str | None:
    """The page text `ref` was matched on for `change` (`candidates_of`):
    its innermost page, or the enclosing block whose text ETS shows (a
    nested block shown as a section of its parent page)."""
    by_ref = {p["ref"]: p for p in places}
    place = by_ref.get(ref) or {}
    _, shown_page = page_parts(change["page"])
    matched = [t for t in place.get("pages") or [place.get("page")] if t in best_pages(places, shown_page)]
    return matched[-1] if matched else place.get("page")


def module_probes(places: list[dict], cands: list[str], template: str | None = None) -> dict[str, str]:
    """For candidates spread over several groups (module instances, or
    channels named by a placeholder): per group, in tree order, a reference
    on the same page (its first), whose being shown tells that the group's
    page is shown. {} for one group."""
    by_ref = {p["ref"]: p for p in places}
    groups = list(dict.fromkeys(by_ref[r]["group"] for r in cands if r in by_ref))
    if len(groups) < 2 or None in groups:
        return {}
    page = template or by_ref[cands[0]]["page"]
    out: dict[str, str] = {}
    for p in places:
        if p["group"] in groups and p["group"] not in out and page in (p.get("pages") or [p["page"]]):
            out[p["group"]] = p["ref"]
    return out


def module_instance_refs(places: list[dict], surveys: list[list[dict]], change: dict, cands: list[str],
                         shown: set, probes: dict[str, str]) -> list[str] | None:
    """The shown candidates of the group (module instance, or channel named
    by a placeholder) whose page the change is on: the groups whose page
    the evaluator shows (`probes` in `shown`), in tree order, are the pages
    ETS lists in order, so the change's page, the k-th page that is this
    page (`best_pages`, in the first of `surveys` that holds it), is the
    k-th of them. The candidates of that group the evaluator shows; [] when
    the group hides the label (the row is then unmapped), None when the
    page order does not tell the group."""
    by_ref = {p["ref"]: p for p in places}
    template = matched_page(places, change, cands[0])
    shown_groups = [g for g, ref in probes.items() if ref in shown]
    channel, _ = page_parts(change["page"])
    tpl_channel = by_ref[cands[0]]["channel"]
    for survey in surveys:
        same = [p for p in survey if template in best_pages(places, page_parts(p)[1])
                and (channel is None or channel_matches(tpl_channel, page_parts(p)[0] or ""))]
        k = next((i for i, p in enumerate(same)
                  if norm(p.get("crumb") or "") == norm(change["page"].get("crumb") or "")), None)
        if k is None:
            continue
        if k >= len(shown_groups) or len(same) != len(shown_groups):
            return None
        chosen = shown_groups[k]
        return [r for r in cands if by_ref[r]["group"] == chosen and r in shown]
    return None


def bussard_shown_refs(model_dir: Path):
    """`model_changes`'s `shown_refs` for the model in `model_dir`: writes
    the values to its device file and returns the stored references
    `bussard device 1.1.1 <scope> --json` shows (not `ignored`), over the
    device-level parameters and every channel."""
    import oracle_model

    def run(*args) -> dict:
        r = subprocess.run([str(oracle_model.BUSSARD), "device", "1.1.1", *args, "--json", "--dir", str(model_dir)],
                           capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
        try:
            return json.loads(r.stdout)
        except ValueError:
            return {}

    def shown(values: dict) -> set[str]:
        (model_dir / "devices" / "1.1.1.toml").write_text(device_toml_with(values))
        # The oracle's models pin no channels in the lock, so every stored
        # parameter is listed at device level; a channel's own, where the
        # lock has channels, with it.
        top = run()
        handles = ["device"] + [c["handle"] for c in top.get("channels") or [] if c.get("handle")]
        out: set[str] = set()
        for h in handles:
            for p in (run(h).get("scope") or {}).get("parameters") or []:
                if not p.get("ignored") and p.get("reference"):
                    out.add(p["reference"])
        return out

    return shown


def device_toml_with(values: dict) -> str:
    lines = ['address = "1.1.1"', 'name = "ets sweep"', "", "[parameters]"]
    lines += [f'"{k}" = {json.dumps(str(v), ensure_ascii=False)}' for k, v in sorted(values.items())]
    return "\n".join(lines) + "\n"


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
    return {k: sum(1 for d in done if d["result"] == k) for k in ("set", "unreachable", "failed", "lost")}


def save_survey(app: str, pages: list[dict]) -> Path:
    SURVEYS.mkdir(parents=True, exist_ok=True)
    path = SURVEYS / f"{app}.json"
    path.write_text(json.dumps({"app": app, "when": datetime.now(timezone.utc).isoformat(), "pages": pages},
                               indent=1, ensure_ascii=False) + "\n")
    return path


def find_row(survey: list[dict], change: dict) -> dict | None:
    """The row of `change` (page by breadcrumb, label, occurrence) in a
    survey."""
    for page in survey:
        if norm(page.get("crumb") or "") != norm(change["page"].get("crumb") or ""):
            continue
        hits = [r for r in page.get("rows") or [] if norm(r.get("label") or "") == norm(change["label"])]
        if len(hits) > change.get("n", 0):
            return hits[change.get("n", 0)]
    return None


def read_back(flow, ia: str, final: list[dict], done: list[dict]) -> None:
    """Record what ETS shows for every set change once all changes are in
    (`shown`), each read on its page by the driver's `read_param` (a number
    or text field exactly, through the clipboard), with how many rows of its
    label the page shows (`rows_with_label`, what `model_changes` maps by).
    A change whose row ETS no longer shows, or whose value is not the one
    set, is `lost`: the run is a driver error and never compared (the
    model is built from `shown` alone). `final` (the last survey) is kept
    for the record; the read does not depend on the walk reaching every
    page."""
    for d in done:
        if d.get("result") != "set":
            continue
        r = flow("read_param", ia=ia, page=d["page"], label=d["label"], n=d.get("n", 0))
        if not r.get("shown"):
            d.update({"result": "lost", "why": r.get("why") or "the row is not shown after the last change"})
            continue
        shown = (r.get("row") or {}).get("value", "")
        d["shown"] = shown
        d["rows_with_label"] = r.get("rows_with_label")
        if norm(str(shown)) != norm(str(d.get("set_to") or "")):
            d.update({"result": "lost", "why": f"ETS shows {shown!r}, not {d.get('set_to')!r}"})


def apply_hook(app: str, seed: int, index: int, changes: int, model: dict | None, enablers: list[dict] | None):
    """`sweep.run_one(before_download=...)`: survey the pages, draw the
    configuration, set it, then the dependent changes, survey once more and
    read every change back; what was asked, set and shown goes to
    params.json in the run directory."""

    def hook(flow, out: Path, ia: str = "1.1.1") -> dict:
        survey: list[dict] = []
        after: list[dict] = []
        final: list[dict] = []
        config: dict = {}
        done: list[dict] = []
        try:
            survey = flow("param_pages", ia=ia, rows=True).get("pages") or []
            save_survey(app, survey)
            config = generate(survey, seed, index, changes, model, enablers)
            done = set_changes(flow, ia, config["changes"])
            if any(d["result"] == "set" for d in done):
                after = flow("param_pages", ia=ia, rows=True).get("pages") or []
                more = dependent_changes(survey, after, seed, index, model)
                if more:
                    done += set_changes(flow, ia, more)
                    final = flow("param_pages", ia=ia, rows=True).get("pages") or []
                else:
                    final = after
                read_back(flow, ia, final, done)
        finally:
            # The Katalog splitter back where the next catalog flow expects it.
            flow("ensure_layout")
            (out / "params.json").write_text(json.dumps(
                {"config": config, "pages": survey, "pages_after": after, "pages_final": final,
                 "changes": done}, indent=1, ensure_ascii=False))
        return counts(done)

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
                              before_download=apply_hook(job["id"], args.seed, index, args.changes, model, enablers))
            got = r.get("before") or {}
            outcome = r["outcome"]
            if outcome == "captured" and (got.get("failed") or got.get("lost")):
                # A change that did not read back: never compared (#424).
                outcome = "driver-error-params"
            entry = {"file": job["file"], "mask": job["mask"], "when": datetime.now(timezone.utc).isoformat(),
                     "outcome": outcome, "error": r.get("error"), "params": got,
                     "repair": (r.get("repair") or {}).get("dir"), "ia": r.get("ia")}
            results[key] = entry
            RESULTS.parent.mkdir(exist_ok=True)
            RESULTS.write_text(json.dumps(dict(sorted(results.items())), indent=1, ensure_ascii=False) + "\n")
            print(f"{entry['outcome']:13} {key} {entry.get('params')}", flush=True)
            done += 1
            if args.limit and done >= args.limit:
                return 0
    return 0


def oracle(args) -> int:
    """Each captured configuration against bussard's plan for the values
    ETS showed after the run (`params.json`: the read-back, see `read_back`)."""
    import defaults
    import sweep

    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    out = json.loads(ORACLE_OUT.read_text()) if ORACLE_OUT.exists() else {}
    wanted = [w.lower() for w in args.filter.split(",") if w]
    if args.representative:
        import params_subset

        wanted = [r["app"].lower() for r in params_subset.load()]
    jobs = {j["id"]: j for j in captured_jobs([])}
    for key, entry in sorted(results.items()):
        if entry.get("outcome") != "captured":
            continue
        if wanted and not any(w in key.lower() for w in wanted):
            continue
        app, name = key.split("/", 1)
        job = jobs.get(app)
        if job is None:
            out[key] = {"verdict": "not-run", "problems": ["not a captured application of the defaults sweep"],
                        "when": datetime.now(timezone.utc).isoformat()}
            print(f"{'not-run':14} {key}", flush=True)
            continue
        run_dir = sweep.CAPTURES / app / name
        recorded = json.loads((run_dir / "params.json").read_text())
        model_dir, problems = change_model(job, args.work, args.work / app / name / "model", recorded)
        if model_dir is None:
            out[key] = {"verdict": "unmapped", "problems": problems[:8]}
        else:
            product = defaults.product_path(job["file"])
            # The address ETS gave the device (1.1.0 for a coupler, #876).
            ia = str(entry.get("ia") or "1.1.1")
            if ia != "1.1.1":
                out[key] = {"verdict": "not-run", "problems": [f"device at {ia}"]}
            else:
                row = f"{ia}|{run_dir / 'ets.pcapng'}|{product}|{app}"
                r = subprocess.run(["bash", str(ORACLE), "--dir", str(model_dir), "--out",
                                    str(args.work / app / name / "oracle"), "--row", row],
                                   capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
                out[key] = summary_verdict(r.stdout + r.stderr, ia)
        out[key]["set"] = (entry.get("params") or {}).get("set")
        out[key]["when"] = datetime.now(timezone.utc).isoformat()
        ORACLE_OUT.write_text(json.dumps(dict(sorted(out.items())), indent=1, ensure_ascii=False) + "\n")
        print(f"{out[key]['verdict']:14} {key} {out[key].get('problems') or ''}", flush=True)
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


def change_model(job: dict, work: Path, out: Path, recorded: dict) -> tuple[Path | None, list[str]]:
    """A model of `job`'s application with the parameter values ETS showed
    after the changes of `recorded` (a params.json), under `out`; None and
    the problems when a change does not map to one reference."""
    import defaults
    import oracle_model

    shared, _ = shared_for(job, work)
    model = model_json(shared, job["id"])
    model_dir = oracle_model.build(out, defaults.product_path(job["file"]), job["id"], mask=job["mask"],
                                   shared=shared)
    # The surveys order a module's pages (one per instance); the last one
    # counts the rows.
    surveys = [recorded.get(k) or [] for k in ("pages_final", "pages_after", "pages")]
    values, problems = model_changes(model, recorded.get("pages_final") or recorded.get("pages_after") or [],
                                     recorded.get("changes") or [], bussard_shown_refs(model_dir), surveys)
    if problems:
        return None, problems
    (model_dir / "devices" / "1.1.1.toml").write_text(device_toml_with(values))
    return model_dir, []


def partial_oracle(job: dict, work: Path) -> dict:
    """The `run=params` oracle row of a recorded `partial` series: knx-sim
    replays the defaults download (step a), `bussard flash
    --parameters-only` runs with the model of the value ETS showed after
    the change, and the device state after it (memory, property elements,
    load-control records) is compared with the state after ETS's partial
    download (step b). Returns {verdict, summary, rows}."""
    import defaults
    import sweep

    app = job["id"]
    base = sweep.CAPTURES / app / "params-partial"
    a, b = base / "a-full" / "ets.pcapng", base / "b-partial-param" / "ets.pcapng"
    recorded = json.loads((base / "b-partial-param" / "params.json").read_text())
    model, problems = change_model(job, work, work / app / "params-partial" / "model", recorded)
    if model is None:
        return {"verdict": "unmapped", "problems": problems}
    lsm = " lsm=memory" if job["mask"] == "0701" else ""
    rows = work / app / "params-partial" / "rows.txt"
    change = (recorded.get("changes") or [{}])[0]
    # A program whose parameters all live in properties writes no memory in
    # this download: the row pins the memory headline and judges the
    # properties (#944, the E804 capture: props=ok(2935) loadctl=ok(4)).
    pins = "expect=not-comparable props=identical loadctl=identical " if property_only(job, work) else ""
    line = (f"1.1.1|{b}|{defaults.product_path(job['file'])}|{app}|ETS partial download after "
            f"{change.get('label', '?')} set to {change.get('shown', '?')}|100.0|{pins}run=params base={a} "
            f"dir={model}{lsm}")
    rows.write_text(line + "\n")
    r = subprocess.run(["bash", str(ORACLE), "--dir", str(model), "--rows", str(rows),
                        "--out", str(work / app / "params-partial" / "oracle")],
                       capture_output=True, text=True, env={**os.environ, "BUSSARD_NO_DOTENV": "1"})
    return {**summary_verdict(r.stdout + r.stderr, "1.1.1"), "exit": r.returncode, "rows": str(rows)}


VERDICTS = ("identical", "differs", "not-comparable")


def summary_verdict(output: str, ia: str) -> dict:
    """The verdict of `ia`'s line in the offline oracle's summary table
    (`<ia>  <system>  <verdict>  ...`), not its section heading ('1.1.1
    (note)'), which also starts with the address."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", output)
    for line in reversed(text.splitlines()):
        m = re.match(re.escape(ia) + r"\s+(\S+)\s+(\S+)", line)
        if m and m.group(2) in VERDICTS:
            return {"verdict": m.group(2), "summary": line.strip()}
    return {"verdict": "oracle-error", "summary": ""}


def property_only(job: dict, work: Path) -> bool:
    """Whether every parameter of the application lives in an interface
    object property (no memory placement)."""
    shared, _ = shared_for(job, work)
    # The imported product model (`<app>@<lang>.json`) holds each
    # parameter's placement; the model cache does not.
    found = sorted(shared.glob(f".bussard/products/*/{job['id']}@*.json"))
    if not found:
        return False
    params_ = json.loads(found[0].read_text()).get("parameters") or {}
    params_ = params_.values() if isinstance(params_, dict) else params_
    params_ = list(params_)
    return bool(params_) and not any(p.get("memory") for p in params_) and any(p.get("property") for p in params_)


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
        flow("ensure_layout")
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
                row = find_row(survey, change)
                if row is None:
                    raise RuntimeError(f"no row {args.label!r} on {args.page!r} in the survey")
                # The control's kind and value as ETS shows them (read_back
                # and value_of need both).
                change.update({"kind": row["kind"], "before": row.get("value", "")})
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
            final = flow("param_pages", ia="1.1.1", rows=True).get("pages") or []
            read_back(flow, "1.1.1", final, done)
            (second / "params.json").write_text(json.dumps({"changes": done, "pages_final": final}, indent=1,
                                                           ensure_ascii=False))
            result["change"] = done[0]
            if done[0]["result"] != "set":
                raise RuntimeError(f"the change did not read back after the download: {done[0]}")
        except Exception as exc:  # noqa: BLE001 - recorded per application
            result["error"] = str(exc)[:600]
        finally:
            sim.stop()
            try:
                flow("ensure_layout")
            except RuntimeError as exc:
                result.setdefault("error", f"ensure_layout: {exc}"[:300])
        if args.oracle and not result.get("error"):
            result["oracle"] = partial_oracle(job, args.work)
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
            p.add_argument("--oracle", action="store_true", help="then run the run=params oracle row")
            p.add_argument("--oracle-only", action="store_true", help="only the oracle row of a recorded series")
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
    if args.cmd == "partial" and args.oracle_only:
        for job in captured_jobs([w.lower() for w in args.filter.split(",") if w]):
            r = partial_oracle(job, args.work)
            print(f"{r['verdict']:14} {job['id']} {r.get('summary') or r.get('error', '')}", flush=True)
        return 0
    if args.cmd == "partial":
        return partial(args)
    return oracle(args)


if __name__ == "__main__":
    sys.exit(main())
