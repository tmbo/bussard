"""ETS driver: operates the ETS 6 GUI in the Windows VM through UI Automation.

Runs INSIDE the VM, in the interactive desktop session (started by a one-shot
scheduled task with /IT; an ssh session cannot see ETS's windows). Speaks JSON
over HTTP on 127.0.0.1:8765; the Mac reaches it through an ssh port forward
(tools/ets-sweep/vm.py), so no Windows firewall rule is needed.

Endpoints (POST JSON unless noted):
  GET  /health                      -> session facts, top-level windows
  POST /tree      {"depth": 3, "window": "<title regex>" | null, "max": 20000}
  POST /screenshot {"window": ..}   -> {"png_base64": ..}
  POST /exec      {"code": ".."}    -> runs Python with pywinauto in scope (dev only,
                                       token in driver.token next to this file)
  POST /ets/<flow> ...              -> the hardcoded ETS flows (added as they are proven)

Deliberately plain stdlib + pywinauto, Python 3.12.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import sys
import time
import traceback
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG = HERE / "driver.log"
TOKEN_FILE = HERE / "driver.token"
PORT = 8765

sys.stdout = open(LOG, "a", buffering=1, encoding="utf-8")  # noqa: SIM115 (long-lived)
sys.stderr = sys.stdout


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


try:
    from pywinauto import Desktop
    from pywinauto.application import Application
except Exception as exc:  # pragma: no cover - startup diagnostics
    log(f"pywinauto import failed: {exc!r}")
    raise

DESKTOP = Desktop(backend="uia")


def ets_app() -> Application:
    """Connect to the running ETS 6 (the GUI process is ETS6N.exe)."""
    return Application(backend="uia").connect(path="ETS6N.exe", timeout=5)


def ets_main_window():
    """The ETS main window (title 'ETS6 - <project>'). Not top_window(): with a
    menu open, pywinauto's top window of the process is the popup itself."""
    from pywinauto import Desktop as _D

    for w in _D(backend="win32").windows():
        try:
            if w.window_text().startswith("ETS6 - ") and w.class_name().startswith("HwndWrapper[ETS6N"):
                return DESKTOP.window(handle=w.handle)
        except Exception:
            pass
    return ets_app().top_window()


def find_window(title_re: str | None):
    if title_re:
        return DESKTOP.window(title_re=title_re)
    return ets_main_window()


def control_tree(win, depth: int, max_chars: int) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        win.print_control_identifiers(depth=depth)
    text = buf.getvalue()
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... truncated ({len(text)} chars total)"
    return text


def screenshot_png(win, bbox=None, scale: float = 1.0) -> str:
    from PIL import ImageGrab

    if win is None:
        img = ImageGrab.grab(bbox=tuple(bbox) if bbox else None)
    else:
        img = win.capture_as_image()
    if scale != 1.0:
        img = img.resize((int(img.width * scale), int(img.height * scale)))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode()


def session_facts() -> dict:
    wins = []
    for w in DESKTOP.windows():
        try:
            wins.append({"title": w.window_text(), "class": w.class_name(), "pid": w.process_id()})
        except Exception:
            pass
    return {
        "ok": True,
        "session": os.environ.get("SESSIONNAME"),
        "user": os.environ.get("USERNAME"),
        "python": sys.version.split()[0],
        "windows": [w for w in wins if w["title"]],
    }


def run_exec(code: str) -> dict:
    scope = {
        "Desktop": Desktop,
        "Application": Application,
        "desktop": DESKTOP,
        "ets_app": ets_app,
        "ets": ets_main_window,
        "find_window": find_window,
        "control_tree": control_tree,
        "ocr": ocr,
        "find_text": find_text,
        "click": click,
        "click_text": click_text,
        "keys": keys,
        "ets_popups": ets_popups,
        "wait_popup": wait_popup,
        "menu_click": menu_click,
        "menu_item": menu_item,
        "choose": choose,
        "menu_items": menu_items,
        "popup_tree": popup_tree,
        "grab": grab,
        "time": time,
        "re": re,
        "result": None,
    }
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(code, scope)  # noqa: S102 - development endpoint, token guarded
    except Exception:
        return {"stdout": buf.getvalue(), "error": traceback.format_exc()[-1500:]}
    return {"stdout": buf.getvalue(), "result": repr(scope.get("result"))}


# ---------------------------------------------------------------- visual layer
# ETS 6 hides the UI Automation tree of its main window (zero children in every
# view, 2026-10-26), while its popups, menus and dialogs expose a normal tree.
# So the main window is operated by screen position and Windows OCR, popups by
# UI Automation. Coordinates are physical pixels of the VM screen (4112x2484).

import difflib

from pywinauto import keyboard, mouse

SCREEN = (0, 0, 4112, 2484)


def grab(bbox=None):
    from PIL import ImageGrab

    return ImageGrab.grab(bbox=tuple(bbox) if bbox else None)


def ocr(bbox=None, lang: str = "de", zoom: int = 1) -> list[dict]:
    """OCR a screen region. Returns lines as {text, x, y, w, h} in screen pixels.
    `zoom` magnifies the crop first: small or low-contrast cells (a selected
    grid row) read reliably at 3x where they vanish at 1x."""
    import winocr

    from PIL import ImageOps

    img = grab(bbox)
    if zoom > 1:
        # Magnify and stretch the contrast: a dimmed window (modal overlay) or
        # a selected grid row leaves grey-on-grey text the OCR skips otherwise.
        img = ImageOps.autocontrast(ImageOps.grayscale(img.resize((img.width * zoom, img.height * zoom))), cutoff=1)
    ox, oy = (bbox[0], bbox[1]) if bbox else (0, 0)
    out = []
    for line in winocr.recognize_pil_sync(img, lang)["lines"]:
        rects = [w["bounding_rect"] for w in line["words"]]
        x0 = min(r["x"] for r in rects) / zoom
        y0 = min(r["y"] for r in rects) / zoom
        x1 = max(r["x"] + r["width"] for r in rects) / zoom
        y1 = max(r["y"] + r["height"] for r in rects) / zoom
        out.append({"text": line["text"], "x": int(ox + x0), "y": int(oy + y0), "w": int(x1 - x0), "h": int(y1 - y0)})
    return out


def _norm(t: str) -> str:
    return re.sub(r"[^a-z0-9äöüß./]", "", t.lower())


def find_text(pattern: str, bbox=None, min_ratio: float = 0.8) -> dict | None:
    """The OCR line best matching `pattern` (substring after normalisation, else
    difflib ratio >= min_ratio). OCR misreads a letter here and there, hence fuzzy."""
    want = _norm(pattern)
    best, best_r = None, 0.0
    for line in ocr(bbox):
        have = _norm(line["text"])
        if want and want in have:
            r = 1.0
        else:
            r = difflib.SequenceMatcher(None, want, have).ratio()
        if r > best_r:
            best, best_r = line, r
    if best and best_r >= min_ratio:
        return {**best, "ratio": round(best_r, 2)}
    return None


def click(x: int, y: int, button: str = "left", double: bool = False) -> None:
    if double:
        mouse.double_click(button=button, coords=(int(x), int(y)))
    else:
        mouse.click(button=button, coords=(int(x), int(y)))


def click_text(pattern: str, bbox=None, dx: int = 0, dy: int = 0, button: str = "left", double: bool = False) -> dict:
    hit = find_text(pattern, bbox)
    if not hit:
        raise RuntimeError(f"text {pattern!r} not on screen in {bbox}")
    click(hit["x"] + hit["w"] // 2 + dx, hit["y"] + hit["h"] // 2 + dy, button, double)
    return hit


def keys(sequence: str, pause: float = 0.05) -> None:
    """pywinauto key syntax: '{ENTER}', '^a' (ctrl+a), '{ESC}', plain text."""
    keyboard.send_keys(sequence, pause=pause, with_spaces=True)


def ets_pid() -> int:
    return ets_main_window().process_id()


def ets_popups() -> list:
    """Visible ETS windows other than the main one: menus, dropdowns, dialogs."""
    from pywinauto import Desktop as _D

    pid = ets_pid()
    main = ets_main_window().handle
    out = []
    for w in _D(backend="win32").windows():
        try:
            if w.process_id() == pid and w.is_visible() and w.handle != main:
                out.append(DESKTOP.window(handle=w.handle))
        except Exception:
            pass
    return out


def wait_popup(timeout: float = 5.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        pops = ets_popups()
        if pops:
            return pops[-1]
        time.sleep(0.2)
    raise RuntimeError("no popup appeared")


def menu_item(item_title: str, timeout: float = 5.0):
    """The visible MenuItem titled `item_title` in any open ETS popup (a menu
    click can leave a tooltip popup around, so every popup is searched)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        for pop in ets_popups():
            for it in pop.descendants(control_type="MenuItem"):
                try:
                    if it.window_text() == item_title and it.is_visible():
                        return it
                except Exception:
                    pass
        time.sleep(0.2)
    raise RuntimeError(f"menu item {item_title!r} not in any popup; popups: {menu_items()}")


def menu_items() -> list[str]:
    out = []
    for pop in ets_popups():
        out += [it.window_text() for it in pop.descendants(control_type="MenuItem")]
    return [t for t in out if "SeparatorMenuItem" not in t]


def menu_click(item_title: str, timeout: float = 5.0) -> None:
    """Click a MenuItem by title in an open popup (UIA works there)."""
    menu_item(item_title, timeout).click_input()
    time.sleep(0.5)


def choose(title: str, bbox=None, uia_timeout: float = 1.5) -> str:
    """Pick a menu entry: by UI Automation when the open popup exposes one, else
    by OCR on the screen (the ETS 'Panels' menu is a popup without a tree)."""
    try:
        menu_item(title, uia_timeout).click_input()
        time.sleep(0.5)
        return "uia"
    except RuntimeError:
        click_text(title, bbox)
        time.sleep(0.5)
        return "ocr"


def popup_tree(depth: int = 6, max_chars: int = 20000) -> str:
    pops = ets_popups()
    return "\n\n".join(control_tree(p, depth, max_chars) for p in pops) if pops else ""


# ---------------------------------------------------------------- ETS flows
# Each flow is a plain function taking the request dict and returning a dict.
# They are hardcoded against ETS 6.4.1 and grow as the sweep proves them.

FLOWS: dict[str, object] = {}


def flow(name):
    def deco(fn):
        FLOWS[name] = fn
        return fn

    return deco


@flow("windows")
def flow_windows(req: dict) -> dict:
    return session_facts()


# Screen layout of ETS 6.4.1 in the sweep project (window maximised on the
# 4112x2484 VM screen; Topologie panel left, device list top, Katalog panel
# bottom, Eigenschaften column right). Physical pixels. Verified 2026-10-27.
LAYOUT = {
    "tab_strip": (0, 0, 4112, 90),
    "logo": (170, 40),
    "toolbar_connection": (3686, 113),      # the connection dropdown (left of the info button)
    "connection_menu": (3400, 130, 4112, 500),
    "toolbar_program_arrow": (2980, 113),   # arrow of 'Programmieren'
    "tree_line_1_1": (150, 480),
    "tree": (0, 360, 660, 700),
    "device_list": (680, 220, 3300, 900),
    "catalog_search": (3213, 1364),
    "catalog_rows": (680, 1440, 3300, 2400),
    "catalog_add": (1355, 2451),
    "catalog_line_dropdown": (948, 2453),
    "catalog_bar": (0, 2420, 1600, 2484),
    "delete_dialog": (1200, 800, 2900, 1700),
    "delete_yes": (2300, 1420, 2500, 1480),
    "medium_dialog": (1200, 900, 3000, 1100),
    "medium_keep": (2250, 1477),
    "ops_header": (3500, 2348),
    "ops_pane": (3320, 680, 4112, 1300),
    "ops_first_expand": (3484, 846),
    "dialog_area": (1200, 700, 3000, 1800),
}

IA_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})\.(\d{1,3})\b")


def _ia_in(text: str) -> str | None:
    m = IA_RE.search(text.replace(" ", ""))
    return ".".join(m.groups()) if m else None


def window_project() -> str:
    """The project of the active tab, from the window title 'ETS6 - <project>'."""
    return ets_main_window().window_text().removeprefix("ETS6 - ")


def require_project(name: str) -> None:
    """Refuse to act unless the active tab is the sweep project: the house
    project is open in the same ETS and must never be programmed from here."""
    have = window_project()
    if have != name:
        raise RuntimeError(f"active project is {have!r}, not {name!r}; refusing")


@flow("state")
def flow_state(req: dict) -> dict:
    return {"project": window_project(), "tabs": [l["text"] for l in ocr(LAYOUT["tab_strip"])], "popups": len(ets_popups())}


@flow("project_tab")
def flow_project_tab(req: dict) -> dict:
    """Bring the tab of project `name` to the front (it must already be open)."""
    name = req["name"]
    if window_project() == name:
        return {"project": name}
    hit = find_text(name, LAYOUT["tab_strip"])
    if not hit:
        raise RuntimeError(f"no tab for project {name!r}: {[l['text'] for l in ocr(LAYOUT['tab_strip'])]}")
    click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
    time.sleep(2)
    require_project(name)
    return {"project": name}


@flow("devices")
def flow_devices(req: dict) -> dict:
    """The devices on line 1.1 of the active project, by OCR of the device list."""
    require_project(req["project"])
    click(*LAYOUT["tree_line_1_1"])
    time.sleep(1.5)
    x0, y0, x1, y1 = LAYOUT["device_list"]
    # Row centres: every OCR line below the header, clustered by height.
    centres: list[int] = []
    for line in ocr(LAYOUT["device_list"]):
        cy = line["y"] + line["h"] // 2
        if cy > y0 + 40 and all(abs(cy - c) > 18 for c in centres):
            centres.append(cy)
    ias = []
    for cy in sorted(centres):
        # The Adresse cell alone, magnified: a selected row's grey background
        # hides it from OCR at native size.
        cell = ocr((690, cy - 18, 860, cy + 18), zoom=3)
        ia = next((_ia_in(l["text"]) for l in cell if _ia_in(l["text"])), None)
        if ia:
            ias.append({"ia": ia, "y": cy})
    return {"devices": ias}


@flow("catalog_add")
def flow_catalog_add(req: dict) -> dict:
    """Search the catalog for `search` (order number works best), select the
    first result row and add it to line 1.1. Returns the device list afterwards."""
    require_project(req["project"])
    before = {d["ia"] for d in flow_devices(req)["devices"]}
    click(*LAYOUT["catalog_search"])
    time.sleep(0.3)
    keys("^a")
    keys(req["search"] + "{ENTER}")
    time.sleep(3)
    click(1000, 1380)  # a neutral spot: closes the search-history dropdown
    time.sleep(0.5)
    rows = [l for l in ocr(LAYOUT["catalog_rows"]) if l["y"] > LAYOUT["catalog_rows"][1] + 40 and l["x"] < 1300]
    # rows: a manufacturer group header, then product rows (indented further)
    product_rows = [l for l in rows if l["x"] > 780]
    if not product_rows:
        raise RuntimeError(f"no catalog row for {req['search']!r}: {[l['text'] for l in rows]}")
    row = product_rows[0]
    click(1300, row["y"] + row["h"] // 2)
    time.sleep(1)
    bar = find_text("1.1 TP Linie", LAYOUT["catalog_bar"])
    if not bar:
        click(*LAYOUT["catalog_line_dropdown"])
        time.sleep(1)
        choose("1.1 TP Linie", (600, 1900, 1300, 2484))
        time.sleep(0.8)
    click(*LAYOUT["catalog_add"])
    time.sleep(3)
    after = flow_devices(req)["devices"]
    new = [d for d in after if d["ia"] not in before]
    return {"devices": after, "added": new, "row": row["text"]}


@flow("delete_device")
def flow_delete_device(req: dict) -> dict:
    require_project(req["project"])
    devs = flow_devices(req)["devices"]
    hit = [d for d in devs if d["ia"] == req["ia"]]
    if not hit:
        return {"deleted": False, "devices": devs}
    click(700, hit[0]["y"])
    time.sleep(0.8)
    keys("{DELETE}")
    time.sleep(2)
    if find_text("Möchten Sie die markierten Objekte", LAYOUT["delete_dialog"]):
        click_text("Ja", LAYOUT["delete_yes"])
        time.sleep(2)
    return {"deleted": True, "devices": flow_devices(req)["devices"]}


@flow("select_connection")
def flow_select_connection(req: dict) -> dict:
    """Make the configured connection `name` current (the quick menu in the toolbar)."""
    require_project(req["project"])
    click(*LAYOUT["toolbar_connection"])
    time.sleep(3)
    entries = [l["text"] for l in ocr(LAYOUT["connection_menu"])]
    click_text(req["name"], LAYOUT["connection_menu"])
    time.sleep(3)
    return {"entries": entries}


PROGRAM_MODES = {
    "full": "Physikalische Adresse & Applikationsprogramm",
    "partial": "Partiell",
    "address": "Physikalische Adresse",
    "overwrite_address": "Überschreibe physikalische Adresse",
    "application": "Applikationsprogramm",
}


@flow("download")
def flow_download(req: dict) -> dict:
    """Select device `ia` in the device list and start a download of `mode`
    (see PROGRAM_MODES). Answers the medium-mismatch check with 'keep'. Does not
    wait for the result: the sweep watches the simulator instead."""
    require_project(req["project"])
    devs = flow_devices(req)["devices"]
    hit = [d for d in devs if d["ia"] == req["ia"]]
    if not hit:
        raise RuntimeError(f"device {req['ia']} not in list: {devs}")
    click(700, hit[0]["y"])
    time.sleep(1)
    click(*LAYOUT["toolbar_program_arrow"])
    time.sleep(1.5)
    menu_click(PROGRAM_MODES[req.get("mode", "application")])
    t0 = time.time()
    kept = False
    while time.time() - t0 < float(req.get("dialog_wait", 20)):
        if find_text("Schnittstellen-Prüfung", LAYOUT["medium_dialog"]):
            click(*LAYOUT["medium_keep"])
            kept = True
            break
        time.sleep(1)
    return {"ia": req["ia"], "mode": req.get("mode", "application"), "medium_dialog_kept": kept}


@flow("history")
def flow_history(req: dict) -> dict:
    """The text of the 'Laufende Operationen' history pane (expanded if needed)."""
    lines = ocr(LAYOUT["ops_pane"])
    if not any("Historie" in l["text"] or "Aktiv" in l["text"] for l in ocr((3320, 600, 4112, 700))):
        click(*LAYOUT["ops_header"])
        time.sleep(2)
    click(*LAYOUT["ops_first_expand"])
    time.sleep(1.5)
    lines = ocr(LAYOUT["ops_pane"])
    return {"lines": [l["text"] for l in lines]}


@flow("catalog_import")
def flow_catalog_import(req: dict) -> dict:
    """Import a `.knxprod` (a path inside the VM) into ETS's catalog: the
    Import button of the Katalog panel, the 'Produktdatei öffnen' file dialog
    (UI Automation), 'Alle Sprachen importieren', then the result panel.
    Returns outcome imported|refused|error, the 'Produkt:' lines and the panel
    text. ETS imports a file it already holds again without complaint."""
    path = req["path"]
    timeout = float(req.get("timeout", 900))
    region = (1500, 400, 3500, 1600)
    btn = find_text("Import", (680, 1340, 1100, 1390))
    wizard_text = " ".join(l["text"] for l in ocr(region))
    attached = False
    if not btn and any(k in wizard_text for k in ("Konvertiere", "erfolgreich", "Produktsprache", "Import auswählen")):
        # An import is already running (a previous call timed out while a
        # large file converted): wait for its result instead of starting over.
        attached = True
    elif not btn:
        raise RuntimeError("the Katalog panel's Import button is not on screen")
    else:
        click(btn["x"] + btn["w"] // 2, btn["y"] + btn["h"] // 2)
        dialog = None
        t0 = time.time()
        while time.time() - t0 < 15:
            dialog = next((p for p in ets_popups() if "Produktdatei" in p.window_text()), None)
            if dialog:
                break
            time.sleep(0.5)
        if dialog is None:
            raise RuntimeError("no 'Produktdatei öffnen' dialog appeared")
        edit = dialog.child_window(title="Dateiname:", control_type="Edit")
        edit.set_edit_text(path)
        time.sleep(0.3)
        edit.type_keys("{ENTER}")
    seen: list[str] = []
    pressed_languages = False
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(2)
        if any("Produktdatei" in p.window_text() for p in ets_popups()):
            # The file dialog is still up: the path was refused.
            keys("{ESC}")
            return {"outcome": "error", "products": [], "message": f"file dialog did not accept {path}"}
        lines = ocr(region)
        texts = [l["text"] for l in lines]
        joined = " ".join(texts)
        if attached and not any(k in joined for k in ("Konvertiere", "erfolgreich", "Produktsprache", "Import", "Signiere", "Lese ", "Lade ")):
            # The wizard went away while nobody watched (its result panel
            # was closed by hand): the caller verifies through the catalog.
            return {"outcome": "done_unverified", "products": [], "message": "wizard closed before the result was read", "attached": True}
        if "Import auswählen" in joined or "Import auswahlen" in joined:
            # Multi-product file: a selection list; take every product.
            hit = find_text("Alle Produkte importieren", (2200, 1700, 3000, 1860))
            if hit:
                click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
                seen.append("all products")
                time.sleep(1)
                continue
        if "Produktsprache" in joined and not pressed_languages:
            click_text("Alle Sprachen importieren", (1900, 1490, 2400, 1560))
            pressed_languages = True
            continue
        if "erfolgreich" in joined:
            # Re-read the panel magnified: the order number and name matter.
            fine = [l["text"] for l in ocr((1700, 1050, 2600, 1480), zoom=2)]
            products = [t.split(":", 1)[1].strip() for t in fine if t.startswith("Produkt")]
            ok = find_text("OK", (2300, 1450, 2700, 1600), min_ratio=0.6)
            if ok:
                click(ok["x"] + ok["w"] // 2, ok["y"] + ok["h"] // 2)
            else:
                click(2488, 1528)  # where the result panel's OK sits (OCR misses two letters at times)
            time.sleep(1)
            return {"outcome": "imported", "products": products, "message": joined[:600], "attached": attached}
        if any(k in joined for k in ("Fehler", "fehlgeschlagen", "nicht importiert", "ungültig", "Ausnahme")):
            for label in ("OK", "Schließen", "Abbrechen"):
                if find_text(label, (1900, 1460, 2700, 1580)):
                    click_text(label, (1900, 1460, 2700, 1580))
                    break
            time.sleep(1)
            return {"outcome": "refused", "products": [], "message": joined[:800]}
        # A page with a plain 'Importieren' or 'Weiter' button (product
        # selection for multi-product files).
        for label in ("Importieren", "Weiter"):
            hit = find_text(label, (1900, 1460, 2700, 1580))
            if hit and hit["ratio"] >= 0.9 and "Alle Sprachen" not in hit["text"]:
                click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
                seen.append(f"pressed {label}")
                break
    # No ESC: ETS keeps converting, and the next call attaches to it.
    return {"outcome": "error", "products": [], "message": f"timed out after {int(timeout)}s; last: {joined[:400]}; {seen}"}


@flow("catalog_search")
def flow_catalog_search(req: dict) -> dict:
    """Type `term` into the Katalog panel's search box and return the result
    rows (order number, name, application) read magnified."""
    click(*LAYOUT["catalog_search"])
    time.sleep(0.3)
    keys("^a")
    keys(req["term"] + "{ENTER}")
    time.sleep(float(req.get("wait", 3)))
    click(1000, 1380)  # closes the search-history dropdown
    time.sleep(0.5)
    x0, y0, x1, y1 = LAYOUT["catalog_rows"]
    rows = []
    for line in ocr((x0, y0 + 40, x1, y1), zoom=2):
        rows.append({"text": line["text"], "x": line["x"], "y": line["y"]})
    return {"term": req["term"], "rows": rows}


@flow("dialogs")
def flow_dialogs(req: dict) -> dict:
    """Any dialog text in the middle of the screen, for the watchdog."""
    return {"lines": [l["text"] for l in ocr(LAYOUT["dialog_area"])]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # route http logs to our file
        log("http " + (fmt % args))

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            try:
                self._send(200, session_facts())
            except Exception as exc:
                self._send(500, {"ok": False, "error": repr(exc)})
        else:
            self._send(404, {"error": "unknown path"})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError as exc:
            self._send(400, {"error": f"bad json: {exc}"})
            return
        t0 = time.time()
        try:
            if self.path == "/tree":
                win = find_window(req.get("window"))
                self._send(200, {"tree": control_tree(win, int(req.get("depth", 3)), int(req.get("max", 20000)))})
            elif self.path == "/screenshot":
                win = None if req.get("window") in (None, "desktop") else find_window(req.get("window"))
                self._send(200, {"png_base64": screenshot_png(win, req.get("bbox"), float(req.get("scale", 1.0)))})
            elif self.path == "/ocr":
                self._send(200, {"lines": ocr(req.get("bbox"))})
            elif self.path == "/popups":
                self._send(200, {"tree": popup_tree(int(req.get("depth", 6)), int(req.get("max", 20000)))})
            elif self.path == "/exec":
                token = TOKEN_FILE.read_text().strip() if TOKEN_FILE.exists() else None
                if not token or req.get("token") != token:
                    self._send(403, {"error": "bad token"})
                    return
                self._send(200, run_exec(req.get("code", "")))
            elif self.path.startswith("/ets/"):
                name = self.path[len("/ets/") :]
                fn = FLOWS.get(name)
                if fn is None:
                    self._send(404, {"error": f"unknown flow {name}", "flows": sorted(FLOWS)})
                    return
                out = fn(req)
                out.setdefault("ok", True)
                self._send(200, out)
            else:
                self._send(404, {"error": "unknown path"})
        except Exception as exc:
            log(f"{self.path} failed: {traceback.format_exc()}")
            self._send(500, {"ok": False, "error": repr(exc), "trace": traceback.format_exc()[-2000:]})
        finally:
            log(f"{self.path} {time.time() - t0:.1f}s")


def _reload_watch(srv: ThreadingHTTPServer) -> None:
    """Re-exec this process when ets_driver.py changes on disk, so a new upload
    takes effect without anyone starting the driver in the desktop session again."""
    me = Path(__file__).resolve()
    stamp = me.stat().st_mtime
    while True:
        time.sleep(2)
        try:
            now = me.stat().st_mtime
        except OSError:
            continue
        if now != stamp:
            # Not os.execv: on Windows it joins argv without quoting, so the space
            # in "C:\Program Files\Python312" killed the first attempt (2026-10-26).
            log("source changed, restarting")
            srv.server_close()
            import subprocess

            subprocess.Popen(
                [sys.executable, str(me)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
            time.sleep(1)
            os._exit(0)


def main() -> None:
    log(f"driver starting pid={os.getpid()} session={os.environ.get('SESSIONNAME')} user={os.environ.get('USERNAME')}")
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(base64.b16encode(os.urandom(16)).decode())
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    import threading

    threading.Thread(target=_reload_watch, args=(srv,), daemon=True).start()
    log(f"listening on 127.0.0.1:{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
