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
    scope = {**globals(), **scope}  # every driver helper, for developing flows
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


def scale() -> float:
    """Physical screen width / the 4112-pixel layout every coordinate here is
    written in. The RDP session ran at 4112x2484; on the VM console (after
    `tscon`, when no RDP client is attached) the desktop is 2056 wide with the
    same relative layout, so clicks, grabs and OCR positions scale by this."""
    import ctypes

    return ctypes.windll.user32.GetSystemMetrics(0) / 4112.0


def grab(bbox=None):
    """A screenshot of `bbox` (layout coordinates), in physical pixels."""
    from PIL import ImageGrab

    if bbox:
        s = scale()
        bbox = tuple(int(round(v * s)) for v in bbox)
    return ImageGrab.grab(bbox=tuple(bbox) if bbox else None)


def ocr(bbox=None, lang: str = "de", zoom: int = 1) -> list[dict]:
    """OCR a screen region. Returns lines as {text, x, y, w, h} in screen pixels.
    `zoom` magnifies the crop first: small or low-contrast cells (a selected
    grid row) read reliably at 3x where they vanish at 1x."""
    import winocr

    from PIL import ImageOps

    s = scale()
    if s < 0.9:
        # A half-size console desktop: magnify so text keeps the pixel size
        # the OCR read well at 4112 wide.
        zoom = max(zoom, 2)
    img = grab(bbox)
    if zoom > 1:
        # Magnify and stretch the contrast: a dimmed window (modal overlay) or
        # a selected grid row leaves grey-on-grey text the OCR skips otherwise.
        img = ImageOps.autocontrast(ImageOps.grayscale(img.resize((img.width * zoom, img.height * zoom))), cutoff=1)
    ox, oy = (bbox[0], bbox[1]) if bbox else (0, 0)
    out = []
    for line in winocr.recognize_pil_sync(img, lang)["lines"]:
        rects = [w["bounding_rect"] for w in line["words"]]
        # OCR pixels -> physical pixels (/zoom) -> layout coordinates (/s).
        x0 = min(r["x"] for r in rects) / zoom / s
        y0 = min(r["y"] for r in rects) / zoom / s
        x1 = max(r["x"] + r["width"] for r in rects) / zoom / s
        y1 = max(r["y"] + r["height"] for r in rects) / zoom / s
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
    """Click at layout coordinates (scaled to the physical screen)."""
    s = scale()
    at = (int(round(x * s)), int(round(y * s)))
    for attempt in range(4):
        try:
            if double:
                mouse.double_click(button=button, coords=at)
            else:
                mouse.click(button=button, coords=at)
            return
        except OSError:
            # SetCursorPos fails with 258 'Wartevorgang abgebrochen' while the
            # session's input desktop is busy (just after an RDP reconnect).
            if attempt == 3:
                raise
            time.sleep(1.5)


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
    "toolbar_connection": (3686, 113),
    "toolbar_panels": (3535, 113),           # 'Panels' dropdown      # the connection dropdown (left of the info button)
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
    t = text.replace(" ", "")
    # Every sweep device sits on line 1.1; the device icon left of the
    # address reads as a digit at times ('91.1.1'), so look for 1.1.N.
    m = re.search(r"1\.1\.(\d{1,3})\b", t)
    if m:
        return f"1.1.{m.group(1)}"
    m = IA_RE.search(t)
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


def line_1_1() -> tuple[int, int]:
    """Screen position of '1.1 TP Linie' in the Topologie tree, expanding the
    tree when ETS reopened it collapsed (after a restart, 2026-10-28)."""
    tree = LAYOUT["tree"]
    for attempt in range(3):
        # The sweep project holds exactly one TP line; the selection highlight
        # garbles its number at times ('IJ:: TP Linie'), so match on the rest,
        # magnified on a second look.
        lines = ocr(tree, zoom=1 if attempt == 0 else 3)
        tp = [l for l in lines if "TP Linie" in l["text"] or "TP Unie" in l["text"]]
        if tp:
            hit = tp[0]
            return hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2
        main = next((l for l in lines if "Haupt" in l["text"]), None) or next(
            (l for l in lines if l["text"].strip().startswith("IP") or "1.0" in l["text"]), None)
        if not main:
            raise RuntimeError(f"no 'IP Hauptlinie' in the Topologie tree: {[l['text'] for l in lines]}")
        click(18, main["y"] + main["h"] // 2)  # the expander arrow left of the line
        time.sleep(1.5)
    raise RuntimeError("'1.1 TP Linie' did not appear in the Topologie tree")


@flow("devices")
def flow_devices(req: dict) -> dict:
    """The devices on line 1.1 of the active project, by OCR of the device list."""
    require_project(req["project"])
    click(*line_1_1())
    time.sleep(1.5)
    x0, y0, x1, y1 = LAYOUT["device_list"]
    # Row centres: every OCR line below the header, clustered by height.
    centres: list[int] = []
    for line in ocr(LAYOUT["device_list"]):
        cy = line["y"] + line["h"] // 2
        if cy > y0 + 40 and all(abs(cy - c) > 18 for c in centres):
            centres.append(cy)
    native = [l for l in ocr(LAYOUT["device_list"]) if l["x"] < 860 and _ia_in(l["text"])]
    ias = []
    for cy in sorted(centres):
        ia = next((_ia_in(l["text"]) for l in native if abs(l["y"] + l["h"] // 2 - cy) < 16), None)
        for zoom in (3, 2, 4):
            if ia:
                break
            # The Adresse cell alone, magnified: a selected row's grey
            # background hides it at native size; one zoom level misses a
            # row now and then, another reads it.
            cell = ocr((690, cy - 18, 860, cy + 18), zoom=zoom)
            ia = next((_ia_in(l["text"]) for l in cell if _ia_in(l["text"])), None)
        if ia:
            ias.append({"ia": ia, "y": cy})
    return {"devices": ias}


class CompatModeRequired(RuntimeError):
    """ETS wants to switch to compatibility mode for this product. Declined by
    the owner's rule (2026-10-28): such products are skipped, not run."""


def decline_compat_mode() -> str | None:
    """Decline ETS's compatibility-mode prompt (old product data) and return
    its text; the caller records the product as skipped."""
    lines = ocr((900, 500, 3300, 2000))
    joined = " ".join(l["text"] for l in lines)
    if "ompatibilit" not in joined:
        return None
    for label in ("Nein", "Abbrechen", "Nicht", "Schließen"):
        hit = find_text(label, (1500, 900, 3300, 2000), min_ratio=0.9)
        if hit and "ompatibilit" not in hit["text"]:
            click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
            break
    else:
        keys("{ESC}")
    time.sleep(2)
    return joined[:400]


def ensure_ets_running(project: str = "ets-sweep") -> list[str]:
    """Start ETS and open `project` when ETS is not running (it closed after a
    compatibility prompt, 2026-10-28)."""
    import subprocess

    did: list[str] = []
    try:
        ets_app()
        running = True
    except Exception:
        running = False
    if running:
        if window_project() == project:
            return did
        # ETS runs but shows its start page (or another tab): close a settings
        # dialog left open, then open the project's tile.
        if find_text("Einstellungen", (600, 100, 1200, 180), min_ratio=0.9) and find_text("Schließen", (3100, 2300, 3500, 2420)):
            click_text("Schließen", (3100, 2300, 3500, 2420))
            time.sleep(1.5)
        tab = find_text(project, (0, 0, 4112, 90), min_ratio=0.9)
        if tab:
            click(tab["x"] + tab["w"] // 2, tab["y"] + tab["h"] // 2)
            time.sleep(3)
        else:
            hit = find_text(project, (0, 700, 4112, 2400), min_ratio=0.9)
            if not hit:
                raise RuntimeError(f"ETS shows {window_project()!r} and no tile or tab for {project!r}")
            click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
            t0 = time.time()
            while time.time() - t0 < 120 and window_project() != project:
                time.sleep(3)
            time.sleep(5)
        did.append("opened project")
        did.append(str(ensure_layout()))
        return did
    subprocess.Popen([r"C:\Program Files (x86)\ETS6\ETS6.exe"], creationflags=subprocess.DETACHED_PROCESS)
    did.append("started ETS")
    t0 = time.time()
    while time.time() - t0 < 240:
        time.sleep(5)
        try:
            w = ets_main_window()
            if w.window_text().startswith("ETS6"):
                break
        except Exception:
            continue
    time.sleep(10)
    import ctypes

    ctypes.windll.user32.ShowWindow(ets_main_window().handle, 3)
    time.sleep(2)
    if window_project() != project:
        hit = find_text(project, (0, 900, 4112, 1500), min_ratio=0.9)
        if not hit:
            raise RuntimeError(f"ETS started, but no project tile {project!r} on the overview")
        click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
        did.append("opened project")
        t0 = time.time()
        while time.time() - t0 < 120 and window_project() != project:
            time.sleep(3)
        time.sleep(5)
    did.append(str(ensure_layout()))
    return did


def wait_busy(timeout: float = 300) -> float:
    """Wait while ETS shows a progress overlay ('Löschen …', 'Hinzufügen …'):
    deleting a large device (Zennio ALLinBOX 1612, 110 kB of parameters) takes
    minutes, and clicks meanwhile go nowhere. Returns the seconds waited."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        text = " ".join(l["text"] for l in ocr((1550, 900, 2560, 1100)))
        # 'Importiere Daten...' / 'Download aus dem Online-Katalog' /
        # 'Zusammenführen der Produktdaten': ETS merges an added product with
        # its online-catalog entry for ~10 s before the device appears.
        if not re.search(r"(Löschen|Hinzufügen|Einfügen|Speichern|Laden|Konvertiere|Importiere|Download aus|Zusammenführen)", text):
            return time.time() - t0
        time.sleep(2)
    raise RuntimeError(f"ETS still busy after {int(timeout)} s")


def dismiss_password_dialog() -> bool:
    """'Projektpasswort setzen': ETS asks for a project password the first
    time a KNX Secure capable product joins a project without one. The plain
    sweep answers Abbrechen (no project security); the secure pass (part 4)
    sets one instead. Without this the next keystrokes land in the field."""
    if not find_text("Projektpasswort setzen", (1300, 750, 2800, 900), min_ratio=0.8):
        return False
    hit = find_text("Abbrechen", (2200, 1600, 2800, 1760))
    if hit:
        click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
    else:
        keys("{ESC}")
    time.sleep(1.5)
    return True


def _digits(t: str) -> str:
    return re.sub(r"[^0-9a-z]", "", t.lower())


def _canon(t: str) -> str:
    """An order number as OCR may read it: case-folded, the letters OCR mixes
    up with digits unified (I/l/1/| and O/0), punctuation and spaces dropped."""
    t = t.lower().translate(str.maketrans({"l": "i", "1": "i", "|": "i", "!": "i", "0": "o"}))
    return re.sub(r"[^0-9a-z]", "", t)


def search_term(order: str) -> str:
    """ETS's catalog search does not take an order number's wildcard suffix
    ('754411xx', 'BM/A4.11-13x', '4007841059xxx'); search its fixed part."""
    return re.sub(r"(?<=[0-9.\-])x+$", "", order.strip(), flags=re.IGNORECASE) or order


def catalog_rows(expand: bool = True) -> list[dict]:
    """The catalog result rows as {y, name, order, application, version},
    grouped from OCR lines by height; manufacturer group headers are left out.
    A collapsed manufacturer group (ETS keeps a group collapsed across
    searches) is expanded first."""
    dy = catalog_dy()
    x0, y0, x1, y1 = LAYOUT["catalog_rows"]
    lines = ocr((x0, y0 + 40 + dy, x1, min(y1 + dy, 2440)))
    if expand and not any(l["x"] >= 1130 for l in lines):
        # No product rows: expand collapsed manufacturer headers (left column;
        # the first one sits just above the scanned area).
        heads = [l for l in ocr((x0, y0 + dy, 1300, min(y1 + dy, 2440))) if l["x"] < 800 and l["y"] > y0 + dy + 10]
        for head in heads[:6]:
            click(707, head["y"] + head["h"] // 2)
            time.sleep(1)
        lines = ocr((x0, y0 + 40 + dy, x1, min(y1 + dy, 2440)))
    rows: list[dict] = []
    for line in sorted(lines, key=lambda l: l["y"]):
        cy = line["y"] + line["h"] // 2
        row = next((r for r in rows if abs(r["y"] - cy) < 14), None)
        if row is None:
            row = {"y": cy, "cells": []}
            rows.append(row)
        row["cells"].append(line)
    out = []
    for r in rows:
        def cell(lo: int, hi: int) -> str:
            return " ".join(c["text"] for c in r["cells"] if lo <= c["x"] < hi).strip()
        version = cell(2560, 2740)
        order = cell(1970, 2240)
        if not version and order:
            # A short version ("1.1") can vanish at native size: read the
            # cell magnified, at more than one zoom.
            for zoom in (3, 2, 4):
                version = " ".join(l["text"] for l in ocr((2560, r["y"] - 20, 2740, r["y"] + 20), zoom=zoom)).strip()
                if version:
                    break
        if not version and not order:
            continue  # a manufacturer group header
        out.append({"y": r["y"], "name": cell(1130, 1970), "order": cell(1970, 2240),
                    "application": cell(2300, 2560), "version": version, "online": row_is_online(r["y"])})
    return out


def row_is_online(y: int) -> bool:
    """Whether a catalog row is an online-catalog entry (cloud icon at x
    694-725) rather than an imported product. ETS lists its online catalog
    next to the local one since the product store was cleared (2026-10-28)."""
    from PIL import ImageOps

    img = ImageOps.grayscale(grab((690, y - 16, 730, y + 16)))
    w, h = img.size
    px = img.load()
    dark_cols = sum(1 for x in range(w) if min(px[x, yy] for yy in range(h)) < 180)
    return dark_cols >= 8


@flow("catalog_rows")
def flow_catalog_rows(req: dict) -> dict:
    return {"rows": catalog_rows()}


@flow("catalog_add")
def flow_catalog_add(req: dict) -> dict:
    """Search the catalog for `search` (an order number), pick the row whose
    order number matches and whose application version is `version` (as ETS
    shows it, e.g. "2.3"), and add it to line 1.1. Returns the device list."""
    require_project(req["project"])
    dismiss_password_dialog()
    wait_busy()
    before = {d["ia"] for d in flow_devices(req)["devices"]}
    dy = catalog_dy()
    sx, sy = LAYOUT["catalog_search"]
    def search(term: str) -> tuple[list[dict], list[dict]]:
        want = _canon(term)
        rows: list[dict] = []
        for attempt in range(4):
            click(sx, sy + dy)
            time.sleep(0.3)
            keys("^a")
            keys("{DEL}")
            time.sleep(0.5)
            keys(term)
            time.sleep(0.4)
            keys("{DEL}{ENTER}")  # drop ETS's autocompleted suffix (ZPR1612 -> ZPR1612V3)
            time.sleep(3 + 2 * attempt)
            click(1000, 1380 + dy)  # a neutral spot: closes the search-history dropdown
            time.sleep(0.5)
            rows = catalog_rows()
            # Only rows of THIS search count: ETS leaves the previous search's
            # rows up for a while (a third of the misses in the first full run).
            hits = [r for r in rows if want and (want in _canon(r["order"]) or want in _canon(r["name"]))]
            if hits:
                return rows, hits
        return rows, []

    order = _canon(search_term(req["search"]))
    want_version = _digits(req.get("version", ""))

    def pick(hits: list[dict]) -> dict | None:
        # Imported products only: an online-catalog row would make ETS fetch
        # product data from the internet instead of our corpus file.
        hits = [r for r in hits if not r.get("online")]
        # The order number exactly (ZPR1612 is not ZPR1612V2), else a prefix.
        exact = [r for r in hits if _canon(r["order"]) == order] or [r for r in hits if _canon(r["order"]).startswith(order)]
        match = [r for r in exact if want_version and _digits(r["version"]) == want_version]
        if match:
            return match[0]
        if len(exact) == 1 and (not want_version or not exact[0]["version"]):
            # The only local row with this order number, its version unread.
            return exact[0]
        return None

    rows, hits = search(search_term(req["search"]))
    row = pick(hits)
    if row is None and req.get("fallback_search"):
        # ETS's search by order number shows only some versions of a product
        # family at times (ZPR1612 listed only the v2 product); the product
        # name lists them all.
        rows, more = search(req["fallback_search"])
        hits = hits + more
        row = pick(more)
    if row is None:
        if hits:
            raise RuntimeError(f"catalog version mismatch: {req['search']!r} shows {[(r['order'], r['version']) for r in hits][:8]}, wanted {req.get('version')!r}")
        raise RuntimeError(f"not found in catalog search: {req['search']!r}; rows {rows[:4]}")
    click(1300, row["y"])
    time.sleep(1)
    bar = (LAYOUT["catalog_bar"][0], LAYOUT["catalog_bar"][1] + dy, LAYOUT["catalog_bar"][2], min(LAYOUT["catalog_bar"][3] + dy, 2484))
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        # The add bar's target line follows the tree selection: select the
        # line, then the catalog row again.
        click(*line_1_1())
        time.sleep(1.5)
        click(1300, row["y"])
        time.sleep(1)
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        lx, ly = LAYOUT["catalog_line_dropdown"]
        click(lx, ly + dy)
        time.sleep(1)
        choose("1.1 TP Linie", (600, 1600, 1300, 2484))
        time.sleep(0.8)
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        raise RuntimeError(f"the add bar does not target 1.1 TP Linie: {[l['text'] for l in ocr(bar)]}")
    # The 'Elemente' count left of the add bar must be 1; an interrupted
    # flow once left it empty (marked red), and Hinzufügen then adds nothing.
    count = (130, LAYOUT["catalog_add"][1] + dy - 25, 300, LAYOUT["catalog_add"][1] + dy + 25)
    if not any(l["text"].strip() == "1" for l in ocr(count, zoom=3)):
        click(200, LAYOUT["catalog_add"][1] + dy)
        time.sleep(0.3)
        keys("^a")
        keys("1{TAB}")
        time.sleep(0.5)
    ax, ay = LAYOUT["catalog_add"]
    click(ax, ay + dy)
    time.sleep(3)
    wait_busy()
    # A KNX Secure capable product raises 'Projektpasswort setzen' a few
    # seconds after it was added (seen up to ~8 s, 2026-10-28): wait for it.
    password_dialog = False
    t0 = time.time()
    while time.time() - t0 < float(req.get("password_wait", 12)):
        invalid = " ".join(l["text"] for l in ocr((1400, 1000, 2700, 1350)))
        if "Validierung fehlgeschlagen" in invalid or "defekte Daten" in invalid:
            # ETS's product store holds data it cannot validate for this
            # product (Zennio ALLinBOX 1612 v2): it refuses the add.
            click_text("OK", (2500, 1380, 2700, 1460))
            time.sleep(1)
            raise RuntimeError(f"ETS product data invalid: {invalid[:200]}")
        compat = decline_compat_mode()
        if compat:
            raise CompatModeRequired(f"ETS asked for compatibility mode on adding: {compat[:200]}")
        if dismiss_password_dialog():
            password_dialog = True
            break
        time.sleep(1)
    # When ETS merges the product with its online-catalog entry ('Importiere
    # Daten... / Zusammenführen der Produktdaten', ALLinBOX 1612 1.3,
    # 2026-10-28) the device shows up 10-30 s after the click: poll.
    t0 = time.time()
    while True:
        wait_busy()
        after = flow_devices(req)["devices"]
        new = [d for d in after if d["ia"] not in before]
        if new or time.time() - t0 > float(req.get("add_wait", 60)):
            break
        if dismiss_password_dialog():
            password_dialog = True
        time.sleep(2)
    return {"devices": after, "added": new, "row": row, "password_dialog": password_dialog}


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
    # The confirmation comes later for a larger product (over 2 s for an MDT
    # room actuator): wait for it, confirm, and check the device is gone.
    t0 = time.time()
    confirmed = False
    while time.time() - t0 < float(req.get("confirm_wait", 10)):
        time.sleep(1)
        if time.time() - t0 > 3 and not find_text("Möchten Sie", LAYOUT["delete_dialog"]):
            # ETS deletes without asking once its confirmation is switched off
            # (it was, 2026-10-28): the device leaving the list is the answer.
            wait_busy()
            if all(d["ia"] != req["ia"] for d in flow_devices(req)["devices"]):
                confirmed = True
                break
        if find_text("Möchten Sie die markierten Objekte", LAYOUT["delete_dialog"]):
            # Confirm only when the dialog names the device: an interrupted
            # flow once left the line selected, and 'Ja' deleted line 1.1
            # (2026-10-28).
            named = " ".join(l["text"] for l in ocr(LAYOUT["delete_dialog"]))
            if req["ia"] in named.replace(" ", "") and "Linie" not in named:
                click_text("Ja", LAYOUT["delete_yes"])
                confirmed = True
            else:
                click_text("Nein", (2450, 1420, 2700, 1480))
                raise RuntimeError(f"delete dialog does not name {req['ia']}: {named[:200]}")
            break
    time.sleep(2)
    waited = wait_busy()
    # A large product leaves the list seconds after the key press (ALLinBOX
    # 1612, 2026-10-28): poll before calling the delete failed.
    t1 = time.time()
    while True:
        after = flow_devices(req)["devices"]
        gone = all(d["ia"] != req["ia"] for d in after)
        if gone or time.time() - t1 > 20:
            break
        time.sleep(2)
        waited += wait_busy()
    confirmed = confirmed or gone
    return {"deleted": confirmed and all(d["ia"] != req["ia"] for d in after), "devices": after, "busy_wait": round(waited)}


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
    hit = [d for d in devs if d["ia"] == req["ia"]] or [d for d in devs if d["ia"].endswith("." + req["ia"].split(".", 1)[1]) and len(devs) == 1]
    if not hit:
        raise RuntimeError(f"device {req['ia']} not in list: {devs}")
    click(700, hit[0]["y"])
    time.sleep(1)
    click(*LAYOUT["toolbar_program_arrow"])
    time.sleep(1.5)
    menu_click(PROGRAM_MODES[req.get("mode", "application")])
    t0 = time.time()
    kept = False
    password = False
    while time.time() - t0 < float(req.get("dialog_wait", 20)):
        if find_text("Schnittstellen-Prüfung", LAYOUT["medium_dialog"]):
            click(*LAYOUT["medium_keep"])
            kept = True
            break
        if dismiss_password_dialog():
            password = True
        compat = decline_compat_mode()
        if compat:
            raise CompatModeRequired(f"ETS asked for compatibility mode on download: {compat[:200]}")
        time.sleep(1)
    return {"ia": req["ia"], "mode": req.get("mode", "application"), "medium_dialog_kept": kept, "password_dialog": password}


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


def dismiss_ets_error() -> str | None:
    """Close an 'ETS - Fehler' dialog (an internal ETS exception, e.g. the
    'Sammlung wurde geändert' one that hit after the 286th catalog import on
    2026-10-27) and return its text. Those dialogs are overlays: OCR only."""
    lines = ocr((1200, 950, 3000, 1300))
    joined = " ".join(l["text"] for l in lines)
    if "Fehler" not in joined:
        return None
    ok = find_text("OK", (2400, 1180, 2800, 1260), min_ratio=0.6)
    if ok:
        click(ok["x"] + ok["w"] // 2, ok["y"] + ok["h"] // 2)
    else:
        click(2600, 1226)
    time.sleep(1.5)
    return joined[:400]


@flow("ets_error")
def flow_ets_error(req: dict) -> dict:
    return {"dismissed": dismiss_ets_error()}


def ensure_layout() -> dict:
    """Bring ETS back to the sweep layout that LAYOUT assumes: main window
    maximized, the Topologie panel on top and the Katalog panel below. ETS
    restarts itself at times (after a catalog update, 2026-10-27) and then
    opens the project in its default single-panel layout."""
    import ctypes

    did = []
    w = ets_main_window()
    r = w.rectangle()
    if (r.right - r.left) < SCREEN[2] * scale() - 20:
        ctypes.windll.user32.ShowWindow(w.handle, 3)  # SW_MAXIMIZE
        time.sleep(1.5)
        did.append("maximized")
    for _ in range(2):
        # Any panel above the Topologie panel (ETS reopens 'Gebäude' after a
        # restart) pushes the Katalog panel down: close the top panel while it
        # is not Topologie (its close button sits at the panel header's right).
        top = find_text("Gebäude", (0, 160, 660, 210)) or find_text("Gruppenadressen", (0, 160, 660, 210))
        if not top:
            break
        click(648, 185)
        time.sleep(2)
        did.append("closed " + top["text"])
    if not find_text("Topologie", (0, 160, 660, 210)):
        click(*LAYOUT["toolbar_panels"])
        time.sleep(1.2)
        choose("Topologie", (3400, 140, 3900, 620))
        time.sleep(2.5)
        did.append("topologie")
    headers = [l for l in ocr((0, 200, 660, 2440)) if _norm(l["text"]) == "katalog"]
    for extra in sorted(headers, key=lambda l: l["y"])[1:]:
        # A second Katalog panel (opened by an earlier restore): close it.
        click(648, extra["y"] + 12)
        time.sleep(2)
        did.append("closed duplicate katalog")
    if not headers:
        click(*LAYOUT["toolbar_panels"])
        time.sleep(1.2)
        choose("Alle Panels", (3400, 140, 3900, 620))
        time.sleep(1.2)
        choose("Katalog", (2800, 140, 4112, 1200))
        time.sleep(3)
        did.append("katalog")
    return {"did": did, "import_button": bool(catalog_import_button()), "catalog_dy": catalog_dy()}


def catalog_import_button() -> dict | None:
    """The Katalog panel's Import button wherever the panel sits."""
    hits = [l for l in ocr((680, 200, 1100, 2440)) if _norm(l["text"]) in ("import", "impart", "imp0rt")]
    return min(hits, key=lambda l: abs(l["y"] - 1354)) if hits else None


def catalog_dy() -> int:
    """Vertical offset of the Katalog panel from the layout LAYOUT was
    measured in (Import button at y=1354): ETS reopens panels with other
    splitter positions after a restart."""
    btn = catalog_import_button()
    return btn["y"] - 1354 if btn else 0


@flow("ensure_layout")
def flow_ensure_layout(req: dict) -> dict:
    return ensure_layout()


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
    ets_error = dismiss_ets_error()
    if not catalog_import_button():
        ensure_layout()
    btn = catalog_import_button()
    wizard_text = " ".join(l["text"] for l in ocr(region))
    attached = False
    for _ in range(3):
        if "erfolgreich" not in wizard_text and "fehlgeschlagen" not in wizard_text:
            break
        # A previous file's result panel is still up (its OK click missed
        # once and covered the Import button for 39 files, 2026-10-27):
        # close it by position, then look again.
        click(2488, 1528)
        time.sleep(1.5)
        btn = catalog_import_button()
        wizard_text = " ".join(l["text"] for l in ocr(region))
    if not btn and any(k in wizard_text for k in ("Konvertiere", "Signiere", "Produktsprache", "Import auswählen")):
        # An import is already running (a previous call timed out while a
        # large file converted): wait for its result instead of starting over.
        attached = True
    elif not btn:
        raise RuntimeError("the Katalog panel's Import button is not on screen")
    else:
        dialog = None
        for attempt in range(3):
            # The click lands on nothing now and then while ETS refreshes the
            # catalog after the previous import (43 of 498 files on the first
            # pass, 2026-10-27): press Import again before giving up.
            click(btn["x"] + btn["w"] // 2, btn["y"] + btn["h"] // 2)
            t0 = time.time()
            while time.time() - t0 < 15:
                dialog = next((p for p in ets_popups() if "Produktdatei" in p.window_text()), None)
                if dialog:
                    break
                time.sleep(0.5)
            if dialog:
                break
            dismiss_ets_error()
            btn = catalog_import_button() or btn
        if dialog is None:
            raise RuntimeError("no 'Produktdatei öffnen' dialog appeared after 3 clicks")
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
            products = [t.partition(":")[2].strip() or t[len("Produkt"):].strip() for t in fine if t.startswith("Produkt")]
            for _ in range(3):
                ok = find_text("OK", (2300, 1450, 2700, 1600), min_ratio=0.6)
                if ok:
                    click(ok["x"] + ok["w"] // 2, ok["y"] + ok["h"] // 2)
                else:
                    click(2488, 1528)  # where the result panel's OK sits
                time.sleep(1.5)
                if "erfolgreich" not in " ".join(l["text"] for l in ocr(region)):
                    break
            return {"outcome": "imported", "products": products, "message": joined[:600], "attached": attached, "ets_error": ets_error}
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
    dy = catalog_dy()
    sx, sy = LAYOUT["catalog_search"]
    click(sx, sy + dy)
    time.sleep(0.3)
    keys("^a")
    keys(req["term"])
    time.sleep(0.4)
    keys("{DEL}{ENTER}")  # drop ETS's autocompleted suffix
    time.sleep(float(req.get("wait", 3)))
    click(1000, 1380 + dy)  # closes the search-history dropdown
    time.sleep(0.5)
    x0, y0, x1, y1 = LAYOUT["catalog_rows"]
    y0, y1 = y0 + dy, min(y1 + dy, 2440)
    rows = []
    for line in ocr((x0, y0 + 40, x1, y1), zoom=2):
        rows.append({"text": line["text"], "x": line["x"], "y": line["y"]})
    return {"term": req["term"], "rows": rows}


@flow("catalog_remove")
def flow_catalog_remove(req: dict) -> dict:
    """Delete the imported catalog products a search for `term` lists (not
    online-catalog entries), one row at a time, until none is left. ETS
    deletes a catalog product on the Delete key without asking. Keeps the
    catalog small: the sweep imports a product file, runs it and removes it,
    since ETS slowed down and broke with the whole corpus in its store."""
    require_project(req["project"])
    removed = []
    rows: list[dict] = []
    for _ in range(int(req.get("max", 40))):
        rows = [r for r in catalog_search_rows(req["term"]) if not r.get("online")]
        if not rows:
            break
        row = rows[0]
        click(1300, row["y"])
        time.sleep(0.8)
        keys("{DELETE}")
        time.sleep(2)
        # A confirmation, should one appear for some product.
        text = " ".join(l["text"] for l in ocr((1200, 700, 3000, 1800)))
        if "Möchten Sie" in text:
            for label in ("Ja", "OK"):
                hit = find_text(label, (1800, 1300, 3000, 1800), min_ratio=0.95)
                if hit:
                    click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
                    break
        wait_busy()
        removed.append(f"{row['order']} {row['version']}")
    return {"removed": removed, "left": rows}


def catalog_search_rows(term: str) -> list[dict]:
    """Type `term` into the catalog search and return the rows of that search."""
    dy = catalog_dy()
    sx, sy = LAYOUT["catalog_search"]
    want = _canon(term)
    rows: list[dict] = []
    for attempt in range(3):
        click(sx, sy + dy)
        time.sleep(0.3)
        keys("^a")
        keys("{DEL}")
        time.sleep(0.5)
        keys(term)
        time.sleep(0.4)
        keys("{DEL}{ENTER}")  # drop ETS's autocompleted suffix
        time.sleep(3 + 2 * attempt)
        click(1000, 1380 + dy)
        time.sleep(0.5)
        rows = [r for r in catalog_rows() if want in _canon(r["order"]) or want in _canon(r["name"])]
        if rows:
            return rows
    return rows


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
                # Watchdog before every flow: a modal left open by the
                # previous one (the project-password dialog, an ETS error)
                # would swallow this flow's clicks and keystrokes.
                if abs(scale() - 1.0) > 0.01:
                    # Not the 4112-wide RDP desktop the layout was measured on
                    # (the VM console is 1280x800 and lays ETS out
                    # differently): refuse rather than click beside the target.
                    raise RuntimeError(f"desktop is not the RDP layout (scale {scale():.3f}); reconnect the RDP session")
                started = ensure_ets_running(req.get("project", "ets-sweep")) if name != "windows" else []
                if name not in ("windows", "state"):
                    import ctypes

                    fg = ctypes.windll.user32.GetForegroundWindow()
                    if fg != ets_main_window().handle and not ets_popups():
                        # Someone works in the VM (another window is in front):
                        # refuse instead of clicking into their windows.
                        raise RuntimeError("desktop in use: ETS is not the foreground window; the sweep waits")
                compat = decline_compat_mode()
                if compat:
                    raise CompatModeRequired(f"ETS asked for compatibility mode before {name}: {compat[:200]}")
                watchdog = {"password_dialog": dismiss_password_dialog(), "ets_error": dismiss_ets_error(),
                            "ets_started": started}
                out = fn(req)
                out.setdefault("ok", True)
                if any(watchdog.values()):
                    out["watchdog"] = watchdog
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
