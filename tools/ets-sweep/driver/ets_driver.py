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
import threading
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

# The catalog row rules (#881), shared with the Mac-side tests; `vm.py
# install` uploads the file next to this one.
sys.path.insert(0, str(HERE))
import catalog_pick  # noqa: E402


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
    for attempt in range(6):
        try:
            if double:
                mouse.double_click(button=button, coords=at)
            else:
                mouse.click(button=button, coords=at)
            return
        except Exception as exc:  # noqa: BLE001 - pywintypes.error is no OSError
            # SetCursorPos fails with 258 'Wartevorgang abgebrochen' while the
            # session's input desktop is busy (just after an RDP reconnect,
            # and once mid-sweep, 2026-10-28); pywinauto reports 'There is no
            # active desktop' for the same moment.
            transient = "SetCursorPos" in str(exc) or "no active desktop" in str(exc)
            if attempt == 5 or not transient and not isinstance(exc, OSError):
                raise
            time.sleep(3)


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
    # The breadcrumb under the tabs: names the selected line or device.
    "breadcrumb": (150, 80, 2300, 150),
    # The toolbar's add button: 'Geräte hinzufügen' with a line selected,
    # 'Hinzufügen' with a device selected.
    "toolbar_add": (2200, 80, 2600, 150),
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
    # The dialog grows with a two-line device name (Dinuy ITKNT, 2026-11-05):
    # its Ja moved to y 1476.
    "delete_yes": (1300, 1380, 2800, 1580),  # OCR reads nothing in a narrow crop
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


def click_button(label: str, bbox: tuple[int, int, int, int]) -> None:
    """Clicks the OCR line that is exactly `label` (a leading check mark or
    cross allowed). A wide search strip also holds other text: the fuzzy
    match took 'Secure, Schalter/Jalousie 8-fach' for 'Ja' (2026-11-06)."""
    hits = [l for l in ocr(bbox) if re.fullmatch(rf"\W{{0,3}}\s*{re.escape(label)}", l["text"].strip())]
    if not hits:
        raise RuntimeError(f"button {label!r} not on screen in {bbox}")
    hit = hits[0]
    click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)


def project_tab_hit(name: str) -> dict | None:
    """The tab of project `name` in the tab strip. OCR splits a hyphenated
    name into fragments ('ets', '-sweep', '-secure', 2026-11-04): when no
    single line matches, adjacent fragments on one row are joined."""
    hit = find_text(name, LAYOUT["tab_strip"])
    if hit and re.sub(r"\s", "", hit["text"]) == name:
        return hit
    lines = sorted(ocr(LAYOUT["tab_strip"]), key=lambda l: l["x"])
    for i in range(len(lines)):
        for j in range(i + 1, min(i + 5, len(lines) + 1)):
            group = lines[i:j]
            if any(abs(l["y"] - group[0]["y"]) > 10 for l in group):
                break
            if "".join(re.sub(r"\s", "", l["text"]) for l in group) == name:
                x1 = max(l["x"] + l["w"] for l in group)
                return {"text": name, "x": group[0]["x"], "y": group[0]["y"],
                        "w": x1 - group[0]["x"], "h": max(l["h"] for l in group)}
    return hit


@flow("project_tab")
def flow_project_tab(req: dict) -> dict:
    """Bring the tab of project `name` to the front (it must already be open)."""
    name = req["name"]
    if window_project() == name:
        return {"project": name}
    hit = project_tab_hit(name)
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
    for attempt in range(4):
        if attempt == 2:
            # A raised Katalog panel squeezes the tree to a few rows (Import at
            # y 467, 2026-11-06): put the splitter back first.
            restore_catalog_splitter()
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
            # Collapsed down to the backbone (seen 2026-10-28): select it and
            # expand it with the arrow key, then look again.
            backbone = next((l for l in lines if "Backbone" in l["text"]), None)
            if not backbone:
                raise RuntimeError(f"no 'IP Hauptlinie' in the Topologie tree: {[l['text'] for l in lines]}")
            click(backbone["x"] + backbone["w"] // 2, backbone["y"] + backbone["h"] // 2)
            time.sleep(0.5)
            keys("{RIGHT}")
            time.sleep(1.5)
            continue
        click(18, main["y"] + main["h"] // 2)  # the expander arrow left of the line
        time.sleep(1.5)
    raise RuntimeError("'1.1 TP Linie' did not appear in the Topologie tree")


def click_tab(word: str) -> bool:
    """Clicks the tab `word` of the strip above the centre view, where OCR
    reads it; OCR may join the strip into one line ('Segmente 0 Geräte 3'),
    so the word is aimed at by its share of the line's characters."""
    tab = find_text(word, (680, 150, 1600, 220))
    if tab is None:
        return False
    text = tab["text"]
    at = max(text.find(word), 0) + len(word) // 2
    click(tab["x"] + tab["w"] * at // max(len(text), 1), tab["y"] + tab["h"] // 2)
    return True


@flow("devices")
def flow_devices(req: dict) -> dict:
    """The devices on line 1.1 of the active project, by OCR of the device list."""
    require_project(req["project"])
    click(*line_1_1())
    time.sleep(1.5)
    # The line view reopens on the tab it showed last; after a device's
    # parameter view that can be 'Segmente' (2026-10-31): the device list is
    # the 'Geräte' tab.
    if click_tab("Geräte"):
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
    # 'Abbrechen' first, and no 'Nicht': that one matched the warning's own
    # text ('konnten nicht programmiert werden') and the click missed the
    # button, so the prompt stayed and five imports failed (Berker Funk
    # Taster, 2026-11-05). Never the restart button.
    for label in ("Abbrechen", "Nein", "Schließen"):
        hit = find_text(label, (1500, 900, 3300, 2000), min_ratio=0.9)
        if hit and "ompatibilit" not in hit["text"] and "neu starten" not in hit["text"]:
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
    # A started ETS can open behind another window (Explorer, 2026-10-28):
    # bring it to the front before reading its start page.
    try:
        ets_main_window().set_focus()
    except Exception:
        pass
    time.sleep(2)
    if window_project() != project:
        hit = None
        t1 = time.time()
        while not hit and time.time() - t1 < 60:
            hit = find_text(project, (0, 700, 4112, 2400), min_ratio=0.9)
            if not hit:
                time.sleep(5)
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


def dismiss_password_dialog(password: str | None = None) -> bool:
    """'Projektpasswort setzen': ETS asks for a project password the first
    time a KNX Secure capable product joins a project without one. The plain
    sweep answers Abbrechen (no project security); the secure pass (part 4,
    #423) passes `password` and sets it instead (`set_project_password`).
    Without this the next keystrokes land in the field."""
    if password:
        return set_project_password(password)
    if not find_text("Projektpasswort setzen", (1300, 750, 2800, 900), min_ratio=0.8):
        return False
    hit = find_text("Abbrechen", (2200, 1600, 2800, 1760))
    if hit:
        click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
    else:
        keys("{ESC}")
    time.sleep(1.5)
    return True


# ---------------------------------------------------------------- secure pass (#423)
# UNVERIFIED against ETS: written offline on 2026-10-30 while a sweep held
# the VM. Every step anchors on dialog text read by OCR and fails loudly with
# what it saw; the sweep's repair loop keeps a screenshot. Keystrokes only
# type text and press Tab, Enter or Escape (never Delete or Backspace).

PASSWORD_DIALOG = (1200, 700, 3000, 1800)


def set_project_password(password: str) -> bool:
    """Answers ETS's project password dialog with `password`: 'Projektpasswort
    setzen' (two fields, the second a confirmation) or a prompt for the
    password of a protected project (one field). The first field holds the
    focus when the dialog opens. Returns whether a dialog was answered."""
    if re.search(r"[+^%~(){}\[\]]", password):
        # pywinauto's send_keys reads these as modifiers and groups.
        raise RuntimeError("the project password must not contain + ^ % ~ ( ) { } [ ]")
    lines = ocr(PASSWORD_DIALOG)
    text = " ".join(l["text"] for l in lines)
    if "Projektpasswort" not in text and not ("Passwort" in text and "Projekt" in text):
        return False
    keys(password, pause=0.02)
    if re.search(r"(bestätig|wiederhol|Bestätig|Wiederhol)", text):
        keys("{TAB}")
        keys(password, pause=0.02)
    # 'Projektpasswort setzen' does not take Enter: its button 'Passwort
    # setzen' sits at the dialog's bottom right (ETS 6.4.1, 2026-11-04).
    time.sleep(0.5)
    button = find_text("Passwort setzen", (PASSWORD_DIALOG[0], 1600, PASSWORD_DIALOG[2], PASSWORD_DIALOG[3]))
    if button:
        click(button["x"] + button["w"] // 2, button["y"] + button["h"] // 2)
    else:
        keys("{ENTER}")
    time.sleep(2)
    after = " ".join(l["text"] for l in ocr(PASSWORD_DIALOG))
    if "Projektpasswort" in after:
        keys("{ESC}")
        raise RuntimeError(f"the project password dialog stayed open: {after[:200]}")
    return True


def enter_certificate(certificate: str) -> bool:
    """Types the device certificate (the FDSK label, 36 characters in six
    groups) into ETS's certificate prompt, when one is open: ETS asks for it
    before the first secure download of a device it holds none for."""
    text = " ".join(l["text"] for l in ocr(PASSWORD_DIALOG))
    if "Zertifikat" not in text:
        return False
    keys(certificate, pause=0.02)
    time.sleep(0.5)
    # The dialog's 'OK' sits at its bottom right next to 'Später'.
    button = find_text("OK", (2300, 1580, 2560, 1680), min_ratio=0.9)
    if button:
        click(button["x"] + button["w"] // 2, button["y"] + button["h"] // 2)
    else:
        keys("{ENTER}")
    time.sleep(2)
    after = " ".join(l["text"] for l in ocr(PASSWORD_DIALOG))
    if "Zertifikat" in after and re.search(r"(ungültig|Ungültig|falsch|Fehler)", after):
        keys("{ESC}")
        raise RuntimeError(f"ETS refused the device certificate: {after[:200]}")
    return True


def export_from_tab_menu(project: str, entry_re: str, path: str, password: str | None = None,
                         wait: float = 120) -> dict:
    """An export ETS offers in the project tab's context menu: the entry
    matching `entry_re`, ETS's save dialog (a Win32 dialog, UI Automation:
    the file name field set to `path`, then Enter), the export password when
    one is asked for, and the file appearing at `path` in the VM."""
    require_project(project)
    hit = project_tab_hit(project)
    if not hit:
        raise RuntimeError(f"no tab for project {project!r}")
    click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2, button="right")
    time.sleep(1.5)
    items = menu_items()
    entry = next((i for i in items if re.search(entry_re, i, re.I)), None)
    if entry is None:
        keys("{ESC}")
        raise RuntimeError(f"no entry like {entry_re!r} in the project tab's menu: {items[:16]}")
    menu_click(entry)
    time.sleep(2)
    dialog = wait_popup(10)
    save_as(dialog, path)
    answered = set_project_password(password) if password else False
    deadline = time.time() + wait
    while time.time() < deadline and not os.path.exists(path):
        time.sleep(1)
    wait_busy()
    return {"path": path, "exported": os.path.exists(path), "password_dialog": answered, "menu_entry": entry}


def save_as(dialog, path: str) -> None:
    """Saves through a Windows save dialog: its file name field (automation id
    1001, 'Dateiname:'), then Enter. The first visible Edit is the file list's
    'Name' column header: setting that one left ETS's default name in place
    and the file landed in the last folder used (2026-11-04)."""
    names = [e for e in dialog.descendants(control_type="Edit") if e.element_info.automation_id == "1001"]
    if not names:
        keys("{ESC}")
        raise RuntimeError(f"the save dialog has no file name field: {popup_tree(4, 3000)[:400]}")
    # Typed, not set: set_edit_text shows the text but the dialog saves its
    # own default name (it asked to overwrite that, 2026-11-04).
    names[0].click_input()
    time.sleep(0.3)
    keys("^a")
    keys(path, pause=0.01)
    time.sleep(0.5)
    buttons = [b for b in dialog.descendants(control_type="Button") if b.window_text() == "Speichern"]
    if buttons:
        buttons[0].click_input()
    else:
        keys("{ENTER}")
    time.sleep(2)
    # A rerun finds the file: replace it (the prompt names our path).
    for w in ets_popups():
        text = " ".join(t.window_text() for t in w.descendants(control_type="Text"))
        if "bereits vorhanden" in text and os.path.basename(path) in text:
            for b in w.descendants(control_type="Button"):
                if b.window_text() == "Ja":
                    b.click_input()
                    time.sleep(2)
                    break


def project_tile(project: str) -> dict:
    """The tile of `project` on ETS's start page (its name under the icon)."""
    lines = ocr((0, 1150, 4112, 1320))
    hits = [l for l in lines if re.sub(r"\s", "", l["text"]) == project]
    if not hits:
        raise RuntimeError(f"no tile for project {project!r}: {[l['text'] for l in lines][:12]}")
    return hits[0]


@flow("export_keyring")
def flow_export_keyring(req: dict) -> dict:
    """`export_keyring_once`, again once when UI Automation failed on the way
    ('Ein Ereignis konnte keinen Abonnenten aufrufen', a COMError, right
    after a download on 2026-11-04)."""
    started = time.time()
    try:
        return export_keyring_once(req)
    except Exception as e:  # noqa: BLE001 - only the COM failure is retried
        if "COMError" not in repr(e) and "Abonnenten" not in str(e):
            raise
        # The failure also hits after the save dialog wrote the file (the
        # overwrite check walks a closing popup): a file written since the
        # flow started is the export.
        time.sleep(3)
        path = req["path"]
        if os.path.exists(path) and os.path.getmtime(path) >= started - 1:
            for w in ets_popups():
                try:
                    w.close()
                except Exception:  # noqa: BLE001 - a stale popup is gone already
                    pass
            click(3450, 93)
            time.sleep(1.5)
            hit = project_tab_hit(req["project"])
            if hit:
                click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
                time.sleep(2)
            return {"path": path, "exported": True, "com_error_after_save": repr(e)[:120]}
        return {**export_keyring_once(req), "retried": repr(e)[:120]}


def export_keyring_once(req: dict) -> dict:
    """Exports the project's keyring (`.knxkeys`) to `path` in the VM,
    protected with `password` (#423). ETS 6.4.1 has it on the start page
    (checked 2026-11-04): the project tile's 'Details', its 'Sicherheit'
    page, 'Backup Schlüsselbund', a password dialog whose OK takes a second
    click once the password is valid, then a Windows save dialog. The
    project tab has no context menu."""
    project, path, password = req["project"], req["path"], req["password"]
    if re.search(r"[+^%~(){}\[\]]", password):
        raise RuntimeError("the keyring password must not contain + ^ % ~ ( ) { } [ ]")
    require_project(project)
    click(200, 40)  # the start page tab
    time.sleep(3)
    tile = project_tile(project)
    click(tile["x"] + tile["w"] // 2, tile["y"] - 150, button="right")
    time.sleep(1.5)
    items = menu_items()
    if "Details" not in items:
        keys("{ESC}")
        raise RuntimeError(f"the tile menu of {project!r} has no 'Details': {items[:10]}")
    menu_click("Details")
    time.sleep(3)
    try:
        click_text("Sicherheit", (1630, 700, 1950, 820))
        time.sleep(3)
        click_text("Backup Schlüsselbund", (2850, 320, 3400, 400))
        time.sleep(3)
        if not find_text("Schlüsselbund mit Passwort", (1350, 860, 2750, 950), min_ratio=0.8):
            raise RuntimeError("no keyring password dialog after 'Backup Schlüsselbund'")
        keys(password, pause=0.02)
        time.sleep(1)
        # 'Gerätezertifikate hinzufügen' puts the FDSKs in the keyring: the
        # frames ETS sends before it writes the tool key are secured with
        # the FDSK and decode only then (11 of 104 frames without, syn-secure
        # 2026-11-04).
        box = find_text("Gerätezertifikate hinzufügen", (1380, 1440, 2000, 1520), min_ratio=0.8)
        if not box:
            raise RuntimeError("no 'Gerätezertifikate hinzufügen' box in the keyring password dialog")
        click(box["x"] - 35, box["y"] + box["h"] // 2)
        time.sleep(0.5)
        for _ in range(4):
            if ets_popups():
                break
            click_text("OK", (2330, 1570, 2480, 1630))
            time.sleep(2.5)
        save_as(wait_popup(10), path)
        deadline = time.time() + 60
        while time.time() < deadline and not os.path.exists(path):
            time.sleep(1)
        wait_busy()
    finally:
        # Close the details dialog (its X; Escape leaves it open) and go back
        # to the project's tab.
        for w in ets_popups():
            try:
                w.close()
            except Exception:  # noqa: BLE001 - a stale popup is gone already
                pass
        click(3450, 93)
        time.sleep(1.5)
        hit = project_tab_hit(project)
        if hit:
            click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
            time.sleep(2)
    return {"path": path, "exported": os.path.exists(path)}


@flow("export_project")
def flow_export_project(req: dict) -> dict:
    """Exports the project (`.knxproj`) to `path` in the VM (#424): `bussard
    import` of it is the model state a parameter-set row compares against."""
    return export_from_tab_menu(req["project"], r"^(Projekt )?export", req["path"], req.get("project_password"))


# ---------------------------------------------------------------- parameter editor (#424)
# Checked against ETS 6.4.1 on 2026-10-31 (syn-minimal): the device's
# 'Parameter' tab, next to 'Kommunikationsobjekte' above the object table,
# shows the page list on the left (to x 1120) and each parameter as a row of
# label (from x 1140) and control (from x 1625), above the catalogue pane
# (y 1300). The device's context menu has
# no parameter entry: the first version of this flow matched another entry
# and restarted the device. Read by OCR, as the main window has no tree.
PARAM_PAGES = (680, 260, 1120, 1300)
PARAM_AREA = (1125, 260, 3300, 1300)


def open_device_parameters(ia: str) -> str:
    """Opens the parameter view of device `ia`: the device selected in the
    Topologie tree, then its 'Parameter' tab."""
    open_device_objects(ia)
    for _ in range(3):
        time.sleep(1.5)
        tab = find_text("Parameter", (680, 150, 1600, 220))
        if tab is None:
            raise RuntimeError("no 'Parameter' tab above the device's view")
        text = tab["text"]
        at = max(text.find("Parameter"), 0) + len("Parameter") // 2
        click(tab["x"] + tab["w"] * at // max(len(text), 1), tab["y"] + tab["h"] // 2)
        time.sleep(2)
        wait_busy()
        # The object table's header is gone once the parameter view shows.
        if not find_text("Objektfunktion", (680, 220, 3400, 260)):
            return "Parameter"
    raise RuntimeError("the 'Parameter' tab did not open")


def param_page_lines() -> list[dict]:
    return [l for l in ocr(PARAM_PAGES) if len(l["text"].strip()) > 1]


@flow("param_pages")
def flow_param_pages(req: dict) -> dict:
    """The pages of device `ia`'s parameter view, as ETS lists them."""
    require_project(req["project"])
    entry = open_device_parameters(req["ia"])
    return {"pages": [l["text"].strip() for l in param_page_lines()], "menu_entry": entry}


def _row_cells(label: dict, lines: list[dict]) -> list[dict]:
    """The OCR lines on the label's row right of it (the control's text)."""
    cy = label["y"] + label["h"] // 2
    return sorted((l for l in lines if abs(l["y"] + l["h"] // 2 - cy) < 18 and l["x"] > label["x"] + label["w"]),
                  key=lambda l: l["x"])


@flow("set_param")
def flow_set_param(req: dict) -> dict:
    """Sets the parameter labelled `text` to `value` (as ETS shows it) on the
    first page of `pages` that shows it. `kind` enum: the option of that name
    on the label's row (radio buttons), else the row's dropdown (a popup,
    UI Automation). `kind` int: the row's field, select all, type, Tab. The
    row is read again afterwards. A label on no page: {"set": false}."""
    require_project(req["project"])
    want, value = _norm(req["text"]), str(req["value"])
    seen: list[str] = []
    for page in req.get("pages") or [None]:
        if page is not None:
            hit = next((l for l in param_page_lines() if l["text"].strip() == page), None)
            if hit is None:
                continue
            click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
            time.sleep(1.5)
        lines = ocr(PARAM_AREA)
        label = next((l for l in lines if _norm(l["text"]) == want), None) \
            or next((l for l in lines if want and want in _norm(l["text"])), None)
        if label is None:
            seen += [l["text"] for l in lines[:6]]
            continue
        cells = _row_cells(label, lines)
        if not cells:
            raise RuntimeError(f"no control on the row of {req['text']!r} (page {page!r})")
        option = next((c for c in cells if _norm(c["text"]) == _norm(value)), None)
        if req.get("kind") == "enum" and option is not None and len(cells) > 1:
            click(option["x"] - 30, option["y"] + option["h"] // 2)  # the radio button left of its text
        elif req.get("kind") == "enum":
            cell = cells[0]
            click(cell["x"] + cell["w"] // 2, cell["y"] + cell["h"] // 2)
            time.sleep(1)
            choose(value, (cell["x"] - 50, cell["y"], cell["x"] + 1200, min(cell["y"] + 1400, 2484)))
        else:
            cell = cells[0]
            click(cell["x"] + cell["w"] // 2, cell["y"] + cell["h"] // 2)
            time.sleep(0.5)
            keys("^a")
            keys(value)
            keys("{TAB}")
        time.sleep(1.5)
        wait_busy()
        after = _row_cells(label, ocr(PARAM_AREA))
        shown = " ".join(c["text"] for c in after)
        return {"set": _norm(value) in _norm(shown), "page": page, "row": shown[:200]}
    return {"set": False, "seen": seen[:24]}


def _digits(t: str) -> str:
    # Noise before the first digit goes (OCR read MDT's '2.1' as 'h 2.1',
    # 2026-10-28); letters after it stay (a version such as '1.0a').
    return re.sub(r"[^0-9a-z]", "", re.sub(r"^[^0-9]+", "", t.lower()))


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
    """The catalog result rows as {y, name, order, application, version,
    online, manufacturer}, grouped from OCR lines by height. A manufacturer
    group header is not a row: its text becomes the `manufacturer` of the rows
    below it (#881); the first header sits just above the scanned area and is
    read from that band, else the rows above the first header get "".
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
    # The first group's header, just above the scanned rows (left column).
    band = [l for l in ocr((x0, y0 + dy, 1130, y0 + 40 + dy)) if l["y"] > y0 + dy + 5]
    manufacturer = " ".join(l["text"] for l in sorted(band, key=lambda l: l["x"])).strip()
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
            # A manufacturer group header: it names the rows below it.
            manufacturer = " ".join(c["text"] for c in sorted(r["cells"], key=lambda c: c["x"])).strip()
            continue
        out.append({"y": r["y"], "name": cell(1130, 1970), "order": cell(1970, 2240),
                    "application": cell(2300, 2560), "version": version, "online": row_is_online(r["y"]),
                    "manufacturer": manufacturer})
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
    shows it, e.g. "2.3"), and add it to line 1.1. Returns the device list.

    Every row carries its manufacturer group header (`manufacturer`). With
    `require_manufacturer` and `manufacturer` (the product file's
    manufacturer name) only rows under that manufacturer's group count, and
    among them those whose application cell matches `application` when any
    does (catalog_pick.file_rows, #881): a product of another manufacturer
    that shares the order number is never added; when every row is a
    stranger's the flow raises 'catalog manufacturer mismatch' with the rows
    seen."""
    require_project(req["project"])
    dismiss_password_dialog(req.get("project_password"))
    wait_busy()
    # ETS moves its splitters between jobs at times: put them back first.
    restore_tree_splitter()
    restore_catalog_splitter()
    before = {d["ia"] for d in flow_devices(req)["devices"]}
    dy = catalog_dy()
    sx, sy = LAYOUT["catalog_search"]
    def search(term: str) -> tuple[list[dict], list[dict]]:
        want = _canon(term)
        rows: list[dict] = []
        for attempt in range(4):
            type_search(term, dy)
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

    def pick(hits: list[dict], name: str = "") -> dict | None:
        if req.get("require_manufacturer"):
            hits = catalog_pick.file_rows(hits, req.get("manufacturer") or "", req.get("application") or "")
        # Imported products first: an online-catalog row would make ETS fetch
        # product data from the internet instead of our corpus file. ETS shows
        # an imported product that also sits in its online catalog at the same
        # version as one online row (MDT SCN-BWM55 4.4, 2026-10-29): take that
        # row when no local one exists and order number and version match.
        local = [r for r in hits if not r.get("online")]
        if not local:
            same = [r for r in hits if _canon(r["order"]) == order and want_version
                    and _digits(r["version"]) == want_version]
            if len(same) == 1:
                return same[0]
        hits = local
        # The order number exactly (ZPR1612 is not ZPR1612V2), else a prefix.
        exact = [r for r in hits if _canon(r["order"]) == order] or [r for r in hits if _canon(r["order"]).startswith(order)]
        if not exact and name:
            # A search by product name whose order cell OCR left empty
            # (ALLinBOX 88 v2, 2026-10-28): the exact name stands in for it.
            exact = [r for r in hits if not r["order"].strip() and _canon(r["name"]) == _canon(name)]
        if len(exact) == 1:
            # The sweep imports one product file at a time, so the only local
            # row with this order number is the product: its version cell
            # (often truncated or noisy in OCR) is not checked.
            return exact[0]
        match = [r for r in exact if want_version and _digits(r["version"]) == want_version]
        if match:
            return match[0]
        return None

    rows, hits = search(search_term(req["search"]))
    row = pick(hits)
    if row is None and req.get("fallback_search"):
        # ETS's search by order number shows only some versions of a product
        # family at times (ZPR1612 listed only the v2 product); the product
        # name lists them all.
        rows, more = search(req["fallback_search"])
        hits = hits + more
        row = pick(more, req["fallback_search"])
    if row is None:
        if hits:
            raise RuntimeError(f"catalog version mismatch: {req['search']!r} shows {[(r['order'], r['version'], 'online' if r.get('online') else 'local') for r in hits][:8]}, wanted {req.get('version')!r}")
        raise RuntimeError(f"not found in catalog search: {req['search']!r}; rows {rows[:4]}")
    click(1300, row["y"])
    time.sleep(1)
    # The add bar, its line dropdown, the count and Hinzufügen sit at the
    # window's bottom edge: only the panel's top moves with its splitter
    # (Import at y 971 instead of 1354 after ETS restored another layout,
    # 2026-11-05), so they take no `dy`.
    bar = LAYOUT["catalog_bar"]
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        # The add bar's target line follows the tree selection: select the
        # line, then the catalog row again.
        click(*line_1_1())
        time.sleep(1.5)
        click(1300, row["y"])
        time.sleep(1)
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        lx, ly = LAYOUT["catalog_line_dropdown"]
        click(lx, ly)
        time.sleep(1)
        choose("1.1 TP Linie", (600, 1600, 1300, 2484))
        time.sleep(0.8)
    if not find_text("1.1 TP Linie", bar, min_ratio=0.75):
        raise RuntimeError(f"the add bar does not target 1.1 TP Linie: {[l['text'] for l in ocr(bar)]}")
    # The 'Elemente' count left of the add bar must be 1; an interrupted
    # flow once left it empty (marked red), and Hinzufügen then adds nothing.
    count = (130, LAYOUT["catalog_add"][1] - 25, 300, LAYOUT["catalog_add"][1] + 25)
    if not any(l["text"].strip() == "1" for l in ocr(count, zoom=3)):
        click(200, LAYOUT["catalog_add"][1])
        time.sleep(0.3)
        keys("^a")
        keys("1{TAB}")
        time.sleep(0.5)
    ax, ay = LAYOUT["catalog_add"]
    click(ax, ay)
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
        if dismiss_password_dialog(req.get("project_password")):
            password_dialog = True
            break
        time.sleep(1)
    # With the project password set, ETS asks for the device certificate
    # right away ('Gerätezertifikat hinzufügen', ETS 6.4.1, 2026-11-04).
    certificate = False
    if req.get("certificate"):
        t0 = time.time()
        while time.time() - t0 < float(req.get("certificate_wait", 10)) and not certificate:
            certificate = enter_certificate(req["certificate"])
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
        if dismiss_password_dialog(req.get("project_password")):
            password_dialog = True
        # ETS asks for compatibility mode for some old products only once the
        # add has run for a while (ABB A-A033, 2026-10-28); the next job then
        # met the prompt and was charged with it.
        compat = decline_compat_mode()
        if compat:
            raise CompatModeRequired(f"ETS asked for compatibility mode on adding: {compat[:200]}")
        time.sleep(2)
    return {"devices": after, "added": new, "row": row, "password_dialog": password_dialog,
            "certificate": certificate}


@flow("delete_device")
def flow_delete_device(req: dict) -> dict:
    require_project(req["project"])
    devs = flow_devices(req)["devices"]
    hit = [d for d in devs if d["ia"] == req["ia"]]
    if not hit:
        return {"deleted": False, "devices": devs}
    # ETS deletes without asking now, and a Delete key acts on whatever holds
    # the selection: it removed line 1.1 and area 1 (2026-10-28). The device
    # is deleted through its own row's context menu instead, and only when
    # that row shows the address and is highlighted, and the menu is a
    # device's menu.
    from pywinauto import mouse

    y = hit[0]["y"]
    click(1000, y)
    time.sleep(0.8)
    # Three readings of the same row, any of which may show the address: OCR
    # read a secure device's shield icon into it from x 680 ('06M.1.1' for
    # 1.1.1, Theben SM 4) and dropped it from x 750 ('JU 1 secure' only),
    # 2026-11-05; the address column alone, magnified, read it both times.
    band = " ".join(l["text"] for crop, zoom in (((680, y - 20, 1700, y + 20), 2),
                                                 ((750, y - 20, 1700, y + 20), 2),
                                                 ((750, y - 20, 1000, y + 20), 3))
                    for l in ocr(crop, zoom=zoom))
    # OCR reads the address's ones as 'l' at times ('l.l.l', 2026-11-04).
    band = " ".join(t.translate(str.maketrans("lI|", "111")) if re.fullmatch(r"[\dlI|]+\.[\dlI|]+\.[\dlI|-]+", t) else t
                    for t in band.split())
    if not re.search(rf"(?<![\d.]){re.escape(req['ia'])}(?![\d.])", band):
        raise RuntimeError(f"delete: the row at y={y} reads {band[:80]!r}, not device {req['ia']}")
    # Selected reads blue (219, 234, 255) once the pointer is off the row; a
    # hovered row is grey and an unselected one white.
    s_ = scale()
    mouse.move(coords=(int(2600 * s_), int(1200 * s_)))
    time.sleep(0.4)
    # The background is the most common light colour along the row: one
    # sample point hit blue link text (82, 129, 190) of a long product name.
    from collections import Counter

    strip = grab((700, y - 2, 3200, y + 2)).convert("RGB")
    light = [p for p in strip.getdata() if min(p) > 180]
    r, g, b = Counter(light).most_common(1)[0][0] if light else (0, 0, 0)
    if not (b > r + 20 and b > 230):
        raise RuntimeError(f"delete: the row of {req['ia']} is not highlighted (rgb {r},{g},{b})")
    # The menu's entries come from UI Automation, or, when UIA shows none
    # (after an ETS restart the popup opened but listed nothing, 2026-10-29),
    # from OCR of the menu that opens right of and below the pointer.
    items: list[str] = []
    lines: list[dict] = []
    for _ in range(3):
        mouse.right_click(coords=(int(1000 * s_), int(y * s_)))
        time.sleep(1.2)
        items = menu_items()
        if items:
            break
        lines = ocr((1000, y, 1800, y + 1300))
        items = [re.sub(r"^\W*[XO]?\s+", "", l["text"]).strip() for l in lines]
        if items:
            break
        time.sleep(2)
    # A device's menu offers 'Gerät neu starten'; a line's or area's does not.
    if "Gerät neu starten" not in items or "Löschen" not in items:
        keys("{ESC}")
        raise RuntimeError(f"delete: unexpected context menu for {req['ia']}: {items[:12]}")
    if lines:
        hit = next(l for l in lines if l["text"].strip().endswith("Löschen") and l["x"] < 1300)
        click(1100, hit["y"] + hit["h"] // 2)
    else:
        menu_click("Löschen")
    # The confirmation comes later for a larger product (over 2 s for an MDT
    # room actuator): wait for it, confirm, and check the device is gone.
    t0 = time.time()
    confirmed = False
    # A large product shows the confirmation late: once after 10 s, so the
    # dialog stayed open and blocked the next imports (2026-11-06).
    while time.time() - t0 < float(req.get("confirm_wait", 30)):
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
                click_button("Ja", LAYOUT["delete_yes"])
                confirmed = True
            else:
                click_button("Nein", (1300, 1380, 2800, 1580))
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


# The device's 'Kommunikationsobjekte' table (layout x ranges, measured
# 2026-10-28 on the Ekinex EK-E72): number, name, linked addresses, flags.
GO_TABLE = (680, 260, 3400, 1240)
GO_COLS = {"number": (690, 830), "name": (830, 1280), "ga": (1840, 2000), "flags": (2090, 2300)}
GA_RE = re.compile(r"\d{1,2}/\d{1,2}/\d{1,3}")
# Centres of the K, L, S, Ü, A flag columns.
GO_FLAG_X = (2120, 2159, 2200, 2241, 2280)


def open_device_objects(ia: str) -> None:
    """Select device `ia` in the Topologie tree and show its object table."""
    click(*line_1_1())
    time.sleep(1)
    # The node reads '> 1.1.1 <product>' (its expander arrow first).
    tree = [l for l in ocr(LAYOUT["tree"]) if re.match(rf"^\W*{re.escape(ia)}\b", l["text"].strip())]
    if not tree:
        raise RuntimeError(f"device {ia} not in the Topologie tree")
    t = tree[0]
    click(t["x"] + t["w"] // 2, t["y"] + t["h"] // 2)
    # OCR joins the tab strip into one line ('Kanäle 5 Kommunikationsobjekte 22');
    # it takes a few seconds to switch from the line's tabs.
    t0, tabs = time.time(), ""
    while time.time() - t0 < 8 and "Kommunikationsobjekte" not in tabs:
        time.sleep(1)
        tabs = " ".join(l["text"] for l in ocr((680, 150, 1600, 220)))
    if "Kommunikationsobjekte" not in tabs:
        raise RuntimeError(f"the object table did not open: {tabs!r}")
    # The tab where OCR reads it: its place moves with the tabs before it (a
    # device without channels has no 'Kanäle' tab, and 1090 then hits the
    # 'Parameter' tab; syn-minimal, 2026-10-31).
    tab = find_text("Kommunikationsobjekte", (680, 150, 1600, 220))
    if tab is not None:
        # OCR may join the strip into one line ('Kanäle 5 Kommunikationsobjekte
        # 22'): aim at the word by its share of the line's characters.
        text = tab["text"]
        at = max(text.find("Kommunikation"), 0) + len("Kommunikation") // 2
        click(tab["x"] + tab["w"] * at // max(len(text), 1), tab["y"] + tab["h"] // 2)
    else:
        click(1090, 188)
    time.sleep(1)


def read_objects(numbers: list[int] | None = None) -> list[dict]:
    """Rows of the open object table: number, name, addresses, flags.

    `numbers`, the object numbers the caller knows the table lists in order
    (a synthetic product's com objects): when OCR reads no number at all and
    the table has exactly that many rows, the rows take them in order. Windows
    OCR reads neither a lone '0' nor a lone '1' (syn-minimal, 2026-10-31)."""
    lines = ocr(GO_TABLE)
    rows: dict[int, dict] = {}
    # Numbers magnified: a lone '1' in a selected row went unread.
    for l in ocr((GO_COLS["number"][0], GO_TABLE[1], GO_COLS["number"][1], GO_TABLE[3]), zoom=2):
        cy = l["y"] + l["h"] // 2
        if l["text"].strip().isdigit():
            rows[cy] = {"number": int(l["text"].strip()), "y": cy, "name": "", "gas": [], "flags": ""}
    # Rows whose number OCR missed: Windows OCR never reads a lone '1'
    # (2026-10-28, any zoom or crop). Infer it from the neighbours when only
    # one number fits, else take a single narrow glyph as '1'.
    for l in lines:
        cy = l["y"] + l["h"] // 2
        if GO_COLS["name"][0] <= l["x"] + 4 < GO_COLS["name"][1] and all(abs(y - cy) >= 14 for y in rows):
            rows[cy] = {"number": None, "y": cy, "name": "", "gas": [], "flags": ""}
    ordered = sorted(rows.values(), key=lambda r: r["y"])
    if numbers and all(r["number"] is None for r in ordered) and len(ordered) == len(numbers):
        for r, n in zip(ordered, numbers):
            r["number"] = int(n)
    for i, r in enumerate(ordered):
        if r["number"] is not None:
            continue
        prev = next((o["number"] for o in reversed(ordered[:i]) if o["number"] is not None), None)
        nxt = next((o["number"] for o in ordered[i + 1:] if o["number"] is not None), None)
        if prev is not None and nxt is not None and nxt - prev == 2:
            r["number"] = prev + 1
            continue
        img = grab((722, r["y"] - 16, 830, r["y"] + 16)).convert("L")
        cols = [x for x in range(img.width) if any(img.getpixel((x, y)) < 150 for y in range(img.height))]
        if cols and cols[-1] - cols[0] <= img.height // 3 and (nxt is None or nxt > 1) and (prev is None or prev < 1):
            r["number"] = 1
    rows = {cy: r for cy, r in rows.items() if r["number"] is not None}

    def row_at(cy: int) -> dict | None:
        best = min(rows, key=lambda y: abs(y - cy), default=None)
        return rows[best] if best is not None and abs(best - cy) < 14 else None
    for l in lines:
        cx, cy = l["x"] + 4, l["y"] + l["h"] // 2
        r = row_at(cy)
        if not r:
            continue
        if GO_COLS["name"][0] <= cx < GO_COLS["name"][1]:
            r["name"] = (r["name"] + " " + l["text"]).strip()
        for ga in GA_RE.findall(l["text"]):
            if cx >= GO_COLS["ga"][0] - 400 and ga not in r["gas"]:
                r["gas"].append(ga)
    # The address column magnified as well: '1/0/4' next to a link went
    # unread in the plain pass (EK-E72 object 27, 2026-10-28).
    for l in ocr((GO_COLS["ga"][0], GO_TABLE[1], GO_COLS["ga"][1] + 10, GO_TABLE[3]), zoom=3):
        r = row_at(l["y"] + l["h"] // 2)
        if r:
            for ga in GA_RE.findall(l["text"].replace(" ", "")):
                if ga not in r["gas"]:
                    r["gas"].append(ga)
    # Flags by ink, not OCR (single letters next to '-' read badly): a cell
    # holds 28+ dark pixels with its letter, 10-12 with the dash (EK-E72,
    # 2026-10-28).
    for r in rows.values():
        flags = ""
        for letter, xc in zip("KLSÜA", GO_FLAG_X):
            img = grab((xc - 14, r["y"] - 14, xc + 14, r["y"] + 14)).convert("L")
            if sum(1 for p in img.getdata() if p < 120) > 20:
                flags += letter
        r["flags"] = flags
    return sorted(rows.values(), key=lambda r: r["y"])


@flow("objects")
def flow_objects(req: dict) -> dict:
    """The object table of device `ia`: number, name, linked group
    addresses and the flags ETS shows (K L S Ü A)."""
    require_project(req["project"])
    open_device_objects(req["ia"])
    return {"objects": read_objects(req.get("numbers"))}


def _object_row(number: int, numbers: list[int] | None = None) -> dict:
    rows = read_objects(numbers)
    hit = [r for r in rows if r["number"] == number]
    if not hit:
        raise RuntimeError(f"object {number} not in the table (hidden by a parameter?): {[r['number'] for r in rows]}")
    return hit[0]


@flow("link")
def flow_link(req: dict) -> dict:
    """Link object `number` of device `ia` to group address `ga` ('1/0/9'):
    the object's context menu 'Verbinden mit...', the address typed into
    the dialog's field, 'Erstellen & Verbinden' (ETS creates the address
    when the project lacks it) or 'Verbinden'. Verified in the table."""
    require_project(req["project"])
    from pywinauto import mouse

    open_device_objects(req["ia"])
    row = _object_row(int(req["number"]), req.get("numbers"))
    if req["ga"] in row["gas"]:
        return {"linked": True, "already": True, "row": row}
    s = scale()
    mouse.right_click(coords=(int(1000 * s), int(row["y"] * s)))
    time.sleep(1.2)
    menu_click("Verbinden mit...")
    # The dialog can take several seconds to open (syn-minimal, 2026-10-31).
    t0 = time.time()
    while not find_text("Mit Gruppenadresse verbinden", (1500, 560, 2600, 680)):
        if time.time() - t0 > 12:
            raise RuntimeError("the link dialog did not open")
        time.sleep(1)
    click(1720, 1718)  # the address field left of 'Neue Gruppenadresse'
    time.sleep(0.3)
    keys("^a")
    keys(req["ga"])
    time.sleep(1.2)
    # The button reads 'Erstellen & Verbinden' for a new address and
    # 'Verbinden' for an existing one; OCR prefixes its link icon ('00').
    buttons = [l for l in ocr((1800, 1830, 2300, 1910)) if "Verbinden" in l["text"]]
    if not buttons:
        raise RuntimeError("no 'Verbinden' button in the link dialog")
    b = buttons[0]
    # The first click after typing only commits the field at times (the
    # dialog stayed open, 2026-10-28): click until the dialog closes.
    for _ in range(3):
        click(b["x"] + b["w"] - 60, b["y"] + b["h"] // 2)
        time.sleep(2)
        if not find_text("Mit Gruppenadresse verbinden", (1500, 560, 2600, 680)):
            break
    else:
        raise RuntimeError("the link dialog did not close")
    time.sleep(1)
    # An address the project already holds with another object size: ETS asks
    # whether to take the object's datatype for it ('... abweichende
    # Objektgröße ...', syn-minimal, 2026-10-31). OK takes it.
    if find_text("abweichende Objektgröße", (1260, 1100, 2850, 1260), min_ratio=0.7):
        click_text("OK", (2450, 1410, 2700, 1500))
        time.sleep(1.5)
    row = _object_row(int(req["number"]), req.get("numbers"))
    if req["ga"] not in row["gas"]:
        # OCR reads nothing on the selected row (blue text): click below the
        # rows to clear the selection and read again (syn-minimal, 2026-10-31).
        click(1500, GO_TABLE[3] - 20)
        time.sleep(1)
        row = _object_row(int(req["number"]), req.get("numbers"))
    if req["ga"] not in row["gas"]:
        raise RuntimeError(f"object {req['number']} shows {row['gas']} after linking {req['ga']}")
    return {"linked": True, "row": row}


@flow("unlink")
def flow_unlink(req: dict) -> dict:
    """Remove the link of object `number` of device `ia` to `ga` (context
    menu 'Trennen'). Verified in the table."""
    require_project(req["project"])
    from pywinauto import mouse

    open_device_objects(req["ia"])
    row = _object_row(int(req["number"]), req.get("numbers"))
    if req["ga"] not in row["gas"]:
        return {"unlinked": True, "already": True, "row": row}
    s = scale()
    mouse.right_click(coords=(int(1000 * s), int(row["y"] * s)))
    time.sleep(1.2)
    menu_click("Trennen")
    time.sleep(2)
    row = _object_row(int(req["number"]), req.get("numbers"))
    if req["ga"] in row["gas"]:
        raise RuntimeError(f"object {req['number']} still shows {req['ga']}: {row}")
    return {"unlinked": True, "row": row}


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
    certificate = False
    while time.time() - t0 < float(req.get("dialog_wait", 20)):
        if find_text("Schnittstellen-Prüfung", LAYOUT["medium_dialog"]):
            click(*LAYOUT["medium_keep"])
            kept = True
            break
        if dismiss_password_dialog(req.get("project_password")):
            password = True
        if req.get("certificate") and enter_certificate(req["certificate"]):
            certificate = True
        compat = decline_compat_mode()
        if compat:
            raise CompatModeRequired(f"ETS asked for compatibility mode on download: {compat[:200]}")
        time.sleep(1)
    return {"ia": req["ia"], "mode": req.get("mode", "application"), "medium_dialog_kept": kept, "password_dialog": password,
            "certificate_dialog": certificate}


@flow("history")
def flow_history(req: dict) -> dict:
    """The text of the 'Laufende Operationen' history pane (expanded if needed).
    The pane belongs to the active tab: a call without `project` let the
    watchdog switch to ets-sweep, and the secure run read that project's
    'Abgeschlossen' for its own failed download (2026-11-04)."""
    if req.get("project"):
        require_project(req["project"])
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
    # The dialog grows with its text: its OK sat at y=1226 once and y=1460
    # another time (2026-10-29), so look for it in the whole lower half.
    oks = [l for l in ocr((1300, 1100, 2800, 1700)) if l["text"].strip() == "OK"]
    if oks:
        ok = oks[0]
        click(ok["x"] + ok["w"] // 2, ok["y"] + ok["h"] // 2)
    else:
        click(2600, 1226)
    time.sleep(1.5)
    return joined[:400]


def finish_language_dialog() -> bool:
    """Answer a 'Produktsprache(n) auswählen' dialog an import left open (it
    blocked every click and every later product failed, 2026-10-29): import
    all languages and wait for that import to end."""
    if not find_text("Produktsprache", (1700, 950, 2600, 1060), min_ratio=0.7):
        return False
    click_text("Alle Sprachen importieren", (1900, 1490, 2400, 1560))
    t0 = time.time()
    while time.time() - t0 < 900:
        time.sleep(5)
        text = " ".join(l["text"] for l in ocr((1500, 850, 2700, 1600)))
        if not re.search(r"Konvertiere|Importiere|Signiere|Analysiere", text):
            break
    dismiss_ets_error()
    return True


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
    for moved in (restore_tree_splitter(), restore_catalog_splitter()):
        if moved:
            did.append(moved)
    return {"did": did, "import_button": bool(catalog_import_button()), "catalog_dy": catalog_dy()}


def restore_tree_splitter() -> str | None:
    """Drag the splitter between the Topologie tree and the centre view back
    to x 680, where LAYOUT's centre view starts: the device list's header
    ('Sic Adresse Raum') begins at x 735 then. It moved 37 px right once and
    the device selection clicked the search folder instead, so the download
    menu was empty for eight jobs (2026-11-06)."""
    from pywinauto import mouse

    head = next((l for l in ocr((600, 220, 1000, 262)) if l["text"].startswith("Sic")), None)
    if not head or abs(head["x"] - 735) <= 10:
        return None
    s_ = scale()
    x0, x1, y = 680 + head["x"] - 735, 680, 1000
    mouse.press(coords=(int(x0 * s_), int(y * s_)))
    time.sleep(0.3)
    for k in range(1, 6):
        mouse.move(coords=(int((x0 + (x1 - x0) * k / 5) * s_), int(y * s_)))
        time.sleep(0.05)
    mouse.release(coords=(int(x1 * s_), int(y * s_)))
    time.sleep(1.5)
    return f"tree splitter {x0} -> {x1}"


def restore_catalog_splitter() -> str | None:
    """Drag the splitter between the Topologie and Katalog panels back to the
    layout LAYOUT was measured in (Import at y 1354). ETS restores other
    positions after a restart: Import at 971 (2026-11-05) and at 467, where
    the Topologie tree showed no line 1.1 and eight jobs failed (2026-11-06).
    The splitter's grip sits 48 px above the Import button."""
    from pywinauto import mouse

    btn = catalog_import_button()
    if not btn or abs(btn["y"] - 1354) <= 50:
        return None
    s_ = scale()
    y0, y1 = btn["y"] - 48, 1354 - 48
    mouse.press(coords=(int(1703 * s_), int(y0 * s_)))
    time.sleep(0.3)
    for k in range(1, 11):
        mouse.move(coords=(int(1703 * s_), int((y0 + (y1 - y0) * k / 10) * s_)))
        time.sleep(0.05)
    mouse.release(coords=(int(1703 * s_), int(y1 * s_)))
    time.sleep(2)
    after = catalog_import_button()
    return f"catalog splitter {btn['y']} -> {after['y'] if after else None}"


def catalog_import_button() -> dict | None:
    """The Katalog panel's Import button wherever the panel sits."""
    # The first word: OCR joins an enabled 'Herunterladen' next to it into one
    # line ('Import Herunterladen', 2026-10-28).
    # The first two words: the panel's close icon left of the button joins the
    # line as 'X Import' (31 imports in a row refused, 2026-11-08 04:06).
    hits = [l for l in ocr((680, 200, 1100, 2440))
            if any(_norm(w) in ("import", "impart", "imp0rt") for w in l["text"].split()[:2])]
    if not hits:
        return None
    hit = dict(min(hits, key=lambda l: abs(l["y"] - 1354)))
    # Where to click: three characters into the word Import, wherever it sits
    # in the line ('X Import' put x + 40 on the close icon's gap, and five
    # imports in a row opened no file dialog, 2026-11-08 04:40).
    words = hit["text"].split()
    i = next(k for k, w in enumerate(words) if _norm(w) in ("import", "impart", "imp0rt"))
    before = len(" ".join(words[:i])) + (1 if i else 0)
    cw = hit["w"] / max(len(hit["text"]), 1)
    hit["click_x"] = hit["x"] + int((before + 3) * cw)
    return hit


def type_search(term: str, dy: int) -> None:
    """Type `term` into the Katalog search box and run the search, with no
    Delete key at all: a Delete that reached the Topologie tree removed line
    1.1 twice (ETS asks no confirmation; 2026-10-28). Ctrl+A and the typed
    term replace the old text; the trailing space stops ETS's autocompletion
    (ZPR1612 -> ZPR1612V3), which the search ignores. Letters typed
    elsewhere do no harm."""
    sx, sy = LAYOUT["catalog_search"]
    click(sx, sy + dy)
    time.sleep(0.3)
    keys("^a")
    keys(term + " ")
    time.sleep(0.3)
    keys("{ENTER}")


def expand_catalog_tree() -> bool:
    """Expand the Katalog panel's manufacturer tree when ETS collapsed it to
    a sidebar: every catalog column then sits ~600 px further left and the
    row reader finds nothing (seven ABB products read as 'not in catalog',
    2026-10-28). The collapsed panel shows its Import button near x=140."""
    hits = [l for l in ocr((0, 200, 680, 2440))
            if l["text"].split() and _norm(l["text"].split()[0]) in ("import", "impart", "imp0rt")]
    if not hits:
        return False
    click(25, hits[0]["y"] + 2)  # the '>' expander at the panel's left edge
    time.sleep(2)
    return True


def catalog_dy() -> int:
    """Vertical offset of the Katalog panel from the layout LAYOUT was
    measured in (Import button at y=1354): ETS reopens panels with other
    splitter positions after a restart."""
    btn = catalog_import_button()
    if not btn and expand_catalog_tree():
        btn = catalog_import_button()
    return btn["y"] - 1354 if btn else 0


PRODUCT_STORE = Path(r"C:\ProgramData\KNX\ETS6\ProductStore")


def ets_running() -> bool:
    import subprocess

    # Bytes: tasklist's console code page made the decoded output None once.
    out = subprocess.run(["tasklist", "/fi", "imagename eq ETS6N.exe"], capture_output=True).stdout or b""
    return b"ETS6N.exe" in out


@flow("reset_catalog")
def flow_reset_catalog(req: dict) -> dict:
    """Close ETS, clear its product store, start it again on the sweep
    project. Faster than removing every imported product from the catalog
    one row at a time; the sweep calls it every few hundred products. The
    manufacturer folders are moved aside (to ProductStore-cleared-<time>)
    and deleted afterwards, the store's version file stays. Every project
    tab ETS had open is closed with it; ETS saves projects as it goes."""
    import shutil
    import subprocess

    did: list[str] = []
    if ets_running():
        ets_main_window().close()
        did.append("closed ETS")
    t0 = time.time()
    while ets_running() and time.time() - t0 < 120:
        time.sleep(2)
    if ets_running():
        subprocess.run(["taskkill", "/f", "/im", "ETS6N.exe"], capture_output=True)
        subprocess.run(["taskkill", "/f", "/im", "ETS6.exe"], capture_output=True)
        time.sleep(5)
        did.append("killed ETS after 120 s")
    aside = PRODUCT_STORE.with_name(f"ProductStore-cleared-{time.strftime('%Y%m%d-%H%M%S')}")
    aside.mkdir()
    moved = []
    for d in PRODUCT_STORE.iterdir():
        if d.is_dir() and d.name.startswith("M-"):
            shutil.move(str(d), str(aside / d.name))
            moved.append(d.name)
    did.append(f"cleared {len(moved)} manufacturers")
    if req.get("delete", True):
        shutil.rmtree(aside, ignore_errors=True)
    did += ensure_ets_running(req.get("project", "ets-sweep"))
    return {"did": did, "manufacturers": moved}


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
    # A file dialog a failed import left open (a COMError right after it
    # opened, 2026-11-05) covers the Import button: every later import failed.
    for w in ets_popups():
        try:
            if w.window_text() != "Produktdatei öffnen":
                continue
            for b in w.descendants(control_type="Button"):
                if b.window_text() == "Abbrechen":
                    b.click_input()
                    time.sleep(1.5)
                    break
        except Exception:  # noqa: BLE001 - a closing popup is gone already
            pass
    # Removing a large product (ALLinBOX 1612) keeps ETS busy after the remove
    # flow returned; three imports in a row found no button (2026-10-28).
    wait_busy()
    t_btn = time.time()
    while not catalog_import_button() and time.time() - t_btn < 30:
        time.sleep(2)
        wait_busy()
    if not catalog_import_button():
        expand_catalog_tree()
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
            click(btn["click_x"], btn["y"] + btn["h"] // 2)  # the word Import, not a joined neighbour
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
    type_search(req["term"], dy)
    time.sleep(float(req.get("wait", 3)))
    click(1000, 1380 + dy)  # closes the search-history dropdown
    time.sleep(0.5)
    x0, y0, x1, y1 = LAYOUT["catalog_rows"]
    y0, y1 = y0 + dy, min(y1 + dy, 2440)
    rows = []
    for line in ocr((x0, y0 + 40, x1, y1), zoom=2):
        rows.append({"text": line["text"], "x": line["x"], "y": line["y"]})
    return {"term": req["term"], "rows": rows}


def catalog_search_rows(term: str) -> list[dict]:
    """Type `term` into the catalog search and return the rows of that search."""
    dy = catalog_dy()
    sx, sy = LAYOUT["catalog_search"]
    want = _canon(term)
    rows: list[dict] = []
    for attempt in range(3):
        type_search(term, dy)
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
        global IN_FLIGHT
        with IN_FLIGHT_LOCK:
            IN_FLIGHT += 1
        try:
            self._do_post()
        finally:
            with IN_FLIGHT_LOCK:
                IN_FLIGHT -= 1

    def _do_post(self) -> None:
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
                if name == "reset_catalog":
                    # Closes and starts ETS itself; nothing to guard yet.
                    out = fn(req)
                    out.setdefault("ok", True)
                    self._send(200, out)
                    return
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
                watchdog = {"language_dialog": finish_language_dialog(),
                            "password_dialog": dismiss_password_dialog(req.get("project_password")), "ets_error": dismiss_ets_error(),
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


# Requests being served: an upload restarts the driver only between flows,
# so a running sweep loses no flow to it.
IN_FLIGHT = 0
IN_FLIGHT_LOCK = threading.Lock()


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
            t_idle = time.time()
            while IN_FLIGHT and time.time() - t_idle < 1800:
                time.sleep(0.5)
            # Not os.execv: on Windows it joins argv without quoting, so the space
            # in "C:\Program Files\Python312" killed the first attempt (2026-10-26).
            log("source changed, restarting")
            import subprocess

            # Spawn first, then stop serving. srv.shutdown() returns once
            # serve_forever() in the main thread has ended; main() then returns
            # and the interpreter kills this daemon thread, so a Popen placed
            # after the shutdown never ran and no driver was left (2026-11-07
            # 16:33 with server_close() first, 2026-11-08 04:09 and 08:43 with
            # shutdown() first). The replacement retries the bind for 30 s
            # while this process still holds the port.
            subprocess.Popen(
                [sys.executable, str(me)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
            log("replacement spawned")
            srv.shutdown()
            srv.server_close()
            log("old driver exiting")
            os._exit(0)


def main() -> None:
    log(f"driver starting pid={os.getpid()} session={os.environ.get('SESSIONNAME')} user={os.environ.get('USERNAME')}")
    if not TOKEN_FILE.exists():
        TOKEN_FILE.write_text(base64.b16encode(os.urandom(16)).decode())
    # The predecessor may still hold the port for a moment after its
    # shutdown: retry the bind.
    for attempt in range(30):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
            break
        except OSError as exc:
            if attempt == 29:
                log(f"cannot bind 127.0.0.1:{PORT}: {exc!r}")
                raise
            time.sleep(1)
    srv.daemon_threads = True

    threading.Thread(target=_reload_watch, args=(srv,), daemon=True).start()
    log(f"listening on 127.0.0.1:{PORT}")
    srv.serve_forever()
    # serve_forever() ends only when the reload watcher shut the server down;
    # give that thread time to finish its log line and exit the process itself.
    time.sleep(30)


if __name__ == "__main__":
    main()
