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

if __name__ == "__main__":
    # The running driver logs to driver.log; the offline tests import the
    # module for its pure helpers and keep their own output.
    sys.stdout = open(LOG, "a", buffering=1, encoding="utf-8")  # noqa: SIM115 (long-lived)
    sys.stderr = sys.stdout


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# What a request cost on the screen, logged with its time (`/ets/link 9.1s
# clicks=4 ocr=12`): the measure of the link flow's speed (#478).
COUNTS = {"clicks": 0, "ocr": 0}


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
        # Which process answers: `vm.py install` waits for another pid
        # than the one that answered before the upload.
        "pid": os.getpid(),
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
    COUNTS["ocr"] += 1
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
            COUNTS["clicks"] += 1
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


def menu_click(item_title: str, timeout: float = 5.0, settle: float = 0.5) -> None:
    """Click a MenuItem by title in an open popup (UIA works there), then
    wait `settle` seconds (0 when the caller polls for what comes next)."""
    menu_item(item_title, timeout).click_input()
    COUNTS["clicks"] += 1
    time.sleep(settle)


def wait_for(name: str, cond, timeout: float, interval: float = 0.2):
    """Poll `cond()` until it returns something truthy or `timeout` seconds
    passed; returns its last value. Every wait is logged with its duration
    (`wait <name> 0.84s ok`), the measure the link path's pauses were cut by
    (#478)."""
    t0 = time.time()
    while True:
        value = cond()
        if value or time.time() - t0 >= timeout:
            log(f"wait {name} {time.time() - t0:.2f}s {'ok' if value else 'timeout'}")
            return value
        time.sleep(interval)


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


def _icon_word(w: str) -> bool:
    """A button's icon as OCR reads it: a check mark or cross ('√', 'v',
    'V', 'X', '✓'), at most two characters and no digit."""
    return len(w) <= 2 and not any(ch.isdigit() for ch in w)


def button_hits(lines: list[dict], label: str) -> list[dict]:
    """Every OCR line `button_hit` would take for `label`, in line order."""
    out = []
    for l in lines:
        hit = button_hit([l], label)
        if hit:
            out.append(hit)
    return out


def button_hit(lines: list[dict], label: str) -> dict | None:
    """The OCR line of the button `label` and where to click it: the label is
    a whole word of a short line (at most five words), after icon words
    or the other button. The check mark in
    front of 'Ja' reads as '√ Ja', 'v Ja' or 'V Ja' (2026-11-08, #997), the
    way the Katalog panel's close icon joins 'X Import' (#968). OCR also joins
    the two buttons of the delete confirmation into one line ('√ Ja X Nein',
    2026-11-09: 'Ja' was never the last word, 'Nein' always was, and every
    delete ended "not on screen; dialog closed with Nein"), so the label may
    be followed by more words. Exact, not fuzzy: a wide search strip also
    holds other text, and the fuzzy match took 'Secure, Schalter/Jalousie
    8-fach' for 'Ja' (2026-11-06). The hit carries `click_x`, `click_y`: the
    middle of the word, not of the icon."""
    for l in lines:
        words = l["text"].split()
        for i, w in enumerate(words):
            glued = w != label and re.fullmatch(rf"\W{{1,2}}{re.escape(label)}", w) is not None
            if w != label and not glued:
                continue
            # A short line only (both buttons and their icons make five
            # words); the words before the label are icons or the other button.
            if len(words) > 5 or not all(_icon_word(x) or x in ("Ja", "Nein") for x in words[:i]):
                break
            # The label's characters: the words before it, their spaces, and
            # the glued icon, measured at the line's mean character width.
            before = len(" ".join(words[:i])) + (1 if i else 0) + (len(w) - len(label) if glued else 0)
            cw = l["w"] / max(len(l["text"].strip()), 1)
            return {**l, "click_x": l["x"] + int((before + len(label) / 2) * cw), "click_y": l["y"] + l["h"] // 2}
    return None


def click_button(label: str, bbox: tuple[int, int, int, int]) -> None:
    """Clicks the button `label` (see `button_hit`) inside the word."""
    lines = ocr(bbox)
    hit = button_hit(lines, label)
    if not hit:
        # What OCR read, so a miss can be diagnosed from the row's error
        # (every delete of 2026-11-09 missed 'Ja' and no log said why).
        seen = [(l["text"], l["x"], l["y"]) for l in lines][:12]
        raise RuntimeError(f"button {label!r} not on screen in {bbox}; OCR read {seen}")
    click(hit["click_x"], hit["click_y"])


def leftover_delete_dialog(lines: list[dict]) -> dict | None:
    """The 'Nein' button of an open delete confirmation ('Löschen' title,
    'Ja' and 'Nein'), from OCR lines of LAYOUT['delete_dialog']. ETS's dialog
    is no UIA popup (`ets_popups()` lists nothing), so only OCR finds it; a
    missed 'Ja' left it open and every import after it failed (2026-11-08,
    #997). Both the title and the button must be there: a context menu also
    holds a 'Löschen' line, but no 'Nein'."""
    if not any(re.fullmatch(r"\W{0,3}\s*Löschen", l["text"].strip()) for l in lines):
        return None
    return button_hit(lines, "Nein")



def ja_beside_nein(nein: dict | None) -> dict | None:
    """Where the delete confirmation's 'Ja' sits when OCR reads its 'Nein'
    but not the 'Ja' (2026-11-09: the region's OCR gave 'X' and 'Nein' and
    nothing of the check-marked 'Ja', with the driver of #1003). The two
    buttons share one line; the word 'Ja' starts about 144 px left of the
    word 'Nein' and is about 30 px wide (screenshot of 2026-11-08 23:06:
    'Ja' at x 2380, 'Nein' at x 2524; OCR of 2026-11-09 10:58: 'Nein' at
    x 2584). The click lands in the middle of that word; `confirm_delete`
    checks afterwards that the dialog is gone."""
    if not nein:
        return None
    return {"click_x": nein["x"] - 128, "click_y": nein["y"] + nein["h"] // 2}


def ja_on_the_line_of(jas: list[dict], nein: dict | None) -> dict | None:
    """The 'Ja' hit that sits on the same line as the dialog's 'Nein' (both
    buttons share one line). The search region also covers catalog rows,
    whose "SL Ready" cell reads 'Ja' for a secure product; a click there
    left the dialog open ("still open after 'Ja'", 2026-11-09). Without a
    'Nein' the first hit is taken, as before."""
    if nein is None:
        return jas[0] if jas else None
    same = [j for j in jas if abs(j["y"] - nein["y"]) <= 15]
    return same[0] if same else None


def _keep_delete_dialog_image() -> None:
    """The dialog as it looked, for the next diagnosis (#997)."""
    try:
        grab(LAYOUT["delete_dialog"]).save(str(HERE / "cap" / "delete-dialog.png"))
    except Exception as exc:  # noqa: BLE001 - a diagnostic only
        log(f"delete dialog screenshot failed: {exc}")

# How often confirm_delete looks for the confirmation after its click, 1.5 s
# apart (12 s): a Data Secure device's delete took longer than the single
# 1.5 s look of before (ets-sweep-secure, 2026-11-10).
DELETE_POLLS = 8


def confirm_delete() -> None:
    """Answer the delete confirmation with 'Ja'. A dialog left open fails
    every import after it (2026-11-08, #997): when 'Ja' is not found, or the
    dialog is still there after the click, it is answered with 'Nein' before
    the error is raised, so the next flow finds the Katalog panel."""
    bbox = LAYOUT["delete_yes"]
    lines = ocr(bbox)
    nein = button_hit(lines, "Nein")
    hit = ja_on_the_line_of(button_hits(lines, "Ja"), nein)
    if hit is None:
        _keep_delete_dialog_image()
        hit = ja_beside_nein(nein)
        if hit is None:
            seen = [(l["text"], l["x"], l["y"]) for l in lines][:12]
            closed = close_delete_dialog()
            raise RuntimeError(f"button 'Ja' not on screen in {bbox}; OCR read {seen}; dialog {'closed with Nein' if closed else 'left open'}")
        log(f"'Ja' not read by OCR; clicking beside 'Nein' at ({hit['click_x']}, {hit['click_y']})")
    click(hit["click_x"], hit["click_y"])
    # Deleting a Data Secure device takes longer: ETS shows its progress
    # ('Löschen ...', 'Gerät ... gelöscht', only 'Abbrechen') before the
    # confirmation is gone (ets-sweep-secure, 2026-11-10). Wait for it rather
    # than press Enter into that dialog.
    for _ in range(DELETE_POLLS):
        time.sleep(1.5)
        still = leftover_delete_dialog(ocr(LAYOUT["delete_dialog"]))
        if not still:
            break
    if still:
        # The click on the word did not take (2026-11-09 11:25, at (2457,
        # 1456) inside the highlighted button, image in cap/delete-dialog.png)
        # while 'Ja' is the dialog's focused default button: Enter confirms it.
        log(f"delete dialog still open after the click at ({hit['click_x']}, {hit['click_y']}); pressing Enter")
        keys("{ENTER}")
        time.sleep(1.5)
        if leftover_delete_dialog(ocr(LAYOUT["delete_dialog"])):
            _keep_delete_dialog_image()
            closed = close_delete_dialog()
            raise RuntimeError(
                f"delete dialog still open after 'Ja' at ({hit['click_x']}, {hit['click_y']}) and Enter; "
                f"{'closed with Nein' if closed else 'left open'}"
            )


def close_delete_dialog() -> bool:
    """Answer a delete confirmation a failed delete left open with 'Nein'
    (never 'Ja': it may name another object than the next flow expects).
    True when one was closed."""
    hit = leftover_delete_dialog(ocr(LAYOUT["delete_dialog"]))
    if not hit:
        return False
    log(f"closing a leftover delete confirmation at ({hit['click_x']}, {hit['click_y']})")
    click(hit["click_x"], hit["click_y"])
    time.sleep(1.5)
    return True


def project_tab_hit(name: str) -> dict | None:
    """The tab of project `name` in the tab strip. OCR splits a hyphenated
    name into fragments ('ets', '-sweep', '-secure', 2026-11-04): when no
    single line matches, adjacent fragments on one row are joined."""
    lines = ocr(LAYOUT["tab_strip"])
    whole = whole_name_hits(lines, name)
    if whole:
        return whole[0]
    # A misread name (OCR's 'ets-sweep' as 'ets-swee p'): the fuzzy match,
    # unless it is the first fragment of another project's name ('ets-sweep'
    # before '-secure', #423).
    hit = find_text(name, LAYOUT["tab_strip"])
    if hit and (followed_closely(lines, hit) or re.match(re.escape(_norm(name)) + r"[a-z0-9]", _norm(hit["text"]))):
        return None
    return hit


def followed_closely(lines: list[dict], hit: dict) -> bool:
    """Whether another OCR line starts right after `hit` on its row: `hit`
    is then a fragment of a longer name, not a whole one."""
    return any(abs(l["y"] - hit["y"]) <= 10 and 0 <= l["x"] - (hit["x"] + hit["w"]) <= 60 for l in lines)


def whole_name_hits(lines: list[dict], name: str) -> list[dict]:
    """`joined_texts` hits of `name` that no further fragment follows: a
    name OCR split ('ets-sweep', '-secure') never passes for the project
    named by its first fragment (#423)."""
    return [h for h in joined_texts(lines, name) if not followed_closely(lines, h)]


def joined_texts(lines: list[dict], name: str) -> list[dict]:
    """Every OCR line, or run of adjacent lines on one row, whose text
    without blanks is exactly `name`, left to right: OCR splits a hyphenated
    name into fragments ('ets-sweep', '-secure' under a start page tile,
    2026-11-10)."""
    out = []
    rows: list[list[dict]] = []
    for line in sorted(lines, key=lambda l: l["y"]):
        if rows and line["y"] - rows[-1][0]["y"] <= 10:
            rows[-1].append(line)
        else:
            rows.append([line])
    lines = [l for row in rows for l in sorted(row, key=lambda l: l["x"])]
    for i in range(len(lines)):
        for j in range(i + 1, min(i + 5, len(lines) + 1)):
            group = lines[i:j]
            if any(abs(l["y"] - group[0]["y"]) > 10 for l in group):
                break
            if any(b["x"] - (a["x"] + a["w"]) > 60 for a, b in zip(group, group[1:])):
                break
            if "".join(re.sub(r"\s", "", l["text"]) for l in group) == name:
                x1 = max(l["x"] + l["w"] for l in group)
                out.append({"text": name, "x": group[0]["x"], "y": group[0]["y"],
                            "w": x1 - group[0]["x"], "h": max(l["h"] for l in group)})
                break
    return out


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
        if not main and any(_norm(l["text"]) == "gewerke" for l in lines):
            # The Gebäude view in the tree's place: ets-sweep-secure reopens
            # its 'Gebäude' panels after ETS loaded it (2026-11-10, seven rows
            # failed here). Restore the sweep layout and look again.
            ensure_layout()
            continue
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


def start_page_tile(project: str) -> dict | None:
    """The tile of `project` on ETS's start page (`project_tile`, whose name
    must match exactly: 'ets-sweep' is a prefix of 'ets-sweep-secure',
    #423), or None when the start page shows none."""
    try:
        return project_tile(project)
    except RuntimeError:
        return None


def open_start_page() -> bool:
    """Shows ETS's start page (the project tiles) while a project is open:
    the 'ETS6 Professional' tab at the left of the tab strip."""
    click(200, 40)  # the start page tab, as export_keyring_once
    time.sleep(3)
    return True


def open_project_tile(hit: dict, project: str, password: str | None = None) -> None:
    """Clicks a project tile and waits until ETS shows `project`, answering
    the project password prompt of a protected project (the secure pass's
    `ets-sweep-secure`, #423) with `password`."""
    click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
    t0 = time.time()
    while time.time() - t0 < 120 and window_project() != project:
        if password:
            set_project_password(password)
        time.sleep(3)
    time.sleep(5)


def ensure_ets_running(project: str = "ets-sweep", password: str | None = None) -> list[str]:
    """Start ETS and open `project` when ETS is not running (it closed after a
    compatibility prompt, 2026-10-28), or bring `project` to the front when
    ETS shows another one: its tab, else its tile on the start page
    (`password` answers a protected project's prompt)."""
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
        tab = project_tab_hit(project)
        if tab and _norm(tab["text"]) == _norm(project):
            click(tab["x"] + tab["w"] // 2, tab["y"] + tab["h"] // 2)
            time.sleep(3)
        else:
            hit = start_page_tile(project)
            if not hit and window_project() and open_start_page():
                # Another project is open in front (the plain sweep's
                # 'ets-sweep' before a secure run, 2026-11-10): its tiles are
                # on the start page.
                did.append("start page")
                hit = start_page_tile(project)
            if not hit:
                raise RuntimeError(f"ETS shows {window_project()!r} and no tile or tab for {project!r}")
            open_project_tile(hit, project, password)
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
            hit = start_page_tile(project)
            if not hit:
                time.sleep(5)
        if not hit:
            raise RuntimeError(f"ETS started, but no project tile {project!r} on the overview")
        open_project_tile(hit, project, password)
        did.append("opened project")
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
    # Opening a protected project keeps its prompt on screen while ETS
    # decrypts and loads the project (more than 2 s for ets-sweep-secure,
    # 2026-11-10: the project opened after the driver had given up).
    t0 = time.time()
    while True:
        time.sleep(2)
        after = " ".join(l["text"] for l in ocr(PASSWORD_DIALOG))
        if "Projektpasswort" not in after:
            return True
        if time.time() - t0 > 30 or re.search(r"(falsch|ungültig|Ungültig|nicht korrekt)", after):
            break
    keys("{ESC}")
    raise RuntimeError(f"the project password dialog stayed open: {after[:200]}")


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
    # A name OCR split in two ('ets-sweep', '-secure') must not pass for the
    # project whose name is its first fragment: whole names are matched on
    # the joined row (`joined_texts`), and a fragment followed closely by
    # another one is not a whole name.
    for hit in whole_name_hits(lines, project):
        return hit
    raise RuntimeError(f"no tile for project {project!r}: {[l['text'] for l in lines][:12]}")


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
    import` of it is the model state a parameter-set row compares against.
    ETS 6.4.1 has no context menu on the project tab; the export is the
    project tile's 'Export' on the start page (checked 2026-11-10), a
    Windows save dialog, then ETS's progress dialog until the file is
    written. ETS exports the product data of every device the project ever
    held: 17.5 GB for `ets-sweep` after the sweep (2026-11-10), more than
    14 minutes, so `wait` (seconds) bounds it."""
    project, path = req["project"], req["path"]
    require_project(project)
    click(200, 40)  # the start page tab
    wait_for("start page", lambda: find_text(project, (0, 1150, 4112, 1320)), 10, 0.5)
    tile = project_tile(project)
    click(tile["x"] + tile["w"] // 2, tile["y"] - 150, button="right")
    try:
        menu_click("Export", timeout=5, settle=0)
        dialog = wait_popup(10)
        save_as(dialog, path)
        done = wait_for("project exported", lambda: os.path.exists(path) and not find_text(
            "Exportiere Projektdateien", (1500, 900, 2600, 1100)), float(req.get("wait", 1800)), 2)
        if not done:
            # The file appears while ETS still writes it: only a closed
            # progress dialog is a finished export.
            raise RuntimeError(f"the export of {project!r} did not finish within {req.get('wait', 1800)} s")
    finally:
        close_menus()
        hit = project_tab_hit(project)
        if hit:
            click(hit["x"] + hit["w"] // 2, hit["y"] + hit["h"] // 2)
            wait_for("project tab", lambda: window_project() == project, 5, 0.3)
    return {"path": path, "exported": os.path.exists(path)}


# ---------------------------------------------------------------- parameter editor (#424)
# Measured on ETS 6.4.1 on 2026-11-10 (Hager TYMS616D, E804). The device's
# 'Parameter' tab, next to 'Kommunikationsobjekte', shows the page tree on
# the left and each parameter as a row of label (x 1140..1610) and control
# (from x 1625). The main window has no UI Automation tree, so the view is
# read by OCR and pixels; a dropdown's open list is a popup with one
# (ListItem > Text per option).
#
# Why the first version (2026-10-30) set nothing on the Hager programs
# (2026-11-08): the page list is a tree whose channels ('Ausgang 1' .. 16)
# hold their pages collapsed and run past the visible list, so the pages
# it clicked were not those of the parameter; a 0/1 parameter is a checkbox
# with no text on its row ('no control on the row'); and the generator took
# parameters from the whole product model, most of them on pages ETS does
# not show at defaults. Now the parameter view is made tall (the Katalog
# splitter dragged down, put back by `restore_catalog_splitter` at the next
# catalog flow), pages are walked with the keyboard (Down selects the next
# page and expands a channel; the tree scrolls itself), each page is
# identified by the breadcrumb ETS shows above it, and each row's control is
# told apart by its pixels: checkbox, radio buttons, dropdown, number field
# (spinner) or text field.
PARAM_LIST = (690, 290, 1115, 2270)
PARAM_ROWS = (1125, 290, 3400, 2270)
BREADCRUMB = (680, 235, 3300, 285)
CONTROL_X = 1625
LABEL_X_MAX = 1610
# The splitter grip between the centre view and the Katalog panel when the
# parameter view is tall: the panel keeps its header (Import at y ~2339).
PARAM_TALL_GRIP = 2290


def open_device_parameters(ia: str) -> str:
    """Opens the parameter view of device `ia`: the device selected in the
    Topologie tree, then its 'Parameter' tab; the view made tall."""
    if parameter_view_of(ia):
        param_view_tall()
        return "Parameter"
    open_device_objects(ia)
    for _ in range(3):
        if not click_tab("Parameter"):
            raise RuntimeError("no 'Parameter' tab above the device's view")
        wait_busy()
        # The object table's header is gone once the parameter view shows.
        if wait_for("parameter view", lambda: not find_text("Objektfunktion", (680, 220, 3400, 260)), 5, 0.3):
            param_view_tall()
            return "Parameter"
    raise RuntimeError("the 'Parameter' tab did not open")


def parameter_view_of(ia: str) -> bool:
    """True when the centre view shows device `ia`'s parameter pages
    already: its breadcrumb names the device and no object table shows."""
    crumb = " ".join(l["text"] for l in ocr(BREADCRUMB))
    return tree_node_of(crumb, ia) and find_text("Objektfunktion", (680, 220, 3400, 260)) is None \
        and find_text("Parameter", (680, 150, 1600, 220)) is not None


def param_view_tall() -> str | None:
    """Drag the Katalog splitter down so the page tree and the parameter
    rows get the screen's height (a page of ~40 rows shows whole)."""
    from pywinauto import mouse

    btn = catalog_import_button()
    if btn and btn["y"] - 48 >= PARAM_TALL_GRIP - 30:
        return None
    y0 = (btn["y"] if btn else 1354) - 48
    s_ = scale()
    mouse.press(coords=(int(1703 * s_), int(y0 * s_)))
    time.sleep(0.3)
    for k in range(1, 11):
        mouse.move(coords=(int(1703 * s_), int((y0 + (PARAM_TALL_GRIP - y0) * k / 10) * s_)))
        time.sleep(0.05)
    mouse.release(coords=(int(1703 * s_), int(PARAM_TALL_GRIP * s_)))
    wait_for("tall parameter view", lambda: (catalog_import_button() or {}).get("y", 0) > 2200, 3, 0.3)
    return f"param view tall from {y0}"


def _dark(p) -> bool:
    """A border, glyph or tick pixel: no channel bright (yellow highlight
    and light blue fill are not dark)."""
    return max(p[:3]) < 225


def _grey(p) -> bool:
    """A dropdown's fill (242, 242, 242)."""
    return all(236 <= c <= 247 for c in p[:3])


def _blue(p) -> bool:
    """Text of the selected page, or a checked checkbox's fill/tick."""
    r, g, b = p[:3]
    return b > 150 and b - r > 30


def _tick(p) -> bool:
    """A checkbox's tick: a darker blue (113, 152, 204), not its light fill
    (219, 234, 255) nor the grey border."""
    r, g, b = p[:3]
    return r < 175 and b > 170 and b - r > 50


def merge_labels(lines: list[dict]) -> list[dict]:
    """The label column's OCR lines joined where ETS wrapped a label: the
    next line starts within 16 px below the last one at the same indent."""
    out: list[dict] = []
    for l in sorted((l for l in lines if l["x"] < LABEL_X_MAX and l["text"].strip()), key=lambda l: l["y"]):
        last = out[-1] if out else None
        if last and 0 <= l["y"] - (last["y"] + last["h"]) < 16 and abs(l["x"] - last["x"]) < 30:
            last["text"] = f"{last['text']} {l['text']}"
            last["h"] = l["y"] + l["h"] - last["y"]
            last["w"] = max(last["w"], l["w"])
        else:
            out.append(dict(l))
    return out


def _circle_like(t: str) -> bool:
    return t.strip() in ("O", "o", "0", "Q", "C", "()", "(O)", "(o)", "(0)", "@", "®", "©", "•", "◉")


# A radio circle OCR glued to the option word after it ('OUND', '@UND',
# '(O)UND'): the glyphs it reads a circle as, at the start of one word.
GLUED_CIRCLE = re.compile(r"^(\(\s*[Oo0]\s*\)|[O0Q@®©•◉])(?=[A-ZÄÖÜ0-9])")


def ring_at(px, cx: int, cy: int) -> bool:
    """A radio button's circle (diameter ~32) centred near (cx, cy): its
    ring dark 12..17 px out on all four sides. (The selected one's dot
    reaches 9 px out, a text glyph not this far up and down.)"""
    def any_dark(points):
        return any(_dark(px(x, y)) for x, y in points)
    return any_dark((cx + e, cy - d) for d in range(12, 18) for e in (-1, 0, 1)) \
        and any_dark((cx + e, cy + d) for d in range(12, 18) for e in (-1, 0, 1)) \
        and any_dark((cx - d, cy + e) for d in range(12, 18) for e in (-2, 0, 2)) \
        and any_dark((cx + d, cy + e) for d in range(12, 18) for e in (-2, 0, 2)) \
        and not any_dark((cx + e, cy - d) for d in (19, 20, 21) for e in (-1, 0, 1)) \
        and not any_dark((cx + e, cy + d) for d in (19, 20, 21) for e in (-1, 0, 1))


def radio_circles(px, cy: int, cells: list[dict], x_max: int = 3300) -> list[int]:
    """The centres of the radio circles on the row, found along it: a dark
    pixel on the row is a ring's left edge when a ring is centred 15 or 16
    px right of it. OCR reads the options in one line at times
    ('Schalten O Rollladen und Jalousie'), so its cells do not place them."""
    if not cells:
        return []
    out: list[int] = []
    x = CONTROL_X - 4
    while x < x_max:
        if _dark(px(x, cy)):
            hit = next((x + d for d in (15, 16, 14, 17) if ring_at(px, x + d, cy)), None)
            if hit is not None:
                out.append(hit)
                x = hit + 18
                continue
        x += 1
    return out


# How far a radio circle's centre may sit from the row's `y` (the OCR line
# centre of its label). Descenders pull that centre down: on the saved rows
# of #1054 ('Keep the warming log on download', 'Roost layout', row-1.png
# of syn-choose-partial-segment and syn-module-choose, 2026-11-12) the ring
# runs from y-20 to y+11, its centre 4 to 5 px above `y`, and
# `radio_circles` finds both circles for every probe from y-7 to y-2 and
# none at `y`. Rows sit ~60 px apart (Hager TYMS616D), so a neighbour's ring (16 px out)
# stays out of reach of a probe this close.
RING_DY = 8


def radio_row(px, cy: int, cells: list[dict]) -> tuple[list[int], int]:
    """The radio circles on the row labelled at `cy` and the y of their
    centre: `radio_circles` probed at `cy`, then outwards up to `RING_DY`
    px above and below; of the probes that find the most circles, the
    middle one (the ring's centre, not the edge of the band it is found
    in), so the selected test and the click hit the circle's middle."""
    if not cells:
        return [], cy
    found = radio_circles(px, cy, cells)
    hits: dict[int, list[int]] = {0: found} if found else {}
    for dy in range(-RING_DY, RING_DY + 1):
        if dy and (found := radio_circles(px, cy + dy, cells)):
            hits[dy] = found
    if not hits:
        return [], cy
    most = max(len(v) for v in hits.values())
    band = sorted(dy for dy, v in hits.items() if len(v) == most)
    mid = band[len(band) // 2]
    return hits[mid], cy + mid


def split_at_circles(cells: list[dict], circles: list[int]) -> list[dict]:
    """OCR cells cut where a radio circle sits inside one ('Schalten O
    Rollladen und Jalousie' over the second circle): the text split at the
    word boundary nearest the circle's share of the width, the circle's 'O'
    dropped."""
    out: list[dict] = []
    for c in cells:
        words = c["text"].split()
        at = next((cx for cx in circles if c["x"] - 4 <= cx <= c["x"] + 40), None)
        if len(words) > 1 and _circle_like(words[0]) and at is not None:
            # The circle read as the line's first letter ('O Rollladen ...').
            c = {**c, "text": " ".join(words[1:]), "x": at + 20, "w": c["w"] - (at + 20 - c["x"])}
        elif words and at is not None and c["x"] < at and GLUED_CIRCLE.match(words[0]):
            # The circle glued to a short option word ('OUND' over the
            # circle at 1640, Hager E802 'Art der logischen Funktion',
            # #1049): the cell starts left of the circle's centre, so no
            # option took it and the option read ''.
            text = GLUED_CIRCLE.sub("", c["text"], count=1).strip()
            c = {**c, "text": text, "x": at + 20, "w": c["w"] - (at + 20 - c["x"])}
        parts = [c]
        for cx in circles:
            last = parts[-1]
            if not (last["x"] + 10 < cx < last["x"] + last["w"] - 10):
                continue
            words = last["text"].split()
            cw = last["w"] / max(len(last["text"]), 1)
            pos, cut = 0, 0
            for k, w in enumerate(words):
                if last["x"] + (pos + len(w) / 2) * cw > cx:
                    break
                cut = k + 1
                pos += len(w) + 1
            left, right = words[:cut], words[cut:]
            if right and _circle_like(right[0]):
                right = right[1:]
            if left and _circle_like(left[-1]):
                left = left[:-1]
            parts[-1] = {**last, "text": " ".join(left), "w": int(cx - 16 - last["x"])}
            parts.append({**last, "text": " ".join(right), "x": cx + 20, "w": int(last["x"] + last["w"] - cx - 20)})
        out += [p for p in parts if p["text"]]
    return out


def classify_control(px, cy: int, cells: list[dict]) -> dict:
    """What control sits on the row centred at `cy` (layout y): `px(x, y)`
    gives a pixel (layout coordinates), `cells` the OCR lines right of the
    label column on that row. Returns {kind, value, options?, box?}:
    - dropdown: grey fill across x 1640..1760; value its text;
    - number / text: a white box with borders above and below the row at
      x 1700; number when spinner arrows sit at its right end;
    - checkbox: a ~32 px box at CONTROL_X with no text beside it; value
      '1' when checked (light blue fill or a tick inside), else '0';
    - radio: option texts right of ~32 px circles; value the option whose
      circle has a dark centre;
    - none: a heading or note."""
    # Above and below the text, inside the box (a dropdown is ~46 px tall).
    if sum(_grey(px(x, y)) for x in range(1640, 1760, 4) for y in (cy - 12, cy + 12)) > 40:
        right = next((x for x in range(1760, 3300, 2) if not _grey(px(x, cy)) and not _dark(px(x, cy))), 3300)
        text = " ".join(c["text"] for c in cells if c["x"] < right)
        return {"kind": "dropdown", "value": text.strip(), "box": [CONTROL_X, right]}
    # A field's borders run ~21 px above and below the row's centre; a
    # radio option's text at x 1700 stays within ~9 px.
    above = any(_dark(px(1700, y)) for y in range(cy - 26, cy - 12))
    below = any(_dark(px(1700, y)) for y in range(cy + 12, cy + 27))
    if above and below:
        top = max(y for y in range(cy - 26, cy - 12) if _dark(px(1700, y)))
        probe = top + 3
        right = next((x for x in range(1710, 3300, 2) if _dark(px(x, probe))), 3300)
        spinner = any(_dark(px(x, y)) for x in range(right - 28, right - 4, 2) for y in range(cy - 10, cy + 10, 2))
        inside = [c for c in cells if c["x"] < right]
        unit = " ".join(c["text"] for c in cells if c["x"] > right).strip()
        return {"kind": "number" if spinner else "text", "value": " ".join(c["text"] for c in inside).strip(),
                "box": [CONTROL_X, right], "unit": unit}
    circles, ring_y = radio_row(px, cy, cells)
    # A checkbox: a ~32 px square at CONTROL_X, its left side a grey border
    # when clear, light blue fill (219, 234, 255) when checked. A value ETS
    # shows as plain text in the control column (a fixed setting, Hager
    # TXB692F 'Ausgangskontakt  Schließer') is no checkbox: its glyphs read
    # as one (2026-11-11).
    side = max(sum(_dark(px(x, y)) or _blue(px(x, y)) for y in range(cy - 13, cy + 14))
               for x in (CONTROL_X, CONTROL_X + 1, CONTROL_X + 2, CONTROL_X + 3))
    text_at_control = any(c["x"] < CONTROL_X + 40 and not _circle_like(c["text"]) for c in cells)
    box = side >= 20 and not text_at_control
    if circles:
        # Each option's text: the cells between its circle and the next
        # (OCR splits '0 = Aus, 1 = Ein' and drops the lone '1').
        pieces = split_at_circles(cells, circles)
        opts = []
        for i, cx in enumerate(circles):
            end = circles[i + 1] if i + 1 < len(circles) else 99999
            text = " ".join(c["text"] for c in pieces if cx < c["x"] < end and not _circle_like(c["text"])).strip()
            # The selected circle has a filled centre (195, 208, 221).
            opts.append({"text": text, "x": cx, "y": ring_y, "selected": _dark(px(cx, ring_y))})
        chosen = next((o["text"] for o in opts if o["selected"]), "")
        return {"kind": "radio", "value": chosen, "options": opts}
    if box:
        # The tick (113, 152, 204) decides, not the light blue fill: a box
        # just cleared kept the fill while focused, and read as checked
        # (four "1 -> 0" changes on 2026-11-11).
        checked = sum(_tick(px(x, y)) for x in range(CONTROL_X + 6, CONTROL_X + 27)
                      for y in range(cy - 9, cy + 10)) > 3
        return {"kind": "checkbox", "value": "1" if checked else "0"}
    return {"kind": "none", "value": " ".join(c["text"] for c in cells).strip()}


def ocr_ink(bbox: tuple[int, int, int, int], pad: int = 12) -> list[dict]:
    """OCR of the part of `bbox` that holds ink. Windows OCR placed the
    lines of a mostly blank 2275 x 1980 crop 21 px right and 24 px up
    (Hager TXB692F, five rows, 2026-11-11), so every row was read beside its
    control; the same rows OCR'd in a crop around them sit right."""
    from PIL import ImageOps

    img = ImageOps.grayscale(grab(bbox))
    s = img.width / (bbox[2] - bbox[0])
    box = ImageOps.invert(img).point(lambda v: 255 if v > 60 else 0).getbbox()
    if box is None:
        return []
    x0, y0, x1, y1 = (int(v / s) for v in box)
    inner = (max(bbox[0], bbox[0] + x0 - pad), max(bbox[1], bbox[1] + y0 - pad),
             min(bbox[2], bbox[0] + x1 + pad), min(bbox[3], bbox[1] + y1 + pad))
    return ocr(inner)


def fill_option_texts(row: dict, read) -> None:
    """A radio row's options whose text the row's OCR line did not give
    (#1049: Hager E802 'Art der logischen Funktion' read options '' and
    'ODER', so the change was set and recorded as ''): each such option's
    span, from right of its circle to the next circle, read again on its
    own by `read(bbox)` (magnified OCR); a short word alone in a small crop
    reads where the whole line dropped it. The row's value follows its
    selected option. An option still unread stays '' (`set_row` refuses
    to set it)."""
    opts = row.get("options") or []
    for i, o in enumerate(opts):
        if o.get("text"):
            continue
        end = opts[i + 1]["x"] - 18 if i + 1 < len(opts) else min(o["x"] + 420, PARAM_ROWS[2])
        bbox = (o["x"] + 17, o["y"] - 22, max(end, o["x"] + 60), o["y"] + 22)
        try:
            cells = read(bbox)
        except Exception:  # noqa: BLE001 - a second read is best effort
            continue
        text = " ".join(c["text"] for c in sorted(cells, key=lambda c: c["x"])
                        if not _circle_like(c["text"])).strip()
        o["text"] = GLUED_CIRCLE.sub("", text, count=1).strip()
    if any(o.get("selected") for o in opts):
        row["value"] = next(o["text"] for o in opts if o.get("selected"))


def param_rows() -> list[dict]:
    """The rows of the shown parameter page: {label, n, kind, value, y, ...};
    `n` counts earlier rows of the same label on the page (Hager's three
    'Einschaltverzögerung' fields for h, min and s)."""
    park_mouse()
    # The breadcrumb changes before the rows do: read until two reads agree.
    last: dict = {"lines": None}

    def settled():
        lines = ocr_ink(PARAM_ROWS)
        # Texts and places: a page slides in, its rows read with the right
        # text 22 px above their controls (2026-11-11), and a click there
        # missed the checkbox.
        same = last["lines"] is not None and [(l["text"], l["x"] // 4, l["y"] // 4) for l in lines] == \
            [(l["text"], l["x"] // 4, l["y"] // 4) for l in last["lines"]]
        last["lines"] = lines
        return same
    wait_for("rows settled", settled, 3, 0.25)
    img = grab(PARAM_ROWS).convert("RGB")
    s = img.width / (PARAM_ROWS[2] - PARAM_ROWS[0])

    def px(x: int, y: int):
        x = min(max(int((x - PARAM_ROWS[0]) * s), 0), img.width - 1)
        y = min(max(int((y - PARAM_ROWS[1]) * s), 0), img.height - 1)
        return img.getpixel((x, y))

    lines = last["lines"]
    cells = [l for l in lines if l["x"] >= LABEL_X_MAX]
    rows, seen = [], {}
    for label in merge_labels(lines):
        cy = label["y"] + label["h"] // 2
        on_row = sorted((c for c in cells if abs(c["y"] + c["h"] // 2 - cy) < 20), key=lambda c: c["x"])
        row = {"label": label["text"].strip(), "y": cy, **classify_control(px, cy, on_row)}
        if row["kind"] in ("number", "text"):
            row["value"] = field_ocr(img, s, row)
        if row["kind"] == "radio":
            fill_option_texts(row, lambda bbox: ocr(bbox, zoom=3))
        key = _norm(row["label"])
        row["n"] = seen.get(key, 0)
        seen[key] = row["n"] + 1
        rows.append(row)
    return rows


def selected_page() -> dict:
    """The page shown: ETS's breadcrumb above the rows ('<device> > Ausgang
    1 > - A1: Zeiten für Schaltobjekt') and the selected entry of the page
    tree (blue text), with its y."""
    crumb = " ".join(l["text"] for l in ocr(BREADCRUMB)).strip()
    img = grab(PARAM_LIST).convert("RGB")
    s = img.width / (PARAM_LIST[2] - PARAM_LIST[0])
    page, y, top = None, None, None
    for l in ocr_ink(PARAM_LIST):
        if len(l["text"].strip()) < 2:
            continue
        if top is None or l["y"] < top[1]:
            top = (l["text"].strip(), l["y"])
        blue = sum(_blue(img.getpixel((min(int((x - PARAM_LIST[0]) * s), img.width - 1),
                                       min(int((yy - PARAM_LIST[1]) * s), img.height - 1))))
                   for x in range(l["x"], l["x"] + l["w"], 3) for yy in range(l["y"], l["y"] + l["h"], 3))
        if blue > 6:
            page, y = l["text"].strip(), l["y"]
    # The device part of the breadcrumb is the same on every page.
    path = crumb.split(">", 1)[1].strip() if ">" in crumb else crumb
    return {"crumb": path, "page": page, "y": y, "top": top}


def other_entry(a: dict, b: dict) -> bool:
    """Whether two reads of the selection are two tree entries although
    their texts may be alike: the highlight sits at another y while the
    tree did not scroll (its top line the same). Two child pages of one
    name ('Feeder' twice under 'General', syn-module-repeat, #1054) read
    as the same page by text alone, so Down looked like no move."""
    if a.get("y") is None or b.get("y") is None or not a.get("top") or not b.get("top"):
        return False
    (ta, ya), (tb, yb) = a["top"], b["top"]
    scrolled = abs(ya - yb) >= 10 or not _alike(ta, tb)
    return not scrolled and abs(a["y"] - b["y"]) >= 10


def _page_key(t: str) -> str:
    """A page or label text as OCR may read it: 'Al-16' is 'A1-16' (an l
    after a capital A before a digit, hyphen, colon or the end)."""
    t = re.sub(r"(?<=A)l(?=[\d\-:\s]|$)", "1", t or "")
    return _norm(t)


def _letter_tokens(t: str) -> list[str]:
    """The capital letters that stand alone in `t` ('Eingang A:', 'A / B',
    'A-P'): a channel or input name, not a misread inside a word."""
    t = re.sub(r"(?<=A)l(?=[\d\-:\s]|$)", "1", t or "")
    return re.findall(r"(?<![^\W\d_])[A-Z](?![^\W\d_])", t)


def _alike(a: str | None, b: str | None, ratio: float = 0.85) -> bool:
    """OCR reads the same entry differently at times ('Ausqanq 10' low in
    the tree, 'Al' for 'A1'): the same digits and letters close. Digits
    must agree exactly ('Ausgang 1: ...' is not 'Ausgang 2: ...'), and so
    must the capital letters that stand alone ('Eingang A:' is not
    'Eingang B:', issue #1050: the walk took the next input's page for the
    same one and stopped)."""
    if _letter_tokens(a or "") != _letter_tokens(b or ""):
        return False
    a, b = _page_key(a or ""), _page_key(b or "")
    if a == b:
        return True
    if not a or not b or re.sub(r"\D", "", a) != re.sub(r"\D", "", b):
        return False
    return difflib.SequenceMatcher(None, a, b).ratio() >= ratio


def same_page(a: dict, b: dict) -> bool:
    """The same page: the breadcrumb (read in one line at the top) alike,
    and the selected tree entry alike."""
    return _alike(a.get("crumb"), b.get("crumb"), 0.9) and _alike(a.get("page"), b.get("page"))


def channel_node_of(prev: dict, page: dict) -> bool:
    """Whether `prev`, read just before `page`, was the channel node of
    `page`'s channel showing `page` highlighted: the same page text, the
    same channel (the breadcrumb's first part), and a breadcrumb that does
    not end in that page (`Ausgang 5` or `Ausgang 5 > ...`). Two channels'
    pages of one name ('K1 > Allgemein', 'K2 > Allgemein') are two pages."""
    if not _alike(prev.get("page"), page.get("page")) or other_entry(prev, page):
        # Another tree entry (two pages of one name): no channel node.
        return False
    parts = [p.strip() for p in (prev.get("crumb") or "").split(">")]
    theirs = [p.strip() for p in (page.get("crumb") or "").split(">")]
    if not parts or not theirs or not _alike(parts[0], theirs[0]):
        return False
    return len(parts) == 1 or parts[-1].endswith("...") or not _alike(parts[-1], prev.get("page"))


def page_consistent(p: dict) -> bool:
    """The breadcrumb and the tree's selection name the same page: ETS
    updates the breadcrumb first and the highlight a moment later. A
    breadcrumb ETS shortened ('Ausgang 5 > ...') cannot tell."""
    last = (p.get("crumb") or "").rsplit(">", 1)[-1].strip()
    if not last:
        return False
    if not p.get("page"):
        # A channel node ('Ausgang 1'): ETS highlights no entry in blue.
        return True
    if last.endswith("...") or p["page"].endswith("..."):
        return True
    # A channel node selected ('Ausgang 2') highlights its first page
    # ('Ausgang 2: Funktionsfreigabe').
    return _alike(last, p["page"]) or _norm(p["page"]).startswith(_norm(last))


def settled_page(timeout: float = 3.0) -> dict | None:
    """The selected page once two reads agree and the breadcrumb matches
    the selection (`page_consistent`), or None."""
    seen: dict = {"p": None}

    def stable():
        p = selected_page()
        ok = seen["p"] is not None and same_page(p, seen["p"]) and page_consistent(p)
        seen["p"] = p
        return ok
    return seen["p"] if wait_for("page settled", stable, timeout, 0.25) else None


def first_page() -> dict:
    """Select the first page of the tree and return it, with the tree's
    last page under "last" (End, then Home): a click on a visible entry
    puts the keyboard focus in the tree, End and Home select its last and
    first entry (the tree scrolls by itself). The walk ends at the last
    page, not at the first Down that seems to change nothing."""
    lines = [l for l in ocr_ink(PARAM_LIST) if len(l["text"].strip()) > 1]
    if not lines:
        raise RuntimeError("the parameter view shows no page tree")
    top = min(lines, key=lambda l: l["y"])
    click(top["x"] + top["w"] // 2, top["y"] + top["h"] // 2)
    time.sleep(0.3)
    keys("{END}")
    last = settled_page(5) or selected_page()
    keys("{HOME}")
    seen: dict = {}

    def at_top():
        p = settled_page(2)
        if p is None or same_page(p, last):
            return False
        seen["p"] = p
        lines = [l for l in ocr_ink(PARAM_LIST) if len(l["text"].strip()) > 1]
        return p.get("y") is not None and lines and p["y"] <= min(l["y"] for l in lines) + 5
    if not wait_for("first page", at_top, 6, 0.3):
        seen["p"] = settled_page(3) or selected_page()
    return {**seen["p"], "last": last}


def next_page(current: dict) -> dict | None:
    """Down in the page tree: the next page (a channel expands when
    selected), or None when the selection does not move. The page counts
    once two reads agree and its breadcrumb matches the selection. A Down
    ETS takes long to show (a page just switched on, right after a device
    was added) is waited for once more before it counts as the end.

    Only safe while the keyboard focus is in the tree: `first_page` puts it
    there, and nothing between two calls may click into the rows (Down in a
    number field counts it down: a walk that read fields by the clipboard
    left 19 s for a default of 20 s, 2026-11-10)."""
    keys("{DOWN}")
    seen: dict = {"p": None}

    def moved():
        p = selected_page()
        stable = seen["p"] is not None and same_page(p, seen["p"])
        seen["p"] = p
        return stable and (not same_page(p, current) or other_entry(p, current)) and page_consistent(p)
    if wait_for("next page", moved, 4, 0.2):
        return seen["p"]
    late = settled_page(4)
    return late if late is not None and (not same_page(late, current) or other_entry(late, current)) else None


def walk_pages(limit: int = 400):
    """Every page of the tree in order, selecting each: yields
    (index, page). Channels are expanded on the way. The walk goes on
    until Down moves nothing; the tree's last entry (`first_page`, End)
    only tells a short walk from a finished one: a Down that moves nothing
    before it is pressed once more (logged) and, failing again, ends the
    walk short (`WALK["short"]`). Past it the walk continues, since End
    selects a collapsed channel's node whose pages appear only once the
    walk expands it (Hager 'Ausgang 9')."""
    page = first_page()
    last = page.pop("last", None)
    reached = last is None
    WALK["short"] = False
    for i in range(limit):
        yield i, page
        reached = reached or same_page(page, last)
        if collapsed_entry(page):
            expand_entry(page)
        nxt = next_page(page)
        if nxt is None and not reached:
            log(f"walk: Down did not move from {page.get('crumb')!r}; once more")
            nxt = next_page(page)
            if nxt is None:
                WALK["short"] = True
        if nxt is None:
            return
        page = nxt


def collapsed_entry(page: dict) -> bool:
    """Whether the page's tree entry is drawn with a '+' expander: a page
    whose child pages (module instances, #1054) stay hidden until it is
    expanded. Down skips them, so the walk listed only '+ General' on
    syn-module-repeat after 'Number of feeders' = 2 (2026-11-12)."""
    return (page.get("page") or "").lstrip().startswith("+")


def expand_entry(page: dict) -> bool:
    """Expand the selected collapsed entry with Right (the tree keeps the
    keyboard focus during the walk, see `next_page`); True once ETS draws
    it without the '+'."""
    keys("{RIGHT}")
    done = wait_for("tree entry expanded", lambda: not collapsed_entry(selected_page() or {}), 2, 0.2)
    if not done:
        log(f"walk: {page.get('page')!r} did not expand")
    return bool(done)


# Whether the last walk ended before the tree's last page.
WALK: dict = {"short": False}


@flow("param_pages")
def flow_param_pages(req: dict) -> dict:
    """Device `ia`'s parameter pages as ETS lists them (channels expanded),
    each {crumb, page}; with `rows`, each page's rows (`param_rows`): the
    survey a parameter set is drawn from (#424)."""
    require_project(req["project"])
    entry = open_device_parameters(req["ia"])
    pages: list[dict] = []
    for i, page in walk_pages(int(req.get("limit", 400))):
        if not page.get("page"):
            # A channel node ('Ausgang 5'): Down selects its first page next.
            continue
        if pages and channel_node_of(pages[-1], page):
            # A channel node read with its first page's highlight
            # ('Ausgang 5 > ...'): keep the page itself, selected next.
            pages.pop()
        if req.get("rows"):
            page = {**page, "rows": param_rows()}
        pages.append({**page, "index": len(pages), "page_n": page_occurrence(pages, page)})
    return {"pages": pages, "menu_entry": entry, "short": WALK["short"]}


def page_occurrence(pages: list[dict], page: dict) -> int:
    """How many pages of `pages` (walk order) read as `page` (`same_page`):
    0 for the first page of its name, 1 for the second 'Feeder' (#1054).
    `go_to_page` takes it back as the target's `page_n`."""
    return sum(1 for p in pages if same_page(p, page))


def tree_entries() -> list[dict]:
    return [l for l in ocr_ink(PARAM_LIST) if len(l["text"].strip()) > 1]


def scroll_tree(notches: int) -> bool:
    """Turn the wheel over the page tree (positive: up); True when the
    visible entries changed."""
    from pywinauto import mouse

    before = [l["text"] for l in tree_entries()]
    s_ = scale()
    for _ in range(abs(notches)):
        mouse.scroll(coords=(int(900 * s_), int(1200 * s_)), wheel_dist=10 if notches > 0 else -10)
    return bool(wait_for("tree scrolled", lambda: [l["text"] for l in tree_entries()] != before, 1.5, 0.2))


def go_to_page(target: dict, limit: int = 60) -> dict:
    """Select the page `target` ({crumb, page}) by clicking its entry in
    the page tree, scrolled with the wheel to find it, else by walking the
    tree (a page in a collapsed channel). No keys before a tree entry was
    clicked, since the focus may sit in a field the last change typed
    into. Raises LookupError when no page is it (a page the configuration
    hides).

    `page_n` in `target` picks the n-th page of that name in tree order
    (`param_pages` counts them the same way, `page_occurrence`): with the
    tree scrolled to the top, the n-th entry like it on screen is clicked;
    when fewer show, the tree is walked and the n-th page like it taken."""
    n = int(target.get("page_n") or 0)
    if n:
        return go_to_nth_page(target, n)
    if same_page(selected_page(), target):
        return selected_page()
    tried: set = set()
    while scroll_tree(5):
        pass
    for _ in range(limit):
        for l in tree_entries():
            key = (_norm(l["text"]), l["y"])
            if not _alike(l["text"], target.get("page")) or key in tried:
                continue
            tried.add(key)
            click(l["x"] + l["w"] // 2, l["y"] + l["h"] // 2)
            if wait_for("page by click", lambda: same_page(selected_page(), target), 2.5, 0.25):
                return selected_page()
        if not scroll_tree(-5):
            break
        tried = set()
    log(f"go_to_page: no tree entry like {target.get('page')!r}; seen {[l['text'] for l in tree_entries()][:40]}")
    # A page of a channel ETS shows collapsed (after a download): walk the
    # tree, which expands channels. `first_page` clicks a tree entry first,
    # so the keys go to the tree, not to a field.
    for _, page in walk_pages():
        if same_page(page, target):
            return page
    raise LookupError(f"page {target.get('crumb')!r} not in the tree")


def go_to_nth_page(target: dict, n: int) -> dict:
    """`go_to_page` for the `n`-th (from 0) page named like `target`."""
    while scroll_tree(5):
        pass
    hits = sorted((l for l in tree_entries() if _alike(l["text"], target.get("page"))), key=lambda l: l["y"])
    if len(hits) > n:
        l = hits[n]
        click(l["x"] + l["w"] // 2, l["y"] + l["h"] // 2)
        if wait_for("page by click", lambda: same_page(selected_page(), target), 2.5, 0.25):
            return {**selected_page(), "page_n": n}
    # Not all on screen (or a collapsed parent): walk, counting.
    seen, last = 0, None
    for _, page in walk_pages():
        if not same_page(page, target):
            continue
        if last is not None and not other_entry(last, page) and abs((last.get("y") or 0) - (page.get("y") or 0)) < 10:
            continue  # the same entry read twice (a channel node, then its page)
        if seen == n:
            return {**page, "page_n": n}
        seen, last = seen + 1, page
    raise LookupError(f"page {target.get('crumb')!r} ({n}) not in the tree")


def find_param_row(rows: list[dict], label: str, n: int = 0) -> dict | None:
    want = _norm(label)
    hits = [r for r in rows if _norm(r["label"]) == want]
    if len(hits) <= n:
        hits = [r for r in rows if difflib.SequenceMatcher(None, want, _norm(r["label"])).ratio() >= 0.9]
    return hits[n] if len(hits) > n else None


def dropdown_options(row: dict) -> list[str]:
    """Open the row's dropdown and read its options (popup, UI Automation);
    the list stays open for `pick_option`."""
    x0, x1 = row["box"]
    click((x0 + x1) // 2, row["y"])
    pop = wait_for("dropdown list", lambda: next((p for p in ets_popups()
                                                  if p.descendants(control_type="ListItem")), None), 3, 0.2)
    if pop is None:
        # A dropdown ETS shows but does not open (read-only, Ekinex 4741
        # 'Last Typ', 2026-11-11): nothing was changed, so the change is
        # unreachable, not a failed write.
        keys("{ESC}")
        raise LookupError(f"the dropdown of {row['label']!r} opened no list (read-only?)")
    out = []
    for it in pop.descendants(control_type="ListItem"):
        texts = [t.window_text() for t in it.descendants(control_type="Text")]
        out.append(" ".join(t for t in texts if t).strip())
    return out


def popup_lists_open() -> bool:
    """Whether an ETS popup still shows list items (an open dropdown). A
    popup that closes between `ets_popups()` and the query raises
    (pywinauto's InvalidWindowHandle): that one is closed, not an error. The
    race failed `pick_option` twice on the MDT 00B1 rerun of #1050."""
    for p in ets_popups():
        try:
            if p.descendants(control_type="ListItem"):
                return True
        except Exception:  # noqa: BLE001 - a vanished popup is a closed one
            continue
    return False


def pick_option(text: str) -> bool:
    """Click the open dropdown's option `text`."""
    for pop in ets_popups():
        try:
            items = pop.descendants(control_type="ListItem")
        except Exception:  # noqa: BLE001 - a popup closed under us holds no option
            continue
        for it in items:
            texts = " ".join(t.window_text() for t in it.descendants(control_type="Text")).strip()
            if texts == text:
                it.click_input()
                COUNTS["clicks"] += 1
                # The open list covers the dropdown: read the row after.
                wait_for("dropdown closed", lambda: not popup_lists_open(), 2, 0.15)
                return True
    return False


def choose_value(row: dict, req: dict, options: list[str] | None = None) -> str:
    """The value to set: `value` as given, else (with `pick`, a float in
    [0, 1)) one of the other options of the row, chosen by `pick`."""
    if req.get("value") not in (None, ""):
        return str(req["value"])
    others = [o for o in (options or []) if _norm(o) != _norm(row.get("value") or "")]
    if not others:
        raise LookupError(f"{row['label']!r} offers no other value than {row.get('value')!r}")
    return others[min(int(float(req.get("pick", 0)) * len(others)), len(others) - 1)]


def clipboard_text() -> str:
    import win32clipboard

    win32clipboard.OpenClipboard()
    try:
        return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
    except TypeError:  # no text on the clipboard
        return ""
    finally:
        win32clipboard.CloseClipboard()


def field_ocr(img, s: float, row: dict) -> str:
    """A field's content read off the screenshot without touching it: OCR,
    and for a lone number OCR skips, its ink repeated (`cell_number`).
    Best effort; `field_value` reads it exactly but clicks the field."""
    from PIL import ImageOps

    x0, x1 = row["box"]
    box = tuple(int(v) for v in ((x0 + 6 - PARAM_ROWS[0]) * s, (row["y"] - 14 - PARAM_ROWS[1]) * s,
                                 (x1 - 32 - PARAM_ROWS[0]) * s, (row["y"] + 14 - PARAM_ROWS[1]) * s))
    crop = img.crop(box)
    import winocr

    COUNTS["ocr"] += 1
    big = ImageOps.autocontrast(ImageOps.grayscale(crop.resize((crop.width * 3, crop.height * 3))), cutoff=1)
    text = " ".join(l["text"] for l in winocr.recognize_pil_sync(big.convert("RGB"), "de")["lines"]).strip()
    if text:
        return text
    n = cell_number(ImageOps.grayscale(crop))
    return "" if n is None else str(n)


def field_value(row: dict) -> str:
    """A number or text field's content, by the clipboard: OCR reads no
    lone digit in a field, magnified or not (2026-11-10). The field is
    clicked, selected and copied; nothing is typed."""
    import win32clipboard

    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.CloseClipboard()
    click(CONTROL_X + 30, row["y"])
    keys("^a")
    keys("^c")
    return (wait_for("field copied", clipboard_text, 1.5, 0.1) or "").strip()


def type_into(row: dict, value: str, page: dict | None = None) -> None:
    """Replace a field's content: click, select all, type, Tab. The field
    takes keys a moment after the click: typed 0.2 s after it, the 1 for
    the hours of Hager's 'Sendeverzögerung' was lost (2026-11-10). Right
    after a page walk the first click into a field switched the page to
    another tree entry once ('Ausgang 10', 2026-11-10), and the keys went to
    the tree: with `page`, the page is checked after the click and selected
    again, and nothing is typed while another page shows."""
    for attempt in range(2):
        click(CONTROL_X + 30, row["y"])
        time.sleep(0.5)
        if page is None or same_page(selected_page(), page):
            break
        go_to_page(page)
    else:
        raise LookupError(f"the page left {page.get('crumb')!r} when its field was clicked")
    keys("^a")
    time.sleep(0.1)
    keys(value)
    time.sleep(0.3)
    keys("{TAB}")


def set_row(row: dict, req: dict, page: dict | None = None) -> tuple[str, str]:
    """Set `row` as `req` asks; returns (the value asked, what to compare
    the row's value with afterwards)."""
    kind = row["kind"]
    if kind == "checkbox":
        value = str(req.get("value") or ("0" if row["value"] == "1" else "1"))
        if value != row["value"]:
            click(CONTROL_X + 16, row["y"])
        return value, value
    if kind == "radio":
        # An option whose text was not read is never chosen nor set: its
        # value would be recorded as '' and map to nothing (#1049).
        value = choose_value(row, req, [o["text"] for o in row["options"] if o["text"]])
        opt = next((o for o in row["options"] if o["text"] and _norm(o["text"]) == _norm(value)), None)
        if opt is None:
            raise LookupError(f"{row['label']!r} has no option {value!r}: {[o['text'] for o in row['options']]}")
        click(opt["x"], opt.get("y", row["y"]))
        return value, opt["text"]
    if kind == "dropdown":
        options = dropdown_options(row)
        value = choose_value(row, req, options)
        if not pick_option(value):
            keys("{ESC}")
            raise LookupError(f"{row['label']!r} has no option {value!r}: {options}")
        return value, value
    if kind in ("number", "text"):
        value = choose_value(row, req)
        type_into(row, value, page)
        return value, value
    raise LookupError(f"{row['label']!r}: no control ETS lets the driver set ({kind})")


def row_bbox(row: dict) -> tuple[int, int, int, int]:
    """The screen box of a parameter row, label to the control column's
    right end, for a screenshot of a row the driver could not set."""
    y = int(row.get("y") or 0)
    return (PARAM_LIST[2], max(y - 40, PARAM_ROWS[1]), PARAM_ROWS[2], y + 40)


@flow("set_param")
def flow_set_param(req: dict) -> dict:
    """Set the parameter of row `label` (the `n`-th row of that label) on
    page `page` ({crumb, page} from `param_pages`) of device `ia`. With
    `value` the value as ETS shows it ('1'/'0' for a checkbox), else `pick`
    chooses another option of a radio or dropdown row (a checkbox toggles).
    The row is read again until it shows the value. A page or row not
    shown: {"set": false, "unreachable": why}."""
    require_project(req["project"])
    open_device_parameters(req["ia"])
    try:
        page = go_to_page(req["page"])
    except LookupError as exc:
        return {"set": False, "unreachable": str(exc)}
    rows = param_rows()
    row = find_param_row(rows, req["label"], int(req.get("n", 0)))
    if row is None:
        return {"set": False, "unreachable": f"no row {req['label']!r} on the page",
                "seen": [r["label"] for r in rows][:30], "page": page}
    if req.get("kind") and req["kind"] != row["kind"]:
        return {"set": False, "unreachable": f"{req['label']!r} is a {row['kind']} now, not a {req['kind']}",
                "row": row}
    try:
        value, expect = set_row(row, req, page)
    except LookupError as exc:
        out = {"set": False, "unreachable": str(exc), "row": row}
        if row["kind"] == "none":
            # A row the classifier read as no control (two options with
            # their circles not found, #1054: 'O overwrite keep'): the row's
            # pixels are the evidence the next fix needs.
            try:
                buf = io.BytesIO()
                grab(row_bbox(row)).save(buf, format="PNG")
                out["row_png"] = base64.b64encode(buf.getvalue()).decode()
            except Exception as shot:  # noqa: BLE001 - evidence, not a step
                out["row_png_error"] = str(shot)[:200]
        return out
    seen: dict = {}

    def shows():
        wait_busy()
        after = find_param_row(param_rows(), req["label"], int(req.get("n", 0)))
        if after is not None and after["kind"] in ("number", "text"):
            after["value"] = field_value(after)
        seen["row"] = after
        return after is not None and _norm(after.get("value") or "") == _norm(expect)
    ok = wait_for("parameter shows value", shows, 4, 0.4)
    if not ok and row["kind"] in ("number", "text") and seen.get("row"):
        # Once more: a field that lost the keys keeps its old value.
        try:
            type_into(seen["row"], value, page)
        except LookupError as exc:
            return {"set": False, "unreachable": str(exc), "row": row}
        ok = wait_for("parameter shows value", shows, 4, 0.4)
    return {"set": bool(ok), "value": value, "before": row.get("value"), "row": seen.get("row"), "page": page}


@flow("read_param")
def flow_read_param(req: dict) -> dict:
    """The value ETS shows for row `label` (`n`-th of that label) on page
    `page` of device `ia`, as `set_param` reads it back (a field by the
    clipboard): {"shown": false, "why": ...} when the page or row is not
    shown. The parameter-set run reads every change once more after the
    last one, so the model holds what ETS shows, not what was meant."""
    require_project(req["project"])
    open_device_parameters(req["ia"])
    try:
        page = go_to_page(req["page"])
    except LookupError as exc:
        return {"shown": False, "why": str(exc)}
    rows = param_rows()
    row = find_param_row(rows, req["label"], int(req.get("n", 0)))
    if row is None:
        return {"shown": False, "why": f"no row {req['label']!r} on the page", "page": page}
    if row["kind"] in ("number", "text"):
        row["value"] = field_value(row)
    # The exact match `find_param_row` and `params.model_changes` count by:
    # 'Sendeverzögerung Ein' and '... Aus' are two labels.
    rows_with_label = sum(1 for r in rows if _norm(r["label"]) == _norm(req["label"]))
    return {"shown": True, "row": row, "page": page, "rows_with_label": rows_with_label}


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


# The catalog's result columns (layout x ranges) as measured on 2026-10-28:
# name, order number, application, version.
CATALOG_COLS = {"name": (1130, 1970), "order": (1970, 2240), "application": (2300, 2560), "version": (2560, 2740)}
CATALOG_HEADS = {"name": "Name", "order": "Bestellnummer", "application": "Applikation", "version": "Version"}


def word_x(line: dict, word: str) -> int | None:
    """The left x of `word` inside an OCR line, by its share of the line's
    characters (OCR joins neighbouring headers: 'Medie Applikation')."""
    at = line["text"].find(word)
    if at < 0:
        return None
    return line["x"] + line["w"] * at // max(len(line["text"]), 1)


def catalog_columns(header: list[dict]) -> dict[str, tuple[int, int]]:
    """The x ranges of the catalog's name, order, application and version
    columns from its header row's OCR lines: each column from just left of
    its header to just left of the next one's. ETS showed two more columns
    ('Sic', 'Hersteller') before 'Name' on 2026-11-10 and every cell moved
    330 px to the right: the rows' order cell read empty and every add
    failed as a version mismatch (#478). Columns whose header OCR missed
    keep the measured ranges."""
    found = {}
    for key, word in CATALOG_HEADS.items():
        xs = [x for l in header if (x := word_x(l, word)) is not None]
        if xs:
            found[key] = min(xs) - 20
    if len(found) < len(CATALOG_HEADS):
        return dict(CATALOG_COLS)
    order = ["name", "order", "application", "version"]
    cols = {}
    for i, key in enumerate(order):
        lo = found[key]
        hi = found[order[i + 1]] if i + 1 < len(order) else lo + (CATALOG_COLS["version"][1] - CATALOG_COLS["version"][0])
        cols[key] = (lo, hi)
    # The order column ends where 'Medie' starts, not at 'Applikation'.
    medie = [x for l in header if (x := word_x(l, "Medi")) is not None]
    if medie and cols["order"][0] < min(medie) - 20 < cols["order"][1]:
        cols["order"] = (cols["order"][0], min(medie) - 20)
    return cols


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
    # The header row sits 31 px above the scanned area (y 1409 at dy 0).
    cols = catalog_columns(ocr((x0, y0 + dy - 50, x1, y0 + dy + 5)))
    name_x = cols["name"][0]
    lines = ocr((x0, y0 + 40 + dy, x1, min(y1 + dy, 2440)))
    if expand and not any(l["x"] >= name_x for l in lines):
        # No product rows: expand collapsed manufacturer headers (left column;
        # the first one sits just above the scanned area).
        heads = [l for l in ocr((x0, y0 + dy, 1300, min(y1 + dy, 2440))) if l["x"] < 800 and l["y"] > y0 + dy + 10]
        for head in heads[:6]:
            click(707, head["y"] + head["h"] // 2)
            time.sleep(1)
        lines = ocr((x0, y0 + 40 + dy, x1, min(y1 + dy, 2440)))
    # The first group's header, just above the scanned rows (left column).
    band = [l for l in ocr((x0, y0 + dy, name_x, y0 + 40 + dy)) if l["y"] > y0 + dy + 5]
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
        version = cell(*cols["version"])
        order = cell(*cols["order"])
        if not version and order:
            # A short version ("1.1") can vanish at native size: read the
            # cell magnified, at more than one zoom.
            for zoom in (3, 2, 4):
                version = " ".join(l["text"] for l in ocr((cols["version"][0], r["y"] - 20, cols["version"][1], r["y"] + 20),
                                                          zoom=zoom)).strip()
                if version:
                    break
        if not version and not order:
            # A manufacturer group header: it names the rows below it.
            manufacturer = " ".join(c["text"] for c in sorted(r["cells"], key=lambda c: c["x"])).strip()
            continue
        out.append({"y": r["y"], "name": cell(*cols["name"]), "order": order,
                    "application": cell(*cols["application"]), "version": version, "online": row_is_online(r["y"]),
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
    catalog_layout()
    return {"rows": catalog_rows()}


@flow("catalog_add")
def flow_catalog_add(req: dict) -> dict:
    """Search the catalog for `search` (an order number), pick the row whose
    order number matches and whose application version is `version` (as ETS
    shows it, e.g. "2.3"), and add it to line 1.1. Returns the device list
    and the row added, which carries its manufacturer group header (#881)."""
    require_project(req["project"])
    dismiss_password_dialog(req.get("project_password"))
    wait_busy()
    # ETS moves its splitters between jobs at times, and leaves the Katalog
    # panel collapsed after the parameter editor: put them back first.
    restore_tree_splitter()
    catalog_layout()
    closed_delete_dialog = close_delete_dialog()
    before = {d["ia"] for d in flow_devices(req)["devices"]}
    if before and req.get("clear", True):
        # A device a failed delete left in the project pushes the new one to
        # another address (#876): delete it first, or report the clean-up as
        # failed instead of adding next to it (#997).
        for ia in sorted(before):
            try:
                gone = flow_delete_device({**req, "ia": ia}).get("deleted")
            except Exception as exc:  # noqa: BLE001 - reported as the clean-up failure
                raise RuntimeError(f"clean-up failed: device {ia} left in the project before the add: {exc}") from exc
            if not gone:
                raise RuntimeError(f"clean-up failed: device {ia} left in the project before the add")
        before = {d["ia"] for d in flow_devices(req)["devices"]}
        if before:
            raise RuntimeError(f"clean-up failed: devices {sorted(before)} left in the project before the add")
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
            "certificate": certificate, "closed_delete_dialog": closed_delete_dialog}


@flow("delete_device")
def flow_delete_device(req: dict) -> dict:
    require_project(req["project"])
    close_delete_dialog()
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
                confirm_delete()
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
GO_COLS = {"number": (690, 830), "name": (830, 1280), "ga": (1840, 2000), "size": (2000, 2090), "flags": (2090, 2300)}
GA_RE = re.compile(r"\d{1,2}/\d{1,2}/\d{1,3}")
SIZE_RE = re.compile(r"(\d+)\s*(bits?|bytes?)\b", re.IGNORECASE)


def object_size(text: str) -> str | None:
    """The 'Länge' cell normalised ('1 bit', '2 bytes'), or None. ETS links
    an address only to objects of one size (#478), so the links variant
    pairs a second address by it."""
    m = SIZE_RE.search(text)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower().rstrip("s")
    return f"{n} {unit}{'s' if n != 1 and unit == 'byte' else ''}"
# Centres of the K, L, S, Ü, A flag columns.
GO_FLAG_X = (2120, 2159, 2200, 2241, 2280)


def tree_node_of(text: str, ia: str) -> bool:
    """True when a Topologie tree line is the node of device `ia`: the
    address as a whole word (not the line '1.1 TP Linie', not 1.1.10)."""
    return re.search(rf"(?<![\d.]){re.escape(ia)}(?![\d.])", text.replace(" ", " ")) is not None


def open_device_objects(ia: str) -> None:
    """Select device `ia` in the Topologie tree and show its object table."""
    click(*line_1_1())
    time.sleep(1)
    # The node reads '> 1.1.1 <product>' (its expander arrow first); OCR
    # reads the arrow and the device icon as a letter at times ('m 1.1.1 KCI
    # 4 S0' missed, Zennio KCI 4 S0, 2026-11-10), so the address is looked
    # for as a word anywhere in the line.
    lines = ocr(LAYOUT["tree"])
    tree = [l for l in lines if tree_node_of(l["text"], ia)]
    if not tree:
        raise RuntimeError(f"device {ia} not in the Topologie tree: {[l['text'] for l in lines]}")
    t = tree[0]
    click(t["x"] + t["w"] // 2, t["y"] + t["h"] // 2)
    # OCR joins the tab strip into one line ('Kanäle 5 Kommunikationsobjekte 22');
    # it takes a few seconds to switch from the line's tabs.
    seen = {"tabs": ""}

    def tabs_shown() -> bool:
        seen["tabs"] = " ".join(l["text"] for l in ocr((680, 150, 1600, 220)))
        return "Kommunikationsobjekte" in seen["tabs"]
    time.sleep(0.3)
    wait_for("device tabs", tabs_shown, 8, 0.3)
    tabs = seen["tabs"]
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
    # The table is there when its number column reads a number; a table of
    # object 1 alone never does (OCR skips a lone '1'): it waits out the 3 s.
    time.sleep(0.3)
    wait_for("object table", table_numbers, 3)


def table_numbers() -> dict[int, int]:
    """The object numbers the open table's number column shows: row centre y
    -> number (magnified: a lone '1' in a selected row went unread at 1x)."""
    out = {}
    for l in ocr((GO_COLS["number"][0], GO_TABLE[1], GO_COLS["number"][1], GO_TABLE[3]), zoom=2):
        if l["text"].strip().isdigit():
            out[l["y"] + l["h"] // 2] = int(l["text"].strip())
    return out


def view_changed(rows: list[dict], numbers: dict[int, int]) -> bool:
    """True when the table no longer shows `rows` where they were: a number
    read now that `rows` lack or that moved by a row (14 px), or no number
    at all. The link flow re-reads the whole table only then (#478)."""
    if not numbers:
        return True
    at = {r["number"]: r["y"] for r in rows}
    return any(n not in at or abs(at[n] - y) >= 14 for y, n in numbers.items())


def ink_box(img, dark: int = 150) -> tuple[int, int, int, int] | None:
    """The bounding box (x0, y0, x1, y1, exclusive) of the pixels darker
    than `dark` in a greyscale image, or None when it holds no ink."""
    xs = [x for x in range(img.width) if any(img.getpixel((x, y)) < dark for y in range(img.height))]
    ys = [y for y in range(img.height) if any(img.getpixel((x, y)) < dark for x in range(img.width))]
    return (xs[0], ys[0], xs[-1] + 1, ys[-1] + 1) if xs and ys else None


def has_hole(img) -> bool:
    """True when the ink of a number cell (greyscale) has light pixels
    between dark ones across its middle row: a 0 (or a 6, 8, 9)."""
    box = ink_box(img)
    if box is None:
        return False
    x0, y0, x1, y1 = box
    mid = [img.getpixel((x, (y0 + y1) // 2)) < 150 for x in range(x0, x1)]
    first, last = mid.index(True), len(mid) - 1 - mid[::-1].index(True)
    return any(not d for d in mid[first:last + 1])


def lone_one(img) -> bool:
    """True when a number cell (greyscale) holds a lone 1: one glyph at most
    0.45 times as wide as it is tall, without a hole. A 1 measured 6 x 17
    pixels, a 0 or a 7 is half as wide as tall or more (2026-11-10)."""
    box = ink_box(img)
    if box is None:
        return False
    x0, y0, x1, y1 = box
    return (x1 - x0) <= 0.45 * (y1 - y0) and not has_hole(img)


def cell_digit(img, ocr_number: int | None) -> int | None:
    """The number of a cell OCR's plain pass skipped, from the repeated-glyph
    OCR (`ocr_number`) checked against the ink: OCR read the selected row's
    lone 1 of the ise KNX Vaillant as 0 (2026-11-10), so a 1 must be a lone
    narrow glyph and a 0 a glyph with a hole that is not one; a lone 1 is
    taken by its shape whatever OCR read. None when they disagree."""
    if lone_one(img):
        # Only a 1 is that narrow: whatever OCR made of it (0 and 4 for the
        # Vaillant's selected row).
        return 1
    if ocr_number == 1 or ocr_number == 0 and not has_hole(img):
        return None
    return ocr_number


def repeated_number(text: str) -> int | None:
    """The number OCR read in a cell repeated three times ('7 7 7', '12 12
    12', 'lll' for 111 read as letters), or None unless all repeats agree."""
    t = text.translate(str.maketrans({"l": "1", "I": "1", "|": "1", "O": "0", "o": "0", "D": "0"}))
    parts = t.split()
    if len(parts) == 1 and len(parts[0]) % 3 == 0 and parts[0].isdigit():
        k = len(parts[0]) // 3
        parts = [parts[0][i:i + k] for i in range(0, len(parts[0]), k)]
    if len(parts) == 3 and all(p.isdigit() for p in parts) and len(set(parts)) == 1:
        return int(parts[0])
    return None


def cell_number(img) -> int | None:
    """The object number in a number cell (greyscale crop) that OCR skipped:
    the cell's ink repeated three times side by side, magnified, read by OCR
    (`repeated_number`)."""
    import winocr
    from PIL import Image, ImageOps

    box = ink_box(img)
    if box is None:
        return None
    glyph = img.crop((max(box[0] - 2, 0), max(box[1] - 2, 0), box[2] + 2, box[3] + 2))
    gap = glyph.height
    canvas = Image.new("L", (3 * glyph.width + 4 * gap, glyph.height + 2 * gap), 255)
    for i in range(3):
        canvas.paste(glyph, (gap + i * (glyph.width + gap), gap))
    canvas = ImageOps.autocontrast(canvas.resize((canvas.width * 4, canvas.height * 4)), cutoff=1)
    COUNTS["ocr"] += 1
    text = " ".join(l["text"] for l in winocr.recognize_pil_sync(canvas.convert("RGB"), "de")["lines"])
    return repeated_number(text)


def read_objects(numbers: list[int] | None = None) -> list[dict]:
    """Rows of the open object table: number, name, addresses, size, flags.

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
            rows[cy] = {"number": int(l["text"].strip()), "y": cy, "name": "", "gas": [], "size": None, "flags": ""}
    # Rows whose number OCR missed: Windows OCR never reads a lone '1'
    # (2026-10-28, any zoom or crop). Infer it from the neighbours when only
    # one number fits, else take a single narrow glyph as '1'.
    for l in lines:
        cy = l["y"] + l["h"] // 2
        if GO_COLS["name"][0] <= l["x"] + 4 < GO_COLS["name"][1] and all(abs(y - cy) >= 14 for y in rows):
            rows[cy] = {"number": None, "y": cy, "name": "", "gas": [], "size": None, "flags": ""}
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
        # Read the cell's digits by OCR of the glyphs repeated ('7 7 7'):
        # Windows OCR skips a lone digit but reads a word of them; a 0 or 1
        # it reads must match the glyph's shape (`cell_digit`). Until 2026-11-10
        # every narrow glyph was taken as 1: the MDT AKK's object 0 and the
        # DALI Basic's object 2 were recorded as 1, and the links oracle
        # modelled the neighbour of the object ETS linked (#478).
        n = cell_digit(img, cell_number(img))
        if n is not None and (prev is None or prev < n) and (nxt is None or nxt > n):
            r["number"] = n
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
        # 'Länge', right-aligned: OCR may join it to the address before it.
        if GO_COLS["ga"][0] <= l["x"] + l["w"] and l["x"] < GO_COLS["size"][1] and r["size"] is None:
            r["size"] = object_size(l["text"])
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
    park_mouse()
    return {"objects": read_objects(req.get("numbers"))}


def _object_row(number: int, numbers: list[int] | None = None) -> dict:
    rows = read_objects(numbers)
    hit = [r for r in rows if r["number"] == number]
    if not hit:
        raise RuntimeError(f"object {number} not in the table (hidden by a parameter?): {[r['number'] for r in rows]}")
    return hit[0]


# The 'Mit Gruppenadresse verbinden' dialog (layout coordinates, the
# screenshot of 2026-11-10 at half scale: title at y ~610, the address field
# framed at x 1606..1846, y 1674..1756, 'Verbinden' and 'Abbrechen' at y ~1887).
LINK_TITLE = (1500, 560, 2600, 680)
LINK_FIELD = (1606, 1670, 1848, 1760)
LINK_BUTTONS = (1800, 1830, 2560, 1920)
# 'Verbinden' alone: OCR of the wider strip may join both buttons in a line.
LINK_VERBINDEN = (1800, 1830, 2300, 1910)
LINK_LIST = (1600, 960, 2440, 1500)


def link_dialog_open() -> bool:
    return find_text("Mit Gruppenadresse verbinden", LINK_TITLE) is not None


def close_link_dialog() -> bool:
    """Cancel a 'Mit Gruppenadresse verbinden' dialog left open with
    'Abbrechen' (Escape when OCR misses the button). True when one was open
    and is gone now. Like the delete confirmation it is found by OCR."""
    if not link_dialog_open():
        return False
    hit = button_hit(ocr(LINK_BUTTONS), "Abbrechen")
    if hit:
        log(f"closing a link dialog with Abbrechen at ({hit['click_x']}, {hit['click_y']})")
        click(hit["click_x"], hit["click_y"])
    else:
        log("closing a link dialog with Escape ('Abbrechen' not read)")
        keys("{ESC}")
    # Was a fixed 1.5 s, and 1.5 s more after an Escape.
    if not wait_for("link dialog cancelled", lambda: not link_dialog_open(), 1.5):
        keys("{ESC}")
        wait_for("link dialog cancelled", lambda: not link_dialog_open(), 1.5)
    return not link_dialog_open()


def red_frame(img) -> bool:
    """True when the address field's crop (`LINK_FIELD`) holds ETS's red
    error frame: a row and a column of strong red each spanning most of the
    crop. The address icon inside the field is red as well, but small: it
    never spans the crop (half-scale screenshot of 2026-11-10: frame rows of
    121 red pixels of 121, the icon 13)."""
    rgb = img.convert("RGB")
    w, h = rgb.width, rgb.height

    def red(x: int, y: int) -> bool:
        r, g, b = rgb.getpixel((x, y))
        return r > 170 and g < 100 and b < 100
    row = any(sum(red(x, y) for x in range(w)) > 0.8 * w for y in range(h))
    col = any(sum(red(x, y) for y in range(h)) > 0.7 * h for x in range(w))
    return row and col


def greyed_out(img) -> bool:
    """True when a button label's crop holds no dark ink: ETS greys out a
    disabled 'Verbinden' (lightest 144 of 255, no pixel under 120) where
    'Abbrechen' beside it reads near black (47, 156 pixels under 120;
    2026-11-10)."""
    return not any(p < 120 for p in img.convert("L").getdata())


def link_refusal(button: dict) -> str | None:
    """Why the open link dialog will not take the typed address, or None:
    the red frame of the address field or a greyed-out 'Verbinden' (the OCR
    line `button`). The reason names the addresses the dialog's list offers
    (only those of the object's size)."""
    why = []
    if red_frame(grab(LINK_FIELD)):
        why.append("the address field shows an error")
    pad = 4
    if greyed_out(grab((button["x"] - pad, button["y"] - pad, button["x"] + button["w"] + pad, button["y"] + button["h"] + pad))):
        why.append("'Verbinden' is disabled")
    if not why:
        return None
    offered = sorted({ga for l in ocr(LINK_LIST) for ga in GA_RE.findall(l["text"].replace(" ", ""))})
    return " and ".join(why) + f" (the dialog offers {', '.join(offered) or 'no address'}, addresses of the object's size)"


# ETS's questions after a link: a dialog titled 'Mit Gruppenadresse
# verbinden' as well, with a question icon, its title at y ~1068 (the link
# dialog's is at ~610), OK and Abbrechen at y ~1456 where its width puts
# them. Seen: an address of another object size ('... abweichende
# Objektgröße ...', syn-minimal 2026-10-31, 879 414 knx) and datatypes of
# different main types ('Sollen Datentypen aus verschiedenen
# Hauptdatentypen zugewiesen werden?', ise KNX Hue, 2026-11-10). Both are
# answered OK, as a person linking the object would.
QUESTION_TITLE = (1400, 1030, 2850, 1110)
QUESTION_BUTTONS = (1260, 1410, 2850, 1510)


def _ga_text(text: str) -> str:
    """An address as OCR reads it in the dialog's field, normalised: no
    spaces, the letters it takes for 1 and 0 back to digits."""
    return re.sub(r"\s", "", text).translate(str.maketrans({"l": "1", "I": "1", "|": "1", "O": "0", "o": "0"}))


def field_shows(ga: str) -> bool:
    """True when the link dialog's address field reads `ga`: the typed text
    has landed and ETS has judged it (red frame or not)."""
    return any(ga in _ga_text(l["text"]) for l in ocr(LINK_FIELD, zoom=2))


def gas_at(y: int) -> list[str]:
    """The addresses the object table's row at `y` shows (the address column
    and the text left of it, magnified as `read_objects` reads them)."""
    band = (GO_COLS["ga"][0] - 400, y - 18, GO_COLS["size"][1], y + 18)
    found: list[str] = []
    for l in ocr(band, zoom=3):
        for ga in GA_RE.findall(l["text"].replace(" ", "")):
            if ga not in found:
                found.append(ga)
    return found


def link_row(row: dict, number: int, ga: str) -> dict:
    """The dialog part of one link in the open object table: the row's
    context menu 'Verbinden mit...', the address typed into the dialog's
    field, 'Erstellen & Verbinden' (ETS creates the address when the project
    lacks it) or 'Verbinden'. {"linked": True} once the dialog closed, or
    {"linked": False, "refused": why} when ETS refused the address and the
    dialog was cancelled. Raises (after closing the dialog) on anything else.

    Every pause is a poll for the state the next click needs (#478): the
    menu item (menu_item polls), the dialog open, the typed address in the
    field, the dialog closed."""
    from pywinauto import mouse

    s = scale()
    # The second link's context menu showed on screen without a MenuItem UI
    # Automation could see (ise KNX Sonos and MDT AKK, 2026-11-10: 'not in
    # any popup', then the open menu covered the Katalog panel for the next
    # import): the entry is clicked by OCR then. A menu that does not come
    # is closed and the row right-clicked again.
    for attempt in range(3):
        mouse.right_click(coords=(int(1000 * s), int(row["y"] * s)))
        COUNTS["clicks"] += 1
        try:
            if not wait_for("context menu", ets_popups, 3):
                raise RuntimeError("no context menu")
            try:
                menu_click("Verbinden mit...", timeout=MENU_UIA["timeout"], settle=0)
            except RuntimeError:
                log(f"link: 'Verbinden mit...' not in the menu's UI Automation tree; by OCR")
                # Once blind, the table's menus stay so for the flow: look
                # only briefly next time.
                MENU_UIA["timeout"] = 0.3
                click_text("Verbinden mit", (900, max(0, row["y"] - 800), 1700, min(2484, row["y"] + 800)))
            break
        except RuntimeError as exc:
            log(f"link: context menu for object {number} failed (attempt {attempt + 1}): {exc}; closing it")
            close_menus()
            if attempt == 2:
                raise
    # The dialog can take several seconds to open (syn-minimal, 2026-10-31).
    if not wait_for("link dialog open", link_dialog_open, 12):
        # One that opens late must not stay (#478).
        time.sleep(3)
        closed = close_link_dialog()
        raise RuntimeError(f"the link dialog did not open{'; it did later, closed with Abbrechen' if closed else ''}")
    click(1720, 1718)  # the address field left of 'Neue Gruppenadresse'
    keys("^a")
    keys(ga)
    # Was a fixed 1.2 s: the field reading the address is the state the
    # red-frame check needs. OCR that cannot read the field costs the 2 s.
    wait_for("address in field", lambda: field_shows(ga), 2, 0.1)
    # The button reads 'Erstellen & Verbinden' for a new address and
    # 'Verbinden' for an existing one; OCR prefixes its link icon ('00').
    buttons = [l for l in ocr(LINK_VERBINDEN) if "Verbinden" in l["text"]]
    if not buttons:
        closed = close_link_dialog()
        raise RuntimeError(f"no 'Verbinden' button in the link dialog; {'closed with Abbrechen' if closed else 'left open'}")
    b = buttons[0]

    def refuse(refused: str) -> dict:
        reason = f"ETS refused {ga} for object {number}: {refused}"
        closed = close_link_dialog()
        log(f"link: {reason}; {'closed with Abbrechen' if closed else 'dialog left open'}")
        if not closed:
            raise RuntimeError(f"{reason}; the link dialog did not close with Abbrechen")
        return {"linked": False, "refused": reason}

    # ETS takes only an address of the object's size (its list offers just
    # those); for another one it frames the field red and greys 'Verbinden'
    # out (ise KNX Sonos object 12, 1 bit, given 1/0/2 of a 1-byte object,
    # 2026-11-10). The red frame is ETS's verdict on the typed text: cancel
    # and report, never wait for a close that cannot come.
    if red_frame(grab(LINK_FIELD)):
        return refuse(link_refusal(b) or "the address field shows an error")
    # The first click after typing only commits the field at times (the
    # dialog stayed open, 2026-10-28): click until the dialog closes. Was a
    # fixed 2 s after each click.
    for _ in range(3):
        click(b["x"] + b["w"] - 60, b["y"] + b["h"] // 2)
        if wait_for("link dialog closed", lambda: not link_dialog_open(), 2.5):
            break
    else:
        refused = link_refusal(b)
        if refused:
            return refuse(refused)
        closed = close_link_dialog()
        raise RuntimeError(f"the link dialog did not close; {'closed with Abbrechen' if closed else 'left open'}")
    # In a secure project, linking a plain address to an object that has a
    # secured one makes ETS ask first ("Sicherheitshinweis": 1/0/2 forced
    # off, linked to the switch object next to 1/0/1, 2026-11-13).
    notice = confirm_security_notice(2.5)
    return {"linked": True, **({"notice": notice} if notice else {})}


# How long `link_row` looks for the menu entry by UI Automation before OCR;
# `flow_links` resets it per call.
MENU_UIA = {"timeout": 1.5}


def link_question_open() -> bool:
    """True while ETS's question after a link is open (`QUESTION_TITLE`)."""
    return find_text("Mit Gruppenadresse verbinden", QUESTION_TITLE) is not None


def answer_link_question(label: str) -> bool:
    """Click `label` ('OK' or 'Abbrechen') in ETS's question after a link
    (Enter or Escape when OCR misses the button); True once it closed."""
    hit = button_hit(ocr(QUESTION_BUTTONS), label)
    if hit:
        click(hit["click_x"], hit["click_y"])
    else:
        keys("{ENTER}" if label == "OK" else "{ESC}")
    return bool(wait_for("link question closed", lambda: not link_question_open(), 3, 0.3))


def close_link_question() -> bool:
    """Cancel ETS's question after a link when one is open: left open after
    a failed link it covered the Katalog panel and every import after it
    failed (879 414 knx and ise KNX Hue, 2026-11-10). True when one was open."""
    if not link_question_open():
        return False
    log("closing a question after a link with Abbrechen")
    answer_link_question("Abbrechen")
    return True


# Where the mouse rests while the object table is read: the right panel's
# empty lower part. Resting over the table, after the click that clears a
# selection, ETS's tooltip showed addresses over rows 95 and 96 of the DALI
# Basic 1f and the last read gave them links ETS never made (2026-11-10).
PARK = (3700, 2200)


def park_mouse() -> None:
    """Move the mouse off the object table (no click), so no tooltip
    covers rows while they are read."""
    from pywinauto import mouse

    s = scale()
    mouse.move(coords=(int(PARK[0] * s), int(PARK[1] * s)))


def close_menus() -> bool:
    """Close context menus ETS has open (Escape until none is left, at most
    three): a late one covers the table and the Katalog panel. True when one
    was open."""
    had = False
    for _ in range(3):
        if not ets_popups():
            break
        had = True
        keys("{ESC}")
        wait_for("menu closed", lambda: not ets_popups(), 1.5)
    return had


def find_row(number: int, rows: list[dict], numbers: list[int] | None = None) -> tuple[dict | None, list[dict]]:
    """The table row of object `number`, and the rows it was found among.
    Looks in `rows` (the last read) first; when it is not there the view
    changed: read again, then scroll the table to its top and down a page at
    a time (the mouse wheel over the rows) until the row shows or the table
    ends."""
    hit = next((r for r in rows if r["number"] == number), None)
    if hit:
        return hit, rows
    rows = read_objects(numbers)
    hit = next((r for r in rows if r["number"] == number), None)
    if hit:
        return hit, rows
    from pywinauto import mouse

    s = scale()
    at = (int(1500 * s), int((GO_TABLE[1] + GO_TABLE[3]) // 2 * s))
    mouse.scroll(coords=at, wheel_dist=40)
    seen: list[int] = []
    for _ in range(12):
        park_mouse()
        time.sleep(0.3)
        rows = read_objects(numbers)
        hit = next((r for r in rows if r["number"] == number), None)
        shown = [r["number"] for r in rows]
        log(f"find_row {number}: the table shows {shown}")
        if hit or not shown or shown == seen or max(shown) > number:
            return hit, rows
        seen = shown
        mouse.scroll(coords=at, wheel_dist=-5)
    return None, rows


def verify_link(row: dict, rows: list[dict], number: int, ga: str,
                numbers: list[int] | None = None) -> tuple[dict, list[dict]]:
    """The row of object `number` once the table shows `ga` on it, and the
    rows of the table as last read. Answers ETS's question about another
    object size with OK. Reads only the row while the view stays put (its
    numbers where they were); the whole table when it moved or the row did
    not show the address (a selected row's blue text reads badly: a click
    below the rows clears the selection first). Raises when the address is
    not on the row."""
    seen: dict = {}
    park_mouse()

    def settled():
        seen["gas"] = gas_at(row["y"])
        if ga in seen["gas"]:
            return "shown"
        return "prompt" if link_question_open() else None
    state = wait_for("row shows the address", settled, 2.5)
    if state == "prompt":
        # ETS asks about the address's size or datatype: OK takes the link.
        answer_link_question("OK")
        state = wait_for("row shows the address", lambda: settled() == "shown" and "shown", 2.5)
    if state == "shown" and not view_changed(rows, table_numbers()):
        new = {**row, "gas": seen["gas"]}
        return new, [new if r is row else r for r in rows]
    if state != "shown":
        # OCR reads nothing on the selected row (blue text): click below the
        # rows to clear the selection and read again (syn-minimal, 2026-10-31).
        click(1500, GO_TABLE[3] - 20)
        park_mouse()
        time.sleep(0.5)
    hit, rows = find_row(number, [], numbers)
    if hit is not None and ga not in hit["gas"] and state == "shown":
        # The row showed the address before the view moved: read it once
        # more without its selection.
        click(1500, GO_TABLE[3] - 20)
        park_mouse()
        time.sleep(0.5)
        hit, rows = find_row(number, [], numbers)
    if hit is not None and ga not in hit["gas"]:
        # ETS shows the address seconds late at times (ise KNX viega object
        # 40, 2026-11-10): look at the row a while longer before failing.
        late = wait_for("row shows the address late", lambda: ga in gas_at(hit["y"]) and gas_at(hit["y"]), 4, 0.5)
        if late:
            hit = {**hit, "gas": late}
    if hit is None or ga not in hit["gas"]:
        raise RuntimeError(f"object {number} shows {hit and hit['gas']} after linking {ga}")
    return hit, rows


@flow("links")
def flow_links(req: dict) -> dict:
    """Link objects of device `ia` from ONE opened object table (#478):
    `links` [[number, ga], ...] in order. The device is selected and its
    'Kommunikationsobjekte' table opened once (`open` false: the `objects`
    flow just did, so the table showing is used, and opened only when none
    of the objects is on it); each link is then the row's dialog
    (`link_row`) and a check of the row (`verify_link`). A refused address
    is cancelled and reported, the next link goes on. Returns each link's
    outcome and, unless `final` is false, the table after the links
    (`objects`, as the `objects` flow reads it)."""
    require_project(req["project"])
    # A link dialog a failed link left open covers the object table and the
    # Katalog panel: every import after it failed (2026-11-10, #478).
    closed = close_link_question() | close_link_dialog()
    MENU_UIA["timeout"] = 1.5
    numbers = req.get("numbers")
    wanted = [(int(n), str(g)) for n, g in req["links"]]
    opened = bool(req.get("open", True))
    if opened:
        open_device_objects(req["ia"])
    rows = read_objects(numbers)
    if not opened and not any(r["number"] == n for r in rows for n, _ in wanted):
        open_device_objects(req["ia"])
        opened = True
        rows = read_objects(numbers)
    out = []
    try:
        for number, ga in wanted:
            row, rows = find_row(number, rows, numbers)
            if row is None:
                raise RuntimeError(f"object {number} not in the table (hidden by a parameter?): {[r['number'] for r in rows]}")
            if ga in row["gas"]:
                out.append({"number": number, "ga": ga, "linked": True, "already": True, "row": row})
                continue
            r = link_row(row, number, ga)
            if r["linked"]:
                row, rows = verify_link(row, rows, number, ga, numbers)
            out.append({"number": number, "ga": ga, **r, "row": row})
    except Exception:
        # Leave nothing open over the table and the Katalog panel: the next
        # import looks for its button there.
        close_menus()
        close_link_question()
        close_link_dialog()
        raise
    result = {"links": out, "opened": opened, "closed_link_dialog": closed}
    if req.get("final", True):
        park_mouse()
        result["objects"] = with_linked_rows(read_objects(numbers), out)
    return result


def with_linked_rows(objects: list[dict], links: list[dict]) -> list[dict]:
    """The table read after the links, with every row a link verified that
    this read missed (OCR skipped its number: Gira S1 object 2, 2026-11-10)
    added back as the link last read it, so objects.json names each object
    ETS linked."""
    have = {r["number"] for r in objects}
    rows = {}
    for link in links:
        row = link.get("row")
        if link.get("linked") and row and row.get("number") not in have:
            rows[row["number"]] = row
    # A row of the last read at the place of an added one is that object
    # under a misread number (the ise KNX Hue's object 1 read as 0 after its
    # link, 2026-11-10: objects.json held both, and the links oracle modelled
    # a link ETS never made). The number the link was made and verified on
    # stands.
    kept = [r for r in objects if all(abs(r["y"] - a["y"]) >= 14 for a in rows.values())]
    for r in objects:
        if r not in kept:
            log(f"objects: row at y {r['y']} read as {r['number']}, linked as "
                f"{next(a['number'] for a in rows.values() if abs(r['y'] - a['y']) < 14)}; the link's number stands")
    return sorted(kept + list(rows.values()), key=lambda r: r["y"])


@flow("link")
def flow_link(req: dict) -> dict:
    """Link object `number` of device `ia` to group address `ga` ('1/0/9'):
    one link of `flow_links`, the table opened for it. Verified in the table."""
    out = flow_links({**req, "links": [[req["number"], req["ga"]]], "open": True, "final": False})
    r = out["links"][0]
    return {**{k: v for k, v in r.items() if k not in ("number", "ga")}, "closed_link_dialog": out["closed_link_dialog"]}


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
    COUNTS["clicks"] += 1
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
        if cancel_connection_choice():
            # Never pick another interface: the owner's real one is listed.
            raise RuntimeError("download: ETS asked to choose a connection (the sim's did not answer); cancelled")
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


# The device context menu's "Entladen" submenu (ETS 6.4.1, mapped 2026-11-13
# on syn-minimal, #1056): two entries, opened by hovering "Entladen". The
# context menu has no UI Automation tree; its submenu lists the entries both
# by UIA (twice, once per menu instance) and on screen, so the entry is
# clicked where OCR reads it. There is no confirmation: ETS connects at once.
UNLOAD_ENTRIES = {
    "application": "Applikationsprogramm",
    "full": "Physikalische Adresse und Applikationsprogramm",
}


def unload_entry(lines: list[dict], what: str) -> dict | None:
    """The OCR line of the "Entladen" submenu entry for `what` (see
    UNLOAD_ENTRIES). The full entry carries its shortcut on the same line
    ("... Applikationsprogramm Strg + U"); the application entry is the line
    that names no address."""
    want = _norm(UNLOAD_ENTRIES[what])
    for line in lines:
        have = _norm(line["text"])
        if what == "full" and have.startswith(want):
            return line
        if what == "application" and have.startswith(want) and "adresse" not in have:
            return line
    return None


def connection_choice_open() -> bool:
    """Whether ETS shows "Verbindung auswählen": the connection it was told to
    use is not answering and it offers the interfaces it found, the owner's
    real KNX IP interface among them (2026-11-13, an unload with no sim
    running). Never pick one there."""
    return bool(find_text("Verbindung auswählen", (1250, 820, 2860, 960)))


def cancel_connection_choice() -> bool:
    """Answer "Verbindung auswählen" with Abbrechen; True when it was open."""
    if not connection_choice_open():
        return False
    hits = [l for l in ocr((1250, 1200, 2900, 1800)) if l["text"].strip() == "Abbrechen"]
    if not hits:
        keys("{ESC}")
    else:
        h = hits[0]
        click(h["x"] + h["w"] // 2, h["y"] + h["h"] // 2)
    time.sleep(1.5)
    return True


@flow("unload")
def flow_unload(req: dict) -> dict:
    """ETS's "Entladen" of device `ia`: `what` is "application" (the
    application program) or "full" (individual address and application),
    from the device row's context menu. Like `download`, it does not wait
    for the result; the sim's log and ETS's history tell it. A "Verbindung
    auswählen" dialog (the selected connection does not answer) is cancelled
    and raises: the flow never picks another interface."""
    from pywinauto import mouse

    require_project(req["project"])
    what = req.get("what", "application")
    if what not in UNLOAD_ENTRIES:
        raise RuntimeError(f"unload: unknown what={what!r}, one of {sorted(UNLOAD_ENTRIES)}")
    devs = flow_devices(req)["devices"]
    hit = [d for d in devs if d["ia"] == req["ia"]]
    if not hit:
        raise RuntimeError(f"device {req['ia']} not in list: {devs}")
    y = hit[0]["y"]
    s_ = scale()
    click(700, y)
    time.sleep(1)
    mouse.move(coords=(int(1000 * s_), int(600 * s_)))
    time.sleep(0.4)
    lines: list[dict] = []
    for _ in range(3):
        mouse.right_click(coords=(int(1000 * s_), int(y * s_)))
        time.sleep(1.5)
        lines = ocr((1000, y, 1900, y + 1300))
        if any(_norm(l["text"]).endswith("entladen") for l in lines):
            break
        keys("{ESC}")
        time.sleep(1)
    texts = [l["text"] for l in lines]
    entry = next((l for l in lines if _norm(l["text"]).endswith("entladen") and l["x"] < 1300), None)
    if entry is None or not any("Gerät neu starten" in t for t in texts):
        keys("{ESC}")
        raise RuntimeError(f"unload: no device menu with 'Entladen' for {req['ia']}: {texts[:12]}")
    ey = entry["y"] + entry["h"] // 2
    mouse.move(coords=(int(1150 * s_), int(ey * s_)))
    time.sleep(1.5)
    sub = ocr((1500, ey - 60, 2900, ey + 200))
    pick = unload_entry(sub, what)
    if pick is None:
        keys("{ESC}")
        keys("{ESC}")
        raise RuntimeError(f"unload: no {UNLOAD_ENTRIES[what]!r} in the Entladen submenu: {[l['text'] for l in sub]}")
    click(pick["x"] + 80, pick["y"] + pick["h"] // 2)
    t0 = time.time()
    password = certificate = False
    while time.time() - t0 < float(req.get("dialog_wait", 12)):
        if cancel_connection_choice():
            raise RuntimeError("unload: ETS asked to choose a connection (the sim's did not answer); cancelled")
        if dismiss_password_dialog(req.get("project_password")):
            password = True
        if req.get("certificate") and enter_certificate(req["certificate"]):
            certificate = True
        time.sleep(1)
    return {"ia": req["ia"], "what": what, "entry": pick["text"], "password_dialog": password,
            "certificate_dialog": certificate}


# A group address's "Sicherheit" in the Eigenschaften panel (ETS 6.4.1, mapped
# 2026-11-13 in ets-sweep-secure, #1054): a dropdown under the label, its
# list a popup with UI Automation ListItems.
GA_SECURITY_TEXT = {"auto": "Automatisch", "on": "Erzwungen an", "off": "Erzwungen aus"}
# The left column below the Katalog panel, where the Panels menu opens the
# group-address panel ("Gruppenadressen" header at x 67, its close button at
# x 648 on the header's line; the tree's own "Gruppenadressen" node at x 57
# sits below it).
LEFT_LOWER = (0, 1300, 680, 2500)


def ga_panel_header(lines: list[dict]) -> dict | None:
    """The group-address panel's header among OCR lines of LEFT_LOWER: the
    topmost "Gruppenadressen" at the column's left edge."""
    heads = [l for l in lines if l["text"].strip() == "Gruppenadressen" and l["x"] < 120]
    return min(heads, key=lambda l: l["y"]) if heads else None


def ga_tree_entry(lines: list[dict], prefix: str, below: int) -> dict | None:
    """The tree entry of a main ("1") or middle ("1/0") group below the
    panel header at y `below`: the line whose text, apart from an icon OCR
    reads as a few symbols ("88 1/0 Neue Mittelgruppe"), starts with
    `prefix` and a space."""
    for line in sorted(lines, key=lambda l: l["y"]):
        if line["y"] <= below:
            continue
        text = re.sub(r"^[^0-9]*", "", line["text"].strip())
        if "/" in prefix:
            m = re.search(r"(?:^|\s)(\d+/\d+)\s", text)
            if m and m.group(1) == prefix:
                return line
        elif text.startswith(prefix + " ") and not re.match(r"\d+\s+\d+/", text):
            return line
    return None


def ga_security_value(lines: list[dict]) -> str | None:
    """What the Sicherheit dropdown shows: the line below the "Sicherheit"
    label among OCR lines of the Eigenschaften panel."""
    label = next((l for l in lines if l["text"].strip() == "Sicherheit"), None)
    if label is None:
        return None
    below = sorted((l for l in lines if label["y"] + 10 < l["y"] < label["y"] + 90), key=lambda l: l["y"])
    return below[0]["text"].strip() if below else None


def close_ga_panel() -> bool:
    """Close the group-address panel below the Katalog panel; it squeezes the
    Katalog panel so `catalog_add` no longer finds the add bar (session 3
    left one open in ets-sweep-secure, which failed two adds on 2026-11-13)."""
    head = ga_panel_header(ocr(LEFT_LOWER))
    if not head:
        return False
    click(648, head["y"] + 12)
    time.sleep(2)
    return True


def restore_ops_pane() -> bool:
    """Open "Laufende Operationen" again when the Eigenschaften panel took the
    right-hand column (its header then sits at the column's foot, y 2357;
    OCR missed it under the "Windows aktivieren" watermark, 2026-11-13)."""
    if any("Historie" in l["text"] or "Aktiv" in l["text"] for l in ocr((3320, 600, 4112, 700))):
        return False
    click(3600, 2357)
    time.sleep(2)
    return True


def confirm_security_notice(wait: float = 6.0) -> list[str]:
    """Answer ETS's "Sicherheitshinweis" with Weiter and return its text.
    ETS shows it when a security change affects other addresses: setting
    1/0/2 to "Erzwungen aus" listed 1/0/1 and 1/0/2 as unencrypted, since
    one object (the switch) is linked to both (2026-11-13). An empty list
    when no notice came."""
    t0 = time.time()
    while time.time() - t0 < wait:
        if find_text("Sicherheitshinweis", (1550, 900, 2560, 1040)):
            text = [l["text"] for l in ocr((1550, 900, 2560, 1450))]
            hits = [l for l in ocr((1550, 1100, 2600, 1800)) if l["text"].strip().endswith("Weiter")]
            if not hits:
                raise RuntimeError(f"ga_security: no Weiter on the security notice: {text}")
            h = hits[0]
            click(h["x"] + h["w"] // 2, h["y"] + h["h"] // 2)
            time.sleep(2)
            return text
        time.sleep(0.5)
    return []


@flow("ga_security")
def flow_ga_security(req: dict) -> dict:
    """Set the security of group address `ga` ("1/0/2") to `security`
    ("off", "on" or "auto", GA_SECURITY_TEXT) in the project's
    Eigenschaften panel, read it back, and put the layout back: the
    group-address panel closed, the operations pane open (#1054, a plain
    address next to secured ones)."""
    require_project(req["project"])
    want = GA_SECURITY_TEXT[req.get("security", "off")]
    notice: list[str] = []
    main, middle, _ = req["ga"].split("/")
    head = ga_panel_header(ocr(LEFT_LOWER))
    if head is None:
        click(*LAYOUT["toolbar_panels"])
        time.sleep(1.2)
        choose("Gruppenadressen", (3400, 140, 3900, 620))
        time.sleep(3)
        head = ga_panel_header(ocr(LEFT_LOWER))
        if head is None:
            raise RuntimeError("ga_security: the Gruppenadressen panel did not open")
    try:
        tree = ocr((0, head["y"], 680, 2440))
        mid = ga_tree_entry(tree, f"{main}/{middle}", head["y"])
        if mid is None:
            top = ga_tree_entry(tree, main, head["y"])
            if top is None:
                raise RuntimeError(f"ga_security: no main group {main} in {[l['text'] for l in tree]}")
            click(13, top["y"] + top["h"] // 2)
            time.sleep(1.5)
            mid = ga_tree_entry(ocr((0, head["y"], 680, 2440)), f"{main}/{middle}", head["y"])
            if mid is None:
                raise RuntimeError(f"ga_security: no middle group {main}/{middle}")
        click(mid["x"] + 40, mid["y"] + mid["h"] // 2)
        time.sleep(2)
        rows = [l for l in ocr((700, head["y"] + 60, 1300, 2440)) if l["text"].replace(" ", "") == req["ga"]]
        if not rows:
            raise RuntimeError(f"ga_security: no row {req['ga']} in the group-address list")
        click(1000, rows[0]["y"] + rows[0]["h"] // 2)
        time.sleep(1)
        props = ocr((3420, 160, 4112, 1400))
        if ga_security_value(props) is None:
            click(3563, 193)  # the Eigenschaften header of the right-hand column
            time.sleep(2.5)
            props = ocr((3420, 160, 4112, 1400))
        before = ga_security_value(props)
        label = next((l for l in props if l["text"].strip() == "Sicherheit"), None)
        if label is None or before is None:
            raise RuntimeError(f"ga_security: no Sicherheit field: {[l['text'] for l in props][:20]}")
        value = next(l for l in props if l["text"].strip() == before and l["y"] > label["y"])
        if before != want:
            click(3757, value["y"] + value["h"] // 2)
            time.sleep(1.5)
            item = None
            for pop in ets_popups():
                for it in pop.descendants(control_type="ListItem"):
                    try:
                        if it.window_text() == want:
                            item = it
                    except Exception:  # noqa: BLE001 - a stale element of a closing popup
                        pass
            if item is None:
                keys("{ESC}")
                raise RuntimeError(f"ga_security: no option {want!r} in the Sicherheit list")
            item.click_input()
            COUNTS["clicks"] += 1
            time.sleep(1.5)
            notice = confirm_security_notice()
        shown = ga_security_value(ocr((3420, 160, 4112, 1400)))
    finally:
        # The operations pane back on top (the history flow reads it there),
        # then the group-address panel closed.
        restore_ops_pane()
        close_ga_panel()
    if shown != want:
        raise RuntimeError(f"ga_security: {req['ga']} shows {shown!r} after setting {want!r}")
    return {"ga": req["ga"], "before": before, "security": shown, "notice": notice}


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
    for _ in range(4):
        # Three 'Gebäude' panels were stacked in ets-sweep-secure (2026-11-10).
        # Any panel above the Topologie panel (ETS reopens 'Gebäude' after a
        # restart) pushes the Katalog panel down: close the top panel while it
        # is not Topologie (its close button sits at the panel header's right).
        top = find_text("Gebäude", (0, 160, 660, 210)) or find_text("Gruppenadressen", (0, 160, 660, 210))
        if not top:
            break
        click(648, 185)
        time.sleep(2)
        did.append("closed " + top["text"])
    if close_ga_panel():
        # A group-address panel below the Katalog panel (ga_security, or one
        # left open by hand) squeezes the Katalog panel (2026-11-13).
        did.append("closed Gruppenadressen below Katalog")
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
    # The first three words: the panel's close icon left of the button joins the
    # line as 'X Import' (31 imports in a row refused, 2026-11-08 04:06), and
    # with the collapse arrow as 'v X Import' after a restart (2026-11-10 09:40).
    # The strip reaches x 1300: after the reset of 2026-11-10 the Katalog
    # tree column was wider and the word Import started at x 1067, past
    # the old right edge (1100), so OCR read only the icons.
    hits = [l for l in ocr((680, 200, 1300, 2440))
            if any(_norm(w) in ("import", "impart", "imp0rt") for w in l["text"].split()[:3])]
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


# How far the Import button may sit from where LAYOUT measured it (y 1354)
# before a catalog flow restores the layout (`restore_catalog_splitter`
# moves it back from the same distance).
CATALOG_DY_MAX = 50


def catalog_layout(tries: int = 3) -> dict:
    """Put the Katalog panel where LAYOUT expects it before a catalog flow
    reads it. After the parameter editor the panel stayed collapsed (its
    splitter at y 2339) and the next search read no rows ("ETS does not list
    ... after the import", #1054, 2026-11-12); `ensure_layout` restores it,
    but right after a download it sometimes does not, so it is retried until
    the Import button sits within CATALOG_DY_MAX of y 1354."""
    did = []
    for attempt in range(tries):
        btn = catalog_import_button()
        if btn and abs(btn["y"] - 1354) <= CATALOG_DY_MAX:
            return {"ok": True, "tries": attempt, "did": did}
        wait_busy(60)
        did.append(ensure_layout().get("did", []))
        time.sleep(1 + attempt)
    btn = catalog_import_button()
    return {"ok": bool(btn and abs(btn["y"] - 1354) <= CATALOG_DY_MAX), "tries": tries, "did": did}


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



def result_ok(lines: list[dict]) -> dict:
    """Where to click the import result panel's OK: the OCR line 'OK' in the
    wizard region, else the place it had on 2026-10-27 (2488, 1528). On
    2026-11-09 16:47 the panel of a 200-product Theben file sat higher
    (OK at about 2416, 1486), the fixed click missed, and the catalog reset
    then tried to close ETS under the modal (COMError)."""
    hit = button_hit(lines, "OK")
    if hit:
        return {"click_x": hit["click_x"], "click_y": hit["click_y"]}
    return {"click_x": 2488, "click_y": 1528}


def close_result_panel(region: tuple[int, int, int, int]) -> bool:
    """Click away an import result panel ('erfolgreich' or 'fehlgeschlagen')
    that is still up in `region`; True when one was there."""
    lines = ocr(region)
    text = " ".join(l["text"] for l in lines)
    if "erfolgreich" not in text and "fehlgeschlagen" not in text:
        return False
    ok = result_ok(lines)
    click(ok["click_x"], ok["click_y"])
    time.sleep(1.5)
    return True

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
        if close_result_panel((1500, 400, 3500, 1600)):
            did.append("closed a result panel")
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
    did += ensure_ets_running(req.get("project", "ets-sweep"), req.get("project_password"))
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
    # A delete confirmation a failed delete left open covers the Katalog
    # panel: every later import failed (2026-11-08, #997).
    closed_delete_dialog = close_delete_dialog()
    # So does a link dialog a failed link left open (2026-11-10, #478).
    closed_link_dialog = close_link_dialog()
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
    # A Katalog panel the parameter editor left collapsed (#1054): restore
    # it here, not only when no button is found below. An open result panel
    # hides the button; that case is handled below, without ensure_layout.
    first = catalog_import_button()
    if first and abs(first["y"] - 1354) > CATALOG_DY_MAX:
        catalog_layout()
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
        # close it, then look again.
        ok = result_ok(ocr(region))
        click(ok["click_x"], ok["click_y"])
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
                    ok = result_ok(ocr(region))
                    click(ok["click_x"], ok["click_y"])
                time.sleep(1.5)
                if "erfolgreich" not in " ".join(l["text"] for l in ocr(region)):
                    break
            return {"outcome": "imported", "products": products, "message": joined[:600], "attached": attached, "ets_error": ets_error,
                    "closed_delete_dialog": closed_delete_dialog, "closed_link_dialog": closed_link_dialog}
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
    catalog_layout()
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
        before = dict(COUNTS)
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
                started = (ensure_ets_running(req.get("project", "ets-sweep"), req.get("project_password"))
                           if name != "windows" else [])
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
            log(f"{self.path} {time.time() - t0:.1f}s " + " ".join(f"{k}={COUNTS[k] - before[k]}" for k in COUNTS))


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
            # The file settles first (an upload in progress changes it
            # again), and a replacement is spawned only from a file that
            # compiles: one that read a half-written upload died before it
            # logged a line, and no driver was left (2026-11-11 14:38Z).
            time.sleep(2)
            try:
                if me.stat().st_mtime != now:
                    continue
                compile(me.read_text(encoding="utf-8"), str(me), "exec")
            except (OSError, SyntaxError, ValueError) as exc:
                log(f"source changed but does not compile, keeping the running driver: {exc!r}")
                stamp = now
                continue
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
            # Its start-up output goes to driver-start.log: a replacement
            # that fails before it opens the log is visible there.
            start_log = open(me.parent / "driver-start.log", "a", encoding="utf-8")  # noqa: SIM115 (handed to the child)
            subprocess.Popen(
                [sys.executable, str(me)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True, stdout=start_log, stderr=subprocess.STDOUT,
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
