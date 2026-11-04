// The pairing page (#809, #820): keeps the list of certificates current with
// a long poll on `status` (relative to the page's token path), folds steps 1
// and 2 into one line once the phone joined, and copies the phone link. At
// the end it points back to the chat, which continues by itself (#831), and
// tries to close the tab; a browser only lets a script close a window a
// script opened, so the message stays when it refuses.
// Every text goes in with textContent; the server's strings are already in
// the glossary's words (dev/glossary.md).

const $ = (id) => document.getElementById(id);

/** Retries before the page says bussard stopped answering. */
const MAX_FAILURES = 4;

/** Local mode: the certificate page runs in a browser on this computer. */
const LOCAL = document.body.classList.contains("local");

/** How long the end stays on screen before the page tries to close. */
const CLOSE_DELAY_MS = 4000;

let version = null;
let shown = 0;
let rendered = false;
let sawRunning = false;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setState(text, tone) {
  const state = $("state");
  state.textContent = text;
  state.className = `state ${tone}`;
}

function row(cert) {
  const li = document.createElement("li");
  li.className = `label ${cert.tone}`;
  const line = document.createElement("div");
  line.className = "row";
  const serial = document.createElement("span");
  serial.className = "code";
  serial.textContent = cert.serial;
  const pill = document.createElement("span");
  pill.className = "pill";
  pill.textContent = cert.badge;
  line.append(serial, pill);
  const detail = document.createElement("div");
  detail.className = "detail";
  detail.textContent = cert.detail;
  li.append(line, detail);
  return li;
}

/** Folds steps 1 and 2 into the one line of `text`; `again` offers them back. */
function compact(text, again) {
  document.body.classList.add("connected");
  $("compact").hidden = false;
  $("compact-text").textContent = text;
  $("toggle-setup").hidden = !again;
  if (!again) document.body.classList.remove("show-setup");
}

function render(status) {
  const list = $("labels");
  const certs = status.certificates;
  // Rows only ever arrive at the end; redraw if the list got shorter.
  if (certs.length < shown) {
    list.replaceChildren();
    shown = 0;
  }
  for (const cert of certs.slice(shown)) {
    const li = row(cert);
    // Animate what arrives while the page is open, not the first load.
    if (rendered) li.classList.add("enter");
    list.prepend(li);
  }
  shown = certs.length;
  rendered = true;
  if (status.running) sawRunning = true;
  $("refused").hidden = !(status.refused_phones > 0);
  $("labels-empty").hidden = certs.length > 0;
  $("summary").textContent = certs.length ? status.summary : "Nothing sent yet";

  if (!status.running) {
    const problems = certs.some((c) => c.tone === "bad");
    setState("Finished", problems ? "warn" : "done");
    // The link is no use any more: the session code stays for reference.
    compact("Session closed", false);
    $("list-title").textContent = "Certificates";
    $("labels-empty").textContent = "No certificates were sent.";
    const end = $("end");
    end.hidden = false;
    end.className = `banner ${problems ? "warn" : "info"}`;
    $("end-title").textContent =
      status.ended ?? "Done. You can close this tab and go back to your chat.";
    $("end-summary").textContent = certs.length ? status.summary : "";
    const steps = $("next-steps");
    steps.replaceChildren();
    for (const step of status.next_steps) {
      const li = document.createElement("li");
      const cmd = document.createElement("code");
      cmd.textContent = step.command;
      li.append(cmd, document.createTextNode(` ${step.why}`));
      steps.append(li);
    }
    document.body.classList.add("ended");
    // Only a session that ended while this tab watched: a reload of an
    // ended page stays open.
    if (sawRunning) setTimeout(() => window.close(), CLOSE_DELAY_MS);
  } else if (status.phones > 0) {
    setState(LOCAL ? "Connected" : "Phone connected", "live");
    compact(LOCAL ? "Certificate page connected" : "Phone connected", true);
  } else {
    setState(LOCAL ? "Waiting for the certificate page" : "Waiting for your phone", "waiting");
  }
}

async function poll() {
  let failures = 0;
  for (;;) {
    try {
      const query = version === null ? "" : `?after=${version}`;
      const response = await fetch(`status${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`status ${response.status}`);
      const body = await response.json();
      version = body.version;
      failures = 0;
      render(body.status);
      if (!body.status.running) return;
    } catch {
      failures += 1;
      if (failures >= MAX_FAILURES) {
        setState("bussard stopped this page", "warn");
        return;
      }
      await sleep(1000 * failures);
    }
  }
}

function setupToggle() {
  const button = $("toggle-setup");
  const label = () => (LOCAL ? "the steps" : "the QR code");
  button.textContent = `Show ${label()}`;
  button.addEventListener("click", () => {
    const open = document.body.classList.toggle("show-setup");
    button.setAttribute("aria-expanded", String(open));
    button.textContent = `${open ? "Hide" : "Show"} ${label()}`;
  });
}

function setupCopy() {
  const button = $("copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("phone-link").textContent);
      button.textContent = "Copied";
    } catch {
      // No clipboard: select the link so Cmd-C or Ctrl-C copies it.
      const range = document.createRange();
      range.selectNodeContents($("phone-link"));
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = "Selected";
    }
    setTimeout(() => {
      button.textContent = "Copy";
    }, 2000);
  });
}

setupToggle();
setupCopy();
poll();
