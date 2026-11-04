// The pairing page (#809): keeps the list of certificates current with a
// long poll on `status` (relative to the page's token path) and copies the
// phone link. Every text goes in with textContent; the server's strings are
// already in the glossary's words (dev/glossary.md).

const $ = (id) => document.getElementById(id);

/** Retries before the page says bussard stopped answering. */
const MAX_FAILURES = 4;

let version = null;
let shown = 0;
let rendered = false;

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
  $("refused").hidden = !(status.refused_phones > 0);
  $("labels-empty").hidden = certs.length > 0;
  $("summary").textContent = certs.length ? status.summary : "Nothing sent yet";

  if (!status.running) {
    const problems = certs.some((c) => c.tone === "bad");
    setState("Finished", problems ? "warn" : "done");
    const end = $("end");
    end.hidden = false;
    end.className = `banner ${problems ? "warn" : "info"}`;
    $("end-title").textContent = status.ended ?? "Finished.";
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
  } else if (status.phones > 0) {
    setState("Phone connected", "live");
  } else {
    setState("Waiting for your phone", "waiting");
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

setupCopy();
poll();
