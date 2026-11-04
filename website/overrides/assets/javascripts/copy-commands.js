// The copy button on a `console` code block copies the commands only: the
// prompt (`$ `) and the output lines are left out, so the clipboard holds
// what the reader types. Material's button reads `data-clipboard-text`
// before `data-clipboard-target`, so this sets it on the click, in the
// capture phase, before the clipboard handler runs. Other languages are
// untouched.
(function () {
  function commandsOf(code) {
    var lines = [];
    var line = "";
    var output = false;
    function push(text) {
      var parts = text.split("\n");
      for (var i = 0; i < parts.length; i++) {
        line += parts[i];
        if (i < parts.length - 1) {
          if (!output) lines.push(line.replace(/\s+$/, ""));
          line = "";
          output = false;
        }
      }
    }
    function walk(node) {
      for (var n = node.firstChild; n; n = n.nextSibling) {
        if (n.nodeType === 3) {
          push(n.textContent);
        } else if (n.classList && n.classList.contains("gp")) {
          // the prompt: dropped, but a newline inside it still ends the line
          push(n.textContent.replace(/[^\n]/g, ""));
        } else if (n.classList && n.classList.contains("go")) {
          output = true;
          push(n.textContent);
        } else {
          walk(n);
        }
      }
    }
    walk(code);
    if (line && !output) lines.push(line.replace(/\s+$/, ""));
    return lines.filter(function (l) { return l.length > 0; }).join("\n");
  }

  document.addEventListener(
    "click",
    function (ev) {
      var target = ev.target;
      if (!target || !target.closest) return;
      var button = target.closest(".md-code__button[data-clipboard-target]");
      if (!button) return;
      var code = document.querySelector(button.getAttribute("data-clipboard-target"));
      if (!code) return;
      if (!code.closest(".language-console, .language-shell-session")) return;
      button.setAttribute("data-clipboard-text", commandsOf(code));
    },
    true
  );
})();
