//! Opening a page in the human's browser (issue #809): the pairing page of
//! a certificate enrolment session. Behind [`BrowserOpener`] so the tests
//! open nothing.
//!
//! [`SystemBrowser`] runs `open` on macOS, `xdg-open` on Linux and the BSDs
//! and `start` on Windows. It refuses up front when nobody can see a
//! browser window on this computer: an SSH session, or a Linux desktop
//! with neither `DISPLAY` nor `WAYLAND_DISPLAY`.

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long [`SystemBrowser::open`] waits for the opener command to report
/// a failure. `xdg-open` can block for as long as the browser runs, so a
/// command still running after this counts as opened.
const OPEN_WAIT: Duration = Duration::from_secs(5);

/// Opens a URL in the human's browser on this computer.
pub trait BrowserOpener: Send + Sync {
    /// Why no browser window can be shown here, or `None` when one can.
    fn no_display(&self) -> Option<String>;

    /// Opens `url` in the default browser.
    ///
    /// # Errors
    ///
    /// The opener command is missing or failed; the text says how. It never
    /// holds `url`.
    fn open(&self, url: &str) -> Result<(), String>;
}

/// The browser of this computer, through the platform's opener command.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn no_display(&self) -> Option<String> {
        no_display_reason(std::env::consts::OS, |name| std::env::var_os(name))
    }

    fn open(&self, url: &str) -> Result<(), String> {
        let (program, mut command) = opener_command(std::env::consts::OS, url);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| format!("running {program}: {err}"))?;
        let (done, exited) = mpsc::channel();
        // Waits off the caller's thread, and reaps the child either way.
        std::thread::Builder::new()
            .name("browser-open".to_owned())
            .spawn(move || {
                let _ = done.send(child.wait());
            })
            .map_err(|err| format!("waiting for {program}: {err}"))?;
        match exited.recv_timeout(OPEN_WAIT) {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(format!("{program} failed ({status})")),
            Ok(Err(err)) => Err(format!("waiting for {program}: {err}")),
            // Still running: the browser took the page.
            Err(_) => Ok(()),
        }
    }
}

/// The opener command for `os` (as [`std::env::consts::OS`] names it) and
/// its name for messages.
fn opener_command(os: &str, url: &str) -> (&'static str, Command) {
    match os {
        "macos" => {
            let mut command = Command::new("open");
            command.arg(url);
            ("open", command)
        }
        "windows" => {
            // `start` is a cmd built-in; the empty first argument is the
            // window title. The URL is the pairing page's
            // `http://127.0.0.1:<port>/<hex>/`, with nothing cmd would
            // interpret.
            let mut command = Command::new("cmd");
            command.args(["/C", "start", ""]).arg(url);
            ("start", command)
        }
        _ => {
            let mut command = Command::new("xdg-open");
            command.arg(url);
            ("xdg-open", command)
        }
    }
}

/// Why a browser window on `os` cannot be seen, from the environment `var`
/// reads; `None` when it can.
fn no_display_reason(os: &str, var: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<String> {
    let set = |name: &str| var(name).is_some_and(|value| !value.is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") {
        return Some(
            "bussard runs in an SSH session, so a page it opens would show on the remote \
             computer, not in front of you"
                .to_string(),
        );
    }
    let desktop_by_env = !matches!(os, "macos" | "windows" | "ios" | "android");
    if desktop_by_env && !set("DISPLAY") && !set("WAYLAND_DISPLAY") {
        return Some(
            "this computer has no graphical display (neither DISPLAY nor WAYLAND_DISPLAY is \
             set), so bussard cannot open a page"
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn test_no_display_reason_ssh_session_refuses_everywhere() {
        for os in ["macos", "linux", "windows"] {
            let reason = no_display_reason(
                os,
                env(&[
                    ("SSH_CONNECTION", "10.0.0.2 52000 10.0.0.1 22"),
                    ("DISPLAY", ":0"),
                ]),
            );
            assert!(reason.is_some_and(|r| r.contains("SSH")), "{os}");
        }
    }

    #[test]
    fn test_no_display_reason_linux_needs_display_or_wayland() {
        assert!(no_display_reason("linux", env(&[])).is_some());
        assert!(no_display_reason("linux", env(&[("DISPLAY", "")])).is_some());
        assert!(no_display_reason("linux", env(&[("DISPLAY", ":0")])).is_none());
        assert!(no_display_reason("freebsd", env(&[("WAYLAND_DISPLAY", "wayland-0")])).is_none());
    }

    #[test]
    fn test_no_display_reason_macos_and_windows_have_a_display() {
        assert!(no_display_reason("macos", env(&[])).is_none());
        assert!(no_display_reason("windows", env(&[])).is_none());
    }

    #[test]
    fn test_opener_command_per_platform() {
        let url = "http://127.0.0.1:1/00/";
        for (os, program, args) in [
            ("macos", "open", vec![url]),
            ("linux", "xdg-open", vec![url]),
            ("windows", "cmd", vec!["/C", "start", "", url]),
        ] {
            let (_, command) = opener_command(os, url);
            assert_eq!(command.get_program(), program, "{os}");
            let got: Vec<_> = command.get_args().collect();
            assert_eq!(got, args, "{os}");
        }
    }
}
