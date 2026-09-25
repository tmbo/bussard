//! Embedded frontend assets, served by name.
//!
//! Every file under `assets/` is embedded at compile time via [`include_str!`]
//! so the server is a single self-contained binary with no runtime file
//! dependency. [`asset`] returns the body and MIME type for a known name;
//! unknown names return `None` (the router answers `404`).

/// A served asset: its body and the `Content-Type` to send it with.
pub struct Asset {
    /// The file body (embedded at compile time).
    pub body: &'static str,
    /// The MIME type derived from the file extension.
    pub content_type: &'static str,
}

/// The `index.html` shell served at `GET /`.
pub const INDEX_HTML: &str = include_str!("../assets/index.html");

/// Looks up an asset by its bare file name (no leading path).
///
/// Returns the embedded body and its MIME type for a known asset, or `None` for
/// an unknown name. The set is fixed (the agreed frontend module list plus the
/// self-test page and the projection fixture).
///
/// `fixture-model.json` is the `/api/model` projection of the **synthetic**
/// `fixtures/demo-model/` installation, used by `main.js` as the standalone
/// development fallback when `/api/model` is unreachable. It must never be
/// regenerated from a real `knx/` directory — it ships inside every release
/// binary. See `tests/fixture_model.rs`.
pub fn asset(name: &str) -> Option<Asset> {
    let (body, content_type) = match name {
        "index.html" => (INDEX_HTML, "text/html; charset=utf-8"),
        "test.html" => (
            include_str!("../assets/test.html"),
            "text/html; charset=utf-8",
        ),
        "style.css" => (
            include_str!("../assets/style.css"),
            "text/css; charset=utf-8",
        ),
        "main.js" => (include_str!("../assets/main.js"), JS),
        "store.js" => (include_str!("../assets/store.js"), JS),
        "api.js" => (include_str!("../assets/api.js"), JS),
        "topology.js" => (include_str!("../assets/topology.js"), JS),
        "gatree.js" => (include_str!("../assets/gatree.js"), JS),
        "inspector.js" => (include_str!("../assets/inspector.js"), JS),
        "log.js" => (include_str!("../assets/log.js"), JS),
        "layout.js" => (include_str!("../assets/layout.js"), JS),
        "fixture-model.json" => (
            include_str!("../assets/fixture-model.json"),
            "application/json; charset=utf-8",
        ),
        _ => return None,
    };
    Some(Asset { body, content_type })
}

/// The MIME type used for the JavaScript ES modules.
const JS: &str = "text/javascript; charset=utf-8";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_assets_resolve() {
        for name in [
            "index.html",
            "test.html",
            "style.css",
            "main.js",
            "store.js",
            "api.js",
            "topology.js",
            "gatree.js",
            "inspector.js",
            "log.js",
            "layout.js",
            "fixture-model.json",
        ] {
            assert!(asset(name).is_some(), "asset {name} should resolve");
        }
    }

    #[test]
    fn test_content_types() {
        assert_eq!(asset("main.js").expect("js").content_type, JS);
        assert_eq!(
            asset("style.css").expect("css").content_type,
            "text/css; charset=utf-8"
        );
        assert!(
            asset("index.html")
                .expect("html")
                .content_type
                .starts_with("text/html")
        );
        assert!(
            asset("fixture-model.json")
                .expect("json")
                .content_type
                .starts_with("application/json")
        );
    }

    #[test]
    fn test_unknown_asset_is_none() {
        assert!(asset("secret.txt").is_none());
        assert!(asset("../Cargo.toml").is_none());
    }

    /// The full list of embedded asset names, for exhaustive scanning.
    const ALL_ASSETS: &[&str] = &[
        "index.html",
        "test.html",
        "style.css",
        "main.js",
        "store.js",
        "api.js",
        "topology.js",
        "gatree.js",
        "inspector.js",
        "log.js",
        "layout.js",
        "fixture-model.json",
    ];

    /// No embedded asset may reference an external network resource.
    ///
    /// The page must work fully offline: no CDN scripts, no remote fonts, no
    /// external stylesheets. We scan every embedded asset for `http://` and
    /// `https://` URLs and reject them, with two deliberate exceptions that are
    /// not network fetches:
    ///
    /// - W3C XML namespace URIs (`http://www.w3.org/…`), required by
    ///   `createElementNS` for the SVG underlay. These are identifiers, never
    ///   dereferenced.
    /// - Loopback URLs (`127.0.0.1`, `localhost`), which stay on the machine.
    ///
    /// Any other scheme-URL (a CDN, a font service, an `@import url(http…)`)
    /// fails this test. This is the offline-guarantee regression guard: it trips
    /// the moment a frontend edit reintroduces a remote dependency.
    #[test]
    fn test_no_external_urls_in_assets() {
        // A scheme-URL is allowed only if it is a W3C namespace or loopback.
        fn is_allowed(url: &str) -> bool {
            url.starts_with("http://www.w3.org/")
                || url.starts_with("https://www.w3.org/")
                || url.starts_with("http://127.0.0.1")
                || url.starts_with("https://127.0.0.1")
                || url.starts_with("http://localhost")
                || url.starts_with("https://localhost")
        }

        // Extract every `http://…`/`https://…` token starting at each match.
        fn scheme_urls(body: &str) -> Vec<String> {
            let mut out = Vec::new();
            for scheme in ["http://", "https://"] {
                let mut rest = body;
                while let Some(pos) = rest.find(scheme) {
                    let tail = &rest[pos..];
                    let end = tail
                        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '<'))
                        .unwrap_or(tail.len());
                    out.push(tail[..end].to_string());
                    rest = &tail[end.max(1)..];
                }
            }
            out
        }

        // Explicit remote-dependency fingerprints that must never appear.
        const FORBIDDEN_FRAGMENTS: &[&str] = &[
            "//cdn",
            "@import url(http",
            "fonts.googleapis",
            "fonts.gstatic",
        ];

        for name in ALL_ASSETS {
            let body = asset(name).expect("asset resolves").body;

            for frag in FORBIDDEN_FRAGMENTS {
                assert!(
                    !body.contains(frag),
                    "asset {name} contains a forbidden remote reference {frag:?}"
                );
            }

            for url in scheme_urls(body) {
                assert!(
                    is_allowed(&url),
                    "asset {name} references external URL {url:?}; \
                     the page must work offline (only W3C namespaces and loopback are allowed)"
                );
            }
        }
    }

    /// The reload tooltip and help text are written for the user (issue #252):
    /// no HTTP endpoint and no method in them.
    #[test]
    fn test_index_html_reload_help_names_no_endpoint() {
        let tooltip_at = INDEX_HTML.find("id=\"reload-btn\"");
        let help_at = INDEX_HTML.find("id=\"help-reload\"");
        assert!(
            tooltip_at.is_some() && help_at.is_some(),
            "reload button and help text present"
        );
        for at in [tooltip_at, help_at].into_iter().flatten() {
            // The element's markup up to the end of its first line of content.
            let chunk: String = INDEX_HTML[at..].chars().take(400).collect();
            assert!(
                !chunk.contains("/api"),
                "reload help names an endpoint: {chunk}"
            );
            assert!(
                !chunk.contains("POST"),
                "reload help names a method: {chunk}"
            );
        }
    }
}
