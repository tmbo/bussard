//! The `.knxprod` files of a product corpus directory, shared by the corpus
//! sweep, the env-gated corpus tests and (through `#[path]`) the crate's own
//! env-gated unit tests and the CLI's sim catalog loop.

use std::path::{Path, PathBuf};

/// Collects the `.knxprod` files at or under `dir` (one level of nesting is
/// enough: `bussard import-product` caches downloads under `<dir>/vendor/`).
/// The extension matches in any case: some vendors ship `.KNXPROD`.
/// Sorted and de-duplicated for stable output.
pub fn knxprod_files(dir: &Path) -> Vec<PathBuf> {
    fn is_knxprod(p: &Path) -> bool {
        p.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"))
    }
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for e2 in sub.flatten() {
                        let p2 = e2.path();
                        if is_knxprod(&p2) {
                            out.push(p2);
                        }
                    }
                }
            } else if is_knxprod(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
