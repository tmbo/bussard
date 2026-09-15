//! Mapping ETS `DatapointType` strings to the model's [`Dpt`] type.
//!
//! ETS writes DPTs as `"DPST-<main>-<sub>"` (fully qualified) or `"DPT-<main>"`
//! (main only), and some attributes carry several space-separated DPTs (the
//! first wins). This is a small, deliberate duplicate of the identical helper
//! in `bussard-project::dpt_map`; see the crate `lib.rs` note on the shared-XML
//! dedup opportunity.

use bussard_model::Dpt;

/// Parses an ETS `DatapointType` attribute value into a [`Dpt`].
///
/// Accepts `"DPST-<main>-<sub>"`, `"DPT-<main>"`, and space-separated lists of
/// those (the first entry wins). Returns `None` if the string is empty or does
/// not match either shape.
pub fn parse_ets_dpt(raw: &str) -> Option<Dpt> {
    let first = raw.split_whitespace().next()?;
    if let Some(rest) = first.strip_prefix("DPST-") {
        let mut parts = rest.splitn(2, '-');
        let main: u16 = parts.next()?.parse().ok()?;
        let sub: u16 = parts.next()?.parse().ok()?;
        Some(Dpt::new(main, Some(sub)))
    } else if let Some(rest) = first.strip_prefix("DPT-") {
        let main: u16 = rest.parse().ok()?;
        Some(Dpt::new(main, None))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dpst_and_dpt() {
        assert_eq!(parse_ets_dpt("DPST-1-8"), Some(Dpt::new(1, Some(8))));
        assert_eq!(parse_ets_dpt("DPT-9"), Some(Dpt::new(9, None)));
    }

    #[test]
    fn takes_first_of_list() {
        assert_eq!(
            parse_ets_dpt("DPST-1-1 DPST-1-2"),
            Some(Dpt::new(1, Some(1)))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_ets_dpt(""), None);
        assert_eq!(parse_ets_dpt("nonsense"), None);
        assert_eq!(parse_ets_dpt("DPST-1"), None);
    }
}
