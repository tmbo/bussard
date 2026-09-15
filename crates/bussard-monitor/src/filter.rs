//! Address filtering for the monitor and capture streams.
//!
//! A filter is a comma-separated list of terms; a telegram passes if **any**
//! term matches its source or destination. Each term is one of:
//!
//! - a full group address, e.g. `3/2/0`
//! - a group-address prefix, e.g. `3/` (main) or `3/2/` (main + middle)
//! - a full individual address, e.g. `1.1.30`
//!
//! Whitespace around terms is ignored; an empty expression matches everything.

use std::str::FromStr;

use bussard_model::{GroupAddress, IndividualAddress};

use crate::decode::{DecodedTelegram, DestinationRef};

/// A single filter term.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    /// An exact group address.
    Group(GroupAddress),
    /// A main-group prefix (`3/`): matches GAs whose main equals this.
    GroupMain(u8),
    /// A main+middle prefix (`3/2/`): matches GAs whose main and middle match.
    GroupMainMiddle(u8, u8),
    /// An exact individual address.
    Individual(IndividualAddress),
}

/// A parsed address filter. An empty filter matches every telegram.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filter {
    terms: Vec<Term>,
}

/// An error parsing a filter expression.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid filter term {term:?}: expected a group address (3/2/0), a GA prefix (3/ or 3/2/), or an individual address (1.1.30)"
)]
pub struct FilterParseError {
    /// The offending term.
    pub term: String,
}

impl Filter {
    /// Parses a comma-separated filter expression.
    ///
    /// An empty or all-whitespace expression yields an empty filter that
    /// matches everything.
    pub fn parse(expr: &str) -> Result<Filter, FilterParseError> {
        let mut terms = Vec::new();
        for raw in expr.split(',') {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            terms.push(parse_term(t)?);
        }
        Ok(Filter { terms })
    }

    /// Whether the filter has no terms (and therefore matches everything).
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Whether `telegram` passes the filter.
    ///
    /// An empty filter passes everything; otherwise the telegram passes if any
    /// term matches its source or destination.
    pub fn matches(&self, telegram: &DecodedTelegram) -> bool {
        if self.terms.is_empty() {
            return true;
        }
        let (source, dest) = telegram.addresses();
        self.terms
            .iter()
            .any(|term| term_matches_source(term, source) || term_matches_dest(term, dest))
    }
}

impl FromStr for Filter {
    type Err = FilterParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Filter::parse(s)
    }
}

/// Parses a single (already-trimmed, non-empty) filter term.
fn parse_term(t: &str) -> Result<Term, FilterParseError> {
    let err = || FilterParseError {
        term: t.to_string(),
    };

    // Individual addresses use `.` separators.
    if t.contains('.') {
        return t
            .parse::<IndividualAddress>()
            .map(Term::Individual)
            .map_err(|_| err());
    }

    // Group addresses / prefixes use `/`.
    if t.contains('/') {
        // Split, keeping trailing-empty segments so `3/` and `3/2/` are prefixes.
        let parts: Vec<&str> = t.split('/').collect();
        return match parts.as_slice() {
            // "3/2/0" — full GA.
            [_, _, last] if !last.is_empty() => t
                .parse::<GroupAddress>()
                .map(Term::Group)
                .map_err(|_| err()),
            // "3/" — main prefix.
            [main, ""] => {
                let m = parse_level(main, GroupAddress::MAIN_MAX).ok_or_else(err)?;
                Ok(Term::GroupMain(m))
            }
            // "3/2/" — main+middle prefix.
            [main, middle, ""] => {
                let m = parse_level(main, GroupAddress::MAIN_MAX).ok_or_else(err)?;
                let mid = parse_level(middle, GroupAddress::MIDDLE_MAX).ok_or_else(err)?;
                Ok(Term::GroupMainMiddle(m, mid))
            }
            _ => Err(err()),
        };
    }

    Err(err())
}

/// Parses a single GA level, enforcing its inclusive maximum.
fn parse_level(s: &str, max: u32) -> Option<u8> {
    let v: u32 = s.trim().parse().ok()?;
    if v > max {
        return None;
    }
    Some(v as u8)
}

/// Whether `term` matches an individual source address.
fn term_matches_source(term: &Term, source: IndividualAddress) -> bool {
    matches!(term, Term::Individual(i) if *i == source)
}

/// Whether `term` matches a telegram destination.
fn term_matches_dest(term: &Term, dest: DestinationRef) -> bool {
    match (term, dest) {
        (Term::Individual(i), DestinationRef::Individual(d)) => *i == d,
        (Term::Group(g), DestinationRef::Group(d)) => *g == d,
        (Term::GroupMain(m), DestinationRef::Group(d)) => d.main() == *m,
        (Term::GroupMainMiddle(m, mid), DestinationRef::Group(d)) => {
            d.main() == *m && d.middle() == *mid
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use crate::decode::ApciKind;
    use bussard_model::codec::TypedValue;

    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    fn tel(source: &str, dest: DestinationRef) -> DecodedTelegram {
        DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia(source),
            source_name: None,
            destination: dest,
            destination_name: None,
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(TypedValue::Raw(vec![1])),
            dpt: None,
            object_name: None,
            decode_note: None,
        }
    }

    #[test]
    fn empty_matches_everything() {
        let f = Filter::parse("").unwrap();
        assert!(f.is_empty());
        assert!(f.matches(&tel("1.1.1", DestinationRef::Group(ga("9/1/9")))));

        // Whitespace-only and stray commas are also empty.
        assert!(Filter::parse("  ").unwrap().is_empty());
        assert!(Filter::parse(" , , ").unwrap().is_empty());
    }

    #[test]
    fn exact_ga() {
        let f = Filter::parse("3/2/0").unwrap();
        assert!(f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/2/0")))));
        assert!(!f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/2/1")))));
    }

    #[test]
    fn ga_main_prefix() {
        let f = Filter::parse("3/").unwrap();
        assert!(f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/0/4")))));
        assert!(f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/7/255")))));
        assert!(!f.matches(&tel("1.1.1", DestinationRef::Group(ga("4/0/0")))));
    }

    #[test]
    fn ga_main_middle_prefix() {
        let f = Filter::parse("3/2/").unwrap();
        assert!(f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/2/9")))));
        assert!(!f.matches(&tel("1.1.1", DestinationRef::Group(ga("3/3/9")))));
    }

    #[test]
    fn individual_matches_source_or_dest() {
        let f = Filter::parse("1.1.30").unwrap();
        // As source.
        assert!(f.matches(&tel("1.1.30", DestinationRef::Group(ga("9/1/9")))));
        // As destination.
        assert!(f.matches(&tel("2.2.2", DestinationRef::Individual(ia("1.1.30")))));
        // Neither.
        assert!(!f.matches(&tel("2.2.2", DestinationRef::Group(ga("9/1/9")))));
    }

    #[test]
    fn multiple_terms_any_match() {
        let f = Filter::parse("3/2/0, 1.1.30, 5/").unwrap();
        assert!(f.matches(&tel("9.9.9", DestinationRef::Group(ga("3/2/0")))));
        assert!(f.matches(&tel("1.1.30", DestinationRef::Group(ga("9/1/9")))));
        assert!(f.matches(&tel("9.9.9", DestinationRef::Group(ga("5/1/2")))));
        assert!(!f.matches(&tel("9.9.9", DestinationRef::Group(ga("6/1/2")))));
    }

    #[test]
    fn parse_errors() {
        assert!(Filter::parse("abc").is_err());
        assert!(Filter::parse("3/2/0/1").is_err());
        assert!(Filter::parse("32/0/0").is_err()); // main out of range
        assert!(Filter::parse("3/8/").is_err()); // middle out of range
        assert!(Filter::parse("1.1").is_err()); // incomplete IA
    }
}
