//! Exact serde for `Option<f64>`: the value travels as its IEEE-754 bit
//! pattern, so a parsed product read back from the parsed-product cache
//! (issue #214) carries the very same float, NaN and infinities included. A
//! decimal round trip through JSON is not guaranteed to be exact.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serializes `value` as its bit pattern.
pub(crate) fn serialize<S: Serializer>(value: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    value.map(f64::to_bits).serialize(s)
}

/// Deserializes a bit pattern written by [`serialize`].
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    Ok(Option::<u64>::deserialize(d)?.map(f64::from_bits))
}
