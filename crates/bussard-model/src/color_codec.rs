//! The value codec of a `<TypeColor>` parameter (issue #616): a colour
//! written as `#` and two hex digits per component, placed in memory as one
//! octet per component in the written order.

/// The `Space` of a `<TypeColor>`: the components a colour value carries, in
/// the order they are written and placed in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ColorSpace {
    /// `RGB`: red, green, blue; three octets.
    Rgb,
    /// `RGBW`: red, green, blue, white; four octets.
    Rgbw,
    /// `HSV`: hue, saturation, value; three octets.
    Hsv,
}

impl ColorSpace {
    /// The `Space` attribute value, `None` for a space the schema does not
    /// name (the type then stays an "other" shape).
    pub fn from_attr(space: &str) -> Option<ColorSpace> {
        match space.trim() {
            "RGB" => Some(ColorSpace::Rgb),
            "RGBW" => Some(ColorSpace::Rgbw),
            "HSV" => Some(ColorSpace::Hsv),
            _ => None,
        }
    }

    /// The `Space` attribute as the schema spells it.
    pub fn as_attr(self) -> &'static str {
        match self {
            ColorSpace::Rgb => "RGB",
            ColorSpace::Rgbw => "RGBW",
            ColorSpace::Hsv => "HSV",
        }
    }

    /// The number of components, which is the number of octets in memory.
    pub fn octets(self) -> usize {
        match self {
            ColorSpace::Rgb | ColorSpace::Hsv => 3,
            ColorSpace::Rgbw => 4,
        }
    }

    /// The octets of `value`: `#` followed by two hex digits per component,
    /// in the order the space names them (`#FF8000` is `FF 80 00`). The `#`
    /// may be left out; anything else is refused with the reason.
    ///
    /// Every vendor default in the product corpus (2026-10-30, 181
    /// applications, `RGB` and `HSV`) is written this way. The octet order is
    /// the written order; no ETS capture confirms it yet (the synthetic
    /// product `syn-color-param` and its `-hsv` twin are the oracle rows,
    /// issue #616).
    pub fn encode(self, value: &str) -> std::result::Result<Vec<u8>, String> {
        let raw = value.trim();
        let hex = raw.strip_prefix('#').unwrap_or(raw);
        let want = self.octets() * 2;
        if hex.len() != want || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "`{raw}` is not a {} colour (`#` and {want} hex digits)",
                self.as_attr()
            ));
        }
        (0..self.octets())
            .map(|i| {
                hex.get(i * 2..i * 2 + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| format!("`{raw}` is not a hex colour"))
            })
            .collect()
    }

    /// The value of `bytes` as the model writes it: `#` and two upper-case hex
    /// digits per component. `None` when `bytes` is not the space's width.
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        if bytes.len() != self.octets() {
            return None;
        }
        let mut out = String::from("#");
        for b in bytes {
            out.push_str(&format!("{b:02X}"));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = std::result::Result<(), Box<dyn std::error::Error>>;

    // The octet order below (components in the written order, `#RRGGBB` as
    // `RR GG BB`, `#HHSSVV` as `HH SS VV`) is bussard's reading of the value
    // string; the ETS capture of `syn-color-param` and `syn-color-param-hsv`
    // (issue #616) must confirm it before the issue closes.

    #[test]
    fn test_encode_rgb_written_order() -> R {
        assert_eq!(ColorSpace::Rgb.encode("#FF8001")?, vec![0xFF, 0x80, 0x01]);
        assert_eq!(ColorSpace::Rgb.encode("#00ff00")?, vec![0x00, 0xFF, 0x00]);
        assert_eq!(ColorSpace::Rgb.encode(" 0000FF ")?, vec![0x00, 0x00, 0xFF]);
        Ok(())
    }

    #[test]
    fn test_encode_hsv_written_order() -> R {
        assert_eq!(ColorSpace::Hsv.encode("#FF0000")?, vec![0xFF, 0x00, 0x00]);
        assert_eq!(ColorSpace::Hsv.encode("#2A80C0")?, vec![0x2A, 0x80, 0xC0]);
        Ok(())
    }

    #[test]
    fn test_encode_rgbw_four_octets() -> R {
        assert_eq!(
            ColorSpace::Rgbw.encode("#11223344")?,
            vec![0x11, 0x22, 0x33, 0x44]
        );
        assert!(ColorSpace::Rgbw.encode("#112233").is_err());
        Ok(())
    }

    #[test]
    fn test_encode_refuses_malformed() {
        for bad in [
            "", "#", "0", "#FF00", "#FF00000", "#GG0000", "red", "16711680",
        ] {
            assert!(ColorSpace::Rgb.encode(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn test_decode_round_trip() -> R {
        for space in [ColorSpace::Rgb, ColorSpace::Hsv, ColorSpace::Rgbw] {
            let value = if space == ColorSpace::Rgbw {
                "#0A0B0C0D"
            } else {
                "#0A0B0C"
            };
            let bytes = space.encode(value)?;
            assert_eq!(space.decode(&bytes).as_deref(), Some(value));
        }
        assert_eq!(ColorSpace::Rgb.decode(&[1, 2]), None);
        Ok(())
    }

    #[test]
    fn test_from_attr_schema_spaces() {
        assert_eq!(ColorSpace::from_attr("RGB"), Some(ColorSpace::Rgb));
        assert_eq!(ColorSpace::from_attr("RGBW"), Some(ColorSpace::Rgbw));
        assert_eq!(ColorSpace::from_attr("HSV"), Some(ColorSpace::Hsv));
        assert_eq!(ColorSpace::from_attr("CMYK"), None);
    }
}
