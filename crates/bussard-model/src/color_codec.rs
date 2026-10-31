//! The value codec of a `<TypeColor>` parameter (issue #616): a colour
//! written as `#` and two hex digits per component.
//!
//! `RGB` and `RGBW` values are placed as one octet per component in the
//! written order. An `HSV` value is written as RGB hex too (`#FF0000` is red)
//! and ETS converts it to hue, saturation and value octets (see
//! [`rgb_to_hsv_octets`]); the decoder maps the octets back to an RGB value
//! that converts to the same octets.

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

    /// The number of components, which is the number of octets in memory
    /// and the number of hex pairs in the value (an `HSV` value is written as
    /// RGB hex, three pairs).
    pub fn octets(self) -> usize {
        match self {
            ColorSpace::Rgb | ColorSpace::Hsv => 3,
            ColorSpace::Rgbw => 4,
        }
    }

    /// The octets of `value`: `#` followed by two hex digits per component.
    /// The `#` may be left out; anything else is refused with the reason.
    ///
    /// `RGB` and `RGBW` place the components in the written order
    /// (`#FF8000` is `FF 80 00`), as ETS does (capture of the synthetic
    /// product `syn-color-param`, issue #616). An `HSV` value is RGB hex as
    /// well, converted to hue, saturation and value octets by
    /// [`rgb_to_hsv_octets`] (captures `syn-color-param-hsv` and `-hsv2`).
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
        let components = (0..self.octets())
            .map(|i| {
                hex.get(i * 2..i * 2 + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| format!("`{raw}` is not a hex colour"))
            })
            .collect::<std::result::Result<Vec<u8>, String>>()?;
        match (self, components.as_slice()) {
            (ColorSpace::Hsv, &[r, g, b]) => Ok(rgb_to_hsv_octets(r, g, b).to_vec()),
            _ => Ok(components),
        }
    }

    /// The value of `bytes` as the model writes it: `#` and two upper-case hex
    /// digits per component. `None` when `bytes` is not the space's width.
    ///
    /// `HSV` octets decode to the RGB value whose conversion gives exactly
    /// these octets ([`hsv_octets_to_rgb`]), so the decoded value re-encodes
    /// to what the device holds. The conversion is lossy (several RGB values
    /// share one triple); the one nearest the triple's exact inverse is
    /// shown. A triple no RGB value converts to (ETS never writes one)
    /// decodes as `HSV:HHSSVV`, which the encoder refuses: distinct octets
    /// always decode to distinct strings.
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        if bytes.len() != self.octets() {
            return None;
        }
        if let (ColorSpace::Hsv, &[h, s, v]) = (self, bytes) {
            return Some(match hsv_octets_to_rgb(h, s, v) {
                Some([r, g, b]) => format!("#{r:02X}{g:02X}{b:02X}"),
                None => format!("HSV:{h:02X}{s:02X}{v:02X}"),
            });
        }
        let mut out = String::from("#");
        for b in bytes {
            out.push_str(&format!("{b:02X}"));
        }
        Some(out)
    }
}

/// The hue, saturation and value octets ETS writes for the RGB colour
/// `r`, `g`, `b` of a `TypeColor Space="HSV"` parameter (issue #616).
///
/// With `max` and `min` the largest and smallest component:
///
/// - H = floor(hue_degrees * 255 / 360), the hue in the usual hexcone
///   sectors (red 0, green 120, blue 240 degrees), 0 for a grey;
/// - S = floor(255 * (max - min) / max), 0 when `max` is 0;
/// - V = max.
///
/// Pinned by three ETS 6.4.1 captures into knx-sim (2026-10-31): `#FF0000`
/// gives `00 FF FF` (`syn-color-param-hsv`), `#FC35C7` gives `DF C9 FC` and
/// `#90F32C` gives `3F D0 F3` (`syn-color-param-hsv2`). Of 80 candidate
/// scales (hue in 255, 256, 240, 180 or 100 steps; saturation and value in
/// 255, 256, 240 or 100; truncated or rounded) only this one gives all three.
/// Black (and every grey's hue) is not captured: S is defined as 0 there,
/// which is what the formula's limit and common HSV code give.
pub fn rgb_to_hsv_octets(r: u8, g: u8, b: u8) -> [u8; 3] {
    let (r, g, b) = (u32::from(r), u32::from(g), u32::from(b));
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let d = max - min;
    if d == 0 {
        // A grey (or black): no hue, no saturation. `max` fits in a u8.
        return [0, 0, max as u8];
    }
    // The hue in units of 1/d sector (six sectors of 60 degrees), exact in
    // integers: hue_degrees = 60 * sectors / d, so
    // H = floor(hue_degrees * 255 / 360) = floor(sectors * 255 / (6 * d)).
    let sectors = if max == r {
        // (g - b) / d, taken modulo 6.
        if g >= b { g - b } else { 6 * d - (b - g) }
    } else if max == g {
        // 2 + (b - r) / d, with b - r in [-d, d].
        2 * d + b - r
    } else {
        // 4 + (r - g) / d.
        4 * d + r - g
    };
    // sectors < 6 * d, so the quotient is below 255; S <= 255.
    let h = sectors * 255 / (6 * d);
    let s = 255 * d / max;
    [h as u8, s as u8, max as u8]
}

/// An RGB colour that [`rgb_to_hsv_octets`] converts to `h`, `s`, `v`, the
/// one nearest the exact inverse of the triple (hue `h * 360 / 255` degrees,
/// saturation `s / 255`, value `v`); `None` when no RGB colour converts to
/// the triple (issue #616).
///
/// Every candidate is checked by converting it forward, so the result always
/// re-encodes to the same octets. The search is exact and small: `max` is
/// `v`, `min` is fixed by `s` up to a few values, and only the middle
/// component varies (at most 256 values per sector arrangement).
pub fn hsv_octets_to_rgb(h: u8, s: u8, v: u8) -> Option<[u8; 3]> {
    let target = exact_inverse(h, s, v);
    let mut best: Option<([u8; 3], f64)> = None;
    for min in 0..=v {
        // Saturation is decreasing in `min`; skip the values it rules out.
        if rgb_to_hsv_octets(v, min, min)[1] != s {
            continue;
        }
        for mid in min..=v {
            for cand in [
                [v, mid, min],
                [mid, v, min],
                [min, v, mid],
                [min, mid, v],
                [mid, min, v],
                [v, min, mid],
            ] {
                if rgb_to_hsv_octets(cand[0], cand[1], cand[2]) != [h, s, v] {
                    continue;
                }
                let dist: f64 = cand
                    .iter()
                    .zip(target.iter())
                    .map(|(&c, &t)| (f64::from(c) - t).powi(2))
                    .sum();
                // Strictly nearer only: the first of equals wins, so the
                // result is a function of the octets alone.
                if best.as_ref().is_none_or(|(_, d)| dist < *d) {
                    best = Some((cand, dist));
                }
            }
        }
    }
    best.map(|(rgb, _)| rgb)
}

/// The textbook HSV to RGB inverse of the triple read as hue
/// `h * 360 / 255` degrees, saturation `s / 255` and value `v`, unrounded.
fn exact_inverse(h: u8, s: u8, v: u8) -> [f64; 3] {
    let v = f64::from(v);
    let c = v * f64::from(s) / 255.0;
    let hp = f64::from(h) * 6.0 / 255.0;
    let x = c * (1.0 - ((hp % 2.0) - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    [r + m, g + m, b + m]
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = std::result::Result<(), Box<dyn std::error::Error>>;

    // RGB: components in the written order, confirmed by the ETS capture of
    // `syn-color-param`. HSV: RGB hex converted to H, S, V octets, pinned by
    // the captures of `syn-color-param-hsv` and `-hsv2` (issue #616).

    #[test]
    fn test_encode_rgb_written_order() -> R {
        assert_eq!(ColorSpace::Rgb.encode("#FF8001")?, vec![0xFF, 0x80, 0x01]);
        assert_eq!(ColorSpace::Rgb.encode("#00ff00")?, vec![0x00, 0xFF, 0x00]);
        assert_eq!(ColorSpace::Rgb.encode(" 0000FF ")?, vec![0x00, 0x00, 0xFF]);
        Ok(())
    }

    /// The three captured colours (issue #616): ETS wrote `00 FF FF`,
    /// `DF C9 FC` and `3F D0 F3`.
    #[test]
    fn test_encode_hsv_ets_captures() -> R {
        assert_eq!(ColorSpace::Hsv.encode("#FF0000")?, vec![0x00, 0xFF, 0xFF]);
        assert_eq!(ColorSpace::Hsv.encode("#FC35C7")?, vec![0xDF, 0xC9, 0xFC]);
        assert_eq!(ColorSpace::Hsv.encode("#90f32c")?, vec![0x3F, 0xD0, 0xF3]);
        Ok(())
    }

    /// Black has no saturation (max is 0); bussard writes `00 00 00`. ETS is
    /// not captured on black; the formula's limit and common HSV code give 0.
    /// A grey has no hue either.
    #[test]
    fn test_encode_hsv_black_and_grey() -> R {
        assert_eq!(ColorSpace::Hsv.encode("#000000")?, vec![0, 0, 0]);
        assert_eq!(ColorSpace::Hsv.encode("#808080")?, vec![0, 0, 0x80]);
        assert_eq!(ColorSpace::Hsv.encode("#FFFFFF")?, vec![0, 0, 0xFF]);
        Ok(())
    }

    /// The primaries and secondaries land on their sectors.
    #[test]
    fn test_rgb_to_hsv_octets_sectors() {
        assert_eq!(rgb_to_hsv_octets(0, 255, 0), [85, 255, 255]);
        assert_eq!(rgb_to_hsv_octets(0, 0, 255), [170, 255, 255]);
        assert_eq!(rgb_to_hsv_octets(255, 255, 0), [42, 255, 255]);
        assert_eq!(rgb_to_hsv_octets(255, 0, 255), [212, 255, 255]);
    }

    /// The captured colours decode to an RGB value that re-encodes to the
    /// same octets; red decodes to itself, black to black.
    #[test]
    fn test_decode_hsv_reencodes() -> R {
        assert_eq!(
            ColorSpace::Hsv.decode(&[0x00, 0xFF, 0xFF]).as_deref(),
            Some("#FF0000")
        );
        assert_eq!(
            ColorSpace::Hsv.decode(&[0, 0, 0]).as_deref(),
            Some("#000000")
        );
        for octets in [[0xDF, 0xC9, 0xFC], [0x3F, 0xD0, 0xF3], [0, 0, 0x80]] {
            let text = ColorSpace::Hsv.decode(&octets).ok_or("no decode")?;
            assert_eq!(ColorSpace::Hsv.encode(&text)?, octets.to_vec(), "{text}");
        }
        Ok(())
    }

    /// A triple no RGB value converts to (black with a hue) decodes to a
    /// distinct marker the encoder refuses.
    #[test]
    fn test_decode_hsv_unreachable_triple() {
        assert_eq!(
            ColorSpace::Hsv.decode(&[0x10, 0x00, 0x00]).as_deref(),
            Some("HSV:100000")
        );
        assert!(ColorSpace::Hsv.encode("HSV:100000").is_err());
    }

    /// Every RGB colour round-trips through the octets: decode then encode
    /// gives the octets back (sampled on a grid to keep the test fast).
    #[test]
    fn test_hsv_octets_to_rgb_is_a_preimage() -> R {
        for r in (0..=255u8).step_by(17) {
            for g in (0..=255u8).step_by(15) {
                for b in (0..=255u8).step_by(51) {
                    let octets = rgb_to_hsv_octets(r, g, b);
                    let back =
                        hsv_octets_to_rgb(octets[0], octets[1], octets[2]).ok_or("no preimage")?;
                    assert_eq!(rgb_to_hsv_octets(back[0], back[1], back[2]), octets);
                }
            }
        }
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
        for space in [ColorSpace::Rgb, ColorSpace::Rgbw] {
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
