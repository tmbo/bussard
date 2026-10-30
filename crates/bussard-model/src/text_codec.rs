//! The octets of a `TypeText` parameter (issue #401).
//!
//! An application program names the code page its text parameters are
//! written in: `<Options TextParameterEncoding="iso-8859-15">` (every MDT
//! program in the corpus), `utf-8`, and so on. The field is
//! `TypeText SizeInBit / 8` octets; the text is converted with that code page
//! and padded with NUL to the field. The vendors size their own defaults by
//! it: MDT's `M-0083_A-0255-21` ships the French scene label `Scènario`, eight
//! characters, in an eight-octet field, which only a one-octet-per-character
//! code page holds.
//!
//! A program that declares no encoding takes ISO 8859-1 (Latin-1), as ETS
//! does (issue #416): ETS 6.4.1 downloaded the synthetic product
//! `syn-text-undeclared` (no `TextParameterEncoding`, a 14-octet `TypeText`
//! at its default "Störung") as `53 74 F6 72 75 6E 67 00 00 00 00 00 00 00`,
//! captured in `captures/synthetic/syn-text-undeclared/defaults/`: one octet
//! per character, `ö` as `F6`, NUL-padded. That octet is the same in
//! Windows-1252 and ISO 8859-15; the capture does not show which of them ETS
//! uses where they differ, so the characters whose octet depends on that
//! choice are refused rather than guessed (see [`TextCodec::Undeclared`]).
//!
//! A program that declares a name this module does not know has no stated
//! code page: ASCII text is the same octets in every candidate and is written,
//! anything else is refused.

/// The code page a program's text parameters are converted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextCodec {
    /// `utf-8`.
    Utf8,
    /// `iso-8859-1` (Latin-1): one octet per character, U+0000 to U+00FF.
    Latin1,
    /// `iso-8859-15` (Latin-9): Latin-1 with the euro sign and seven other
    /// characters in place of eight Latin-1 symbols.
    Latin9,
    /// `windows-1252`: Latin-1 with printable characters in 0x80 to 0x9F.
    Windows1252,
    /// `us-ascii`: 7-bit text only.
    Ascii,
    /// No declaration: ISO 8859-1, as ETS writes it (issue #416), limited to
    /// the characters whose octet is the same in ISO 8859-1, Windows-1252 and
    /// ISO 8859-15: ASCII and U+00A0 to U+00FF without the eight Latin-9
    /// replaces. A character outside that set (the euro sign, `Š`, a C1
    /// control, anything beyond U+00FF) is refused: no capture shows what ETS
    /// writes for it.
    Undeclared,
    /// A declared name this module does not know: ASCII text is written (the
    /// same octets in every candidate), anything else refused.
    Unknown,
}

/// Latin-9's eight differences from Latin-1: (octet, character).
const LATIN9: [(u8, char); 8] = [
    (0xA4, '€'),
    (0xA6, 'Š'),
    (0xA8, 'š'),
    (0xB4, 'Ž'),
    (0xB8, 'ž'),
    (0xBC, 'Œ'),
    (0xBD, 'œ'),
    (0xBE, 'Ÿ'),
];

/// Windows-1252's 0x80 to 0x9F; `None` for its five unassigned octets.
const CP1252_HIGH: [Option<char>; 32] = [
    Some('€'),
    None,
    Some('‚'),
    Some('ƒ'),
    Some('„'),
    Some('…'),
    Some('†'),
    Some('‡'),
    Some('ˆ'),
    Some('‰'),
    Some('Š'),
    Some('‹'),
    Some('Œ'),
    None,
    Some('Ž'),
    None,
    None,
    Some('‘'),
    Some('’'),
    Some('“'),
    Some('”'),
    Some('•'),
    Some('–'),
    Some('—'),
    Some('˜'),
    Some('™'),
    Some('š'),
    Some('›'),
    Some('œ'),
    None,
    Some('ž'),
    Some('Ÿ'),
];

impl TextCodec {
    /// The codec a `TextParameterEncoding` value names, by its IANA name or a
    /// common alias, ignoring case. `None` (no declaration) and a name this
    /// module does not know is [`TextCodec::Unknown`].
    pub fn from_declaration(name: Option<&str>) -> TextCodec {
        let Some(name) = name else {
            return TextCodec::Undeclared;
        };
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "utf-8" | "utf8" => TextCodec::Utf8,
            "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" | "l1" => TextCodec::Latin1,
            "iso-8859-15" | "iso8859-15" | "latin9" | "latin-9" | "l9" => TextCodec::Latin9,
            "windows-1252" | "cp1252" => TextCodec::Windows1252,
            "us-ascii" | "ascii" => TextCodec::Ascii,
            _ => TextCodec::Unknown,
        }
    }

    /// The octet `c` is in this one-octet code page, `None` when it has none.
    fn octet(self, c: char) -> Option<u8> {
        let code = u32::from(c);
        if code < 0x80 {
            return u8::try_from(code).ok();
        }
        match self {
            TextCodec::Utf8 | TextCodec::Ascii | TextCodec::Unknown => None,
            TextCodec::Latin1 => u8::try_from(code).ok(),
            TextCodec::Undeclared => u8::try_from(code).ok().filter(|b| undeclared_octet(*b)),
            TextCodec::Latin9 => {
                if let Some((b, _)) = LATIN9.iter().find(|(_, ch)| *ch == c) {
                    return Some(*b);
                }
                let b = u8::try_from(code).ok()?;
                (!LATIN9.iter().any(|(o, _)| *o == b)).then_some(b)
            }
            TextCodec::Windows1252 => {
                if let Some(i) = CP1252_HIGH.iter().position(|ch| *ch == Some(c)) {
                    return u8::try_from(0x80 + i).ok();
                }
                u8::try_from(code).ok().filter(|b| *b >= 0xA0)
            }
        }
    }

    /// The character octet `b` stands for in this one-octet code page.
    fn char_of(self, b: u8) -> Option<char> {
        if b < 0x80 {
            return Some(char::from(b));
        }
        match self {
            TextCodec::Utf8 | TextCodec::Ascii | TextCodec::Unknown => None,
            TextCodec::Latin1 => Some(char::from(b)),
            TextCodec::Undeclared => undeclared_octet(b).then(|| char::from(b)),
            TextCodec::Latin9 => Some(
                LATIN9
                    .iter()
                    .find(|(o, _)| *o == b)
                    .map_or(char::from(b), |(_, c)| *c),
            ),
            TextCodec::Windows1252 => match b {
                0x80..=0x9F => CP1252_HIGH.get(usize::from(b - 0x80)).copied().flatten(),
                _ => Some(char::from(b)),
            },
        }
    }

    /// `text` as the octets of a field of `len` octets: converted with this
    /// code page and padded with NUL.
    ///
    /// # Errors
    ///
    /// The reason, as a sentence fragment, when a character has no octet in
    /// this code page or the text needs more than `len` octets.
    pub fn encode(self, text: &str, len: usize) -> Result<Vec<u8>, String> {
        let mut out = match self {
            TextCodec::Utf8 => text.as_bytes().to_vec(),
            _ => {
                let mut out = Vec::with_capacity(len);
                for c in text.chars() {
                    let Some(b) = self.octet(c) else {
                        return Err(match self {
                            TextCodec::Undeclared => format!(
                                "text `{text}` holds `{c}`, and the program declares no \
                                 TextParameterEncoding: ETS writes such text in ISO 8859-1, \
                                 but for `{c}` its octet is not known (issue #416)"
                            ),
                            TextCodec::Unknown => format!(
                                "text `{text}` holds `{c}`, and the program declares a \
                                 TextParameterEncoding bussard does not know, so only ASCII \
                                 text is written (issue #401)"
                            ),
                            _ => format!(
                                "text `{text}` holds `{c}`, which {} cannot represent",
                                self.name()
                            ),
                        });
                    };
                    out.push(b);
                }
                out
            }
        };
        if out.len() > len {
            return Err(format!(
                "text `{text}` is {} octets in {} but the field holds {len}",
                out.len(),
                self.name()
            ));
        }
        out.resize(len, 0);
        Ok(out)
    }

    /// The text a field holds: its octets up to the last non-NUL one,
    /// converted with this code page (an octet the code page does not assign,
    /// or invalid UTF-8, as U+FFFD).
    pub fn decode(self, field: &[u8]) -> String {
        let end = field.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        let used = field.get(..end).unwrap_or_default();
        match self {
            TextCodec::Utf8 => String::from_utf8_lossy(used).into_owned(),
            // Unknown: as before #401, read non-ASCII octets as UTF-8.
            TextCodec::Unknown => String::from_utf8_lossy(used).into_owned(),
            _ => used
                .iter()
                .map(|b| self.char_of(*b).unwrap_or('\u{FFFD}'))
                .collect(),
        }
    }

    /// The code page's name in messages.
    pub fn name(self) -> &'static str {
        match self {
            TextCodec::Utf8 => "UTF-8",
            TextCodec::Latin1 => "ISO 8859-1",
            TextCodec::Latin9 => "ISO 8859-15",
            TextCodec::Windows1252 => "Windows-1252",
            TextCodec::Undeclared => "ISO 8859-1 (no TextParameterEncoding declared)",
            TextCodec::Ascii | TextCodec::Unknown => "ASCII",
        }
    }
}

/// The octet `b` of an undeclared program's text stands for the same character
/// in ISO 8859-1, Windows-1252 and ISO 8859-15 (issue #416): ASCII, or 0xA0
/// to 0xFF other than Latin-9's eight replacements. 0x80 to 0x9F are C1
/// controls in ISO 8859-1 but printable in Windows-1252.
fn undeclared_octet(b: u8) -> bool {
    b < 0x80 || (b >= 0xA0 && !LATIN9.iter().any(|(o, _)| *o == b))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_from_declaration_names_and_fallback() {
        assert_eq!(
            TextCodec::from_declaration(Some("iso-8859-15")),
            TextCodec::Latin9
        );
        assert_eq!(
            TextCodec::from_declaration(Some("ISO-8859-1")),
            TextCodec::Latin1
        );
        assert_eq!(TextCodec::from_declaration(Some("utf-8")), TextCodec::Utf8);
        assert_eq!(
            TextCodec::from_declaration(Some("Windows-1252")),
            TextCodec::Windows1252
        );
        assert_eq!(
            TextCodec::from_declaration(Some("us-ascii")),
            TextCodec::Ascii
        );
        assert_eq!(TextCodec::from_declaration(None), TextCodec::Undeclared);
        assert_eq!(
            TextCodec::from_declaration(Some("shift_jis")),
            TextCodec::Unknown
        );
    }

    #[test]
    fn test_encode_ascii_is_the_same_in_every_code_page() -> TestResult {
        for codec in [
            TextCodec::Utf8,
            TextCodec::Latin1,
            TextCodec::Latin9,
            TextCodec::Windows1252,
            TextCodec::Ascii,
            TextCodec::Undeclared,
            TextCodec::Unknown,
        ] {
            assert_eq!(codec.encode("Szene", 8)?, b"Szene\0\0\0", "{codec:?}");
            assert_eq!(codec.decode(b"Szene\0\0\0"), "Szene");
        }
        Ok(())
    }

    /// MDT `M-0083_A-0255-21`'s French default: eight characters, eight octets.
    #[test]
    fn test_encode_latin9_accented_label_fits_eight_octets() -> TestResult {
        let octets = TextCodec::Latin9.encode("Scènario", 8)?;
        assert_eq!(octets, b"Sc\xE8nario");
        assert_eq!(TextCodec::Latin9.decode(&octets), "Scènario");
        assert_eq!(TextCodec::Latin1.encode("Décalage", 8)?, b"D\xE9calage");
        // UTF-8 needs nine.
        let err = TextCodec::Utf8
            .encode("Scènario", 8)
            .err()
            .ok_or("utf-8 fits")?;
        assert!(err.contains("9 octets in UTF-8"), "{err}");
        Ok(())
    }

    #[test]
    fn test_encode_latin9_euro_differs_from_latin1() -> TestResult {
        assert_eq!(TextCodec::Latin9.encode("5€", 2)?, b"5\xA4");
        assert_eq!(TextCodec::Latin9.decode(b"5\xA4"), "5€");
        assert_eq!(TextCodec::Windows1252.encode("5€", 2)?, b"5\x80");
        assert_eq!(TextCodec::Windows1252.decode(b"5\x80"), "5€");
        // `¤` is Latin-1's 0xA4, which Latin-9 gives to the euro sign.
        assert!(TextCodec::Latin9.encode("¤", 1).is_err());
        assert!(TextCodec::Latin1.encode("€", 1).is_err());
        Ok(())
    }

    #[test]
    fn test_encode_refuses_a_character_outside_the_code_page() -> TestResult {
        let err = TextCodec::Latin9
            .encode("Küche ✓", 16)
            .err()
            .ok_or("encoded")?;
        assert!(err.contains("`✓`") && err.contains("ISO 8859-15"), "{err}");
        let err = TextCodec::Unknown
            .encode("Küche", 16)
            .err()
            .ok_or("encoded")?;
        assert!(err.contains("issue #401"), "{err}");
        let err = TextCodec::Ascii
            .encode("Küche", 16)
            .err()
            .ok_or("encoded")?;
        assert!(err.contains("ASCII cannot represent"), "{err}");
        Ok(())
    }

    /// ETS 6.4.1's download of `syn-text-undeclared` (issue #416,
    /// `captures/synthetic/syn-text-undeclared/defaults/`): "Störung" in the
    /// 14-octet field of a program without `TextParameterEncoding`.
    #[test]
    fn test_encode_undeclared_is_latin1_nul_padded_as_ets_writes() -> TestResult {
        let octets = TextCodec::Undeclared.encode("Störung", 14)?;
        assert_eq!(
            octets,
            [
                0x53, 0x74, 0xF6, 0x72, 0x75, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(TextCodec::Undeclared.decode(&octets), "Störung");
        assert_eq!(TextCodec::Undeclared.encode("Alarm", 6)?, b"Alarm\0");
        assert_eq!(TextCodec::Undeclared.decode(b"Alarm\0"), "Alarm");
        Ok(())
    }

    /// A character whose octet ETS's choice of code page would decide, or
    /// that no one-octet candidate holds, is refused for an undeclared program.
    #[test]
    fn test_encode_undeclared_refuses_outside_the_common_latin1_range() -> TestResult {
        for text in ["5€", "Šum", "Grün ✓", "\u{0085}", "¤"] {
            let err = TextCodec::Undeclared
                .encode(text, 16)
                .err()
                .ok_or("encoded")?;
            assert!(err.contains("issue #416"), "{err}");
        }
        assert_eq!(TextCodec::Undeclared.decode(b"5\x80"), "5\u{FFFD}");
        Ok(())
    }

    #[test]
    fn test_encode_refuses_a_text_longer_than_the_field() -> TestResult {
        let err = TextCodec::Latin9
            .encode("Scènario1", 8)
            .err()
            .ok_or("encoded")?;
        assert!(err.contains("9 octets") && err.contains("holds 8"), "{err}");
        assert_eq!(TextCodec::Latin9.encode("", 3)?, [0, 0, 0]);
        Ok(())
    }
}
