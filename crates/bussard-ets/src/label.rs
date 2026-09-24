//! Filling the `{{0}}` label placeholder of Dynamic-section texts.
//!
//! A `<Channel>`, `<ParameterBlock>` or `<ComObjectRef>` with a
//! `TextParameterRefId` shows that parameter's value in place of a numbered
//! placeholder in its `Text`: `{{0}}`, or `{{0:default}}` where ETS shows
//! `default` while the parameter is empty (e.g. `"Input {{ArgBeschriftung}}
//! ({{0:...}})"`). [`substitute_label`] does that substitution;
//! [`crate::dynamic::DynamicConfig::label`] reads the label value.
//!
//! Composition with the `{{ArgName}}` resolution in `bussard-project`
//! (`build.rs`, `resolve_placeholders`): run [`substitute_label`] first, then
//! hand the result to `resolve_placeholders`. `substitute_label` touches only
//! numbered tokens, so `{{Arg…}}` tokens pass through for the module-argument
//! lookup; a numbered token left in place (no label) is then stripped there,
//! together with the `()` it leaves behind, as today. The other order does not
//! work: `resolve_placeholders` strips `{{0:…}}` before a label could fill it.

/// Replaces every `{{0}}` and `{{0:default}}` token in `text` with `label`.
///
/// With `label` `None` or blank the text is returned unchanged, so the caller
/// (or `resolve_placeholders`) decides what an unlabelled placeholder becomes;
/// ETS would show the token's `default`. Other tokens (`{{1}}`, `{{Arg…}}`) and
/// an unterminated `{{` are kept verbatim. Real application programs only use
/// index 0: an element has a single `TextParameterRefId`.
pub fn substitute_label(text: &str, label: Option<&str>) -> String {
    let Some(label) = label.filter(|l| !l.trim().is_empty()) else {
        return text.to_string();
    };
    let mut out = String::with_capacity(text.len() + label.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            out.push_str(&rest[open..]);
            return out;
        };
        let token = &after[..close];
        let index = token.split_once(':').map_or(token, |(n, _)| n);
        if index.trim() == "0" {
            out.push_str(label);
        } else {
            out.push_str(&rest[open..open + 2 + close + 2]);
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_label_fills_bare_and_default_tokens() {
        assert_eq!(
            substitute_label("Input {{ArgBeschriftung}} ({{0:...}})", Some("Kitchen")),
            "Input {{ArgBeschriftung}} (Kitchen)"
        );
        assert_eq!(substitute_label("{{0}} - {{0:x}}", Some("A")), "A - A");
    }

    #[test]
    fn test_substitute_label_without_label_keeps_text() {
        let text = "Logic function 1 ({{0:...}})";
        assert_eq!(substitute_label(text, None), text);
        assert_eq!(substitute_label(text, Some("  ")), text);
    }

    #[test]
    fn test_substitute_label_keeps_other_tokens_and_unterminated() {
        assert_eq!(
            substitute_label("{{1:y}} {{0}} {{Arg}} {{0", Some("L")),
            "{{1:y}} L {{Arg}} {{0"
        );
    }
}
