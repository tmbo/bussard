//! The script languages of `<ParameterCalculation>`s (see
//! [`crate::dynamic::ParameterCalculation`]).
//!
//! Product data derives some parameter values with small scripts: VBScript in
//! older programs (an Ekinex thermostat's fan block), JavaScript in newer ones
//! (a Jung LED dimmer's dimming curve, a Zennio dimmer's thermistor table). ETS
//! runs them in a full scripting engine; bussard interprets the subset product
//! data uses. A script is tokenised, parsed and walked here, never handed to an
//! engine: there is no I/O and no host access, only a whitelist of built-ins,
//! and a step budget stops a runaway loop. A construct outside the subset, or a
//! run-time error such as a VBScript division by zero, is refused with
//! [`ScriptError::Unsupported`] rather than guessed, so a caller never writes a
//! value it could not compute.

mod js;
mod vbscript;

/// How many statements and expression nodes one script run may evaluate
/// before it is refused as a runaway loop. Real calculations stay far below:
/// the largest seen (a 218-entry thermistor table) takes a few thousand.
const MAX_STEPS: u64 = 2_000_000;

/// How deeply statements and expressions may nest. Product data stays at a
/// handful of levels; the bound keeps a hostile `((((…` or `Not Not …` from
/// overflowing the stack of the recursive parsers and interpreters.
const MAX_DEPTH: usize = 100;

/// The longest string a script may build, in characters, and the most
/// elements an array may hold. Real calculations build short labels and
/// tables of a few hundred entries; the bounds keep a loop that doubles a
/// string from exhausting memory within the step budget.
const MAX_TEXT: usize = 65_536;

/// The most elements one JavaScript array may hold (see [`MAX_TEXT`]).
const MAX_ARRAY: usize = 65_536;

/// Refuses a string longer than [`MAX_TEXT`].
fn check_text(text: String) -> Result<String, ScriptError> {
    if text.chars().count() > MAX_TEXT {
        return Err(ScriptError::unsupported(format!(
            "string longer than {MAX_TEXT} characters"
        )));
    }
    Ok(text)
}

/// Counts one level of nesting in a recursive parser and refuses past
/// [`MAX_DEPTH`].
fn enter(depth: &mut usize) -> Result<(), ScriptError> {
    *depth += 1;
    if *depth > MAX_DEPTH {
        return Err(ScriptError::unsupported(format!(
            "nested more than {MAX_DEPTH} levels deep"
        )));
    }
    Ok(())
}

/// A value a script reads or produces.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptValue {
    /// A number. Both languages compute with one floating-point number type.
    Number(f64),
    /// A string.
    Text(String),
}

/// Why a script could not be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptError {
    /// The declared language is neither VBScript nor JavaScript.
    #[error("unsupported script language {0:?}")]
    Language(String),
    /// The script uses a construct outside the supported subset, or fails at
    /// run time (an unknown variable, a division by zero in VBScript, the step
    /// budget).
    #[error("unsupported script: {0}")]
    Unsupported(String),
}

impl ScriptError {
    fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

/// Runs `script`, written in `language` (`JavaScript` or `VBScript`, any
/// case), with `inputs` as its variables, and returns the final value of each
/// of `outputs`, in order: `None` for one the script leaves unset.
///
/// Names follow the language: case-insensitive in VBScript, case-sensitive in
/// JavaScript.
///
/// # Errors
///
/// [`ScriptError::Language`] for another language, [`ScriptError::Unsupported`]
/// when the script cannot be parsed or run within the supported subset.
pub fn run_script(
    language: &str,
    script: &str,
    inputs: &[(&str, ScriptValue)],
    outputs: &[&str],
) -> Result<Vec<Option<ScriptValue>>, ScriptError> {
    if language.eq_ignore_ascii_case("javascript") {
        js::run(script, inputs, outputs)
    } else if language.eq_ignore_ascii_case("vbscript") {
        vbscript::run(script, inputs, outputs)
    } else {
        Err(ScriptError::Language(language.to_string()))
    }
}

/// A step counter shared by both interpreters.
#[derive(Debug, Default)]
struct Budget(u64);

impl Budget {
    fn tick(&mut self) -> Result<(), ScriptError> {
        self.0 += 1;
        if self.0 > MAX_STEPS {
            return Err(ScriptError::unsupported("step budget exceeded"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_script_dispatches_by_language() -> Result<(), ScriptError> {
        let inputs = [("x", ScriptValue::Number(2.0))];
        let js = run_script("JavaScript", "var y = x * 3;", &inputs, &["y"])?;
        assert_eq!(js, [Some(ScriptValue::Number(6.0))]);
        let vb = run_script("vbscript", "Y = X * 3", &inputs, &["y"])?;
        assert_eq!(vb, [Some(ScriptValue::Number(6.0))]);
        assert_eq!(
            run_script("Python", "y = 1", &inputs, &["y"]),
            Err(ScriptError::Language("Python".to_string()))
        );
        Ok(())
    }
}
