//! The one output style of the CLI's human text (issue #792).
//!
//! Every command that prints for a person renders through a [`Style`]:
//! aligned [`Table`]s with a dim header, semantic [`Tone`]s (ok green,
//! warning yellow, error red, dim for secondary text), a [`Style::summary`]
//! line, a [`Style::next_steps`] block and [`Symbol`]s with an ASCII
//! fallback. Wording follows `dev/glossary.md`.
//!
//! Colour is on for a terminal unless `NO_COLOR` is set. Symbols are the
//! Unicode ones only when colour is on and the locale is UTF-8; otherwise
//! each has a plain word or ASCII sign, so piped output and logs stay
//! readable. `--json` never goes through this module.

use std::io::IsTerminal;

use owo_colors::OwoColorize;

/// How a piece of text is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tone {
    /// No styling.
    #[default]
    Plain,
    /// Went well: green.
    Ok,
    /// Needs a look: yellow.
    Warn,
    /// Failed: red.
    Error,
    /// Secondary text: dim.
    Dim,
    /// Emphasis: bold.
    Bold,
}

/// A symbol with its ASCII fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Symbol {
    /// KNX Secure is on: a lock, else `secure`.
    Secured,
    /// The separator of a summary line: a middle dot, else a comma.
    Separator,
    /// A missing value: an en dash, else `-`.
    Missing,
    /// The start of a next-step line: an arrow, else `>`.
    Arrow,
}

/// The output style of one stream: whether it colours and whether it may use
/// Unicode symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Style {
    /// ANSI colours on.
    color: bool,
    /// Unicode symbols on.
    unicode: bool,
}

impl Style {
    /// The style of standard output.
    pub(crate) fn stdout() -> Style {
        Style::detect(std::io::stdout().is_terminal())
    }

    /// The style of standard error.
    pub(crate) fn stderr() -> Style {
        Style::detect(std::io::stderr().is_terminal())
    }

    /// Colour on a terminal without `NO_COLOR`; Unicode symbols only then and
    /// on a UTF-8 locale.
    fn detect(terminal: bool) -> Style {
        let color = terminal && std::env::var_os("NO_COLOR").is_none();
        Style {
            color,
            unicode: color && utf8_locale(),
        }
    }

    /// No colour, ASCII symbols: what piped output and logs get.
    #[cfg(test)]
    pub(crate) const fn plain() -> Style {
        Style {
            color: false,
            unicode: false,
        }
    }

    /// Colour and Unicode symbols (tests of the coloured rendering).
    #[cfg(test)]
    pub(crate) const fn rich() -> Style {
        Style {
            color: true,
            unicode: true,
        }
    }

    /// `text` in `tone`.
    pub(crate) fn paint(self, text: &str, tone: Tone) -> String {
        if !self.color {
            return text.to_string();
        }
        match tone {
            Tone::Plain => text.to_string(),
            Tone::Ok => text.green().to_string(),
            Tone::Warn => text.yellow().to_string(),
            Tone::Error => text.red().to_string(),
            Tone::Dim => text.dimmed().to_string(),
            Tone::Bold => text.bold().to_string(),
        }
    }

    /// `text` in green.
    pub(crate) fn ok(self, text: &str) -> String {
        self.paint(text, Tone::Ok)
    }

    /// `text` in yellow.
    pub(crate) fn warn(self, text: &str) -> String {
        self.paint(text, Tone::Warn)
    }

    /// `text` dimmed.
    pub(crate) fn dim(self, text: &str) -> String {
        self.paint(text, Tone::Dim)
    }

    /// `text` in bold.
    pub(crate) fn bold(self, text: &str) -> String {
        self.paint(text, Tone::Bold)
    }

    /// The symbol, or its ASCII fallback.
    pub(crate) fn symbol(self, symbol: Symbol) -> &'static str {
        match (symbol, self.unicode) {
            (Symbol::Secured, true) => "\u{1F512}",
            (Symbol::Secured, false) => "secure",
            (Symbol::Separator, true) => " \u{00B7} ",
            (Symbol::Separator, false) => ", ",
            (Symbol::Missing, true) => "\u{2013}",
            (Symbol::Missing, false) => "-",
            (Symbol::Arrow, true) => "\u{2192}",
            (Symbol::Arrow, false) => ">",
        }
    }

    /// `warning: <message>`, the label in bold yellow.
    pub(crate) fn warning_line(self, message: &str) -> String {
        format!("{}: {message}", self.paint_both("warning", Tone::Warn))
    }

    /// `error: <message>`, the label in bold red.
    pub(crate) fn error_line(self, message: &str) -> String {
        format!("{}: {message}", self.paint_both("error", Tone::Error))
    }

    /// `text` in `tone` and bold.
    fn paint_both(self, text: &str, tone: Tone) -> String {
        if self.color {
            self.paint(&self.bold(text), tone)
        } else {
            text.to_string()
        }
    }

    /// One summary line: the parts joined by the separator symbol, each in
    /// its tone, the line in bold. Parts with empty text are left out.
    pub(crate) fn summary(self, parts: &[(String, Tone)]) -> String {
        let separator = self.dim(self.symbol(Symbol::Separator));
        parts
            .iter()
            .filter(|(text, _)| !text.is_empty())
            .map(|(text, tone)| {
                let tone = if *tone == Tone::Plain {
                    Tone::Bold
                } else {
                    *tone
                };
                self.paint_both(text, tone)
            })
            .collect::<Vec<_>>()
            .join(&separator)
    }

    /// The "Next steps" block: a heading, then each command (bold) with what
    /// it does (dim) below it. Empty when there are no steps.
    pub(crate) fn next_steps(self, steps: &[(&str, &str)]) -> String {
        if steps.is_empty() {
            return String::new();
        }
        let mut out = format!("{}\n", self.bold("Next steps"));
        for (command, why) in steps {
            out.push_str(&format!(
                "  {} {}\n    {}\n",
                self.dim(self.symbol(Symbol::Arrow)),
                self.bold(command),
                self.dim(why)
            ));
        }
        out
    }
}

/// Whether the locale says UTF-8 (`LC_ALL`, then `LC_CTYPE`, then `LANG`,
/// the first one set wins). Windows terminals take UTF-8 when the Windows
/// Terminal says it runs them.
fn utf8_locale() -> bool {
    if cfg!(windows) {
        return std::env::var_os("WT_SESSION").is_some();
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
}

/// `1 device`, `2 devices`: the count with the noun spelled out.
pub(crate) fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// The columns a string takes on a terminal: one per character, two for the
/// wide symbols this module prints (the emoji block).
fn display_width(text: &str) -> usize {
    text.chars()
        .map(|c| {
            if ('\u{1F300}'..='\u{1FAFF}').contains(&c) {
                2
            } else {
                1
            }
        })
        .sum()
}

/// One table cell: its text and tone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cell {
    /// The text, unstyled.
    text: String,
    /// How it is coloured.
    tone: Tone,
}

impl Cell {
    /// A cell in `tone`.
    pub(crate) fn new(text: impl Into<String>, tone: Tone) -> Cell {
        Cell {
            text: text.into(),
            tone,
        }
    }

    /// An unstyled cell.
    pub(crate) fn plain(text: impl Into<String>) -> Cell {
        Cell::new(text, Tone::Plain)
    }
}

impl From<String> for Cell {
    fn from(text: String) -> Cell {
        Cell::plain(text)
    }
}

impl From<&str> for Cell {
    fn from(text: &str) -> Cell {
        Cell::plain(text)
    }
}

/// An aligned table: a dim header and rows of [`Cell`]s, two spaces between
/// columns, no trailing blanks.
#[derive(Debug, Clone, Default)]
pub(crate) struct Table {
    /// The column headings.
    headers: Vec<String>,
    /// The rows; a short row leaves its last columns empty. Cells past the
    /// headings are not shown.
    rows: Vec<Vec<Cell>>,
}

impl Table {
    /// A table with these column headings.
    pub(crate) fn new(headers: &[&str]) -> Table {
        Table {
            headers: headers.iter().map(|h| (*h).to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Adds one row.
    pub(crate) fn row(&mut self, cells: Vec<Cell>) {
        self.rows.push(cells);
    }

    /// Whether the table has no rows.
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The table, one line per row after the header, each ending in `\n`.
    /// A column no row has text in is left out, heading and all.
    pub(crate) fn render(&self, style: Style) -> String {
        let shown: Vec<usize> = (0..self.headers.len())
            .filter(|&i| {
                self.rows
                    .iter()
                    .any(|row| row.get(i).is_some_and(|c| !c.text.is_empty()))
            })
            .collect();
        let pick = |row: &[Cell]| -> Vec<Cell> {
            shown
                .iter()
                .map(|&i| row.get(i).cloned().unwrap_or_default())
                .collect()
        };
        let header: Vec<Cell> = shown
            .iter()
            .map(|&i| Cell::new(self.headers[i].clone(), Tone::Dim))
            .collect();
        let rows: Vec<Vec<Cell>> = self.rows.iter().map(|r| pick(r)).collect();
        let mut widths = vec![0usize; shown.len()];
        for row in std::iter::once(&header).chain(&rows) {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(display_width(&cell.text));
            }
        }
        let mut out = String::new();
        for row in std::iter::once(&header).chain(&rows) {
            let mut line = String::new();
            let last = row
                .iter()
                .rposition(|c| !c.text.is_empty())
                .map_or(0, |i| i + 1);
            for (i, cell) in row.iter().take(last).enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                line.push_str(&style.paint(&cell.text, cell.tone));
                if i + 1 < last {
                    let pad = widths[i].saturating_sub(display_width(&cell.text));
                    line.push_str(&" ".repeat(pad));
                }
            }
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_render_aligns_columns_without_trailing_blanks() {
        let mut table = Table::new(&["Address", "Product", "In project"]);
        table.row(vec!["1.1.4".into(), "MDT JAL-0410.01".into(), "yes".into()]);
        table.row(vec!["1.1.200".into(), "".into(), "no".into()]);
        table.row(vec!["1.1.7".into(), "Jung 2118".into()]);
        assert_eq!(
            table.render(Style::plain()),
            "Address  Product          In project\n\
             1.1.4    MDT JAL-0410.01  yes\n\
             1.1.200                   no\n\
             1.1.7    Jung 2118\n"
        );
    }

    #[test]
    fn test_table_render_leaves_out_empty_columns() {
        let mut table = Table::new(&["Address", "Name", "Keys"]);
        table.row(vec!["1.1.10".into(), "".into(), "tool key".into()]);
        assert_eq!(
            table.render(Style::plain()),
            "Address  Keys\n1.1.10   tool key\n"
        );
    }

    #[test]
    fn test_table_render_colours_header_and_cells() {
        let mut table = Table::new(&["A", "B"]);
        table.row(vec![Cell::new("x", Tone::Ok), Cell::new("y", Tone::Error)]);
        let text = table.render(Style::rich());
        assert!(text.contains(&"A".dimmed().to_string()), "{text:?}");
        assert!(text.contains(&"x".green().to_string()), "{text:?}");
        assert!(text.contains(&"y".red().to_string()), "{text:?}");
    }

    #[test]
    fn test_table_render_counts_the_lock_as_two_columns() {
        let mut table = Table::new(&["S", "N"]);
        table.row(vec!["\u{1F512}".into(), "a".into()]);
        table.row(vec!["".into(), "b".into()]);
        let text = table.render(Style::plain());
        assert_eq!(text, "S   N\n\u{1F512}  a\n    b\n");
    }

    #[test]
    fn test_symbol_falls_back_to_ascii() {
        assert_eq!(Style::plain().symbol(Symbol::Secured), "secure");
        assert_eq!(Style::rich().symbol(Symbol::Secured), "\u{1F512}");
        assert_eq!(Style::plain().symbol(Symbol::Separator), ", ");
    }

    #[test]
    fn test_summary_joins_parts_and_skips_empty_ones() {
        let parts = [
            ("46 devices found".to_string(), Tone::Ok),
            (String::new(), Tone::Plain),
            ("256 addresses in 52 s".to_string(), Tone::Plain),
        ];
        assert_eq!(
            Style::plain().summary(&parts),
            "46 devices found, 256 addresses in 52 s"
        );
        let rich = Style::rich().summary(&parts);
        assert!(rich.contains(" \u{00B7} "), "{rich:?}");
        assert!(rich.contains('\u{1b}'), "{rich:?}");
    }

    #[test]
    fn test_next_steps_lists_command_and_why() {
        assert_eq!(Style::plain().next_steps(&[]), "");
        assert_eq!(
            Style::plain().next_steps(&[("bussard adopt 1.1.7", "adds the device")]),
            "Next steps\n  > bussard adopt 1.1.7\n    adds the device\n"
        );
    }

    #[test]
    fn test_count_spells_the_noun() {
        assert_eq!(count(1, "device", "devices"), "1 device");
        assert_eq!(count(46, "device", "devices"), "46 devices");
        assert_eq!(count(0, "device", "devices"), "0 devices");
    }

    #[test]
    fn test_warning_line_plain() {
        assert_eq!(Style::plain().warning_line("x"), "warning: x");
        assert_eq!(Style::plain().error_line("y"), "error: y");
    }
}
