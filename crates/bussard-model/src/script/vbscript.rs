//! The VBScript subset of parameter calculations.
//!
//! Older product data writes its calculations in VBScript: assignments,
//! `If`/`ElseIf`/`Else`/`End If` (also the single-line form), `Dim`,
//! arithmetic (`+ - * / \ Mod`), concatenation (`&`), comparisons and the
//! bitwise `And`/`Or`/`Not`, with `True` = -1 and `False` = 0 as in VBScript.
//! Names are case-insensitive. A variable that is neither an input nor
//! declared with `Dim` reads as Empty (0 or the empty string) in VBScript, but
//! here reading one before it is assigned is refused: it almost always means a
//! parameter name the script expects did not resolve, and 0 would be a silent
//! wrong value. Everything else is refused.

use std::collections::HashMap;

use super::{Budget, ScriptError, ScriptValue};

/// Runs `src` with `inputs` and returns `outputs` (see [`super::run_script`]).
pub(super) fn run(
    src: &str,
    inputs: &[(&str, ScriptValue)],
    outputs: &[&str],
) -> Result<Vec<Option<ScriptValue>>, ScriptError> {
    let mut parser = Parser::new(tokenize(src)?);
    let program = parser.program()?;
    let mut env: HashMap<String, Value> = parser
        .dims
        .into_iter()
        .map(|name| (name, Value::Empty))
        .collect();
    // The outputs are known names too: unset, they read as Empty.
    env.extend(
        outputs
            .iter()
            .map(|name| (name.to_ascii_lowercase(), Value::Empty)),
    );
    env.extend(
        inputs
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), Value::from(value))),
    );
    let mut interp = Interp {
        env,
        budget: Budget::default(),
    };
    interp.run(&program)?;
    Ok(outputs
        .iter()
        .map(|name| match interp.env.get(&name.to_ascii_lowercase()) {
            None | Some(Value::Empty) => None,
            Some(Value::Num(n)) => Some(ScriptValue::Number(*n)),
            Some(Value::Str(s)) => Some(ScriptValue::Text(s.clone())),
        })
        .collect())
}

// --- tokens -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Op(&'static str),
    Name(String),
    /// A keyword, lower-cased.
    Kw(&'static str),
    /// A line break, which ends a statement and a single-line `If`.
    Nl,
    /// `:`, which ends a statement but not a single-line `If`.
    Colon,
    Eof,
}

const KEYWORDS: &[&str] = &[
    "if", "then", "else", "elseif", "end", "and", "or", "not", "mod", "true", "false", "dim",
];
const OPS: &[&str] = &[
    "<>", "<=", ">=", "+", "-", "*", "/", "\\", "(", ")", "=", "<", ">", "&", ",",
];

fn tokenize(src: &str) -> Result<Vec<Tok>, ScriptError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        match c {
            ' ' | '\t' => i += 1,
            '\'' => {
                while chars.get(i).is_some_and(|&c| c != '\n') {
                    i += 1;
                }
            }
            '\r' | '\n' => {
                if c == '\r' && chars.get(i + 1) == Some(&'\n') {
                    i += 1;
                }
                i += 1;
                out.push(Tok::Nl);
            }
            ':' => {
                i += 1;
                out.push(Tok::Colon);
            }
            '_' => {
                // A line continuation: `_` then only spaces up to the line end.
                let mut j = i + 1;
                while chars.get(j).is_some_and(|&c| c == ' ' || c == '\t') {
                    j += 1;
                }
                match chars.get(j) {
                    Some('\n') => i = j + 1,
                    Some('\r') if chars.get(j + 1) == Some(&'\n') => i = j + 2,
                    _ => return Err(ScriptError::unsupported("unexpected '_'")),
                }
            }
            '"' => {
                let mut text = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('"') if chars.get(i + 1) == Some(&'"') => {
                            text.push('"');
                            i += 2;
                        }
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some(&c) => {
                            text.push(c);
                            i += 1;
                        }
                        None => return Err(ScriptError::unsupported("unterminated string")),
                    }
                }
                out.push(Tok::Str(text));
            }
            c if c.is_ascii_digit()
                || (c == '.' && chars.get(i + 1).is_some_and(char::is_ascii_digit)) =>
            {
                let start = i;
                while chars
                    .get(i)
                    .is_some_and(|c| c.is_ascii_digit() || *c == '.')
                {
                    i += 1;
                }
                if chars.get(i).is_some_and(|c| *c == 'e' || *c == 'E') {
                    let mut j = i + 1;
                    if chars.get(j).is_some_and(|c| *c == '+' || *c == '-') {
                        j += 1;
                    }
                    if chars.get(j).is_some_and(char::is_ascii_digit) {
                        i = j;
                        while chars.get(i).is_some_and(char::is_ascii_digit) {
                            i += 1;
                        }
                    }
                }
                let text: String = chars[start..i].iter().collect();
                let n = text
                    .parse::<f64>()
                    .map_err(|_| ScriptError::unsupported(format!("bad number {text:?}")))?;
                out.push(Tok::Num(n));
            }
            c if c.is_ascii_alphabetic() => {
                let start = i;
                while chars
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let lower = word.to_ascii_lowercase();
                if lower == "rem" {
                    while chars.get(i).is_some_and(|&c| c != '\n') {
                        i += 1;
                    }
                } else if let Some(kw) = KEYWORDS.iter().find(|k| **k == lower) {
                    out.push(Tok::Kw(kw));
                } else {
                    out.push(Tok::Name(lower));
                }
            }
            _ => {
                let op = OPS
                    .iter()
                    .find(|op| {
                        op.chars()
                            .enumerate()
                            .all(|(k, oc)| chars.get(i + k) == Some(&oc))
                    })
                    .ok_or_else(|| {
                        ScriptError::unsupported(format!("unexpected character {c:?}"))
                    })?;
                i += op.len();
                out.push(Tok::Op(op));
            }
        }
    }
    out.push(Tok::Nl);
    out.push(Tok::Eof);
    Ok(out)
}

// --- syntax -----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Mod,
    Concat,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Lit(Value),
    Var(String),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Stmt {
    Assign(String, Expr),
    /// `If` branches (condition, body) and the `Else` body.
    If(Vec<(Expr, Vec<Stmt>)>, Vec<Stmt>),
    Dim,
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
    /// The current nesting of statements and unary expressions (see
    /// [`super::MAX_DEPTH`]).
    depth: usize,
    /// The names declared with `Dim`, lower-cased: they read as Empty
    /// before an assignment, as in VBScript.
    dims: Vec<String>,
}

impl Parser {
    fn new(toks: Vec<Tok>) -> Self {
        Self {
            toks,
            i: 0,
            depth: 0,
            dims: Vec::new(),
        }
    }

    fn peek(&self) -> &Tok {
        self.toks.get(self.i).unwrap_or(&Tok::Eof)
    }

    fn peek_at(&self, offset: usize) -> &Tok {
        self.toks.get(self.i + offset).unwrap_or(&Tok::Eof)
    }

    fn next(&mut self) -> Tok {
        let t = self.peek().clone();
        self.i += 1;
        t
    }

    fn accept_kw(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Tok::Kw(k) if *k == kw) {
            self.i += 1;
            return true;
        }
        false
    }

    fn accept_op(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Tok::Op(o) if *o == op) {
            self.i += 1;
            return true;
        }
        false
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), ScriptError> {
        if self.accept_kw(kw) {
            return Ok(());
        }
        Err(ScriptError::unsupported(format!(
            "expected {kw:?}, got {:?}",
            self.peek()
        )))
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Tok::Nl | Tok::Colon) {
            self.i += 1;
        }
    }

    fn program(&mut self) -> Result<Vec<Stmt>, ScriptError> {
        let stmts = self.block(&[])?;
        if *self.peek() != Tok::Eof {
            return Err(ScriptError::unsupported(format!(
                "unexpected {:?}",
                self.peek()
            )));
        }
        Ok(stmts)
    }

    /// Statements up to (not including) one of the `terminators` keywords, or
    /// the end of the script when there are none.
    fn block(&mut self, terminators: &[&str]) -> Result<Vec<Stmt>, ScriptError> {
        let mut stmts = Vec::new();
        self.skip_newlines();
        loop {
            match self.peek() {
                Tok::Kw(k) if terminators.contains(k) => return Ok(stmts),
                Tok::Eof if terminators.is_empty() => return Ok(stmts),
                Tok::Eof => return Err(ScriptError::unsupported("unterminated If")),
                _ => {}
            }
            stmts.push(self.statement()?);
            self.skip_newlines();
        }
    }

    fn statement(&mut self) -> Result<Stmt, ScriptError> {
        super::enter(&mut self.depth)?;
        let stmt = self.statement_inner();
        self.depth -= 1;
        stmt
    }

    fn statement_inner(&mut self) -> Result<Stmt, ScriptError> {
        if self.accept_kw("if") {
            return self.if_statement();
        }
        if self.accept_kw("dim") {
            loop {
                let Tok::Name(name) = self.next() else {
                    return Err(ScriptError::unsupported("bad Dim"));
                };
                self.dims.push(name.to_ascii_lowercase());
                if !self.accept_op(",") {
                    return Ok(Stmt::Dim);
                }
            }
        }
        if let (Tok::Name(name), Tok::Op("=")) = (self.peek().clone(), self.peek_at(1)) {
            self.i += 2;
            return Ok(Stmt::Assign(name, self.expr()?));
        }
        Err(ScriptError::unsupported(format!(
            "unsupported statement starting {:?}",
            self.peek()
        )))
    }

    fn if_statement(&mut self) -> Result<Stmt, ScriptError> {
        let cond = self.expr()?;
        self.expect_kw("then")?;
        if !matches!(self.peek(), Tok::Nl | Tok::Eof) {
            // The single-line form: `If c Then a : b [Else c : d]`. Every
            // statement up to the end of the line belongs to its branch;
            // `:` separates them, it does not end the `If`.
            let body = self.single_line_branch(true)?;
            let other = if self.accept_kw("else") {
                self.single_line_branch(false)?
            } else {
                Vec::new()
            };
            return Ok(Stmt::If(vec![(cond, body)], other));
        }
        let mut branches = vec![(cond, self.block(&["elseif", "else", "end"])?)];
        let mut other = Vec::new();
        loop {
            if self.accept_kw("elseif") {
                let cond = self.expr()?;
                self.expect_kw("then")?;
                branches.push((cond, self.block(&["elseif", "else", "end"])?));
            } else if self.accept_kw("else") {
                other = self.block(&["end"])?;
            } else {
                self.expect_kw("end")?;
                self.expect_kw("if")?;
                return Ok(Stmt::If(branches, other));
            }
        }
    }

    // Expressions, loosest-binding first (VBScript precedence).

    /// The `:`-separated statements of one branch of a single-line `If`, up
    /// to the end of the line, or to its `Else` for the `Then` branch.
    fn single_line_branch(&mut self, stop_at_else: bool) -> Result<Vec<Stmt>, ScriptError> {
        let mut stmts = Vec::new();
        loop {
            while self.accept_colon() {}
            match self.peek() {
                Tok::Nl | Tok::Eof => return Ok(stmts),
                Tok::Kw("else") if stop_at_else => return Ok(stmts),
                _ => stmts.push(self.statement()?),
            }
        }
    }

    fn accept_colon(&mut self) -> bool {
        if *self.peek() == Tok::Colon {
            self.i += 1;
            return true;
        }
        false
    }

    fn expr(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.and_expr()?;
        while self.accept_kw("or") {
            left = Expr::Bin(BinOp::Or, Box::new(left), Box::new(self.and_expr()?));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.not_expr()?;
        while self.accept_kw("and") {
            left = Expr::Bin(BinOp::And, Box::new(left), Box::new(self.not_expr()?));
        }
        Ok(left)
    }

    fn not_expr(&mut self) -> Result<Expr, ScriptError> {
        if self.accept_kw("not") {
            super::enter(&mut self.depth)?;
            let inner = self.not_expr();
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner?)));
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.concat()?;
        loop {
            let op = match self.peek() {
                Tok::Op("=") => CmpOp::Eq,
                Tok::Op("<>") => CmpOp::Ne,
                Tok::Op("<") => CmpOp::Lt,
                Tok::Op(">") => CmpOp::Gt,
                Tok::Op("<=") => CmpOp::Le,
                Tok::Op(">=") => CmpOp::Ge,
                _ => return Ok(left),
            };
            self.i += 1;
            left = Expr::Cmp(op, Box::new(left), Box::new(self.concat()?));
        }
    }

    fn concat(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.additive()?;
        while self.accept_op("&") {
            left = Expr::Bin(BinOp::Concat, Box::new(left), Box::new(self.additive()?));
        }
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.modulo()?;
        loop {
            let op = if self.accept_op("+") {
                BinOp::Add
            } else if self.accept_op("-") {
                BinOp::Sub
            } else {
                return Ok(left);
            };
            left = Expr::Bin(op, Box::new(left), Box::new(self.modulo()?));
        }
    }

    fn modulo(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.int_div()?;
        while self.accept_kw("mod") {
            left = Expr::Bin(BinOp::Mod, Box::new(left), Box::new(self.int_div()?));
        }
        Ok(left)
    }

    fn int_div(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.term()?;
        while self.accept_op("\\") {
            left = Expr::Bin(BinOp::IntDiv, Box::new(left), Box::new(self.term()?));
        }
        Ok(left)
    }

    fn term(&mut self) -> Result<Expr, ScriptError> {
        let mut left = self.unary()?;
        loop {
            let op = if self.accept_op("*") {
                BinOp::Mul
            } else if self.accept_op("/") {
                BinOp::Div
            } else {
                return Ok(left);
            };
            left = Expr::Bin(op, Box::new(left), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, ScriptError> {
        super::enter(&mut self.depth)?;
        let e = self.unary_inner();
        self.depth -= 1;
        e
    }

    fn unary_inner(&mut self) -> Result<Expr, ScriptError> {
        if self.accept_op("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.accept_op("+") {
            return self.unary();
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Expr, ScriptError> {
        match self.next() {
            Tok::Num(n) => Ok(Expr::Lit(Value::Num(n))),
            Tok::Str(s) => Ok(Expr::Lit(Value::Str(s))),
            Tok::Kw("true") => Ok(Expr::Lit(Value::Num(TRUE))),
            Tok::Kw("false") => Ok(Expr::Lit(Value::Num(FALSE))),
            Tok::Name(name) => {
                if *self.peek() == Tok::Op("(") {
                    return Err(ScriptError::unsupported(format!(
                        "function call {name}() not supported"
                    )));
                }
                Ok(Expr::Var(name))
            }
            Tok::Op("(") => {
                let e = self.expr()?;
                if !self.accept_op(")") {
                    return Err(ScriptError::unsupported("expected ')'"));
                }
                Ok(e)
            }
            other => Err(ScriptError::unsupported(format!("unexpected {other:?}"))),
        }
    }
}

// --- runtime ----------------------------------------------------------------

const TRUE: f64 = -1.0;
const FALSE: f64 = 0.0;

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Empty,
    Num(f64),
    Str(String),
}

impl From<&ScriptValue> for Value {
    fn from(value: &ScriptValue) -> Self {
        match value {
            ScriptValue::Number(n) => Value::Num(*n),
            ScriptValue::Text(s) => Value::Str(s.clone()),
        }
    }
}

impl Value {
    fn num(&self) -> Result<f64, ScriptError> {
        match self {
            Value::Empty => Ok(0.0),
            Value::Num(n) => Ok(*n),
            Value::Str(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .ok_or_else(|| ScriptError::unsupported(format!("type mismatch: {s:?}"))),
        }
    }

    fn text(&self) -> Result<String, ScriptError> {
        Ok(match self {
            Value::Empty => String::new(),
            Value::Num(n) => format_number(*n)?,
            Value::Str(s) => s.clone(),
        })
    }

    fn truth(&self) -> Result<bool, ScriptError> {
        Ok(self.num()? != 0.0)
    }
}

/// VBScript's text for a number (`CStr`): rounded to 15 significant digits,
/// so `0.1 + 0.2` reads `0.3`, and whole numbers without a decimal point.
/// VBScript switches to exponent notation outside about `1e-4 ..< 1e15`; this
/// subset refuses those rather than print them differently.
fn format_number(n: f64) -> Result<String, ScriptError> {
    if n == 0.0 {
        return Ok("0".to_string());
    }
    if !n.is_finite() || !(1e-4..1e15).contains(&n.abs()) {
        return Err(ScriptError::unsupported(format!(
            "the text of {n} (VBScript writes it in exponent form)"
        )));
    }
    // Round to 15 significant digits, then print the shortest form of that.
    let rounded: f64 = format!("{n:.14e}")
        .parse()
        .map_err(|_| ScriptError::unsupported(format!("the text of {n}")))?;
    Ok(if rounded.fract() == 0.0 {
        format!("{rounded:.0}")
    } else {
        format!("{rounded}")
    })
}

/// VBScript rounds the operands of `\`, `Mod`, `And`, `Or` and `Not` to whole
/// numbers, half to even.
fn whole(value: &Value) -> Result<i64, ScriptError> {
    let n = value.num()?.round_ties_even();
    if n.abs() > 2_147_483_647.0 {
        return Err(ScriptError::unsupported("overflow"));
    }
    // The bound above keeps the cast exact.
    Ok(n as i64)
}

fn bool_value(b: bool) -> Value {
    Value::Num(if b { TRUE } else { FALSE })
}

struct Interp {
    env: HashMap<String, Value>,
    budget: Budget,
}

impl Interp {
    fn run(&mut self, stmts: &[Stmt]) -> Result<(), ScriptError> {
        for stmt in stmts {
            self.budget.tick()?;
            match stmt {
                Stmt::Assign(name, e) => {
                    let value = self.eval(e)?;
                    self.env.insert(name.clone(), value);
                }
                Stmt::If(branches, other) => {
                    let mut taken = false;
                    for (cond, body) in branches {
                        if self.eval(cond)?.truth()? {
                            self.run(body)?;
                            taken = true;
                            break;
                        }
                    }
                    if !taken {
                        self.run(other)?;
                    }
                }
                Stmt::Dim => {}
            }
        }
        Ok(())
    }

    fn eval(&mut self, e: &Expr) -> Result<Value, ScriptError> {
        self.budget.tick()?;
        Ok(match e {
            Expr::Lit(v) => v.clone(),
            Expr::Var(name) => self
                .env
                .get(&name.to_ascii_lowercase())
                .cloned()
                .ok_or_else(|| {
                    ScriptError::unsupported(format!(
                        "{name} is read before it is assigned (not an input, output or Dim)"
                    ))
                })?,
            Expr::Neg(inner) => Value::Num(-self.eval(inner)?.num()?),
            Expr::Not(inner) => Value::Num(!whole(&self.eval(inner)?)? as f64),
            Expr::Cmp(op, a, b) => {
                let (a, b) = (self.eval(a)?, self.eval(b)?);
                // VBScript's rules for comparing Variants: a numeric operand is
                // always less than a string one (never equal, no conversion,
                // no type mismatch); an Empty one is "" next to a string and 0
                // next to a number.
                let ordering = match (&a, &b) {
                    (Value::Str(x), Value::Str(y)) => x.cmp(y),
                    (Value::Num(_), Value::Str(_)) => std::cmp::Ordering::Less,
                    (Value::Str(_), Value::Num(_)) => std::cmp::Ordering::Greater,
                    (Value::Empty, Value::Str(y)) => "".cmp(y.as_str()),
                    (Value::Str(x), Value::Empty) => x.as_str().cmp(""),
                    _ => a
                        .num()?
                        .partial_cmp(&b.num()?)
                        .ok_or_else(|| ScriptError::unsupported("comparison with NaN"))?,
                };
                bool_value(match op {
                    CmpOp::Eq => ordering.is_eq(),
                    CmpOp::Ne => ordering.is_ne(),
                    CmpOp::Lt => ordering.is_lt(),
                    CmpOp::Gt => ordering.is_gt(),
                    CmpOp::Le => ordering.is_le(),
                    CmpOp::Ge => ordering.is_ge(),
                })
            }
            Expr::Bin(op, a, b) => {
                let (a, b) = (self.eval(a)?, self.eval(b)?);
                match op {
                    BinOp::Concat => Value::Str(super::check_text(a.text()? + &b.text()?)?),
                    BinOp::Add => match (&a, &b) {
                        (Value::Str(x), Value::Str(y)) => {
                            Value::Str(super::check_text(format!("{x}{y}"))?)
                        }
                        _ => Value::Num(a.num()? + b.num()?),
                    },
                    BinOp::Sub => Value::Num(a.num()? - b.num()?),
                    BinOp::Mul => Value::Num(a.num()? * b.num()?),
                    BinOp::Div => {
                        let divisor = b.num()?;
                        if divisor == 0.0 {
                            return Err(ScriptError::unsupported("division by zero"));
                        }
                        Value::Num(a.num()? / divisor)
                    }
                    BinOp::IntDiv | BinOp::Mod => {
                        let (x, y) = (whole(&a)?, whole(&b)?);
                        if y == 0 {
                            return Err(ScriptError::unsupported("division by zero"));
                        }
                        Value::Num(if *op == BinOp::IntDiv { x / y } else { x % y } as f64)
                    }
                    BinOp::And => Value::Num((whole(&a)? & whole(&b)?) as f64),
                    BinOp::Or => Value::Num((whole(&a)? | whole(&b)?) as f64),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(script: &str, inputs: &[(&str, f64)], output: &str) -> Result<Option<f64>, ScriptError> {
        let inputs: Vec<(&str, ScriptValue)> = inputs
            .iter()
            .map(|(k, v)| (*k, ScriptValue::Number(*v)))
            .collect();
        Ok(
            match run(script, &inputs, &[output])?
                .into_iter()
                .next()
                .flatten()
            {
                Some(ScriptValue::Number(n)) => Some(n),
                _ => None,
            },
        )
    }

    #[test]
    fn test_run_compares_a_number_with_a_string_as_less() -> Result<(), ScriptError> {
        let src = "If label = 2 Then\n  r = 1\nElse\n  r = 0\nEnd If\nlt = (2 < label)";
        for text in ["2", "on"] {
            let inputs = [("label", ScriptValue::Text(text.to_string()))];
            let out = run(src, &inputs, &["r", "lt"])?;
            assert_eq!(
                out,
                vec![
                    Some(ScriptValue::Number(0.0)),
                    Some(ScriptValue::Number(-1.0))
                ],
                "label = {text:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_run_if_elseif_else() -> Result<(), ScriptError> {
        let src =
            "If Mode = 1 Then\n  Fan = 4\nElseIf mode = 2 Then\n  fan = 5\nElse\n  FAN = 0\nEnd If";
        assert_eq!(num(src, &[("mode", 1.0)], "fan")?, Some(4.0));
        assert_eq!(num(src, &[("MODE", 2.0)], "Fan")?, Some(5.0));
        assert_eq!(num(src, &[("mode", 7.0)], "fan")?, Some(0.0));
        Ok(())
    }

    #[test]
    fn test_run_single_line_if_and_line_continuation() -> Result<(), ScriptError> {
        let src = "If a > 1 And _\n   b < 3 Then x = 1 Else x = 2\n' a comment\ny = 7 : z = 8";
        assert_eq!(num(src, &[("a", 2.0), ("b", 1.0)], "x")?, Some(1.0));
        assert_eq!(num(src, &[("a", 0.0), ("b", 1.0)], "x")?, Some(2.0));
        assert_eq!(num(src, &[("a", 0.0), ("b", 0.0)], "z")?, Some(8.0));
        Ok(())
    }

    #[test]
    fn test_run_arithmetic_and_precedence() -> Result<(), ScriptError> {
        assert_eq!(num("x = 2 + 3 * 4 - 6 / 2", &[], "x")?, Some(11.0));
        // `\` and Mod round their operands half to even first.
        assert_eq!(num("x = 7.5 \\ 2", &[], "x")?, Some(4.0));
        assert_eq!(num("x = 6.5 Mod 4", &[], "x")?, Some(2.0));
        assert_eq!(num("x = -7 Mod 3", &[], "x")?, Some(-1.0));
        assert_eq!(num("x = -(2 + 3)", &[], "x")?, Some(-5.0));
        Ok(())
    }

    #[test]
    fn test_run_logic_is_bitwise_with_true_minus_one() -> Result<(), ScriptError> {
        assert_eq!(num("x = (1 < 2) And (3 > 2)", &[], "x")?, Some(-1.0));
        assert_eq!(num("x = Not True", &[], "x")?, Some(0.0));
        assert_eq!(num("x = 12 And 10", &[], "x")?, Some(8.0));
        assert_eq!(num("x = 12 Or 3", &[], "x")?, Some(15.0));
        assert_eq!(num("x = Not 0", &[], "x")?, Some(-1.0));
        Ok(())
    }

    #[test]
    fn test_run_concatenation_and_empty() -> Result<(), ScriptError> {
        let out = run(
            "s = \"a\"\"b\" & n & m",
            &[("n", ScriptValue::Number(3.0))],
            &["s", "m"],
        )?;
        assert_eq!(out, [Some(ScriptValue::Text("a\"b3".to_string())), None]);
        Ok(())
    }

    #[test]
    fn test_run_single_line_if_owns_its_colon_statements() -> Result<(), ScriptError> {
        // In VBScript `b = 2` belongs to the Then branch: with c false it
        // must not run.
        let src = "a = 0 : b = 0\nIf c Then a = 1 : b = 2 Else a = 3 : b = 4\nd = 5";
        let out = |c: f64| run(src, &[("c", ScriptValue::Number(c))], &["a", "b", "d"]);
        let n = |v: f64| Some(ScriptValue::Number(v));
        assert_eq!(out(0.0)?, [n(3.0), n(4.0), n(5.0)]);
        assert_eq!(out(-1.0)?, [n(1.0), n(2.0), n(5.0)]);
        // Without Else, the statements after `:` are still the branch's.
        let src = "b = 0\nIf c Then a = 1 : b = 2";
        assert_eq!(num(src, &[("c", 0.0)], "b")?, Some(0.0));
        Ok(())
    }

    #[test]
    fn test_run_refuses_a_name_read_before_it_is_assigned() -> Result<(), ScriptError> {
        // A parameter name that did not resolve must not read as 0.
        assert!(matches!(
            run("x = never + 1", &[], &["x"]),
            Err(ScriptError::Unsupported(_))
        ));
        // A `Dim` declares it Empty, as in VBScript.
        assert_eq!(num("Dim t\nx = t + 1", &[], "x")?, Some(1.0));
        Ok(())
    }

    #[test]
    fn test_run_refuses_deep_nesting_and_long_strings() {
        let parens = format!("x = {}1{}", "(".repeat(10_000), ")".repeat(10_000));
        let nots = format!("x = {}1", "Not ".repeat(10_000));
        let negs = format!("x = {}1", "-".repeat(10_000));
        let doubling = format!("s = \"ab\"\n{}", "s = s & s\n".repeat(20));
        for src in [parens, nots, negs, doubling] {
            assert!(
                matches!(
                    run(&src, &[], &["x", "s"]),
                    Err(ScriptError::Unsupported(_))
                ),
                "{}",
                &src[..20]
            );
        }
    }

    #[test]
    fn test_format_number_rounds_to_fifteen_digits() -> Result<(), ScriptError> {
        let out = run("s = (0.1 + 0.2) & \"|\" & 2.5 & \"|\" & 7", &[], &["s"])?;
        assert_eq!(out, [Some(ScriptValue::Text("0.3|2.5|7".to_string()))]);
        // Exponent notation is refused, not printed differently.
        assert!(run("s = 1E+20 & \"\"", &[], &["s"]).is_err());
        Ok(())
    }

    #[test]
    fn test_run_refuses_unsupported() {
        for src in [
            "Function f()\nEnd Function",
            "x = Abs(-1)",
            "For i = 1 To 3\nNext",
            "x = 1 / 0",
            "x = 1 Mod 0",
            "If x Then\ny = 1",
            "x = 1 $ 2",
        ] {
            assert!(
                matches!(run(src, &[], &["x"]), Err(ScriptError::Unsupported(_))),
                "{src}"
            );
        }
    }
}
