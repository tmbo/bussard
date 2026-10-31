//! The JavaScript subset of parameter calculations.
//!
//! Newer product data writes its calculations in JavaScript: `var`/`let`/
//! `const`, assignments (`=`, `+=` …), `++`/`--`, `if`, `for`, `while`,
//! `switch`, `break`/`continue`, the conditional operator, arrays, and a
//! whitelist of built-ins (the `Math` functions, `parseInt`, `parseFloat`,
//! `Number`, `isNaN`, `Number.prototype.toFixed`). Values follow JavaScript's
//! conversion rules. All variables are global, as in a top-level script.
//! Functions, objects, `new`, `typeof` and everything else are refused.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{Budget, ScriptError, ScriptValue};

/// Runs `src` with `inputs` and returns `outputs` (see [`super::run_script`]).
pub(super) fn run(
    src: &str,
    inputs: &[(&str, ScriptValue)],
    outputs: &[&str],
) -> Result<Vec<Option<ScriptValue>>, ScriptError> {
    let mut parser = Parser::new(tokenize(src)?);
    let program = parser.program()?;
    check_block_scoping(&parser, inputs, outputs)?;
    let mut interp = Interp {
        env: inputs
            .iter()
            .map(|(name, value)| ((*name).to_string(), Value::from(value)))
            .collect(),
        budget: Budget::default(),
    };
    for stmt in &program {
        match interp.exec(stmt)? {
            Flow::Normal => {}
            Flow::Break | Flow::Continue => {
                return Err(ScriptError::unsupported("break or continue outside a loop"));
            }
        }
    }
    outputs
        .iter()
        .map(|name| match interp.env.get(*name) {
            None | Some(Value::Undefined | Value::Null) => Ok(None),
            Some(Value::Num(n)) => Ok(Some(ScriptValue::Number(*n))),
            Some(Value::Bool(b)) => Ok(Some(ScriptValue::Number(if *b { 1.0 } else { 0.0 }))),
            Some(Value::Str(s)) => Ok(Some(ScriptValue::Text(s.clone()))),
            Some(_) => Err(ScriptError::unsupported(format!(
                "output {name} is not a number or string"
            ))),
        })
        .collect()
}

/// Refuses a `let`/`const` in a nested scope that this subset's flat
/// environment would not scope as JavaScript does: every variable is global
/// here, so a block-scoped name is accepted only when every use of it lies
/// inside a block that declares it, no other declaration of it (a `var`, a
/// top-level `let`, a block declaring it around this one) or input or output
/// shares the name, and no implicit global of that name exists. A nested
/// `let` used only inside its block (`for (let i = 0; …)`, also in two
/// separate loops) behaves the same either way and is accepted.
fn check_block_scoping(
    parser: &Parser,
    inputs: &[(&str, ScriptValue)],
    outputs: &[&str],
) -> Result<(), ScriptError> {
    let shadows = |name: &str| {
        Err(ScriptError::unsupported(format!(
            "block-scoped {name} shadows another variable of the same name"
        )))
    };
    for (k, (name, start, end)) in parser.lexical_ranges.iter().enumerate() {
        let outer = inputs.iter().any(|(n, _)| n == name)
            || outputs.contains(&name.as_str())
            || parser.outer_declared.contains(name);
        if outer {
            return shadows(name);
        }
        // Two blocks declaring the same name, one inside the other.
        let nested = parser
            .lexical_ranges
            .iter()
            .enumerate()
            .any(|(j, (n, s, e))| j != k && n == name && s < end && start < e);
        if nested {
            return shadows(name);
        }
        // A use outside every block declaring it is an implicit global.
        let escapes = parser.refs.iter().any(|(n, at)| {
            n == name
                && !parser
                    .lexical_ranges
                    .iter()
                    .any(|(m, s, e)| m == name && (*s..*e).contains(at))
        });
        if escapes {
            return shadows(name);
        }
    }
    Ok(())
}

// --- tokens -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Op(&'static str),
    Name(String),
    Kw(&'static str),
    Eof,
}

const KEYWORDS: &[&str] = &[
    "var",
    "let",
    "const",
    "if",
    "else",
    "for",
    "while",
    "break",
    "continue",
    "switch",
    "case",
    "default",
    "true",
    "false",
    "null",
    "undefined",
];
/// Longest first, so `===` wins over `==` and `=`.
const OPS: &[&str] = &[
    "===", "!==", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=",
    "+", "-", "*", "/", "%", "<", ">", "=", "!", "?", ":", ";", ",", ".", "(", ")", "{", "}", "[",
    "]",
];

fn tokenize(src: &str) -> Result<Vec<Tok>, ScriptError> {
    let chars: Vec<char> = src.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = at(i) {
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == Some('*') {
            i += 2;
            while !(at(i) == Some('*') && at(i + 1) == Some('/')) {
                if at(i).is_none() {
                    return Err(ScriptError::unsupported("unterminated comment"));
                }
                i += 1;
            }
            i += 2;
        } else if c == '"' || c == '\'' {
            let mut text = String::new();
            i += 1;
            loop {
                match at(i) {
                    Some('\\') => {
                        let escaped = at(i + 1)
                            .ok_or_else(|| ScriptError::unsupported("unterminated string"))?;
                        text.push(match escaped {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '0' if !at(i + 2).is_some_and(|d| d.is_ascii_digit()) => '\0',
                            '\\' | '\'' | '"' => escaped,
                            // `\x41`, `\u00e9`, `\b`, `\v`, `\f`, octal: JavaScript
                            // gives them a meaning this subset does not
                            // implement, so they are refused, not read as
                            // the bare letter.
                            other => {
                                return Err(ScriptError::unsupported(format!(
                                    "string escape \\{other}"
                                )));
                            }
                        });
                        i += 2;
                    }
                    Some(q) if q == c => {
                        i += 1;
                        break;
                    }
                    Some('\n') | None => {
                        return Err(ScriptError::unsupported("unterminated string"));
                    }
                    Some(other) => {
                        text.push(other);
                        i += 1;
                    }
                }
            }
            out.push(Tok::Str(text));
        } else if c.is_ascii_digit() || (c == '.' && at(i + 1).is_some_and(|d| d.is_ascii_digit()))
        {
            let start = i;
            if c == '0' && matches!(at(i + 1), Some('x' | 'X')) {
                i += 2;
                while at(i).is_some_and(|c| c.is_ascii_hexdigit()) {
                    i += 1;
                }
                let digits: String = chars[start + 2..i].iter().collect();
                let n = u64::from_str_radix(&digits, 16)
                    .map_err(|_| ScriptError::unsupported("bad hex number"))?;
                out.push(Tok::Num(n as f64));
                continue;
            }
            while at(i).is_some_and(|c| c.is_ascii_digit() || c == '.') {
                i += 1;
            }
            if matches!(at(i), Some('e' | 'E')) {
                let mut j = i + 1;
                if matches!(at(j), Some('+' | '-')) {
                    j += 1;
                }
                if at(j).is_some_and(|c| c.is_ascii_digit()) {
                    i = j;
                    while at(i).is_some_and(|c| c.is_ascii_digit()) {
                        i += 1;
                    }
                }
            }
            let text: String = chars[start..i].iter().collect();
            let n = text
                .parse::<f64>()
                .map_err(|_| ScriptError::unsupported(format!("bad number {text:?}")))?;
            out.push(Tok::Num(n));
        } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while at(i).is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            match KEYWORDS.iter().find(|k| **k == word) {
                Some(kw) => out.push(Tok::Kw(kw)),
                None => out.push(Tok::Name(word)),
            }
        } else {
            let op = OPS
                .iter()
                .find(|op| op.chars().enumerate().all(|(k, oc)| at(i + k) == Some(oc)))
                .ok_or_else(|| ScriptError::unsupported(format!("unexpected character {c:?}")))?;
            i += op.len();
            out.push(Tok::Op(op));
        }
    }
    out.push(Tok::Eof);
    Ok(out)
}

// --- syntax -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Name(String),
    Array(Vec<Expr>),
    /// The comma operator.
    Seq(Box<Expr>, Box<Expr>),
    /// `target op= value`; `op` is `None` for a plain `=`.
    Assign(Option<&'static str>, Box<Expr>, Box<Expr>),
    /// `++`/`--` (`increment`) on `target`, `prefix` or postfix.
    Update {
        increment: bool,
        target: Box<Expr>,
        prefix: bool,
    },
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Member(Box<Expr>, String),
    Call(Box<Expr>, Vec<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Stmt {
    Expr(Expr),
    /// A declaration: whether it is lexical (`let`/`const`), and its names
    /// with their initializers.
    Var(bool, Vec<(String, Option<Expr>)>),
    Block(Vec<Stmt>),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        step: Option<Expr>,
        body: Box<Stmt>,
    },
    /// The subject and its clauses: a `case` test (`None` for `default`) and
    /// the statements that follow it.
    Switch(Expr, Vec<(Option<Expr>, Vec<Stmt>)>),
    Break,
    Continue,
}

/// Binding strength of a binary operator (higher binds tighter).
fn precedence(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "==" | "!=" | "===" | "!==" => 3,
        "<" | ">" | "<=" | ">=" => 4,
        "+" | "-" => 5,
        "*" | "/" | "%" => 6,
        _ => return None,
    })
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
    /// The current nesting of statements and unary expressions (see
    /// [`super::MAX_DEPTH`]).
    depth: usize,
    /// The open blocks, loops and switches: the token index each starts at
    /// and the `let`/`const` names declared directly in it.
    scopes: Vec<(usize, Vec<String>)>,
    /// Every `let`/`const` declared inside a block, loop or switch, which this
    /// subset makes global, with the token range of its scope (see
    /// [`check_block_scoping`]).
    lexical_ranges: Vec<(String, usize, usize)>,
    /// Names declared by `var` or by a top-level `let`/`const`.
    outer_declared: HashSet<String>,
    /// Every use of a name, with its token index.
    refs: Vec<(String, usize)>,
}

impl Parser {
    fn new(toks: Vec<Tok>) -> Self {
        Self {
            toks,
            i: 0,
            depth: 0,
            scopes: Vec::new(),
            lexical_ranges: Vec::new(),
            outer_declared: HashSet::new(),
            refs: Vec::new(),
        }
    }

    fn peek(&self) -> &Tok {
        self.toks.get(self.i).unwrap_or(&Tok::Eof)
    }

    fn next(&mut self) -> Tok {
        let t = self.peek().clone();
        self.i += 1;
        t
    }

    fn at(&self, text: &str) -> bool {
        matches!(self.peek(), Tok::Op(o) | Tok::Kw(o) if *o == text)
    }

    fn accept(&mut self, text: &str) -> bool {
        if self.at(text) {
            self.i += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, text: &str) -> Result<(), ScriptError> {
        if self.accept(text) {
            return Ok(());
        }
        Err(ScriptError::unsupported(format!(
            "expected {text:?}, got {:?}",
            self.peek()
        )))
    }

    fn program(&mut self) -> Result<Vec<Stmt>, ScriptError> {
        let mut stmts = Vec::new();
        while *self.peek() != Tok::Eof {
            stmts.push(self.statement()?);
        }
        Ok(stmts)
    }

    fn statement(&mut self) -> Result<Stmt, ScriptError> {
        super::enter(&mut self.depth)?;
        let stmt = self.statement_inner();
        self.depth -= 1;
        stmt
    }

    /// Opens a block scope starting at token `start`.
    fn open_scope(&mut self, start: usize) {
        self.scopes.push((start, Vec::new()));
    }

    /// Closes the innermost block scope at the current token, recording the
    /// range of each `let`/`const` it declares.
    fn close_scope(&mut self) {
        if let Some((start, names)) = self.scopes.pop() {
            let end = self.i;
            self.lexical_ranges
                .extend(names.into_iter().map(|n| (n, start, end)));
        }
    }

    fn statement_inner(&mut self) -> Result<Stmt, ScriptError> {
        if self.accept(";") {
            return Ok(Stmt::Block(Vec::new()));
        }
        if self.accept("{") {
            self.open_scope(self.i - 1);
            let mut body = Vec::new();
            while !self.accept("}") {
                if *self.peek() == Tok::Eof {
                    return Err(ScriptError::unsupported("unterminated block"));
                }
                body.push(self.statement()?);
            }
            self.close_scope();
            return Ok(Stmt::Block(body));
        }
        if self.at("var") || self.at("let") || self.at("const") {
            let decl = self.declaration()?;
            self.accept(";");
            return Ok(decl);
        }
        if self.accept("if") {
            self.expect("(")?;
            let cond = self.expr()?;
            self.expect(")")?;
            let then = Box::new(self.statement()?);
            let other = if self.accept("else") {
                Some(Box::new(self.statement()?))
            } else {
                None
            };
            return Ok(Stmt::If(cond, then, other));
        }
        if self.accept("for") {
            // A `let` in the loop head is scoped to the loop.
            self.open_scope(self.i - 1);
            self.expect("(")?;
            let init = if self.at(";") {
                None
            } else if self.at("var") || self.at("let") || self.at("const") {
                Some(Box::new(self.declaration()?))
            } else {
                Some(Box::new(Stmt::Expr(self.expr()?)))
            };
            self.expect(";")?;
            let cond = if self.at(";") {
                None
            } else {
                Some(self.expr()?)
            };
            self.expect(";")?;
            let step = if self.at(")") {
                None
            } else {
                Some(self.expr()?)
            };
            self.expect(")")?;
            let body = Box::new(self.statement()?);
            self.close_scope();
            return Ok(Stmt::For {
                init,
                cond,
                step,
                body,
            });
        }
        if self.accept("while") {
            self.expect("(")?;
            let cond = self.expr()?;
            self.expect(")")?;
            let body = Box::new(self.statement()?);
            return Ok(Stmt::For {
                init: None,
                cond: Some(cond),
                step: None,
                body,
            });
        }
        if self.accept("switch") {
            return self.switch();
        }
        if self.accept("break") {
            self.accept(";");
            return Ok(Stmt::Break);
        }
        if self.accept("continue") {
            self.accept(";");
            return Ok(Stmt::Continue);
        }
        if let Tok::Name(name) = self.peek()
            && name == "function"
        {
            return Err(ScriptError::unsupported(
                "function declarations not supported",
            ));
        }
        let e = self.expr()?;
        self.accept(";");
        Ok(Stmt::Expr(e))
    }

    fn switch(&mut self) -> Result<Stmt, ScriptError> {
        self.expect("(")?;
        let subject = self.expr()?;
        self.expect(")")?;
        self.expect("{")?;
        self.open_scope(self.i - 1);
        let mut clauses = Vec::new();
        while !self.accept("}") {
            let test = if self.accept("case") {
                Some(self.expr()?)
            } else if self.accept("default") {
                None
            } else {
                return Err(ScriptError::unsupported(format!(
                    "expected case or default, got {:?}",
                    self.peek()
                )));
            };
            self.expect(":")?;
            let mut body = Vec::new();
            while !(self.at("case") || self.at("default") || self.at("}")) {
                if *self.peek() == Tok::Eof {
                    return Err(ScriptError::unsupported("unterminated switch"));
                }
                body.push(self.statement()?);
            }
            clauses.push((test, body));
        }
        self.close_scope();
        Ok(Stmt::Switch(subject, clauses))
    }

    fn declaration(&mut self) -> Result<Stmt, ScriptError> {
        let lexical = !self.at("var");
        self.next(); // var / let / const
        let mut decls = Vec::new();
        loop {
            let Tok::Name(name) = self.next() else {
                return Err(ScriptError::unsupported("bad declaration"));
            };
            match self.scopes.last_mut() {
                Some((_, names)) if lexical => names.push(name.clone()),
                _ => {
                    self.outer_declared.insert(name.clone());
                }
            }
            let init = if self.accept("=") {
                Some(self.assignment()?)
            } else {
                None
            };
            decls.push((name, init));
            if !self.accept(",") {
                return Ok(Stmt::Var(lexical, decls));
            }
        }
    }

    fn expr(&mut self) -> Result<Expr, ScriptError> {
        let mut e = self.assignment()?;
        while self.accept(",") {
            e = Expr::Seq(Box::new(e), Box::new(self.assignment()?));
        }
        Ok(e)
    }

    fn assignment(&mut self) -> Result<Expr, ScriptError> {
        let left = self.conditional()?;
        let op = match self.peek() {
            Tok::Op("=") => None,
            Tok::Op("+=") => Some("+"),
            Tok::Op("-=") => Some("-"),
            Tok::Op("*=") => Some("*"),
            Tok::Op("/=") => Some("/"),
            Tok::Op("%=") => Some("%"),
            _ => return Ok(left),
        };
        if !matches!(left, Expr::Name(_) | Expr::Index(..)) {
            return Err(ScriptError::unsupported("invalid assignment target"));
        }
        self.i += 1;
        Ok(Expr::Assign(
            op,
            Box::new(left),
            Box::new(self.assignment()?),
        ))
    }

    fn conditional(&mut self) -> Result<Expr, ScriptError> {
        let cond = self.binary(1)?;
        if self.accept("?") {
            let a = self.assignment()?;
            self.expect(":")?;
            let b = self.assignment()?;
            return Ok(Expr::Cond(Box::new(cond), Box::new(a), Box::new(b)));
        }
        Ok(cond)
    }

    fn binary(&mut self, min: u8) -> Result<Expr, ScriptError> {
        let mut left = self.unary()?;
        loop {
            let (op, prec) = match self.peek() {
                Tok::Op(op) => match precedence(op) {
                    Some(prec) if prec >= min => (*op, prec),
                    _ => return Ok(left),
                },
                _ => return Ok(left),
            };
            self.i += 1;
            left = Expr::Binary(op, Box::new(left), Box::new(self.binary(prec + 1)?));
        }
    }

    fn unary(&mut self) -> Result<Expr, ScriptError> {
        super::enter(&mut self.depth)?;
        let e = self.unary_inner();
        self.depth -= 1;
        e
    }

    fn unary_inner(&mut self) -> Result<Expr, ScriptError> {
        for op in ["!", "-", "+"] {
            if self.accept(op) {
                return Ok(Expr::Unary(op, Box::new(self.unary()?)));
            }
        }
        for (op, increment) in [("++", true), ("--", false)] {
            if self.accept(op) {
                let target = self.unary()?;
                if !matches!(target, Expr::Name(_) | Expr::Index(..)) {
                    return Err(ScriptError::unsupported("invalid increment target"));
                }
                return Ok(Expr::Update {
                    increment,
                    target: Box::new(target),
                    prefix: true,
                });
            }
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Result<Expr, ScriptError> {
        let mut e = self.primary()?;
        loop {
            if self.accept("(") {
                let mut args = Vec::new();
                if !self.accept(")") {
                    loop {
                        args.push(self.assignment()?);
                        if self.accept(")") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                e = Expr::Call(Box::new(e), args);
            } else if self.accept("[") {
                let index = self.expr()?;
                self.expect("]")?;
                e = Expr::Index(Box::new(e), Box::new(index));
            } else if self.accept(".") {
                let name = match self.next() {
                    Tok::Name(name) => name,
                    Tok::Kw(kw) => kw.to_string(),
                    other => {
                        return Err(ScriptError::unsupported(format!("bad member {other:?}")));
                    }
                };
                e = Expr::Member(Box::new(e), name);
            } else if self.at("++") || self.at("--") {
                if !matches!(e, Expr::Name(_) | Expr::Index(..)) {
                    return Err(ScriptError::unsupported("invalid increment target"));
                }
                let increment = self.at("++");
                self.i += 1;
                e = Expr::Update {
                    increment,
                    target: Box::new(e),
                    prefix: false,
                };
            } else {
                return Ok(e);
            }
        }
    }

    fn primary(&mut self) -> Result<Expr, ScriptError> {
        match self.next() {
            Tok::Num(n) => Ok(Expr::Num(n)),
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Kw("true") => Ok(Expr::Bool(true)),
            Tok::Kw("false") => Ok(Expr::Bool(false)),
            Tok::Kw("null") => Ok(Expr::Null),
            Tok::Kw("undefined") => Ok(Expr::Undefined),
            Tok::Name(name) => {
                self.refs.push((name.clone(), self.i - 1));
                Ok(Expr::Name(name))
            }
            Tok::Op("(") => {
                let e = self.expr()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let mut items = Vec::new();
                if !self.accept("]") {
                    loop {
                        items.push(self.assignment()?);
                        if self.accept("]") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                Ok(Expr::Array(items))
            }
            other => Err(ScriptError::unsupported(format!("unexpected {other:?}"))),
        }
    }
}

// --- runtime ----------------------------------------------------------------

/// The whitelisted built-in functions.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Builtin {
    Math(&'static str),
    ParseInt,
    ParseFloat,
    Number,
    IsNaN,
}

const MATH_FUNCTIONS: &[&str] = &[
    "log", "exp", "pow", "sqrt", "abs", "floor", "ceil", "round", "min", "max",
];

#[derive(Debug, Clone)]
enum Value {
    Undefined,
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Rc<RefCell<Vec<Value>>>),
    /// The `Math` object.
    Math,
    Builtin(Builtin),
    /// `x.toFixed`, bound to its number.
    ToFixed(f64),
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
    /// JavaScript's `ToNumber`.
    fn num(&self) -> f64 {
        match self {
            Value::Undefined => f64::NAN,
            Value::Null => 0.0,
            Value::Bool(b) => f64::from(u8::from(*b)),
            Value::Num(n) => *n,
            Value::Str(s) => string_to_number(s),
            // An array too large or too deep to print is not a number
            // either: JavaScript gives NaN for any array of two or more
            // elements.
            Value::Array(_) => self.text().map_or(f64::NAN, |t| string_to_number(&t)),
            Value::Math | Value::Builtin(_) | Value::ToFixed(_) => f64::NAN,
        }
    }

    /// JavaScript's `ToString`, refused for a string past
    /// [`super::MAX_TEXT`] and for arrays nested past [`super::MAX_DEPTH`]
    /// (which a cycle such as `a[0] = a` always is).
    fn text(&self) -> Result<String, ScriptError> {
        self.text_at(0)
    }

    fn text_at(&self, depth: usize) -> Result<String, ScriptError> {
        Ok(match self {
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Num(n) => number_to_string(*n),
            Value::Str(s) => s.clone(),
            Value::Array(items) => {
                if depth >= super::MAX_DEPTH {
                    return Err(ScriptError::unsupported(
                        "array nested too deeply (or containing itself)",
                    ));
                }
                let mut out = String::new();
                for (k, v) in items.borrow().iter().enumerate() {
                    if k > 0 {
                        out.push(',');
                    }
                    if !matches!(v, Value::Undefined | Value::Null) {
                        out.push_str(&v.text_at(depth + 1)?);
                    }
                    if out.len() > super::MAX_TEXT * 4 {
                        break;
                    }
                }
                super::check_text(out)?
            }
            Value::Math => "[object Math]".to_string(),
            Value::Builtin(_) | Value::ToFixed(_) => "function".to_string(),
        })
    }

    fn truthy(&self) -> bool {
        match self {
            Value::Undefined | Value::Null => false,
            Value::Bool(b) => *b,
            Value::Num(n) => *n != 0.0 && !n.is_nan(),
            Value::Str(s) => !s.is_empty(),
            _ => true,
        }
    }

    /// `ToPrimitive`: an array becomes its text; everything else is itself.
    fn primitive(self) -> Result<Value, ScriptError> {
        Ok(match self {
            Value::Array(_) => Value::Str(self.text()?),
            other => other,
        })
    }
}

/// `ToNumber` of a string: decimal or `0x` hex, `Infinity`, else NaN.
fn string_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_or(f64::NAN, |n| n as f64);
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // Rust also accepts `inf`, `nan` and friends; JavaScript does not.
    if t.chars()
        .any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E')
    {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// JavaScript's `Number.prototype.toString()`: the shortest digits that
/// round-trip, positional between 1e-7 and 1e21, exponential outside.
fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_string();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if n == 0.0 {
        return "0".to_string();
    }
    let sign = if n < 0.0 { "-" } else { "" };
    // `{:e}` prints the shortest round-trip digits, e.g. `1.25e-7`.
    let sci = format!("{:e}", n.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    let point = exponent.parse::<i64>().unwrap_or(0) + 1; // `n` in the spec
    let body = if k <= point && point <= 21 {
        format!("{digits}{}", "0".repeat((point - k) as usize))
    } else if 0 < point && point <= 21 {
        let (int, frac) = digits.split_at(point as usize);
        format!("{int}.{frac}")
    } else if -6 < point && point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        let e = point - 1;
        let e_sign = if e < 0 { "-" } else { "+" };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{e_sign}{}", e.abs())
        } else {
            format!("{first}.{rest}e{e_sign}{}", e.abs())
        }
    };
    format!("{sign}{body}")
}

/// `Number.prototype.toFixed(digits)`: the exact value of `x` rounded half up
/// (away from zero) to `digits` decimals.
fn to_fixed(x: f64, digits: f64) -> Result<String, ScriptError> {
    let digits = if digits.is_nan() { 0.0 } else { digits.trunc() };
    if !(0.0..=100.0).contains(&digits) {
        return Err(ScriptError::unsupported("toFixed digits out of range"));
    }
    let digits = digits as usize;
    if !x.is_finite() || x.abs() >= 1e21 {
        return Ok(number_to_string(x));
    }
    // A double's exact decimal expansion has at most 1074 fractional digits,
    // and fixed-precision formatting prints it exactly.
    let exact = format!("{:.1100}", x.abs());
    let (int, frac) = exact.split_once('.').unwrap_or((exact.as_str(), ""));
    let mut kept: Vec<u8> = int.bytes().chain(frac.bytes().take(digits)).collect();
    if frac.as_bytes().get(digits).is_some_and(|d| *d >= b'5') {
        let mut carry = true;
        for d in kept.iter_mut().rev() {
            if *d == b'9' {
                *d = b'0';
            } else {
                *d += 1;
                carry = false;
                break;
            }
        }
        if carry {
            kept.insert(0, b'1');
        }
    }
    let int_len = kept.len() - digits;
    let (int, frac) = kept.split_at(int_len);
    let mut out = String::from_utf8_lossy(int).into_owned();
    if digits > 0 {
        out.push('.');
        out.push_str(&String::from_utf8_lossy(frac));
    }
    Ok(if x < 0.0 { format!("-{out}") } else { out })
}

/// `parseInt(text, radix)`.
fn parse_int(text: &str, radix: Option<f64>) -> f64 {
    let mut s = text.trim_start();
    let negative = s.starts_with('-');
    if negative || s.starts_with('+') {
        s = &s[1..];
    }
    let mut radix = radix
        .filter(|r| !r.is_nan())
        .map_or(0, |r| r.trunc() as i64);
    if (radix == 0 || radix == 16)
        && let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        s = rest;
        radix = 16;
    }
    if radix == 0 {
        radix = 10;
    }
    if !(2..=36).contains(&radix) {
        return f64::NAN;
    }
    let mut value = 0.0_f64;
    let mut any = false;
    for c in s.chars() {
        let Some(d) = c.to_digit(radix as u32) else {
            break;
        };
        value = value * radix as f64 + f64::from(d);
        any = true;
    }
    match (any, negative) {
        (false, _) => f64::NAN,
        (true, true) => -value,
        (true, false) => value,
    }
}

/// `parseFloat(text)`: the longest decimal literal at the start of `text`.
fn parse_float(text: &str) -> f64 {
    let s = text.trim_start();
    let unsigned = s.trim_start_matches(['+', '-']);
    if unsigned.starts_with("Infinity") {
        return if s.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let bytes = s.as_bytes();
    let mut end = 0;
    let mut best = None;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        end = 1;
    }
    let mut seen_point = false;
    let mut seen_digit = false;
    while let Some(&b) = bytes.get(end) {
        if b.is_ascii_digit() {
            seen_digit = true;
            end += 1;
            best = Some(end);
        } else if b == b'.' && !seen_point {
            seen_point = true;
            end += 1;
        } else {
            break;
        }
    }
    if seen_digit && matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut j = end + 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        while bytes.get(j).is_some_and(u8::is_ascii_digit) {
            j += 1;
            best = Some(j);
        }
    }
    best.and_then(|end| s[..end].parse::<f64>().ok())
        .unwrap_or(f64::NAN)
}

/// JavaScript's `Math.round`: halves round up, towards +∞.
fn js_round(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let floor = x.floor();
    if x - floor >= 0.5 { floor + 1.0 } else { floor }
}

fn call_builtin(builtin: Builtin, args: &[Value]) -> Result<Value, ScriptError> {
    let arg = |i: usize| args.get(i).map_or(f64::NAN, Value::num);
    Ok(match builtin {
        Builtin::ParseInt => {
            let text = args
                .first()
                .map_or_else(|| Ok("undefined".to_string()), Value::text)?;
            Value::Num(parse_int(&text, args.get(1).map(Value::num)))
        }
        Builtin::ParseFloat => Value::Num(parse_float(
            &args
                .first()
                .map_or_else(|| Ok("undefined".to_string()), Value::text)?,
        )),
        Builtin::Number => Value::Num(args.first().map_or(0.0, Value::num)),
        Builtin::IsNaN => Value::Bool(arg(0).is_nan()),
        Builtin::Math(name) => Value::Num(match name {
            "log" => arg(0).ln(),
            "exp" => arg(0).exp(),
            "sqrt" => arg(0).sqrt(),
            "abs" => arg(0).abs(),
            "floor" => arg(0).floor(),
            "ceil" => arg(0).ceil(),
            "round" => js_round(arg(0)),
            "pow" => {
                let (x, y) = (arg(0), arg(1));
                // IEEE says 1^±∞ = 1; JavaScript says NaN.
                if x.abs() == 1.0 && y.is_infinite() {
                    f64::NAN
                } else {
                    x.powf(y)
                }
            }
            "min" | "max" => {
                let is_min = name == "min";
                let mut acc = if is_min {
                    f64::INFINITY
                } else {
                    f64::NEG_INFINITY
                };
                for v in args {
                    let n = v.num();
                    if n.is_nan() {
                        return Ok(Value::Num(f64::NAN));
                    }
                    acc = if is_min { acc.min(n) } else { acc.max(n) };
                }
                acc
            }
            other => return Err(ScriptError::unsupported(format!("Math.{other}"))),
        }),
    })
}

/// `a == b`.
fn loose_eq(a: &Value, b: &Value) -> Result<bool, ScriptError> {
    Ok(match (a, b) {
        (Value::Undefined | Value::Null, Value::Undefined | Value::Null) => true,
        (Value::Undefined | Value::Null, _) | (_, Value::Undefined | Value::Null) => false,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => Rc::ptr_eq(x, y),
        (Value::Array(_), _) => loose_eq(&a.clone().primitive()?, b)?,
        (_, Value::Array(_)) => loose_eq(a, &b.clone().primitive()?)?,
        _ => a.num() == b.num(),
    })
}

/// `a === b`.
fn strict_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Num(x), Value::Num(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// The arithmetic operators, `+` included (string concatenation).
fn arithmetic(op: &str, a: Value, b: Value) -> Result<Value, ScriptError> {
    if op == "+" {
        let (a, b) = (a.primitive()?, b.primitive()?);
        if matches!(a, Value::Str(_)) || matches!(b, Value::Str(_)) {
            return Ok(Value::Str(super::check_text(a.text()? + &b.text()?)?));
        }
        return Ok(Value::Num(a.num() + b.num()));
    }
    let (x, y) = (a.num(), b.num());
    // Rust's f64 operators follow IEEE 754, as JavaScript's do: x / 0 is ±∞
    // or NaN, and `%` is fmod with the dividend's sign.
    Ok(Value::Num(match op {
        "-" => x - y,
        "*" => x * y,
        "/" => x / y,
        "%" => x % y,
        other => return Err(ScriptError::unsupported(format!("operator {other}"))),
    }))
}

enum Flow {
    Normal,
    Break,
    Continue,
}

struct Interp {
    env: HashMap<String, Value>,
    budget: Budget,
}

impl Interp {
    fn lookup(&self, name: &str) -> Result<Value, ScriptError> {
        if let Some(v) = self.env.get(name) {
            return Ok(v.clone());
        }
        Ok(match name {
            "Math" => Value::Math,
            "parseInt" => Value::Builtin(Builtin::ParseInt),
            "parseFloat" => Value::Builtin(Builtin::ParseFloat),
            "Number" => Value::Builtin(Builtin::Number),
            "isNaN" => Value::Builtin(Builtin::IsNaN),
            "NaN" => Value::Num(f64::NAN),
            "Infinity" => Value::Num(f64::INFINITY),
            _ => {
                return Err(ScriptError::unsupported(format!(
                    "undefined variable {name}"
                )));
            }
        })
    }

    fn block(&mut self, stmts: &[Stmt]) -> Result<Flow, ScriptError> {
        for stmt in stmts {
            match self.exec(stmt)? {
                Flow::Normal => {}
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec(&mut self, stmt: &Stmt) -> Result<Flow, ScriptError> {
        self.budget.tick()?;
        match stmt {
            Stmt::Expr(e) => {
                self.eval(e)?;
            }
            Stmt::Var(lexical, decls) => {
                for (name, init) in decls {
                    match init {
                        Some(e) => {
                            let v = self.eval(e)?;
                            self.env.insert(name.clone(), v);
                        }
                        // A `let` is a fresh binding each time it runs (every
                        // loop iteration), so it starts undefined.
                        None if *lexical => {
                            self.env.insert(name.clone(), Value::Undefined);
                        }
                        // A `var` keeps the value it already has.
                        None => {
                            self.env.entry(name.clone()).or_insert(Value::Undefined);
                        }
                    }
                }
            }
            Stmt::Block(body) => return self.block(body),
            Stmt::If(cond, then, other) => {
                if self.eval(cond)?.truthy() {
                    return self.exec(then);
                }
                if let Some(other) = other {
                    return self.exec(other);
                }
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                if let Some(init) = init {
                    self.exec(init)?;
                }
                loop {
                    self.budget.tick()?;
                    if let Some(cond) = cond
                        && !self.eval(cond)?.truthy()
                    {
                        break;
                    }
                    if let Flow::Break = self.exec(body)? {
                        break;
                    }
                    if let Some(step) = step {
                        self.eval(step)?;
                    }
                }
            }
            Stmt::Switch(subject, clauses) => {
                // The first case strictly equal to the subject, else
                // `default`; execution falls through until a `break`. A
                // `continue` belongs to an enclosing loop.
                let value = self.eval(subject)?;
                let mut start = None;
                for (i, (test, _)) in clauses.iter().enumerate() {
                    if let Some(test) = test
                        && strict_eq(&value, &self.eval(test)?)
                    {
                        start = Some(i);
                        break;
                    }
                }
                let start = start.or_else(|| clauses.iter().position(|(test, _)| test.is_none()));
                if let Some(start) = start {
                    for (_, body) in &clauses[start..] {
                        match self.block(body)? {
                            Flow::Normal => {}
                            Flow::Break => break,
                            Flow::Continue => return Ok(Flow::Continue),
                        }
                    }
                }
            }
            Stmt::Break => return Ok(Flow::Break),
            Stmt::Continue => return Ok(Flow::Continue),
        }
        Ok(Flow::Normal)
    }

    fn store(&mut self, target: &Expr, value: Value) -> Result<(), ScriptError> {
        match target {
            Expr::Name(name) => {
                self.env.insert(name.clone(), value);
                Ok(())
            }
            Expr::Index(array, index) => {
                let Value::Array(items) = self.eval(array)? else {
                    return Err(ScriptError::unsupported(
                        "indexed assignment to a non-array",
                    ));
                };
                let i = self.eval(index)?.num();
                if !(i.fract() == 0.0 && (0.0..super::MAX_ARRAY as f64).contains(&i)) {
                    return Err(ScriptError::unsupported(format!("bad array index {i}")));
                }
                let i = i as usize;
                let mut items = items.borrow_mut();
                if i >= items.len() {
                    items.resize(i + 1, Value::Undefined);
                }
                items[i] = value;
                Ok(())
            }
            _ => Err(ScriptError::unsupported("invalid assignment target")),
        }
    }

    fn eval(&mut self, e: &Expr) -> Result<Value, ScriptError> {
        self.budget.tick()?;
        Ok(match e {
            Expr::Num(n) => Value::Num(*n),
            Expr::Str(s) => Value::Str(s.clone()),
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Null => Value::Null,
            Expr::Undefined => Value::Undefined,
            Expr::Name(name) => self.lookup(name)?,
            Expr::Array(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.eval(item)?);
                }
                Value::Array(Rc::new(RefCell::new(values)))
            }
            Expr::Seq(a, b) => {
                self.eval(a)?;
                self.eval(b)?
            }
            Expr::Assign(op, target, rhs) => {
                let mut value = self.eval(rhs)?;
                if let Some(op) = op {
                    value = arithmetic(op, self.eval(target)?, value)?;
                }
                self.store(target, value.clone())?;
                value
            }
            Expr::Update {
                increment,
                target,
                prefix,
            } => {
                let old = self.eval(target)?.num();
                let new = if *increment { old + 1.0 } else { old - 1.0 };
                self.store(target, Value::Num(new))?;
                Value::Num(if *prefix { new } else { old })
            }
            Expr::Cond(cond, a, b) => {
                if self.eval(cond)?.truthy() {
                    self.eval(a)?
                } else {
                    self.eval(b)?
                }
            }
            Expr::Unary(op, inner) => {
                let v = self.eval(inner)?;
                match *op {
                    "!" => Value::Bool(!v.truthy()),
                    "-" => Value::Num(-v.num()),
                    _ => Value::Num(v.num()),
                }
            }
            Expr::Binary(op, a, b) => match *op {
                "&&" => {
                    let a = self.eval(a)?;
                    if a.truthy() { self.eval(b)? } else { a }
                }
                "||" => {
                    let a = self.eval(a)?;
                    if a.truthy() { a } else { self.eval(b)? }
                }
                _ => {
                    let (a, b) = (self.eval(a)?, self.eval(b)?);
                    match *op {
                        "==" => Value::Bool(loose_eq(&a, &b)?),
                        "!=" => Value::Bool(!loose_eq(&a, &b)?),
                        "===" => Value::Bool(strict_eq(&a, &b)),
                        "!==" => Value::Bool(!strict_eq(&a, &b)),
                        "<" | ">" | "<=" | ">=" => {
                            let (a, b) = (a.primitive()?, b.primitive()?);
                            let ordering = match (&a, &b) {
                                (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
                                _ => a.num().partial_cmp(&b.num()),
                            };
                            Value::Bool(ordering.is_some_and(|o| match *op {
                                "<" => o.is_lt(),
                                ">" => o.is_gt(),
                                "<=" => o.is_le(),
                                _ => o.is_ge(),
                            }))
                        }
                        _ => arithmetic(op, a, b)?,
                    }
                }
            },
            Expr::Index(array, index) => {
                let (array, index) = (self.eval(array)?, self.eval(index)?.num());
                let i = (index.fract() == 0.0 && index >= 0.0).then_some(index as usize);
                match array {
                    Value::Array(items) => i
                        .and_then(|i| items.borrow().get(i).cloned())
                        .unwrap_or(Value::Undefined),
                    Value::Str(s) => i
                        .and_then(|i| s.chars().nth(i))
                        .map_or(Value::Undefined, |c| Value::Str(c.to_string())),
                    _ => return Err(ScriptError::unsupported("indexing a non-array")),
                }
            }
            Expr::Member(object, name) => match (self.eval(object)?, name.as_str()) {
                (Value::Math, "PI") => Value::Num(std::f64::consts::PI),
                (Value::Math, "E") => Value::Num(std::f64::consts::E),
                (Value::Math, f) => match MATH_FUNCTIONS.iter().find(|m| **m == f) {
                    Some(m) => Value::Builtin(Builtin::Math(m)),
                    None => {
                        return Err(ScriptError::unsupported(format!("Math.{f} not supported")));
                    }
                },
                (Value::Array(items), "length") => Value::Num(items.borrow().len() as f64),
                (Value::Str(s), "length") => Value::Num(s.chars().count() as f64),
                (Value::Num(n), "toFixed") => Value::ToFixed(n),
                (_, other) => {
                    return Err(ScriptError::unsupported(format!(".{other} not supported")));
                }
            },
            Expr::Call(callee, args) => {
                let callee = self.eval(callee)?;
                let mut values = Vec::with_capacity(args.len());
                for arg in args {
                    values.push(self.eval(arg)?);
                }
                match callee {
                    Value::Builtin(builtin) => call_builtin(builtin, &values)?,
                    Value::ToFixed(x) => {
                        Value::Str(to_fixed(x, values.first().map_or(0.0, Value::num))?)
                    }
                    _ => return Err(ScriptError::unsupported("call of a non-function")),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(
        script: &str,
        inputs: &[(&str, ScriptValue)],
        output: &str,
    ) -> Result<Option<ScriptValue>, ScriptError> {
        Ok(run(script, inputs, &[output])?.into_iter().next().flatten())
    }

    fn number(
        script: &str,
        inputs: &[(&str, f64)],
        output: &str,
    ) -> Result<Option<f64>, ScriptError> {
        let inputs: Vec<(&str, ScriptValue)> = inputs
            .iter()
            .map(|(k, v)| (*k, ScriptValue::Number(*v)))
            .collect();
        Ok(match eval(script, &inputs, output)? {
            Some(ScriptValue::Number(n)) => Some(n),
            _ => None,
        })
    }

    fn text(script: &str, output: &str) -> Result<Option<String>, ScriptError> {
        Ok(match eval(script, &[], output)? {
            Some(ScriptValue::Text(s)) => Some(s),
            _ => None,
        })
    }

    #[test]
    fn test_run_control_flow_and_arrays() -> Result<(), ScriptError> {
        let src = "
            var a = [];  // comment
            for (i = 0; i < 5; i++) { a[i] = i * i; }
            var total = 0, k = 0;
            while (k < a.length) { total += a[k]; k++; }
            /* block comment */
            if (total > 20) { big = 1; } else { big = 0; }
            var flag = total == 30 ? 'yes' : 'no';";
        assert_eq!(number(src, &[], "total")?, Some(30.0));
        assert_eq!(number(src, &[], "big")?, Some(1.0));
        assert_eq!(text(src, "flag")?, Some("yes".to_string()));
        Ok(())
    }

    #[test]
    fn test_run_switch_falls_through_and_continue_reaches_the_loop() -> Result<(), ScriptError> {
        let src = "
            var r = 0;
            switch (x) { case 0: r = 10; break; case 1: r = 20; case 2: r = r + 1; break; default: r = 99; }
            for (var i = 0; i < 3; i++) { switch (i) { case 1: continue; default: r = r + 100; } }";
        for (x, want) in [(0.0, 210.0), (1.0, 221.0), (2.0, 201.0), (5.0, 299.0)] {
            assert_eq!(number(src, &[("x", x)], "r")?, Some(want), "x = {x}");
        }
        // case matching is strict: the string "1" is not the number 1.
        let out = eval(src, &[("x", ScriptValue::Text("1".to_string()))], "r")?;
        assert_eq!(out, Some(ScriptValue::Number(299.0)));
        Ok(())
    }

    #[test]
    fn test_run_conversions_and_equality() -> Result<(), ScriptError> {
        assert_eq!(text("s = 1 + '2';", "s")?, Some("12".to_string()));
        assert_eq!(number("n = '6' * '7';", &[], "n")?, Some(42.0));
        assert_eq!(number("n = null + 1;", &[], "n")?, Some(1.0));
        assert_eq!(
            number(
                "n = (undefined == null) && ('1' == 1) && !('1' === 1) ? 1 : 0;",
                &[],
                "n"
            )?,
            Some(1.0)
        );
        assert_eq!(
            number("n = isNaN('abc') && !isNaN('12') ? 1 : 0;", &[], "n")?,
            Some(1.0)
        );
        assert_eq!(text("s = '' + [1, 2, 3];", "s")?, Some("1,2,3".to_string()));
        assert_eq!(number("n = 7 % -3; m = -7 % 3;", &[], "n")?, Some(1.0));
        assert_eq!(number("n = 7 % -3; m = -7 % 3;", &[], "m")?, Some(-1.0));
        assert_eq!(
            number("n = 1 / 0 === Infinity ? 1 : 0;", &[], "n")?,
            Some(1.0)
        );
        Ok(())
    }

    #[test]
    fn test_run_builtins() -> Result<(), ScriptError> {
        assert_eq!(
            number("n = Math.round(2.5) + Math.round(-2.5);", &[], "n")?,
            Some(1.0)
        );
        assert_eq!(number("n = Math.pow(2, 10);", &[], "n")?, Some(1024.0));
        assert_eq!(
            number("n = Math.max(1, 7, 3) - Math.min(4, 2);", &[], "n")?,
            Some(5.0)
        );
        assert_eq!(number("n = parseInt('  42px');", &[], "n")?, Some(42.0));
        assert_eq!(
            number("n = parseInt('ff', 16) + parseInt('0x10');", &[], "n")?,
            Some(271.0)
        );
        assert_eq!(
            number("n = parseFloat('3.5e2xyz');", &[], "n")?,
            Some(350.0)
        );
        assert_eq!(number("n = Number('12.5') * 2;", &[], "n")?, Some(25.0));
        let log = number("n = Math.log(Math.E);", &[], "n")?;
        assert!(log.is_some_and(|l| (l - 1.0).abs() < 1e-12));
        Ok(())
    }

    #[test]
    fn test_to_fixed_rounds_the_exact_value_half_up() -> Result<(), ScriptError> {
        assert_eq!(to_fixed(1.005, 2.0)?, "1.00"); // 1.005 is just below 1.005
        assert_eq!(to_fixed(2.5, 0.0)?, "3");
        assert_eq!(to_fixed(0.125, 2.0)?, "0.13");
        assert_eq!(to_fixed(-1.5, 0.0)?, "-2");
        assert_eq!(to_fixed(-0.0001, 2.0)?, "-0.00");
        assert_eq!(to_fixed(99.996, 2.0)?, "100.00");
        assert_eq!(to_fixed(1234.5678, 1.0)?, "1234.6");
        assert_eq!(
            text("s = (21.456).toFixed(1);", "s")?,
            Some("21.5".to_string())
        );
        Ok(())
    }

    #[test]
    fn test_number_to_string_matches_javascript() {
        for (n, want) in [
            (0.0, "0"),
            (-0.0, "0"),
            (42.0, "42"),
            (-1.5, "-1.5"),
            (0.1, "0.1"),
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (123456789012345680000.0, "123456789012345680000"),
            (f64::NAN, "NaN"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            assert_eq!(number_to_string(n), want, "{n}");
        }
    }

    #[test]
    fn test_run_refuses_unsupported() {
        for src in [
            "function f() { return 1; }",
            "x = new Date();",
            "x = typeof y;",
            "x = Math.random();",
            "x = {a: 1};",
            "x = y;",
            "while (true) {}",
            "x = 'abc'.toUpperCase();",
        ] {
            assert!(
                matches!(run(src, &[], &["x"]), Err(ScriptError::Unsupported(_))),
                "{src}"
            );
        }
    }

    fn refused(script: &str, inputs: &[(&str, ScriptValue)], outputs: &[&str]) -> bool {
        matches!(
            run(script, inputs, outputs),
            Err(ScriptError::Unsupported(_))
        )
    }

    #[test]
    fn test_tokenize_refuses_escapes_outside_the_subset() -> Result<(), ScriptError> {
        assert_eq!(
            text(r#"s = "a\n\t\"\\\'b\0";"#, "s")?,
            Some("a\n\t\"\\'b\0".to_string())
        );
        for esc in [r"\x41", r"\u00e9", r"\b", r"\v", r"\f", r"\07", r"\q"] {
            let src = format!("s = \"{esc}\";");
            assert!(refused(&src, &[], &["s"]), "{esc}");
        }
        Ok(())
    }

    #[test]
    fn test_run_refuses_deep_nesting_without_overflowing() {
        // Product data is untrusted: a hostile nesting is an error, not a
        // stack overflow that aborts the process.
        let parens = format!("x = {}1{};", "(".repeat(10_000), ")".repeat(10_000));
        assert!(refused(&parens, &[], &["x"]));
        let nots = format!("x = {}1;", "!".repeat(10_000));
        assert!(refused(&nots, &[], &["x"]));
        let blocks = format!("{}x = 1;{}", "{".repeat(10_000), "}".repeat(10_000));
        assert!(refused(&blocks, &[], &["x"]));
    }

    #[test]
    fn test_run_refuses_a_string_or_array_past_its_bound() {
        // Doubling a string 30 times fits the step budget but not memory.
        assert!(refused(
            "var s = \"ab\"; for (var i = 0; i < 30; i++) { s += s; }",
            &[],
            &["s"]
        ));
        assert!(refused("var a = []; a[70000] = 1;", &[], &["a"]));
        // An array holding itself has no finite text.
        assert!(refused(
            "var a = [1]; a[0] = a; var s = a + \"\";",
            &[],
            &["s"]
        ));
    }

    #[test]
    fn test_run_refuses_a_block_scoped_shadow() -> Result<(), ScriptError> {
        // All variables are global here, so a nested `let` that shadows
        // another variable would overwrite it: refused.
        let input = [("x", ScriptValue::Number(5.0))];
        assert!(refused(
            "if (true) { let x = 1; } var y = x;",
            &input,
            &["y"]
        ));
        assert!(refused(
            "var t = 2; for (let t = 0; t < 1; t++) {} var y = t;",
            &[],
            &["y"]
        ));
        // A loop counter used only in its loop behaves the same either way.
        assert_eq!(
            number(
                "var y = 0; for (let i = 0; i < 3; i++) { const d = i * 2; y += d; }",
                &[],
                "y"
            )?,
            Some(6.0)
        );
        // An implicit global (assigned without a declaration) that a nested
        // `let` shadows would be clobbered by it: refused.
        assert!(refused(
            "tmp = x * 2; if (x > 3) { let tmp = 0; } y = tmp;",
            &input,
            &["y"]
        ));
        // A block declaring the name inside another that declares it too.
        assert!(refused(
            "var y = 0; { let a = 1; { let a = 2; } y = a; }",
            &[],
            &["y"]
        ));
        // Two loops each with their own counter are fine.
        assert_eq!(
            number(
                "var y = 0; for (let i = 0; i < 2; i++) { y += i; } for (let i = 0; i < 3; i++) { y += i; }",
                &[],
                "y"
            )?,
            Some(4.0)
        );
        Ok(())
    }

    #[test]
    fn test_run_let_without_initializer_is_fresh_each_iteration() -> Result<(), ScriptError> {
        // `m` is re-created as undefined each iteration, so only the
        // iterations that set it count; a `var` would keep the value.
        let src = "var count = 0;
            for (var i = 0; i < 5; i++) { let m; if (i % 2 == 0) { m = 1; } if (m === 1) { count++; } }";
        assert_eq!(number(src, &[], "count")?, Some(3.0));
        let src = "var count = 0;
            for (var i = 0; i < 5; i++) { var m; if (i == 0) { m = 1; } if (m === 1) { count++; } }";
        assert_eq!(number(src, &[], "count")?, Some(5.0));
        Ok(())
    }
}
