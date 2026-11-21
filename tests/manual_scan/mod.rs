//! Source analysis for the architecture guards of the manual control plane
//! (`src/manual/`, Prototype v0.2; audit G-01).
//!
//! The guards used to look for exact strings in comment-stripped text. A
//! `use crate::{daemon, fencing};`, an alias, `super::super::`, a line break,
//! a `"//"` inside a string, a string that says `"mod tests"`, a sub-directory
//! or a `#[path]` module each hid a violation (`audit/ARCHITECTURE_REVIEW.md`
//! section 8). This module reads Rust source a little more like a compiler
//! does, without a parser dependency:
//!
//! 1. [`lex`] removes comments (nested block comments included) and replaces
//!    every string / raw string / char literal by a placeholder, so text in a
//!    literal can neither hide code nor create a match;
//! 2. [`squash`] normalises white space, so a path split over lines or with
//!    blanks around `::` reads the same as the plain one;
//! 3. test-only items (`#[cfg(test)]`) are removed by brace matching, not by
//!    cutting the file at the text "mod tests";
//! 4. `use` declarations are expanded (nested groups, `as`, `self`, `super`,
//!    globs) and every path in the code is resolved through those aliases and
//!    the module's own position, so what is compared is `crate::daemon::X`
//!    however it was spelled.
//!
//! The checks are written as pure functions over a source string, so the
//! evasion forms the auditors found are unit tests of the checks themselves
//! (`mod tests` at the end), not `#[should_panic]` tests of the real tree.
//!
//! Detection limits (also in LIMITATIONS): strings assembled at run time
//! (`format!`, joins) are not evaluated; macros are not expanded; the check
//! of ssh option strings is therefore backed by a pinned list of the
//! literals of the one function that builds them (`remote.rs::argv`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// lexing
// ---------------------------------------------------------------------------

const MARK: char = '\u{1}';

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Comments removed; every literal replaced by `"\u{1}<index>\u{1}"` (char
/// literals by `'_'`); the literal contents (as written, escapes untouched)
/// are returned in order.
pub fn lex(source: &str) -> (String, Vec<String>) {
    let b: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(b.len());
    let mut literals: Vec<String> = Vec::new();
    let mut i = 0;
    let prev_is_ident = |out: &String| out.chars().next_back().is_some_and(is_ident);
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        // raw strings: r"..", r#".."#, br".." , cr".."
        if !prev_is_ident(&out) && (c == 'r' || ((c == 'b' || c == 'c') && next == Some('r'))) {
            let mut j = i + usize::from(c != 'r') + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                j += 1;
                let start = j;
                loop {
                    if j >= b.len() {
                        break;
                    }
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                        break;
                    }
                    j += 1;
                }
                literals.push(b[start..j.min(b.len())].iter().collect());
                out.push_str(&format!("\"{MARK}{}{MARK}\"", literals.len() - 1));
                i = (j + 1 + hashes).min(b.len());
                continue;
            }
        }
        // b"..", c"..", b'.'
        if !prev_is_ident(&out) && (c == 'b' || c == 'c') && next == Some('"') {
            i += 1;
            continue; // the quote is handled by the next iteration
        }
        if !prev_is_ident(&out) && c == 'b' && next == Some('\'') {
            i += 1;
            continue;
        }
        if c == '"' {
            let mut j = i + 1;
            let start = j;
            while j < b.len() && b[j] != '"' {
                j += if b[j] == '\\' { 2 } else { 1 };
            }
            literals.push(b[start..j.min(b.len())].iter().collect());
            out.push_str(&format!("\"{MARK}{}{MARK}\"", literals.len() - 1));
            i = (j + 1).min(b.len());
            continue;
        }
        if c == '\'' {
            // char literal or lifetime / label
            if next == Some('\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != '\'' {
                    j += 1;
                }
                out.push_str("'_'");
                i = (j + 1).min(b.len());
                continue;
            }
            if b.get(i + 2) == Some(&'\'') {
                out.push_str("'_'");
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    (out, literals)
}

/// White space collapsed; a blank next to punctuation removed, so
/// `crate :: daemon`, `crate::\n    daemon` and `crate::daemon` read alike.
pub fn squash(code: &str) -> String {
    let mut collapsed = String::with_capacity(code.len());
    let mut blank = false;
    for c in code.chars() {
        if c.is_whitespace() {
            blank = true;
        } else {
            if blank && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            blank = false;
            collapsed.push(c);
        }
    }
    const PUNCT: &str = "(){}[]<>,;:.=!&|+-*/%^~?@#$\"'";
    let chars: Vec<char> = collapsed.chars().collect();
    let mut out = String::with_capacity(chars.len());
    for (k, &c) in chars.iter().enumerate() {
        if c == ' ' {
            let before = k.checked_sub(1).map(|p| chars[p]);
            let after = chars.get(k + 1).copied();
            let glue = |x: Option<char>| x.is_some_and(|x| PUNCT.contains(x));
            if glue(before) || glue(after) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// What may follow `#[cfg(test)]` directly after a `{` for the attribute to
/// stand on an item or a statement (and not on a match arm, a struct field or
/// an enum variant, where cutting "to the next `}`" would swallow code that
/// is not test-only).
fn starts_an_item_or_statement(after: &str) -> bool {
    const STARTS: &[&str] = &[
        "fn ",
        "pub",
        "mod ",
        "use ",
        "impl",
        "struct ",
        "enum ",
        "const ",
        "static ",
        "trait ",
        "type ",
        "unsafe ",
        "extern ",
        "async ",
        "#[",
        "let ",
        "macro_rules!",
        "{",
    ];
    STARTS.iter().any(|start| after.starts_with(start))
}

/// Remove every `#[cfg(test)]` item (module, function, impl, use, ...) by
/// matching brackets, **where the attribute stands at the beginning of an
/// item or statement**: at the start of the code, after `;` or `}`, after
/// another attribute (`]`), or after `{` when an item or statement follows.
/// Anywhere else (a match arm, a call argument, an enum variant, an array
/// element, a struct field) the attribute alone is removed and the code it
/// was on stays in the analysis: cutting "to the next `}` or `;`" there used
/// to make everything after it disappear (audit RA-E-02), which only ever
/// hides code. Keeping a test-only expression costs at most a false alarm.
pub fn drop_test_items(code: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut s = code.to_string();
    let mut search_from = 0;
    while let Some(found) = s[search_from..].find(ATTR) {
        let start = search_from + found;
        let after_attr = start + ATTR.len();
        let boundary = match s[..start].chars().next_back() {
            None | Some(';' | '}' | ']') => true,
            Some('{') => starts_an_item_or_statement(&s[after_attr..]),
            _ => false,
        };
        if !boundary {
            s.replace_range(start..after_attr, "");
            search_from = start;
            continue;
        }
        let bytes: Vec<char> = s.chars().collect();
        // work on char indices
        let start_c = s[..start].chars().count();
        let mut j = start_c + ATTR.chars().count();
        // further attributes on the same item
        while bytes.get(j) == Some(&'#') && bytes.get(j + 1) == Some(&'[') {
            let mut depth = 0;
            while j < bytes.len() {
                match bytes[j] {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        let mut depth: i32 = 0;
        let mut end = bytes.len();
        let mut k = j;
        while k < bytes.len() {
            match bytes[k] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' => depth -= 1,
                '}' => {
                    depth -= 1;
                    if depth <= 0 {
                        end = k + 1;
                        break;
                    }
                }
                ';' if depth <= 0 => {
                    end = k + 1;
                    break;
                }
                _ => {}
            }
            k += 1;
        }
        let kept: String = bytes[..start_c].iter().chain(bytes[end..].iter()).collect();
        s = kept;
        search_from = start.min(s.len());
        while !s.is_char_boundary(search_from) {
            search_from -= 1;
        }
    }
    s
}

// ---------------------------------------------------------------------------
// a loaded source file
// ---------------------------------------------------------------------------

/// One file, ready for the checks.
pub struct Source {
    /// Module path of the file: `["crate", "manual", "vip"]`.
    pub module: Vec<String>,
    /// Whether this file is the crate root (`main.rs`).
    pub root: bool,
    /// Comments, literals and test-only items removed; white space squashed.
    pub code: String,
    /// The literals that remain in `code` (placeholders refer to them).
    literals: Vec<String>,
}

impl Source {
    /// `code` with the literals put back (comments and test items still
    /// removed): for checks that look at what a string says.
    pub fn with_literals(&self) -> String {
        restore(&self.code, &self.literals)
    }

    /// Every string literal in production code.
    pub fn string_literals(&self) -> Vec<String> {
        self.literals_in(&self.code)
    }

    /// The literals inside `region`, a slice of `self.code`.
    pub fn literals_in(&self, region: &str) -> Vec<String> {
        let mut found = Vec::new();
        let chars: Vec<char> = region.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '"' && chars.get(i + 1) == Some(&MARK) {
                let mut j = i + 2;
                let mut number = String::new();
                while j < chars.len() && chars[j] != MARK {
                    number.push(chars[j]);
                    j += 1;
                }
                if let Ok(index) = number.parse::<usize>() {
                    found.push(self.literals[index].clone());
                }
                i = j + 2;
            } else {
                i += 1;
            }
        }
        found
    }
}

fn restore(code: &str, literals: &[String]) -> String {
    let mut out = String::with_capacity(code.len());
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' && chars.get(i + 1) == Some(&MARK) {
            let mut j = i + 2;
            let mut number = String::new();
            while j < chars.len() && chars[j] != MARK {
                number.push(chars[j]);
                j += 1;
            }
            if let Ok(index) = number.parse::<usize>() {
                out.push('"');
                out.push_str(&literals[index]);
                out.push('"');
                i = j + 2;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Load `text` as the module `module` (`["crate", "manual", "vip"]`).
pub fn load(module: &[&str], text: &str) -> Source {
    let (code, literals) = lex(text);
    let code = drop_test_items(&squash(&code));
    Source {
        root: module == ["crate"],
        module: module.iter().map(|s| (*s).to_string()).collect(),
        code,
        literals,
    }
}

/// Module path of a file below `src/`: `src/manual/vip.rs` ->
/// `crate::manual::vip`, `src/manual/mod.rs` -> `crate::manual`,
/// `src/main.rs` -> `crate`.
pub fn module_of(src_dir: &Path, file: &Path) -> Vec<String> {
    let relative = file.strip_prefix(src_dir).expect("file below src/");
    let mut parts: Vec<String> = vec!["crate".to_string()];
    let components: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    for (i, component) in components.iter().enumerate() {
        let last = i + 1 == components.len();
        if last {
            let stem = component.trim_end_matches(".rs");
            if stem != "mod" && stem != "main" && stem != "lib" {
                parts.push(stem.to_string());
            }
        } else {
            parts.push(component.clone());
        }
    }
    parts
}

/// Every `.rs` file below `dir`, recursively (sub-directories included).
pub fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if name.ends_with(".rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

// ---------------------------------------------------------------------------
// use declarations and path resolution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseItem {
    pub path: Vec<String>,
    pub alias: Option<String>,
    pub glob: bool,
}

struct Cursor<'a> {
    s: &'a [char],
    p: usize,
}

impl Cursor<'_> {
    fn starts_with(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(k, c)| self.s.get(self.p + k) == Some(&c))
    }
    fn ident(&mut self) -> Option<String> {
        let start = self.p;
        while self.s.get(self.p).is_some_and(|c| is_ident(*c)) {
            self.p += 1;
        }
        (self.p > start).then(|| self.s[start..self.p].iter().collect())
    }
}

fn parse_tree(c: &mut Cursor<'_>, prefix: &[String], out: &mut Vec<UseItem>) {
    let mut path = prefix.to_vec();
    if c.starts_with("::") {
        c.p += 2;
    }
    loop {
        match c.s.get(c.p) {
            Some('*') => {
                c.p += 1;
                out.push(UseItem {
                    path,
                    alias: None,
                    glob: true,
                });
                return;
            }
            Some('{') => {
                c.p += 1;
                loop {
                    if c.s.get(c.p) == Some(&'}') {
                        c.p += 1;
                        return;
                    }
                    let before = c.p;
                    parse_tree(c, &path, out);
                    if c.s.get(c.p) == Some(&',') {
                        c.p += 1;
                    }
                    if c.p >= c.s.len() {
                        return;
                    }
                    if c.p == before {
                        // nothing understood here: skip a character rather than loop
                        c.p += 1;
                    }
                }
            }
            _ => {}
        }
        let Some(name) = c.ident() else {
            return;
        };
        let is_self_in_group = name == "self" && !prefix.is_empty() && path.len() == prefix.len();
        if is_self_in_group {
            // `use a::b::{self}` names `a::b` itself.
        } else {
            path.push(name);
        }
        if c.starts_with("::") {
            c.p += 2;
            continue;
        }
        let mut alias = None;
        if c.starts_with(" as ") {
            c.p += 4;
            alias = c.ident();
        }
        out.push(UseItem {
            path,
            alias,
            glob: false,
        });
        return;
    }
}

/// The spans (start, end) of `use ...;` declarations in squashed code.
fn use_spans(code: &str) -> Vec<(usize, usize)> {
    let chars: Vec<char> = code.chars().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i + 3 <= chars.len() {
        if chars[i] == 'u'
            && chars[i + 1] == 's'
            && chars[i + 2] == 'e'
            && (i == 0 || !is_ident(chars[i - 1]))
            && chars
                .get(i + 3)
                .is_some_and(|c| *c == ' ' || *c == '{' || *c == ':')
        {
            let mut j = i + 3;
            let mut depth = 0;
            while j < chars.len() {
                match chars[j] {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    ';' if depth <= 0 => break,
                    _ => {}
                }
                j += 1;
            }
            spans.push((i, (j + 1).min(chars.len())));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    spans
}

/// All `use` items of the file, in order.
pub fn use_items(code: &str) -> Vec<UseItem> {
    let chars: Vec<char> = code.chars().collect();
    let mut items = Vec::new();
    for (start, end) in use_spans(code) {
        let body: Vec<char> = chars[start + 3..end].to_vec();
        let mut cursor = Cursor {
            s: &body,
            p: usize::from(body.first() == Some(&' ')),
        };
        parse_tree(&mut cursor, &[], &mut items);
    }
    items
}

fn code_without_uses(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut last = 0;
    for (start, end) in use_spans(code) {
        out.extend(chars[last..start].iter());
        out.push(';');
        last = end;
    }
    out.extend(chars[last..].iter());
    out
}

/// Top-level module names of the crate (needed to read `manual::x` in
/// `main.rs`, where the crate root is the current module).
pub fn top_level_modules(src_dir: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(src_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let stem = name.trim_end_matches(".rs");
            if stem != "main" && !stem.starts_with('.') {
                names.insert(stem.to_string());
            }
        }
    }
    names
}

pub struct Resolver {
    module: Vec<String>,
    root: bool,
    tops: BTreeSet<String>,
    aliases: BTreeMap<String, Vec<String>>,
    /// The file has `use crate::*;` (or a `super::*` that is the crate root):
    /// every top-level module name is then in scope under its bare name
    /// (audit RA-E-01: `use crate::*; manual::exec::run()`).
    glob_of_root: bool,
}

impl Resolver {
    pub fn new(source: &Source, tops: &BTreeSet<String>) -> Self {
        let mut resolver = Self {
            module: source.module.clone(),
            root: source.root,
            tops: tops.clone(),
            aliases: BTreeMap::new(),
            glob_of_root: false,
        };
        for item in use_items(&source.code) {
            if item.glob {
                if resolver.resolve(&item.path) == ["crate"] {
                    resolver.glob_of_root = true;
                }
                continue;
            }
            let full = resolver.resolve(&item.path);
            let name = item
                .alias
                .clone()
                .or_else(|| item.path.last().cloned())
                .unwrap_or_default();
            if name != "_" && !name.is_empty() {
                resolver.aliases.insert(name, full);
            }
        }
        resolver
    }

    pub fn resolve(&self, path: &[String]) -> Vec<String> {
        let Some(first) = path.first() else {
            return Vec::new();
        };
        match first.as_str() {
            "crate" => path.to_vec(),
            // `self::super::super::x` is `super::super::x` (audit L-2: the
            // `super` after `self` was left unresolved).
            "self" if path.get(1).is_some_and(|s| s == "super") => self.resolve(&path[1..]),
            "self" => self
                .module
                .iter()
                .chain(path[1..].iter())
                .cloned()
                .collect(),
            "super" => {
                let mut module = self.module.clone();
                let mut k = 0;
                while path.get(k).is_some_and(|s| s == "super") {
                    if module.len() > 1 {
                        module.pop();
                    }
                    k += 1;
                }
                module
                    .into_iter()
                    .chain(path[k..].iter().cloned())
                    .collect()
            }
            _ => {
                if let Some(full) = self.aliases.get(first) {
                    return full.iter().chain(path[1..].iter()).cloned().collect();
                }
                if (self.root || self.glob_of_root) && self.tops.contains(first) {
                    return std::iter::once("crate".to_string())
                        .chain(path.iter().cloned())
                        .collect();
                }
                path.to_vec()
            }
        }
    }
}

/// Every path the file refers to, resolved: the `use` items (a glob ends in
/// `*`) and every `a::b::c` chain in the code.
pub fn references(source: &Source, tops: &BTreeSet<String>) -> Vec<Vec<String>> {
    let resolver = Resolver::new(source, tops);
    let mut found: Vec<Vec<String>> = Vec::new();
    for item in use_items(&source.code) {
        let mut path = resolver.resolve(&item.path);
        if item.glob {
            path.push("*".to_string());
        }
        found.push(path);
    }
    let code: Vec<char> = code_without_uses(&source.code).chars().collect();
    let mut i = 0;
    while i < code.len() {
        let c = code[i];
        let starts_ident = (c.is_alphabetic() || c == '_') && (i == 0 || !is_ident(code[i - 1]));
        if starts_ident && (i == 0 || code[i - 1] != '.') {
            let mut chain = Vec::new();
            let mut j = i;
            loop {
                let start = j;
                while j < code.len() && is_ident(code[j]) {
                    j += 1;
                }
                chain.push(code[start..j].iter().collect::<String>());
                if code.get(j) == Some(&':')
                    && code.get(j + 1) == Some(&':')
                    && code
                        .get(j + 2)
                        .is_some_and(|c| c.is_alphabetic() || *c == '_')
                {
                    j += 2;
                    continue;
                }
                break;
            }
            // A lone identifier names nothing outside its module (`pub(crate)`,
            // `mod manual;`, a local); a `use` of an alias is recorded above.
            if chain.len() > 1 {
                found.push(resolver.resolve(&chain));
            }
            i = j;
        } else if c == '_' || c.is_alphanumeric() {
            while i < code.len() && is_ident(code[i]) {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    found
}

/// Attributes (`#[...]`, `#![...]`) in squashed code, as written.
pub fn attributes(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 1 < chars.len() {
        let bang = chars[i] == '#' && chars[i + 1] == '!' && chars.get(i + 2) == Some(&'[');
        if (chars[i] == '#' && chars[i + 1] == '[') || bang {
            let mut j = i + if bang { 2 } else { 1 };
            let start = j;
            let mut depth = 0;
            while j < chars.len() {
                match chars[j] {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            found.push(chars[start..(j + 1).min(chars.len())].iter().collect());
            i = j;
        }
        i += 1;
    }
    found
}

/// An identifier occurs as a whole word.
pub fn has_word(code: &str, word: &str) -> bool {
    code.match_indices(word).any(|(at, _)| {
        let before = code[..at].chars().next_back();
        let after = code[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------

fn path_text(path: &[String]) -> String {
    path.join("::")
}

/// `strict`: any `#[path]` is a violation (the manual plane has none). Not
/// strict (HA files, which use `#[path]` for sibling files): one whose target
/// names the manual plane.
fn module_attribute_and_include_violations(
    source: &Source,
    who: &str,
    strict: bool,
) -> Vec<String> {
    let mut found = Vec::new();
    for attribute in attributes(&source.with_literals()) {
        let compact: String = attribute.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("path=") && (strict || compact.contains("manual")) {
            found.push(format!(
                "{who}: a #[path] attribute can pull in a file from anywhere ({compact})"
            ));
        }
    }
    for macro_name in ["include!", "include_str!", "include_bytes!"] {
        if source.code.contains(macro_name) {
            found.push(format!("{who}: {macro_name} pulls a file in by text"));
        }
    }
    found
}

/// The bodies of the `macro_rules!` definitions in squashed code (without
/// their outer brackets).
pub fn macro_rules_bodies(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut bodies = Vec::new();
    let mut from = 0;
    while let Some(found) = code[from..].find("macro_rules!") {
        let at = from + found;
        let start = code[..at].chars().count() + "macro_rules!".chars().count();
        from = at + "macro_rules!".len();
        // the name, then the opening bracket of the body
        let mut j = start;
        while j < chars.len() && !matches!(chars[j], '{' | '(' | '[') {
            j += 1;
        }
        let Some(&open) = chars.get(j) else { break };
        let close = match open {
            '{' => '}',
            '(' => ')',
            _ => ']',
        };
        let mut depth = 0;
        let mut k = j;
        while k < chars.len() {
            if chars[k] == open {
                depth += 1;
            } else if chars[k] == close {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            k += 1;
        }
        bodies.push(chars[j + 1..k.min(chars.len())].iter().collect());
    }
    bodies
}

/// Forms that give a path a name the reading above does not follow (audit
/// RA-E-01), for every file of the three groups: `extern crate self as c;`
/// (the crate root under another name) and a `macro_rules!` that assembles a
/// path from a macro argument (`crate::$a::run()`, `$crate::...`), which the
/// scan does not expand.
pub fn indirection_violations(who: &str, source: &Source) -> Vec<String> {
    let mut found = Vec::new();
    if has_word(&source.code, "extern") && source.code.contains("extern crate") {
        found.push(format!(
            "{who} uses `extern crate`, which gives a crate path a name the scan does not follow"
        ));
    }
    for body in macro_rules_bodies(&source.code) {
        if body.contains("$crate") || body.contains("::$") {
            found.push(format!(
                "{who} defines a macro that assembles a path from its arguments ({}); the scan \
                 does not expand macros",
                body.chars().take(60).collect::<String>()
            ));
        }
    }
    found
}

/// G1. What a file of the manual plane may refer to under `crate::`: its own
/// plane, and the one audited trust check of the HA code base. Everything
/// else under `crate::` is a violation, whatever it is called and however
/// the path was spelled (an allow list, not a list of known HA modules).
pub fn check_manual_file(who: &str, source: &Source, tops: &BTreeSet<String>) -> Vec<String> {
    let mut found = module_attribute_and_include_violations(source, who, true);
    found.extend(indirection_violations(who, source));
    for path in references(source, tops) {
        if path.first().map(String::as_str) != Some("crate") {
            continue;
        }
        let allowed = path.get(1).map(String::as_str) == Some("manual")
            || path == ["crate", "fencing_backend", "check_executable_trust"]
            // v0.5 shared safety primitives: a neutral kernel lock and the
            // durable manual-operation barrier contract. They contain no HA
            // engine or manual control logic; both planes only call them.
            || path.get(1).map(String::as_str) == Some("control_lock")
            || path.get(1).map(String::as_str) == Some("manual_barrier");
        if !allowed {
            found.push(format!("{who} reaches {}", path_text(&path)));
        }
    }
    for forbidden in ["WitnessSession", "ResourceExecutor", "ResourceWorkflow"] {
        if has_word(&source.code, forbidden) {
            found.push(format!("{who} names {forbidden}"));
        }
    }
    found
}

/// G2. A file of the HA engine must not refer to the manual plane at all.
pub fn check_ha_file(who: &str, source: &Source, tops: &BTreeSet<String>) -> Vec<String> {
    let mut found = module_attribute_and_include_violations(source, who, false);
    found.extend(indirection_violations(who, source));
    for path in references(source, tops) {
        if path.len() >= 2 && path[0] == "crate" && path[1] == "manual" {
            found.push(format!("{who} reaches {}", path_text(&path)));
        }
    }
    found
}

/// The only things the three CLI wiring files may take from the plane, as
/// complete paths (not prefixes).
pub const WIRING_ALLOWED: &[&str] = &[
    "crate::manual::run::resource",
    "crate::manual::run::chronyd",
    "crate::manual::run::agent",
    "crate::manual::run::status_wanted",
    "crate::manual::run::status_overview",
    "crate::manual::run::status_failure_exit",
    "crate::manual::cli_def::ChronydCommands",
    "crate::manual::cli_def::ResourceCommands",
];

/// G3. The wiring files (`main`, `cli`, `status`) use exactly the entry
/// points in [`WIRING_ALLOWED`]. `crate::manual` alone (the `mod`
/// declaration is not a path; an alias of the module is) is not allowed.
pub fn check_wiring_file(who: &str, source: &Source, tops: &BTreeSet<String>) -> Vec<String> {
    let mut found = module_attribute_and_include_violations(source, who, false);
    found.extend(indirection_violations(who, source));
    for path in references(source, tops) {
        if path.len() >= 2 && path[0] == "crate" && path[1] == "manual" {
            let text = path_text(&path);
            if !WIRING_ALLOWED.contains(&text.as_str()) {
                found.push(format!(
                    "{who} reaches {text}, which is not one of the plane's entry points"
                ));
            }
        }
    }
    found
}

fn is_shell_name(literal: &str) -> bool {
    let name = literal.rsplit('/').next().unwrap_or(literal);
    matches!(
        name,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "ash"
            | "busybox"
            | "env"
    )
}

fn is_shell_flag(literal: &str) -> bool {
    let rest = literal.strip_prefix('-').unwrap_or("");
    !rest.is_empty()
        && !literal.starts_with("--")
        && rest.chars().all(|c| c.is_ascii_alphabetic())
        && rest.contains('c')
        && rest.len() <= 3
}

const SPAWN_FUNCTIONS: &[&str] = &[
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "execl",
    "execle",
    "execlp",
    "fexecve",
    "posix_spawn",
    "posix_spawnp",
    "fork",
    "vfork",
    "system",
    "popen",
    "daemon",
];

/// `extern` blocks (`extern "C" { .. }`, `unsafe extern "C" { .. }`,
/// `extern { .. }`) in squashed code: the keyword, an optional ABI string,
/// then an opening brace.
pub fn extern_blocks(code: &str) -> usize {
    let chars: Vec<char> = code.chars().collect();
    let mut count = 0;
    let mut from = 0;
    while let Some(found) = code[from..].find("extern") {
        let at = from + found;
        from = at + "extern".len();
        let before = code[..at].chars().next_back();
        let after_word = code[from..].chars().next();
        if before.is_some_and(is_ident) || after_word.is_some_and(is_ident) {
            continue;
        }
        let mut j = code[..from].chars().count();
        while chars.get(j) == Some(&' ') {
            j += 1;
        }
        if chars.get(j) == Some(&'"') && chars.get(j + 1) == Some(&MARK) {
            j += 2;
            while j < chars.len() && chars[j] != MARK {
                j += 1;
            }
            j += 2;
        }
        while chars.get(j) == Some(&' ') {
            j += 1;
        }
        if chars.get(j) == Some(&'{') {
            count += 1;
        }
    }
    count
}

/// How many times the identifier `syscall` appears other than as the name in
/// a direct call `syscall(..)`: an import under another name
/// (`use libc::syscall as sc`), a parenthesised path `(libc::syscall)(..)`, a
/// function value. The number check below only sees direct calls, so any such
/// use is a finding of its own (final re-audit N-4).
pub fn syscall_non_call_uses(code: &str) -> usize {
    code.match_indices("syscall")
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + "syscall".len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident) && after != Some('(')
        })
        .count()
}

/// The first argument of every call of a function named `syscall` in squashed
/// code (`libc::syscall(libc::SYS_renameat2, ...)` gives `SYS_renameat2`).
pub fn syscall_first_arguments(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (at, _) in code.match_indices("syscall(") {
        if code[..at].chars().next_back().is_some_and(is_ident) {
            continue;
        }
        let rest = &code[at + "syscall(".len()..];
        let mut depth = 0;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth > 0 => depth -= 1,
                ')' | ',' if depth == 0 => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        let argument = rest[..end].trim();
        found.push(
            argument
                .strip_prefix("libc::")
                .unwrap_or(argument)
                .to_string(),
        );
    }
    found
}

/// Match arms (and alternatives) whose pattern is a string literal: in the
/// operation dispatch every arm is an `op::NAME` constant, so that the
/// classification of operations (gated / read-only / file-only) sees all of
/// them. A literal arm (`"x.force" => ...`) would be an operation nobody
/// classified (audit RA-E-05).
pub fn literal_match_arms(code: &str) -> usize {
    let chars: Vec<char> = code.chars().collect();
    let mut count = 0;
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] == '"' && chars[i + 1] == MARK {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != MARK {
                j += 1;
            }
            // chars[j] is the closing MARK, chars[j + 1] the closing quote
            let after: String = chars.iter().skip(j + 2).take(2).collect();
            if after.starts_with("=>") || (after.starts_with('|') && !after.starts_with("||")) {
                count += 1;
            }
            i = j + 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Every string literal followed by `=>`, at any depth: an arm of a nested
/// match as well (`other => match other { "x.force" => .. }`). Unlike
/// [`literal_match_arms`] it ignores alternatives (`"a" | "b"`), which is how an
/// argument test such as `matches!(action, "start" | "stop")` is written
/// (final re-audit D-3).
pub fn literal_arrow_arms(code: &str) -> usize {
    let chars: Vec<char> = code.chars().collect();
    let mut count = 0;
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] == '"' && chars[i + 1] == MARK {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != MARK {
                j += 1;
            }
            let after: String = chars.iter().skip(j + 2).take(2).collect();
            if after.starts_with("=>") {
                count += 1;
            }
            i = j + 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Like [`literal_match_arms`], but only the arms of ONE match expression:
/// the arms at the top level of the block that follows `head` (for example
/// `match request.op.as_str()`). A string pattern in a nested expression, such
/// as `matches!(action, "start" | "stop")` on an argument, is not an arm of the
/// operation dispatch. Panics when `head` is not in `code`, so that a renamed
/// dispatch cannot make the check vacuous.
pub fn literal_arms_of_match(code: &str, head: &str) -> usize {
    let starts: Vec<usize> = code.match_indices(head).map(|(at, _)| at).collect();
    assert!(!starts.is_empty(), "match head not found: {head}");
    // EVERY match with this head counts: a second one (or an earlier one in
    // the same function) must not hide a literal arm (final re-audit N-3).
    starts
        .into_iter()
        .map(|start| literal_arms_after(&code[start + head.len()..], head))
        .sum()
}

fn literal_arms_after(rest: &str, head: &str) -> usize {
    let chars: Vec<char> = rest.chars().collect();
    let begin = chars
        .iter()
        .position(|c| *c == '{')
        .unwrap_or_else(|| panic!("match has no block: {head}"));
    let mut depth = 0usize;
    let mut count = 0;
    let mut i = begin;
    while i < chars.len() {
        match chars[i] {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return count;
                }
            }
            '"' if depth == 1 && chars.get(i + 1) == Some(&MARK) => {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != MARK {
                    j += 1;
                }
                let after: String = chars.iter().skip(j + 2).take(2).collect();
                // `"x" =>`, `"x" |`, and the guard form `"x" if ..`.
                if after.starts_with("=>")
                    || (after.starts_with('|') && !after.starts_with("||"))
                    || after.starts_with("if")
                {
                    count += 1;
                }
                i = j + 1;
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced match block: {head}");
}

/// G4. Processes are started in exactly one place (`exec.rs`) and never
/// through a shell, and the SSH policy never loosens host-key checking.
/// `in_exec` is true for `exec.rs` itself.
pub fn check_spawn_file(
    who: &str,
    source: &Source,
    tops: &BTreeSet<String>,
    in_exec: bool,
) -> Vec<String> {
    let mut found = Vec::new();
    if !in_exec {
        for path in references(source, tops) {
            let text = path_text(&path);
            if text.starts_with("std::process::Command")
                || text.starts_with("core::process::Command")
                || path == ["Command"]
                || path.starts_with(&["tokio".to_string(), "process".to_string()])
            {
                found.push(format!("{who} starts a process directly ({text})"));
            }
        }
        for method in [".spawn(", ".output(", ".exec("] {
            if source.code.contains(method) {
                found.push(format!("{who} starts a process directly ({method})"));
            }
        }
    }
    for path in references(source, tops) {
        if path.first().map(String::as_str) == Some("libc")
            && path
                .get(1)
                .is_some_and(|f| SPAWN_FUNCTIONS.contains(&f.as_str()))
        {
            found.push(format!("{who} uses {}", path_text(&path)));
        }
    }
    // `use std::process::*;` brings `Command` in without naming it.
    for path in references(source, tops) {
        if path.last().map(String::as_str) == Some("*")
            && path.len() >= 2
            && matches!(path[0].as_str(), "std" | "core")
            && path[1] == "process"
        {
            found.push(format!(
                "{who} glob-imports std::process, which hides a Command behind its bare name"
            ));
        }
    }
    // Foreign function declarations: `unsafe extern "C" { fn system(..); }`
    // declares a libc function without a `libc::` path. (An `extern "C" fn`
    // definition, such as a signal handler, declares nothing foreign.)
    if extern_blocks(&source.code) > 0 {
        found.push(format!(
            "{who} has an `extern` block; the plane calls the system only through the listed \
             `libc` items"
        ));
    }
    // One place starts a process, and it does so once.
    if in_exec {
        let starts = source.code.matches("Command::new(").count();
        if starts != 1 {
            found.push(format!(
                "{who} has {starts} `Command::new(` (exactly one is allowed: every process \
                 start goes through one reviewed function)"
            ));
        }
    }
    // The system-call number of `libc::syscall` is checked, not only the name
    // of the function (it was the whole of fsutil's allowance).
    for argument in syscall_first_arguments(&source.code) {
        if !(who.ends_with("fsutil.rs") && argument == "SYS_renameat2") {
            found.push(format!("{who} makes the system call {argument:?}"));
        }
    }
    // A local item named like a system-call number would shadow the libc one
    // and let any value pass the check above (final re-audit D-2).
    if source.code.contains("const SYS_") || source.code.contains("static SYS_") {
        found.push(format!(
            "{who} declares an item named `SYS_*`, which could shadow a libc system-call number"
        ));
    }
    if syscall_non_call_uses(&source.code) > 0 {
        found.push(format!(
            "{who} uses `syscall` other than in a direct call (an alias, a parenthesised path or a \
             function value would hide the system-call number)"
        ));
    }
    for macro_name in ["concat!", "stringify!"] {
        if source.code.contains(macro_name) {
            found.push(format!(
                "{who} uses {macro_name}, which would let a forbidden literal be assembled out of sight"
            ));
        }
    }
    for literal in source.string_literals() {
        let flat: String = literal.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = flat.to_lowercase();
        if is_shell_name(literal.trim()) || is_shell_flag(literal.trim()) {
            found.push(format!("{who} contains the shell literal {literal:?}"));
        }
        if lower.contains("hostkeychecking") && flat != "StrictHostKeyChecking=accept-new" {
            found.push(format!("{who} loosens host-key checking ({literal:?})"));
        }
        if lower.contains("knownhostsfile") && flat != "UserKnownHostsFile={}" {
            found.push(format!(
                "{who} names a known-hosts file other than the pinned one ({literal:?})"
            ));
        }
        if lower.contains("proxycommand") && flat != "ProxyCommand=none" {
            found.push(format!("{who} configures a proxy command ({literal:?})"));
        }
        if lower.contains("/dev/null") && flat != "/dev/null" {
            found.push(format!(
                "{who} points an ssh option at /dev/null ({literal:?})"
            ));
        }
    }
    found
}

/// The markers of MKM-13.5-07 (`mkm_arch_015_no_pid_ipc_or_control_plane`),
/// plus the ones other guards ban in the HA wiring. The plane may use one of
/// them only where [`MARKER_EXCEPTIONS`] says so, with the reason.
pub const FORBIDDEN_MARKERS: &[&str] = &[
    "pidfile",
    "getpid",
    "pgrep",
    "UnixListener",
    "UnixStream",
    "UnixDatagram",
    "signal_hook",
    "daemonize",
    "SIGUSR2",
    "libc::kill",
    "kill(",
    "/proc/",
    // The agent's scan of /proc for a hand-started HA daemon (audit RA-E-03):
    // the scan builds its paths from a `Path`, so the marker above does not
    // see it. These see its entry point and the two ways a scan starts.
    "\"/proc\"",
    "read_dir(\"/proc\"",
    "scan_proc(",
    "Process::",
    "fork(",
    "mqueue",
    "shm_open",
    "bind(",
    "TcpListener",
    "TcpStream",
];

/// (file, marker, reason). Each exception is an *explicit, reviewed* use in
/// the manual plane, a separate island. The Owner's approval of that island
/// is **limited** (Prototype v0.2 on its dedicated GCE only; not for
/// production; not a permanent change of MKM-13.5-07; the conditions are in
/// `prototype/v0.2/LIMITATIONS.md` item 44). The exceptions below are
/// therefore *Prototype-only* and are not a relaxation of MKM-13.5-07 for the
/// HA daemon, whose guards are untouched.
pub const MARKER_EXCEPTIONS: &[(&str, &str, &str)] = &[
    (
        "agent.rs",
        "TcpStream",
        "service probe: the node agent connects (outbound) to the VIP service to show that it answers",
    ),
    (
        "agent.rs",
        "/proc/",
        "boot identity in `ping`: reads /proc/sys/kernel/random/boot_id",
    ),
    (
        "agent.rs",
        "\"/proc\"",
        "process scan: the root agent lists /proc to find a hand-started HA daemon or Witness (exclusion proof, LIMITATIONS 30); it reads command lines and executable links only",
    ),
    (
        "config.rs",
        "\"/proc\"",
        "a deny list of path prefixes for configuration values (/dev, /proc, /sys are refused as state or tool locations); it reads nothing",
    ),
    (
        "agent.rs",
        "scan_proc(",
        "process scan: the call that gives the exclusion check its list of hand-started HA processes (Owner's limited approval of the island, LIMITATIONS 41/44)",
    ),
    (
        "exclusion.rs",
        "scan_proc(",
        "process scan: the function that walks /proc (command line and executable link of each process) for `mikagami daemon run` / `witness run`; vanished processes are skipped, any other read error is a failure (fail closed)",
    ),
    (
        "exec.rs",
        "kill(",
        "kills the process group of the child it started when its deadline passes",
    ),
    (
        "exec.rs",
        "libc::kill",
        "the same group kill, spelled with its path",
    ),
];

/// Markers used in `source` (literals included: `/proc/` is usually one).
pub fn markers_used(source: &Source) -> BTreeSet<&'static str> {
    let text = source.with_literals();
    FORBIDDEN_MARKERS
        .iter()
        .copied()
        .filter(|marker| text.contains(marker))
        .collect()
}

/// The `libc` items a file may use, with the reason (an allow list: a new
/// system call needs a line here and therefore a review).
pub const LIBC_ALLOWED: &[(&str, &[&str], &str)] = &[
    (
        "exec.rs",
        &["kill", "SIGKILL"],
        "kills the process group of a child that outlived its deadline",
    ),
    (
        "fsutil.rs",
        &[
            "O_NOFOLLOW",
            "O_NONBLOCK",
            "O_DIRECTORY",
            "geteuid",
            "syscall",
            "SYS_renameat2",
            "AT_FDCWD",
            "c_uint",
            "ENOSYS",
            "EINVAL",
            "ENOTSUP",
            "flistxattr",
            "fgetxattr",
            "fsetxattr",
            "fremovexattr",
        ],
        "no-follow opens, owner of the invoking user, atomic exchange (renameat2) and extended attributes",
    ),
    (
        "chrony_ctl.rs",
        &["O_NOFOLLOW", "O_NONBLOCK"],
        "the candidate file is opened without following a symlink and without blocking on a FIFO",
    ),
    (
        "agent.rs",
        &["geteuid"],
        "the agent insists on running as root",
    ),
    (
        "chrony_agent.rs",
        &["O_NOFOLLOW"],
        "the lock file is opened without following a symlink",
    ),
    (
        "lease.rs",
        &["O_NOFOLLOW"],
        "state files are opened without following a symlink",
    ),
    (
        "fence.rs",
        &["O_NOFOLLOW"],
        "state files are opened without following a symlink",
    ),
    ("vip.rs", &["geteuid"], "owner check of the state directory"),
    (
        "config.rs",
        &["geteuid"],
        "owner standard for the control configuration and the tools it names",
    ),
    ("run.rs", &[], ""),
    (
        "signals.rs",
        &[
            "SIGINT",
            "SIGTERM",
            "SIGHUP",
            "SIG_DFL",
            "c_int",
            "sighandler_t",
            "signal",
            "write",
            "_exit",
        ],
        "holds SIGINT/SIGTERM/SIGHUP while a command changes something (audit E-01)",
    ),
];

/// The `libc` items (the part after `libc::`) used by a file.
pub fn libc_items(source: &Source, tops: &BTreeSet<String>) -> BTreeSet<String> {
    references(source, tops)
        .into_iter()
        .filter(|p| p.first().map(String::as_str) == Some("libc") && p.len() >= 2)
        .map(|p| p[1].clone())
        .collect()
}

/// G6. How a file of the node agent builds paths (audit E-12, RA-E-06). In
/// squashed code of `source`:
///
/// * no path is made from a string at all except by the reviewed `join`s and
///   `with_file_name` (`Path::new(`, `PathBuf::from(`, `.push(`,
///   `.set_file_name(`, `OsStr::new(`, `OsString::from(` are violations);
/// * the first argument of a file-system call (`fs::..(`, `fsutil::..(`,
///   `File::open(` ...) is never a request value: neither a call of `arg(`
///   (the request accessor) nor one of the `tainted` names (identifiers that
///   carry a value the controller sent, validated or not).
pub fn check_path_building(who: &str, source: &Source, tainted: &[&str]) -> Vec<String> {
    let code = &source.code;
    let mut found = Vec::new();
    for form in [
        "Path::new(",
        "PathBuf::from(",
        ".push(",
        ".set_file_name(",
        "OsStr::new(",
        "OsString::from(",
    ] {
        if code.contains(form) {
            found.push(format!("{who} builds a path with {form}"));
        }
    }
    for prefix in ["fs::", "fsutil::", "File::", "OpenOptions::"] {
        for (at, _) in code.match_indices(prefix) {
            if code[..at].chars().next_back().is_some_and(is_ident) {
                continue;
            }
            let rest = &code[at + prefix.len()..];
            let name_end = rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len());
            if !rest[name_end..].starts_with('(') {
                continue;
            }
            let args = &rest[name_end + 1..];
            let first_end = args.find([',', ')']).unwrap_or(args.len());
            let first = args[..first_end].trim_start_matches('&');
            if first.starts_with("arg(") || tainted.contains(&first) {
                found.push(format!(
                    "{who} passes a request value to {prefix}{}( as a path",
                    &rest[..name_end]
                ));
            }
        }
    }
    found
}

/// Gate check for one agent arm / function body (squashed code): the
/// canonical `if let Err(response) = env.require_exclusive(id) { return
/// response; }` must be present at the outermost level of the body and come
/// before every `change` (audit EX-08). A discarded answer, a gate inside
/// `if false {..}`, a gate after the change, and the name inside a string
/// are all rejected.
pub fn check_gate(body: &str, change_markers: &[&str], base_depth: i32) -> Result<(), String> {
    let flat: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    // The two canonical forms: the proof-less one (kept for the evasion unit
    // tests) and the one that hands the proof on (final R7).
    const GATE: &str = "ifletErr(response)=env.require_exclusive(id){returnresponse;}";
    const GATE_PROOF: &str =
        "letproof=matchenv.require_exclusive(id){Ok(proof)=>proof,Err(response)=>returnresponse,};";
    let Some(gate_at) = flat.find(GATE).or_else(|| flat.find(GATE_PROOF)) else {
        return Err("no `if let Err(response) = env.require_exclusive(id) { return response; }` and \
                    no `let proof = match env.require_exclusive(id) { Ok(proof) => proof, Err(response) => return response }`"
            .into());
    };
    let depth_at = |position: usize| -> i32 {
        flat[..position]
            .chars()
            .map(|c| match c {
                '{' => 1,
                '}' => -1,
                _ => 0,
            })
            .sum()
    };
    if depth_at(gate_at) != base_depth {
        return Err(format!(
            "the gate is nested (depth {}, expected {base_depth}): it may never run",
            depth_at(gate_at)
        ));
    }
    for marker in change_markers {
        let flat_marker: String = marker.chars().filter(|c| !c.is_whitespace()).collect();
        let Some(change_at) = flat.find(&flat_marker) else {
            return Err(format!("{marker} not found in the body"));
        };
        if change_at < gate_at {
            return Err(format!("{marker} comes before the gate"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// unit tests of the checks: the evasion forms of the audit (ARCHITECTURE_REVIEW 8)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tops() -> BTreeSet<String> {
        [
            "daemon",
            "fencing",
            "linux_network",
            "command_service",
            "systemd_service",
            "tcp_runtime",
            "peer_dispatch",
            "heartbeat_runtime",
            "manual",
            "fencing_backend",
            "status",
            "cli",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn g1(module: &[&str], text: &str) -> Vec<String> {
        check_manual_file("manual/x.rs", &load(module, text), &tops())
    }

    const VIP: &[&str] = &["crate", "manual", "vip"];

    #[test]
    fn a_clean_manual_file_passes_g1() {
        assert!(g1(VIP, "use crate::manual::exec::run;\nuse std::fs;\nfn f() { crate::fencing_backend::check_executable_trust(p); }").is_empty());
        assert!(
            g1(
                VIP,
                "use super::lease::Lease; use super::super::manual::agent;"
            )
            .is_empty()
        );
    }

    #[test]
    fn g1_direct_violations_are_found() {
        for text in [
            "use crate::daemon::Foo;",
            "use crate::fencing::Foo;",
            "use crate::fencing_backend::CommandBackend;",
            "fn f() { crate::fencing_backend::CommandBackend::new(); }",
        ] {
            assert!(!g1(VIP, text).is_empty(), "{text}");
        }
    }

    #[test]
    fn g1_evasion_forms_of_the_audit_are_found() {
        for (name, text) in [
            ("grouped use", "use crate::{daemon, fencing};"),
            (
                "nested group with alias",
                "use crate::{manual::exec, linux_network as ln};",
            ),
            ("super::super", "use super::super::daemon::run;"),
            (
                "alias of the crate root",
                "use crate as c; fn f() { c::daemon::run(); }",
            ),
            ("blanks around ::", "fn f() { crate :: daemon :: run(); }"),
            (
                "line break in the path",
                "fn f() { crate::\n    daemon\n    ::run(); }",
            ),
            (
                "HA module not in any list: linux_network",
                "use crate::linux_network::Foo;",
            ),
            (
                "HA module not in any list: command_service",
                "use crate::command_service::Foo;",
            ),
            (
                "HA module not in any list: systemd_service",
                "use crate::systemd_service::Foo;",
            ),
            (
                "HA module not in any list: tcp_runtime",
                "use crate::tcp_runtime::Foo;",
            ),
            (
                "HA module not in any list: peer_dispatch",
                "use crate::peer_dispatch::Foo;",
            ),
            (
                "HA module not in any list: heartbeat_runtime",
                "use crate::heartbeat_runtime::Foo;",
            ),
            (
                "after a string with //",
                "fn f() { let s = \"//\"; crate::daemon::run(); }",
            ),
            (
                "after a string that says mod tests",
                "const _S: &str = \"mod tests\";\nfn f() { crate::daemon::run(); }",
            ),
            (
                "after a real test module",
                "#[cfg(test)]\nmod tests { fn t() {} }\nfn f() { crate::daemon::run(); }",
            ),
            (
                "after a raw string that looks like a comment",
                "const R: &str = r#\"/*\"#;\nuse crate::daemon::X;\nconst Q: &str = r#\"*/\"#;",
            ),
            ("path attribute", "#[path = \"../daemon.rs\"]\nmod d;"),
            (
                "path attribute in cfg_attr",
                "#[cfg_attr(unix, path = \"../daemon.rs\")]\nmod d;",
            ),
            ("include", "const S: &str = include_str!(\"../daemon.rs\");"),
            ("glob of the root", "use crate::*;"),
            (
                "alias of a super chain through another alias",
                "use super::super as root; use root::daemon::X;",
            ),
            (
                "prefix match of the sanctioned function",
                "fn f() { crate::fencing_backend::check_executable_trust_everything(); }",
            ),
            ("names a forbidden type", "fn f(x: ResourceExecutor) {}"),
        ] {
            assert!(
                !g1(VIP, text).is_empty(),
                "evasion not found: {name}: {text}"
            );
        }
    }

    #[test]
    fn g1_a_sanctioned_use_is_not_an_evasion_and_test_code_is_exempt() {
        assert!(
            g1(
                VIP,
                "#[cfg(test)]\nmod tests { use crate::daemon::X; }\nfn ok() {}"
            )
            .is_empty()
        );
        assert!(
            g1(
                VIP,
                "// crate::daemon::run()\n/* use crate::daemon::X; */\nfn ok() {}"
            )
            .is_empty()
        );
        assert!(g1(VIP, "const S: &str = \"crate::daemon::run()\";").is_empty());
        assert!(
            g1(
                &["crate", "manual", "sub", "deep"],
                "use super::super::exec::run;"
            )
            .is_empty()
        );
        assert!(
            !g1(
                &["crate", "manual", "sub", "deep"],
                "use super::super::super::daemon::X;"
            )
            .is_empty()
        );
    }

    fn g2(file: &str, text: &str) -> Vec<String> {
        let module: Vec<&str> = if file == "main" {
            vec!["crate"]
        } else {
            vec!["crate", file]
        };
        check_ha_file(file, &load(&module, text), &tops())
    }

    #[test]
    fn g2_the_ha_engine_cannot_name_the_plane_in_any_spelling() {
        for (name, text) in [
            ("plain", "use crate::manual::exec::run;"),
            ("call", "fn f() { crate::manual::run::agent(None); }"),
            (
                "group alias",
                "use crate::{manual as m}; fn f() { m::exec::run(); }",
            ),
            ("super alias", "use super::manual as m;"),
            ("blanks", "fn f() { crate :: manual :: exec :: run(); }"),
            ("path attribute", "#[path = \"manual/exec.rs\"]\nmod ex;"),
            (
                "after //",
                "fn f() { let s = \"//\"; crate::manual::vip::x(); }",
            ),
            ("glob", "use crate::manual::*;"),
            (
                "root alias",
                "use crate as c; fn f() { c::manual::run::agent(None); }",
            ),
        ] {
            assert!(
                !g2("daemon", text).is_empty(),
                "evasion not found: {name}: {text}"
            );
        }
        assert!(
            g2(
                "daemon",
                "use crate::fencing::Foo; fn f() { manual_like(); }"
            )
            .is_empty()
        );
        assert!(g2("daemon", "// crate::manual::exec\nfn f() {}").is_empty());
    }

    fn g3(file: &str, text: &str) -> Vec<String> {
        let module: Vec<&str> = if file == "main" {
            vec!["crate"]
        } else {
            vec!["crate", file]
        };
        check_wiring_file(file, &load(&module, text), &tops())
    }

    #[test]
    fn g3_wiring_uses_exactly_the_entry_points() {
        assert!(g3("main", "fn m() { manual::run::resource(c); manual::run::chronyd(c); manual::run::agent(c); }").is_empty());
        assert!(
            g3(
                "cli",
                "use crate::manual::cli_def::{ChronydCommands, ResourceCommands};"
            )
            .is_empty()
        );
        assert!(g3("status", "fn s() { crate::manual::run::status_wanted(a, b); crate::manual::run::status_overview(&p); crate::manual::run::status_failure_exit(&f); }").is_empty());
        for (name, text) in [
            (
                "prefix: resource_force",
                "fn m() { manual::run::resource_force(); }",
            ),
            (
                "prefix: status_overview_and_move",
                "fn m() { crate::manual::run::status_overview_and_move(); }",
            ),
            (
                "anything under cli_def",
                "use crate::manual::cli_def::Anything;",
            ),
            ("module alias", "use crate::manual as m;"),
            ("blanks", "fn m() { manual :: vip :: move_vip(); }"),
            (
                "another module",
                "fn m() { crate::manual::vip::move_vip(); }",
            ),
            ("a glob", "use crate::manual::run::*;"),
        ] {
            assert!(
                !g3("main", text).is_empty(),
                "evasion not found: {name}: {text}"
            );
        }
    }

    fn g4(file: &str, text: &str) -> Vec<String> {
        check_spawn_file(
            file,
            &load(&["crate", "manual", "x"], text),
            &tops(),
            file == "exec.rs",
        )
    }

    #[test]
    fn g4_direct_and_disguised_process_starts_are_found() {
        for (name, text) in [
            ("direct", "fn f() { std::process::Command::new(p); }"),
            ("blanks", "fn f() { std :: process :: Command :: new(p); }"),
            ("leading ::", "fn f() { ::std::process::Command::new(p); }"),
            (
                "alias",
                "use std::process::{Command as C}; fn f() { C::new(p); }",
            ),
            (
                "module alias",
                "use std::process; fn f() { process::Command::new(p); }",
            ),
            ("spawn", "fn f(c: X) { c.spawn(); }"),
            ("output", "fn f(c: X) { c.output(); }"),
            ("exec", "fn f(c: X) { c.exec(); }"),
            (
                "sh -c",
                "const A: &str = \"/bin/sh\"; const B: &str = \"-c\";",
            ),
            (
                "usr/bin/sh -lc",
                "const A: &str = \"/usr/bin/sh\"; const B: &str = \"-lc\";",
            ),
            ("dash", "const A: &str = \"/bin/dash\";"),
            ("bash", "const A: &str = \"bash\";"),
            ("env as a launcher", "const A: &str = \"/usr/bin/env\";"),
            ("libc execv", "fn f() { unsafe { libc::execv(p, a); } }"),
            ("libc posix_spawn", "use libc::posix_spawn; fn f() {}"),
            ("libc fork", "fn f() { unsafe { libc::fork(); } }"),
            ("libc system", "fn f() { unsafe { libc::system(c); } }"),
            (
                "host key checking off",
                "const A: &str = \"StrictHostKeyChecking no\";",
            ),
            (
                "host key checking off, =off",
                "const A: &str = \"StrictHostKeyChecking=off\";",
            ),
            (
                "host key checking lower",
                "const A: &str = \"stricthostkeychecking=no\";",
            ),
            (
                "known hosts /dev/null",
                "const A: &str = \"UserKnownHostsFile=/dev/null\";",
            ),
            (
                "global known hosts",
                "const A: &str = \"GlobalKnownHostsFile=/dev/null\";",
            ),
            ("proxy command", "const A: &str = \"ProxyCommand=nc x 22\";"),
            (
                "concatenation",
                "const A: &str = concat!(\"Strict\", \"HostKeyChecking=no\");",
            ),
            (
                "split literal",
                "fn f() { let a = \"StrictHostKeyChecking=\"; let b = \"no\"; }",
            ),
            (
                "after //",
                "fn f() { let s = \"//\"; std::process::Command::new(p); }",
            ),
        ] {
            assert!(
                !g4("vip.rs", text).is_empty(),
                "evasion not found: {name}: {text}"
            );
        }
    }

    #[test]
    fn g4_the_sanctioned_forms_pass() {
        assert!(
            g4(
                "exec.rs",
                "use std::process::{Command, Stdio}; fn f() { Command::new(p).spawn(); }"
            )
            .is_empty()
        );
        assert!(g4("remote.rs", "const A: &str = \"StrictHostKeyChecking=accept-new\"; const B: &str = \"UserKnownHostsFile={}\"; const C: &str = \"ProxyCommand=none\"; const D: &str = \"/dev/null\";").is_empty());
        assert!(
            g4(
                "vip.rs",
                "const A: &str = \"--format=json\"; const B: &str = \"-i\"; const C: &str = \"-o\";"
            )
            .is_empty()
        );
        assert!(g4("vip.rs", "fn f() { std::thread::spawn(g); }").is_empty());
    }

    #[test]
    fn g5_gate_evasions_are_found() {
        let good = "op::X=>{ if let Err(response) = env.require_exclusive(id) { return response; } env.sys.service_action(u, a); }";
        let body = |s: &str| load(&["crate", "manual", "agent"], s).code;
        assert!(check_gate(&body(good), &["service_action("], 1).is_ok());
        for (name, text) in [
            (
                "answer discarded",
                "op::X=>{ let _ = env.require_exclusive(id); env.sys.service_action(u, a); }",
            ),
            (
                "after the change",
                "op::X=>{ env.sys.service_action(u, a); if let Err(response) = env.require_exclusive(id) { return response; } }",
            ),
            (
                "dead code",
                "op::X=>{ if false { if let Err(response) = env.require_exclusive(id) { return response; } } env.sys.service_action(u, a); }",
            ),
            (
                "only in a string",
                "op::X=>{ let s = \"if let Err(response) = env.require_exclusive(id) { return response; }\"; env.sys.service_action(u, a); }",
            ),
            (
                "only in a comment",
                "op::X=>{ // if let Err(response) = env.require_exclusive(id) { return response; }\n env.sys.service_action(u, a); }",
            ),
            (
                "refusal ignored",
                "op::X=>{ if let Err(response) = env.require_exclusive(id) { log(response); } env.sys.service_action(u, a); }",
            ),
            (
                "missing change marker",
                "op::X=>{ if let Err(response) = env.require_exclusive(id) { return response; } }",
            ),
        ] {
            assert!(
                check_gate(&body(text), &["service_action("], 1).is_err(),
                "evasion not found: {name}"
            );
        }
    }

    // ---- round R6: the evasion forms of the second audit (RA-E-01 .. 06) ----

    #[test]
    fn r6_e01_extern_crate_self_macros_and_glob_forms_are_found() {
        // Each of these compiled in the auditors' check; each read as harmless
        // before round R6.
        for (name, text) in [
            (
                "extern crate self gives the root a second name",
                "extern crate self as c; fn f() { c::daemon::run(); }",
            ),
            (
                "a macro assembles the path from an argument",
                "macro_rules! p{($a:ident)=>{crate::$a::run()}}\nfn f() { p!(daemon); }",
            ),
            (
                "a macro with $crate",
                "macro_rules! q { () => { $crate::daemon::run() } }\nfn f() { q!(); }",
            ),
            (
                "a macro with a different bracket and a longer body",
                "macro_rules! r [ ($a:ident, $b:ident) => ( crate::$a::$b() ) ] fn f() { r!(daemon, run); }",
            ),
        ] {
            assert!(!g1(VIP, text).is_empty(), "G1: {name}");
            assert!(!g2("daemon", text).is_empty(), "G2: {name}");
            assert!(!g3("main", text).is_empty(), "G3: {name}");
        }
        // A glob of the crate root puts every top-level module in scope by its
        // bare name: the HA and wiring files reach the plane through it.
        let glob = "use crate::*; fn f() { manual::exec::run(); }";
        assert!(!g2("daemon", glob).is_empty(), "G2: glob + bare name");
        assert!(!g3("cli", glob).is_empty(), "G3: glob + bare name");
        assert!(!g1(VIP, glob).is_empty(), "G1: the glob itself");
        let super_glob = "use super::*; fn f() { manual::exec::run(); }";
        // `super::*` of a module directly below the root is the root.
        assert!(!g2("daemon", super_glob).is_empty(), "G2: super glob");
        // Harmless relatives stay clean.
        assert!(
            g1(
                VIP,
                "macro_rules! m { ($x:expr) => { $x + 1 } } fn f() { m!(1); }"
            )
            .is_empty()
        );
        assert!(
            g2(
                "daemon",
                "use crate::fencing::Foo; fn f() { fencing_like::x(); }"
            )
            .is_empty()
        );
        assert!(
            g1(
                VIP,
                "// extern crate self as c;\nconst S: &str = \"extern crate\";"
            )
            .is_empty()
        );
        let (macro_bodies, none) = (
            macro_rules_bodies(&squash(
                "macro_rules! a { ($x:expr) => { $x } } macro_rules! b { () => { crate::$y } }",
            )),
            macro_rules_bodies("fn f() {}"),
        );
        assert_eq!(macro_bodies.len(), 2);
        assert!(none.is_empty());
    }

    #[test]
    fn r6_e02_cfg_test_on_a_non_item_does_not_hide_the_code_after_it() {
        // The audit's forms: an attribute on a match arm, a call argument, an
        // enum variant, an array element, a struct field. The code after each
        // one used to disappear from the scan.
        for (name, text) in [
            (
                "match arm",
                "fn f(x: u8) { match x { 0 => 1, #[cfg(test)] 1 => 2, _ => { crate::daemon::run(); 3 } }; }",
            ),
            (
                "first match arm",
                "fn f(x: u8) { match x { #[cfg(test)] A => 1, _ => crate::daemon::run() } }",
            ),
            (
                "call argument",
                "fn f() { g(1, #[cfg(test)] 2, crate::daemon::run()); }",
            ),
            (
                "enum variant",
                "enum E { A, #[cfg(test)] B, C }\nfn g() { crate::daemon::run(); }",
            ),
            (
                "array element",
                "fn f() { let _ = [1, #[cfg(test)] 2, 3]; crate::daemon::run(); }",
            ),
            (
                "struct field",
                "struct S { a: u8, #[cfg(test)] b: u8, c: u8 }\nfn g() { crate::daemon::run(); }",
            ),
        ] {
            assert!(
                !g1(VIP, text).is_empty(),
                "code after a cfg(test) {name} is lost"
            );
        }
        // The item forms are still cut out.
        for text in [
            "#[cfg(test)]\nmod tests { fn t() { crate::daemon::run(); } }",
            "fn a() {}\n#[cfg(test)]\nfn t() { crate::daemon::run(); }",
            "impl X { #[cfg(test)] fn t() { crate::daemon::run(); } fn p() {} }",
            "fn a() { #[cfg(test)] { crate::daemon::run(); } let _ = 1; }",
            "fn a() { let _ = 1; #[cfg(test)] crate::daemon::run(); }",
            "use a::b;\n#[cfg(test)]\nuse crate::daemon::X;\nfn ok() {}",
            "#[cfg(test)]\n#[allow(dead_code)]\nfn t() { crate::daemon::run(); }",
        ] {
            assert!(
                g1(VIP, text).is_empty(),
                "a cfg(test) item is not cut out: {text}"
            );
        }
    }

    #[test]
    fn r6_e03_process_scans_proc_reads_and_syscall_numbers_are_found() {
        let used = |text: &str| markers_used(&load(&["crate", "manual", "vip"], text));
        assert!(used("fn f() { std::fs::read_dir(\"/proc\"); }").contains("read_dir(\"/proc\""));
        assert!(used("fn f() { let p = Path::new(\"/proc\"); }").contains("\"/proc\""));
        assert!(used("fn f() { exclusion::scan_proc(p, 1); }").contains("scan_proc("));
        assert!(used("fn f() { let p = \"/proc/self/exe\"; }").contains("/proc/"));
        assert!(used("fn f() { let p = \"/dev/null\"; }").is_empty());
        // The first argument of `libc::syscall` is checked, not only the name.
        assert_eq!(
            syscall_first_arguments(&squash(
                "fn f() { unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, a); } }"
            )),
            ["SYS_renameat2"]
        );
        assert_eq!(
            syscall_first_arguments(&squash(
                "use libc::syscall; fn f() { unsafe { syscall(59, p, a, e) } }"
            )),
            ["59"]
        );
        assert!(syscall_first_arguments(&squash("fn f() { my_syscall(1); }")).is_empty());
        let spawn = |file: &str, text: &str| {
            check_spawn_file(file, &load(&["crate", "manual", "x"], text), &tops(), false)
        };
        assert!(
            !spawn(
                "manual/vip.rs",
                "fn f() { unsafe { libc::syscall(libc::SYS_execve, p, a, e); } }"
            )
            .is_empty()
        );
        assert!(
            !spawn(
                "manual/vip.rs",
                "fn f() { unsafe { libc::syscall(libc::SYS_renameat2, a, b); } }"
            )
            .is_empty()
        );
        assert!(
            !spawn(
                "manual/fsutil.rs",
                "fn f() { unsafe { libc::syscall(libc::SYS_execve, p); } }"
            )
            .is_empty()
        );
        assert!(
            spawn(
                "manual/fsutil.rs",
                "fn f() { unsafe { libc::syscall(libc::SYS_renameat2, a, b); } }"
            )
            .is_empty()
        );
    }

    #[test]
    fn r6_e04_process_globs_extern_blocks_and_a_second_command_new_are_found() {
        for (name, text) in [
            (
                "glob of std::process",
                "use std::process::*; fn f() { let _ = Command::new(\"x\"); }",
            ),
            (
                "an extern block that declares system()",
                "unsafe extern \"C\" { fn system(c: *const i8) -> i32; }\nfn f() {}",
            ),
            (
                "an extern block without ABI",
                "extern { fn system(c: *const i8) -> i32; }",
            ),
            (
                "an extern block of the old form",
                "extern \"C\" { fn fork() -> i32; }",
            ),
        ] {
            assert!(!g4("vip.rs", text).is_empty(), "{name}");
        }
        // An `extern "C" fn` definition (a signal handler) declares nothing.
        assert!(g4("vip.rs", "extern \"C\" fn on_signal(_s: i32) {}\nfn f() {}").is_empty());
        assert_eq!(
            extern_blocks(&load(&["crate", "x"], "unsafe extern \"C\" { fn a(); }").code),
            1
        );
        assert_eq!(
            extern_blocks(&load(&["crate", "x"], "extern \"C\" fn a() {}").code),
            0
        );
        // Exactly one `Command::new(` in exec.rs.
        let exec = |text: &str| {
            check_spawn_file(
                "manual/exec.rs",
                &load(&["crate", "manual", "exec"], text),
                &tops(),
                true,
            )
        };
        assert!(
            exec("use std::process::Command; fn run() { Command::new(p).spawn(); }").is_empty()
        );
        assert!(!exec("use std::process::Command; fn run() { Command::new(p).spawn(); Command::new(q).spawn(); }").is_empty());
        assert!(!exec("fn run() {}").is_empty());
    }

    #[test]
    fn r6_e05_a_literal_match_arm_is_found() {
        let arms = |text: &str| literal_match_arms(&load(&["crate", "manual", "agent"], text).code);
        assert_eq!(
            arms("fn h(n: &str) { match n { op::PING => 1, _ => 2 } }"),
            0
        );
        assert_eq!(
            arms("fn h(n: &str) { match n { \"x.force\" => 1, _ => 2 } }"),
            1
        );
        assert_eq!(
            arms("fn h(n: &str) { match n { op::PING | \"x.force\" => 1, _ => 2 } }"),
            1
        );
        assert_eq!(
            arms("fn h(n: &str) { match n { \"a\" | \"b\" => 1, _ => 2 } }"),
            2
        );
        // Comparisons and calls are not arms.
        assert_eq!(
            arms("fn h(n: &str) { if n == \"a\" || n == \"b\" { f(\"c\"); } }"),
            0
        );
    }

    #[test]
    fn r6_e05_only_the_arms_of_the_named_match_count() {
        let arms = |text: &str, head: &str| {
            literal_arms_of_match(&load(&["crate", "manual", "agent"], text).code, head)
        };
        let head = "match request.op.as_str()";
        // The auditors' form, in the real dispatch shape.
        assert_eq!(
            arms(
                "fn d(r: &R) { match request.op.as_str() { op::PING => 1, \"x.force\" => 2, other => 3 } }",
                head
            ),
            1
        );
        assert_eq!(
            arms(
                "fn d(r: &R) { match request.op.as_str() { op::PING | \"x.force\" => 1, _ => 2 } }",
                head
            ),
            1
        );
        assert_eq!(
            arms(
                "fn d(r: &R) { match request.op.as_str() { \"a\" | \"b\" => 1, _ => 2 } }",
                head
            ),
            2
        );
        // A string pattern deeper down is not an arm of the dispatch.
        assert_eq!(
            arms(
                "fn d(r: &R) { match request.op.as_str() { op::PING => { if !matches!(action, \"start\" | \"stop\") { return; } match x { \"y\" => 1, _ => 2 } } _ => 3 } }",
                head
            ),
            0
        );
        // The arm of ANOTHER match before the head does not count.
        assert_eq!(
            arms(
                "fn d(r: &R) { match other { \"z\" => 1, _ => 2 } match request.op.as_str() { op::PING => 1, _ => 2 } }",
                head
            ),
            0
        );
    }

    #[test]
    fn r6_final_syscall_aliases_and_guard_arms_and_repeated_matches_are_found() {
        let code = |text: &str| load(&["crate", "manual", "fsutil"], text).code;
        // Direct calls are not "non-call" uses; an alias, a parenthesised
        // path and a function value are.
        assert_eq!(
            syscall_non_call_uses(&code(
                "fn f() { unsafe { libc::syscall(libc::SYS_renameat2, a); } }"
            )),
            0
        );
        assert_eq!(
            syscall_non_call_uses(&code(
                "use libc::syscall as sc; fn f() { unsafe { sc(59, p); } }"
            )),
            1
        );
        assert_eq!(
            syscall_non_call_uses(&code("fn f() { unsafe { (libc::syscall)(59, p); } }")),
            1
        );
        assert_eq!(
            syscall_non_call_uses(&code("fn f() { let g = libc::syscall; }")),
            1
        );
        assert_eq!(syscall_non_call_uses(&code("fn f() { my_syscall(1); }")), 0);
        // The guard form and a second match with the same head.
        let arms = |text: &str, head: &str| {
            literal_arms_of_match(&load(&["crate", "manual", "agent"], text).code, head)
        };
        assert_eq!(
            arms(
                "fn d() { match name { \"x.force\" if true => 1, _ => 2 } }",
                "match name"
            ),
            1
        );
        assert_eq!(
            arms(
                "fn d() { match name { op::A => 1, _ => 2 } match name { \"x.force\" => 1, _ => 2 } }",
                "match name"
            ),
            1
        );
    }

    #[test]
    fn r6_final_nested_arrow_arms_are_found_but_argument_alternatives_are_not() {
        let arrow =
            |text: &str| literal_arrow_arms(&load(&["crate", "manual", "agent"], text).code);
        assert_eq!(
            arrow("fn d() { match n { op::A => match o { \"x.force\" => 1, _ => 2 }, _ => 3 } }"),
            1
        );
        assert_eq!(
            arrow("fn d() { if !matches!(action, \"start\" | \"stop\") { return; } }"),
            0
        );
        assert_eq!(arrow("fn d() { f(\"a\"); let x = \"b\"; }"), 0);
    }

    #[test]
    fn r7_self_super_chains_are_resolved() {
        let refs = |text: &str| {
            let source = load(&["crate", "manual", "vip"], text);
            references(&source, &tops())
        };
        let found = refs("fn f() { let _ = self::super::super::config::Config::default; }");
        assert!(
            found
                .iter()
                .any(|p| p.starts_with(&["crate".to_string(), "config".to_string()])),
            "{found:?}"
        );
        let plain = refs("fn f() { let _ = self::helper(); }");
        assert!(
            !plain
                .iter()
                .any(|p| p.starts_with(&["crate".to_string(), "config".to_string()])),
            "{plain:?}"
        );
    }

    #[test]
    fn r6_e06_path_building_forms_and_request_values_as_paths_are_found() {
        let check = |text: &str| {
            check_path_building(
                "chrony_agent.rs",
                &load(&["crate", "manual", "chrony_agent"], text),
                &["stage_id", "backup_id"],
            )
        };
        for (name, text) in [
            (
                "Path::new of a variable",
                "fn f(a: &str) { let p = Path::new(&a); }",
            ),
            (
                "PathBuf::from",
                "fn f(a: &str) { let p = PathBuf::from(a); }",
            ),
            (
                "push of a request value",
                "fn f(a: &str) { let mut p = dir; p.push(arg(args, \"x\")?); }",
            ),
            ("set_file_name", "fn f() { p.set_file_name(name); }"),
            (
                "fs call with the request accessor",
                "fn f() { fs::remove_file(arg(args, \"p\")?); }",
            ),
            (
                "fs call with a request identifier",
                "fn f(stage_id: &str) { fs::remove_file(stage_id); }",
            ),
            (
                "fs call with a borrowed request identifier",
                "fn f(backup_id: &str) { fs::read(&backup_id); }",
            ),
            (
                "fsutil call with a request identifier",
                "fn f(stage_id: &str) { fsutil::write_new_durable(stage_id, b, 0o644); }",
            ),
            (
                "File::open with a request identifier",
                "fn f(stage_id: &str) { File::open(stage_id); }",
            ),
        ] {
            assert!(!check(text).is_empty(), "{name}");
        }
        // The reviewed forms stay clean.
        assert!(check("fn f() { fs::remove_file(&path); fs::read_dir(&dir); fsutil::exchange(staged, live); }").is_empty());
        assert!(check("fn f(stage_id: &str) { let p = dir.join(format!(\"{STAGE_PREFIX}{stage_id}.conf\")); fs::remove_file(&p); }").is_empty());
        assert!(check("fn g() { staged.with_file_name(format!(\"{PREFIX}{stem}\")); }").is_empty());
    }

    #[test]
    fn the_lexer_handles_comments_literals_and_lifetimes() {
        let (code, lits) = lex(
            "fn f<'a>(x: &'a str) { /* a /* nested */ b */ let c = 'x'; let d = '\\n'; let e = \"q\\\"uote\"; let r = r##\"a\"#b\"##; // tail\n let n = b\"by\"; }",
        );
        assert!(!code.contains("nested") && !code.contains("tail"));
        assert!(code.contains("'a"), "lifetimes survive: {code}");
        assert_eq!(lits, ["q\\\"uote", "a\"#b", "by"]);
        // a string with a brace cannot unbalance anything
        let src = load(
            &["crate", "x"],
            "fn f() { let s = \"}\"; }\nfn g() { crate::daemon::x(); }",
        );
        assert!(src.code.contains("crate::daemon::x"));
    }

    #[test]
    fn use_trees_are_expanded() {
        let items = use_items(&squash(
            "use a::b::{self, c as d, e::{f, g::*}}; use ::h::i; use j as _;",
        ));
        let flat: Vec<String> = items
            .iter()
            .map(|i| {
                format!(
                    "{}{}{}",
                    i.path.join("::"),
                    if i.glob { "::*" } else { "" },
                    i.alias
                        .as_ref()
                        .map_or(String::new(), |a| format!(" as {a}"))
                )
            })
            .collect();
        assert_eq!(
            flat,
            [
                "a::b",
                "a::b::c as d",
                "a::b::e::f",
                "a::b::e::g::*",
                "h::i",
                "j as _"
            ]
        );
    }

    #[test]
    fn test_items_are_cut_out_by_brackets_not_by_the_word() {
        let s = squash(
            "fn a() {}\n#[cfg(test)]\nmod tests { fn t() { let x = (1, [2]); } }\nfn b() { crate::daemon::x(); }\n#[cfg(test)]\nfn only_test() {}\n#[cfg(not(test))]\nfn kept() {}",
        );
        let cut = drop_test_items(&s);
        assert!(cut.contains("fn a()") && cut.contains("fn b()") && cut.contains("fn kept()"));
        assert!(!cut.contains("mod tests") && !cut.contains("only_test"));
    }

    #[test]
    fn module_paths_follow_the_file_layout() {
        let src = Path::new("/x/src");
        assert_eq!(module_of(src, Path::new("/x/src/main.rs")), ["crate"]);
        assert_eq!(
            module_of(src, Path::new("/x/src/status.rs")),
            ["crate", "status"]
        );
        assert_eq!(
            module_of(src, Path::new("/x/src/manual/mod.rs")),
            ["crate", "manual"]
        );
        assert_eq!(
            module_of(src, Path::new("/x/src/manual/vip.rs")),
            ["crate", "manual", "vip"]
        );
        assert_eq!(
            module_of(src, Path::new("/x/src/manual/sub/deep.rs")),
            ["crate", "manual", "sub", "deep"]
        );
    }

    #[test]
    fn walking_finds_files_in_sub_directories() {
        let base = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!("mkg-scan-walk-{}", std::process::id()));
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("top.rs"), "").unwrap();
        fs::write(dir.join("a/b/deep.rs"), "").unwrap();
        fs::write(dir.join("a/readme.md"), "").unwrap();
        let names: Vec<String> = walk_rs(&dir)
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().to_string_lossy().into_owned())
            .collect();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(names, ["a/b/deep.rs", "top.rs"]);
    }
}
