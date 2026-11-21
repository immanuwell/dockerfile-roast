//! Static evaluation of the image configuration a Dockerfile build produces.
//!
//! Works over the instructions `parse_document` produces. FROM, ARG, ENV, LABEL,
//! EXPOSE, WORKDIR, USER, CMD, ENTRYPOINT and SHELL shape the result; every other
//! instruction is skipped. A FROM operand equal to an earlier stage's lowercased
//! name continues from that stage's final configuration and variables, and any
//! other operand starts a fresh stage, recorded in `base_image` unless it is
//! `scratch`. An unknown target and a file without stages are the only errors.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::iter::Peekable;
use std::str::Chars;

use crate::parser::{Dockerfile, Instruction, InstructionForm, Word};

/// The `PATH` BuildKit gives a stage built `FROM scratch`.
const SCRATCH_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvalOptions {
    /// `--build-arg` values; later duplicates win.
    pub build_args: Vec<(String, String)>,
    /// Stage name to build; defaults to the last stage.
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageConfig {
    pub env: Vec<(String, String)>,
    pub workdir: String,
    pub user: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub shell: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub exposed_ports: Vec<String>,
    /// Expanded external image the stage chain starts from; `None` for `scratch`.
    pub base_image: Option<String>,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            env: Vec::new(),
            workdir: "/".to_string(),
            user: None,
            cmd: None,
            entrypoint: None,
            shell: vec!["/bin/sh".to_string(), "-c".to_string()],
            labels: Vec::new(),
            exposed_ports: Vec::new(),
            base_image: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    UnknownTarget(String),
    NoStages,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTarget(target) => write!(f, "target stage {target:?} could not be found"),
            Self::NoStages => write!(f, "Dockerfile contains no FROM instruction"),
        }
    }
}

impl std::error::Error for EvalError {}

/// Variables visible to expansion: valued ARGs and ENVs, latest assignment wins.
type Vars = HashMap<String, String>;

/// The config being built, with indexes so that an update never scans what
/// the config already holds.
struct Image {
    config: ImageConfig,
    env_index: HashMap<String, usize>,
    label_index: HashMap<String, usize>,
    ports: HashSet<String>,
    /// Whether `config.workdir` is lexically resolved (an absolute WORKDIR is kept as written).
    workdir_clean: bool,
}

impl Image {
    fn new(config: ImageConfig) -> Self {
        Self {
            env_index: index(&config.env),
            label_index: index(&config.labels),
            ports: config.exposed_ports.iter().cloned().collect(),
            workdir_clean: false,
            config,
        }
    }
}

struct Stage<'a> {
    from: &'a Instruction,
    /// `AS` name, lowercased as BuildKit does when the stage is declared.
    name: Option<String>,
    body: &'a [Instruction],
}

struct Context<'a> {
    escape: char,
    build_args: HashMap<&'a str, &'a str>,
}

pub fn evaluate(dockerfile: &Dockerfile, options: &EvalOptions) -> Result<ImageConfig, EvalError> {
    let instructions = &dockerfile.instructions;
    let from_indices: Vec<usize> = instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| instruction.instruction == "FROM")
        .map(|(index, _)| index)
        .collect();
    let Some(&first_from) = from_indices.first() else {
        return Err(EvalError::NoStages);
    };

    let stages: Vec<Stage<'_>> = from_indices
        .iter()
        .enumerate()
        .map(|(position, &start)| {
            let end = from_indices
                .get(position + 1)
                .copied()
                .unwrap_or(instructions.len());
            let from = &instructions[start];
            let words = arguments(from);
            let name = (words.len() >= 3 && words[1].value.eq_ignore_ascii_case("as"))
                .then(|| words[2].value.to_ascii_lowercase());
            Stage {
                from,
                name,
                body: &instructions[start + 1..end],
            }
        })
        .collect();

    let context = Context {
        escape: dockerfile.escape,
        build_args: options
            .build_args
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect(),
    };
    let mut globals = Vars::new();
    for instruction in &instructions[..first_from] {
        if instruction.instruction == "ARG" {
            context.apply_args(instruction, &mut globals, &Vars::new());
        }
    }

    // The first stage of each name: the one a target or FROM operand refers to.
    let mut first_named: HashMap<&str, usize> = HashMap::new();
    for (position, stage) in stages.iter().enumerate() {
        if let Some(name) = &stage.name {
            first_named.entry(name).or_insert(position);
        }
    }
    let target = match options.target.as_ref().filter(|name| !name.is_empty()) {
        Some(target) => *first_named
            .get(target.to_ascii_lowercase().as_str())
            .ok_or_else(|| EvalError::UnknownTarget(target.clone()))?,
        None => stages.len() - 1,
    };

    let mut chain = vec![target];
    let (config, mut vars) = loop {
        let current = chain[chain.len() - 1];
        let base = arguments(stages[current].from)
            .first()
            .map(|word| context.expand(&word.raw, &globals))
            .unwrap_or_default();
        match first_named.get(base.as_str()) {
            Some(&parent) if parent < current => chain.push(parent),
            _ if base == "scratch" => {
                let config = ImageConfig {
                    env: vec![("PATH".to_string(), SCRATCH_PATH.to_string())],
                    ..ImageConfig::default()
                };
                break (
                    config,
                    Vars::from([("PATH".to_string(), SCRATCH_PATH.to_string())]),
                );
            }
            _ => {
                let config = ImageConfig {
                    base_image: Some(base),
                    ..ImageConfig::default()
                };
                break (config, Vars::new());
            }
        }
    };
    let mut image = Image::new(config);
    for &index in chain.iter().rev() {
        context.run_stage(stages[index].body, &mut image, &mut vars, &globals);
    }
    Ok(image.config)
}

impl Context<'_> {
    fn expand(&self, text: &str, vars: &Vars) -> String {
        let resolve = |name: &str| vars.get(name).cloned();
        Expander {
            chars: text.chars().peekable(),
            escape: self.escape,
            lookup: &resolve,
        }
        .word(None)
    }

    /// Applies an ARG line left to right: each name gets the build arg, else its
    /// expanded default, else (for a bare redeclaration) the value in `fallback`.
    fn apply_args(&self, instruction: &Instruction, vars: &mut Vars, fallback: &Vars) {
        for word in arguments(instruction) {
            let (name, default) = split_assignment(&word.raw);
            let value = match (self.build_args.get(name), default) {
                (Some(value), _) => value.to_string(),
                (None, Some(default)) => self.expand(default, vars),
                (None, None) => match fallback.get(name) {
                    Some(value) => value.clone(),
                    None => continue,
                },
            };
            vars.insert(name.to_string(), value);
        }
    }

    /// Expanded ENV/LABEL pairs; every value sees the variables from before the line.
    fn pairs(&self, instruction: &Instruction, vars: &Vars) -> Vec<(String, String)> {
        key_value_pairs(instruction)
            .into_iter()
            .map(|(key, value)| (self.expand(key, vars), self.expand(value, vars)))
            .collect()
    }

    /// Runs one stage's instructions.
    fn run_stage(&self, body: &[Instruction], image: &mut Image, vars: &mut Vars, globals: &Vars) {
        let config = &mut image.config;
        // CMD and ENTRYPOINT are built once, at the end, from the shell in effect at
        // their line. `cmd` is None while the stage leaves the inherited CMD alone.
        let inherited_shell = std::mem::take(&mut config.shell);
        let mut shell: &[String] = &inherited_shell;
        let mut shell_replaced = false;
        let mut cmd = None;
        let mut entrypoint = None;
        let mut cmd_set = false;
        for instruction in body {
            match instruction.instruction.as_str() {
                "ARG" => self.apply_args(instruction, vars, globals),
                "ENV" => {
                    for (key, value) in self.pairs(instruction, vars) {
                        vars.insert(key.clone(), value.clone());
                        upsert(&mut config.env, &mut image.env_index, key, value);
                    }
                }
                "LABEL" => {
                    for (key, value) in self.pairs(instruction, vars) {
                        upsert(&mut config.labels, &mut image.label_index, key, value);
                    }
                }
                "WORKDIR" => {
                    let path = self.expand(&instruction.command, vars);
                    if path.starts_with('/') {
                        config.workdir = path;
                        image.workdir_clean = false;
                    } else {
                        if !image.workdir_clean {
                            config.workdir = clean_path(&config.workdir);
                            image.workdir_clean = true;
                        }
                        join_path(&mut config.workdir, &path);
                    }
                }
                "USER" => config.user = Some(self.expand(&instruction.command, vars)),
                "EXPOSE" => {
                    for word in arguments(instruction) {
                        let expanded = self.expand(&word.raw, vars);
                        for port in expanded.split_whitespace().flat_map(exposed_ports) {
                            if !image.ports.contains(&port) {
                                image.ports.insert(port.clone());
                                config.exposed_ports.push(port);
                            }
                        }
                    }
                }
                "SHELL" => {
                    if let InstructionForm::Json(json) = &instruction.form {
                        shell = json;
                        shell_replaced = true;
                    }
                }
                "CMD" => {
                    cmd = Some(Some((instruction, shell)));
                    cmd_set = true;
                }
                "ENTRYPOINT" => {
                    entrypoint = Some((instruction, shell));
                    if !cmd_set {
                        cmd = Some(None);
                    }
                }
                _ => {}
            }
        }
        if let Some(cmd) = cmd {
            config.cmd = cmd.map(|(instruction, shell)| command_line(instruction, shell));
        }
        if let Some((instruction, shell)) = entrypoint {
            config.entrypoint = Some(command_line(instruction, shell));
        }
        config.shell = if shell_replaced {
            shell.to_vec()
        } else {
            inherited_shell
        };
    }
}

/// Words following any leading `--flag` options.
fn arguments(instruction: &Instruction) -> &[Word] {
    &instruction.words[instruction.flags.len().min(instruction.words.len())..]
}

fn split_assignment(raw: &str) -> (&str, Option<&str>) {
    match raw.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (raw, None),
    }
}

/// Raw `key=value` pairs of ENV/LABEL, or the legacy `KEY value with spaces`
/// form whose value is the rest of the line.
fn key_value_pairs(instruction: &Instruction) -> Vec<(&str, &str)> {
    let words = arguments(instruction);
    if words.first().is_some_and(|word| !word.raw.contains('=')) {
        return instruction
            .command
            .split_once(char::is_whitespace)
            .map(|(key, value)| vec![(key, value.trim_start())])
            .unwrap_or_default();
    }
    words
        .iter()
        .filter_map(|word| word.raw.split_once('='))
        .collect()
}

/// One EXPOSE operand as `port/protocol` entries: the protocol defaults to
/// `tcp` and is lowercased, and a `lo-hi` range yields one entry per port.
fn exposed_ports(spec: &str) -> Vec<String> {
    if spec.is_empty() {
        return Vec::new();
    }
    let (ports, protocol) = match spec.split_once('/') {
        Some((ports, protocol)) if !protocol.is_empty() => (ports, protocol.to_ascii_lowercase()),
        Some((ports, _)) => (ports, "tcp".to_string()),
        None => (spec, "tcp".to_string()),
    };
    let range = ports
        .split_once('-')
        .and_then(|(low, high)| Some((low.parse::<u16>().ok()?, high.parse::<u16>().ok()?)));
    match range {
        Some((low, high)) => (low..=high)
            .map(|port| format!("{port}/{protocol}"))
            .collect(),
        None => match ports.parse::<u16>() {
            Ok(port) => vec![format!("{port}/{protocol}")],
            Err(_) => vec![format!("{ports}/{protocol}")],
        },
    }
}

fn command_line(instruction: &Instruction, shell: &[String]) -> Vec<String> {
    match &instruction.form {
        InstructionForm::Json(arguments) => arguments.clone(),
        _ => {
            let mut line = shell.to_vec();
            line.push(instruction.logical_arguments.trim().to_string());
            line
        }
    }
}

/// Position of each key in an ordered list of pairs.
fn index(entries: &[(String, String)]) -> HashMap<String, usize> {
    entries
        .iter()
        .enumerate()
        .map(|(position, (key, _))| (key.clone(), position))
        .collect()
}

/// Sets `key` in an ordered list of pairs: a new key is appended, an existing
/// one keeps its position.
fn upsert(
    entries: &mut Vec<(String, String)>,
    index: &mut HashMap<String, usize>,
    key: String,
    value: String,
) {
    match index.entry(key) {
        Entry::Occupied(slot) => entries[*slot.get()].1 = value,
        Entry::Vacant(slot) => {
            entries.push((slot.key().clone(), value));
            slot.insert(entries.len() - 1);
        }
    }
}

/// Lexically resolves `.`, `..` and repeated or trailing `/` in an absolute path.
fn clean_path(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Joins a relative path onto a resolved absolute one, resolving `.`, `..` and
/// repeated or trailing `/` of the relative part as it goes.
fn join_path(workdir: &mut String, relative: &str) {
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => workdir.truncate(workdir.rfind('/').unwrap_or(0).max(1)),
            part => {
                if workdir.len() > 1 {
                    workdir.push('/');
                }
                workdir.push_str(part);
            }
        }
    }
}

/// Word expansion after BuildKit's: quote removal, escapes and the `$V`,
/// `${V}`, `${V:-w}`, `${V-w}`, `${V:+w}` and `${V+w}` forms. Other modifiers
/// (`${V#w}`, `${V%w}`, `${V/a/b}`, `${V:?w}`, ...) give the plain value.
struct Expander<'a, F> {
    chars: Peekable<Chars<'a>>,
    escape: char,
    lookup: &'a F,
}

impl<F: Fn(&str) -> Option<String>> Expander<'_, F> {
    fn word(&mut self, stop: Option<char>) -> String {
        let mut result = String::new();
        while let Some(character) = self.chars.next() {
            match character {
                _ if Some(character) == stop => break,
                '\'' => result.extend(self.chars.by_ref().take_while(|&c| c != '\'')),
                '"' => self.double_quoted(&mut result),
                '$' => result.push_str(&self.variable()),
                _ if character == self.escape => result.extend(self.chars.next()),
                _ => result.push(character),
            }
        }
        result
    }

    fn double_quoted(&mut self, result: &mut String) {
        while let Some(character) = self.chars.next() {
            match character {
                '"' => return,
                '$' => result.push_str(&self.variable()),
                _ if character == self.escape => match self.chars.peek() {
                    Some(&next) if next == '"' || next == '$' || next == self.escape => {
                        result.push(next);
                        self.chars.next();
                    }
                    Some(_) => result.push(character),
                    None => {}
                },
                _ => result.push(character),
            }
        }
    }

    fn variable(&mut self) -> String {
        let braced = self.chars.next_if_eq(&'{').is_some();
        if !braced {
            // BuildKit: `$1x` names `1`; special parameters (`$$`, `$@`, ...) are one character.
            if let Some(first) = self.chars.next_if(|c| "@*#?-$!".contains(*c)) {
                return (self.lookup)(&first.to_string()).unwrap_or_default();
            }
            if self.chars.peek().is_some_and(char::is_ascii_digit) {
                let mut digits = String::new();
                while let Some(digit) = self.chars.next_if(char::is_ascii_digit) {
                    digits.push(digit);
                }
                return (self.lookup)(&digits).unwrap_or_default();
            }
        }
        let mut name = String::new();
        while let Some(character) = self
            .chars
            .next_if(|c| c.is_ascii_alphanumeric() || *c == '_')
        {
            name.push(character);
        }
        if !braced {
            if name.is_empty() {
                return "$".to_string();
            }
            return (self.lookup)(&name).unwrap_or_default();
        }

        let value = (self.lookup)(&name);
        let colon = self.chars.next_if_eq(&':').is_some();
        let set = value
            .as_deref()
            .is_some_and(|value| !colon || !value.is_empty());
        match self.chars.next() {
            Some('-') => {
                let word = self.word(Some('}'));
                if set {
                    value.unwrap_or_default()
                } else {
                    word
                }
            }
            Some('+') => {
                let word = self.word(Some('}'));
                if set {
                    word
                } else {
                    String::new()
                }
            }
            Some('}') | None => value.unwrap_or_default(),
            Some(_) => {
                self.word(Some('}'));
                value.unwrap_or_default()
            }
        }
    }
}
