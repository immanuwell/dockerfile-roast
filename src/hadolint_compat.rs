//! Runtime compatibility layer for replacing a Hadolint CLI invocation.

use crate::linter::{self, LintOptions};
use crate::repository::ContainerEngine;
use crate::rules::{self, Finding, Severity};
use crate::shellcheck;
use anyhow::{bail, Context};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct CliOptions {
    pub files: Vec<PathBuf>,
    pub config: Option<PathBuf>,
    pub format: Option<String>,
    pub outputs: Vec<PathBuf>,
    pub file_path_in_report: Option<PathBuf>,
    pub no_fail: bool,
    pub no_color: bool,
    pub verbose: bool,
    pub error: Vec<String>,
    pub warning: Vec<String>,
    pub info: Vec<String>,
    pub style: Vec<String>,
    pub ignore: Vec<String>,
    pub trusted_registries: Vec<String>,
    pub required_labels: Vec<String>,
    pub strict_labels: bool,
    pub disable_ignore_pragma: bool,
    pub failure_threshold: Option<String>,
    pub report: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HSeverity {
    Ignore,
    Style,
    Info,
    Warning,
    Error,
}

impl HSeverity {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ignore" => Ok(Self::Ignore),
            "style" => Ok(Self::Style),
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            _ => bail!("Invalid Hadolint severity '{value}'; expected error, warning, info, style, ignore, or none"),
        }
    }
    fn text(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Style => "style",
            Self::Ignore => "ignore",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Threshold {
    Severity(HSeverity),
    None,
}

impl Threshold {
    fn parse(value: &str) -> anyhow::Result<Self> {
        if value.eq_ignore_ascii_case("none") {
            Ok(Self::None)
        } else {
            Ok(Self::Severity(HSeverity::parse(value)?))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Tty,
    Json,
    Checkstyle,
    CodeClimate,
    GitLab,
    Gnu,
    Codacy,
    SonarQube,
    Sarif,
    JUnit,
}

impl Format {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tty" | "terminal" => Ok(Self::Tty),
            "json" => Ok(Self::Json),
            "checkstyle" => Ok(Self::Checkstyle),
            "codeclimate" => Ok(Self::CodeClimate),
            "gitlab_codeclimate" | "gitlab-codeclimate" => Ok(Self::GitLab),
            "gnu" => Ok(Self::Gnu),
            "codacy" => Ok(Self::Codacy),
            "sonarqube" => Ok(Self::SonarQube),
            "sarif" => Ok(Self::Sarif),
            "junit" => Ok(Self::JUnit),
            _ => bail!("Unknown Hadolint format '{value}'"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Tty => "tty",
            Self::Json => "json",
            Self::Checkstyle => "checkstyle",
            Self::CodeClimate => "codeclimate",
            Self::GitLab => "gitlab_codeclimate",
            Self::Gnu => "gnu",
            Self::Codacy => "codacy",
            Self::SonarQube => "sonarqube",
            Self::Sarif => "sarif",
            Self::JUnit => "junit",
        }
    }
}

#[derive(Default)]
struct Settings {
    formats: Vec<Format>,
    ignored: BTreeSet<String>,
    overrides: BTreeMap<String, HSeverity>,
    registries: Vec<String>,
    labels: BTreeMap<String, String>,
    strict_labels: bool,
    disable_ignore: bool,
    no_fail: bool,
    no_color: bool,
    verbose: bool,
    threshold: Option<Threshold>,
    warnings: BTreeSet<String>,
    config_path: Option<PathBuf>,
}

#[derive(Clone)]
struct CompatFinding {
    file: String,
    rule: String,
    severity: HSeverity,
    line: usize,
    column: usize,
    message: String,
}

pub fn run(cli: CliOptions) -> anyhow::Result<i32> {
    if cli.report {
        print_report();
        return Ok(0);
    }
    let mut settings = load_settings(cli.config.as_deref())?;
    apply_environment(&mut settings)?;
    apply_cli(&mut settings, &cli)?;
    if settings.formats.is_empty() {
        settings.formats.push(Format::Tty);
    }
    report_warnings(&settings);
    if settings.verbose {
        eprintln!(
            "Hadolint compatibility: config={}, formats={}, ignored={}, overrides={}",
            settings
                .config_path
                .as_ref()
                .map_or("<none>".into(), |p| p.display().to_string()),
            settings
                .formats
                .iter()
                .map(|f| f.name())
                .collect::<Vec<_>>()
                .join(","),
            settings.ignored.len(),
            settings.overrides.len()
        );
    }

    let mapped_df = all_mapped_df();
    let skip_rules = rules::all_rules()
        .into_iter()
        .filter(|r| !mapped_df.contains(r.id))
        .map(|r| r.id.to_string())
        .collect();
    let opts = LintOptions {
        skip_rules,
        check_dockerignore: false,
        engine: ContainerEngine::Docker,
        approved_registries: (!settings.registries.is_empty())
            .then_some(settings.registries.clone()),
        required_labels: settings.labels.clone(),
        strict_labels: settings.strict_labels,
        inline_suppressions: false,
        shellcheck_mode: shellcheck::Mode::Auto,
        ..LintOptions::default()
    };
    let files = if cli.files.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        cli.files.clone()
    };
    let mut findings = Vec::new();
    let mut blocking = false;
    for path in files {
        if path != Path::new("-") && path.is_dir() {
            bail!(
                "Hadolint compatibility expects Dockerfile paths, not directory '{}'",
                path.display()
            );
        }
        let (source, actual_name) = read_source(&path)?;
        let mut result = linter::lint_content(&source, &actual_name, &opts).findings;
        // Hadolint stops at a Dockerfile parse error rather than running rules
        // over the recovered AST. Match that behavior and avoid duplicate
        // DL3061/DL1000 diagnostics for an invalid first instruction.
        if result.iter().any(|finding| finding.rule == "DF071") {
            result.retain(|finding| finding.rule == "DF071");
        }
        if !settings.disable_ignore {
            apply_hadolint_pragmas(&source, &mut result);
        }
        for finding in result {
            let rule = compatible_id(&finding);
            let configured_id = if rule.starts_with("DL") {
                rule.as_str()
            } else {
                finding.rule.as_str()
            };
            if is_ignored(&settings, configured_id, &finding.rule) {
                continue;
            }
            let severity = configured_severity(&settings, configured_id, &finding.rule)
                .unwrap_or_else(|| default_hseverity(&rule, finding.severity));
            if severity == HSeverity::Ignore {
                continue;
            }
            match settings
                .threshold
                .unwrap_or(Threshold::Severity(HSeverity::Info))
            {
                Threshold::Severity(threshold) if severity >= threshold => blocking = true,
                Threshold::Severity(_) | Threshold::None => {}
            }
            findings.push(CompatFinding {
                file: actual_name.clone(),
                rule,
                severity,
                line: finding.line,
                column: finding.column.max(1),
                message: finding.message,
            });
        }
    }
    let output_count = settings.formats.len().max(cli.outputs.len()).max(1);
    for index in 0..output_count {
        let format = settings.formats.get(index).copied().unwrap_or(Format::Tty);
        let report_findings = if uses_report_path(format) {
            cli.file_path_in_report.as_ref().map(|path| {
                let mut report_findings = findings.clone();
                let path = path.display().to_string();
                for finding in &mut report_findings {
                    finding.file.clone_from(&path);
                }
                report_findings
            })
        } else {
            None
        };
        let format_findings = report_findings.as_deref().unwrap_or(&findings);
        let rendered = render(format, format_findings, settings.no_color)?;
        if let Some(path) = cli.outputs.get(index) {
            std::fs::write(path, rendered.as_bytes())
                .with_context(|| format!("Failed to write Hadolint output '{}'", path.display()))?;
        } else {
            std::io::stdout().write_all(rendered.as_bytes())?;
        }
    }
    Ok(if blocking && !settings.no_fail { 1 } else { 0 })
}

fn uses_report_path(format: Format) -> bool {
    matches!(
        format,
        Format::Checkstyle
            | Format::CodeClimate
            | Format::GitLab
            | Format::SonarQube
            | Format::JUnit
    )
}

fn read_source(path: &Path) -> anyhow::Result<(String, String)> {
    if path == Path::new("-") {
        let mut source = String::new();
        std::io::stdin().read_to_string(&mut source)?;
        Ok((source, "-".into()))
    } else {
        Ok((
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read '{}'", path.display()))?,
            path.display().to_string(),
        ))
    }
}

fn load_settings(explicit: Option<&Path>) -> anyhow::Result<Settings> {
    let path = explicit.map(Path::to_path_buf).or_else(discover_config);
    let Some(path) = path else {
        return Ok(Settings::default());
    };
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read Hadolint config '{}'", path.display()))?;
    let value: Value = serde_yaml::from_str(&source)
        .with_context(|| format!("Invalid Hadolint YAML config '{}'", path.display()))?;
    let map = value.as_mapping().ok_or_else(|| {
        anyhow::anyhow!(
            "Hadolint config '{}' must be a YAML mapping",
            path.display()
        )
    })?;
    let mut s = Settings {
        config_path: Some(path),
        ..Settings::default()
    };
    for v in strings(map, "ignored")? {
        s.ignored.insert(norm(&v));
    }
    if let Some(overrides) = get(map, "override") {
        let overrides = overrides
            .as_mapping()
            .ok_or_else(|| anyhow::anyhow!("Hadolint 'override' must be a mapping"))?;
        for (name, sev) in [
            ("error", HSeverity::Error),
            ("warning", HSeverity::Warning),
            ("info", HSeverity::Info),
            ("style", HSeverity::Style),
        ] {
            for v in strings(overrides, name)? {
                s.overrides.insert(norm(&v), sev);
            }
        }
    }
    s.registries = strings(map, "trustedRegistries")?;
    s.labels = string_map(map, "label-schema")?;
    set_bool(map, "strict-labels", &mut s.strict_labels)?;
    set_bool(map, "disable-ignore-pragma", &mut s.disable_ignore)?;
    set_bool(map, "no-fail", &mut s.no_fail)?;
    set_bool(map, "no-color", &mut s.no_color)?;
    set_bool(map, "verbose", &mut s.verbose)?;
    if let Some(v) = get(map, "failure-threshold").and_then(Value::as_str) {
        s.threshold = Some(Threshold::parse(v)?);
    }
    if let Some(v) = get(map, "format").and_then(Value::as_str) {
        s.formats.push(Format::parse(v)?);
    }
    for v in strings(map, "formats")? {
        s.formats.push(Format::parse(&v)?);
    }
    for key in map.keys().filter_map(Value::as_str) {
        if !matches!(
            key,
            "ignored"
                | "override"
                | "trustedRegistries"
                | "label-schema"
                | "strict-labels"
                | "disable-ignore-pragma"
                | "no-fail"
                | "no-color"
                | "verbose"
                | "failure-threshold"
                | "format"
                | "formats"
        ) {
            s.warnings
                .insert(format!("unmatched Hadolint setting '{key}'"));
        }
    }
    note_rule_coverage(&mut s);
    Ok(s)
}

fn discover_config() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let mut candidates = vec![cwd.join(".hadolint.yaml"), cwd.join(".hadolint.yml")];
    if let Some(x) = xdg {
        candidates.extend([x.join("hadolint.yaml"), x.join("hadolint.yml")]);
    }
    if let Some(h) = home {
        candidates.extend([
            h.join(".hadolint/hadolint.yaml"),
            h.join("hadolint/config.yaml"),
            h.join(".hadolint.yaml"),
            h.join(".hadolint.yml"),
        ]);
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn apply_environment(s: &mut Settings) -> anyhow::Result<()> {
    env_bool("HADOLINT_NOFAIL", &mut s.no_fail);
    env_bool("HADOLINT_VERBOSE", &mut s.verbose);
    env_bool("HADOLINT_STRICT_LABELS", &mut s.strict_labels);
    env_bool("HADOLINT_DISABLE_IGNORE_PRAGMA", &mut s.disable_ignore);
    if std::env::var_os("NO_COLOR").is_some() {
        s.no_color = true;
    }
    if let Ok(v) = std::env::var("HADOLINT_FORMAT") {
        for x in csv(&v) {
            s.formats.push(Format::parse(&x)?);
        }
    }
    if let Ok(v) = std::env::var("HADOLINT_FAILURE_THRESHOLD") {
        s.threshold = Some(Threshold::parse(&v)?);
    }
    for (name, sev) in [
        ("HADOLINT_OVERRIDE_ERROR", HSeverity::Error),
        ("HADOLINT_OVERRIDE_WARNING", HSeverity::Warning),
        ("HADOLINT_OVERRIDE_INFO", HSeverity::Info),
        ("HADOLINT_OVERRIDE_STYLE", HSeverity::Style),
    ] {
        if let Ok(v) = std::env::var(name) {
            for x in csv(&v) {
                s.overrides.insert(norm(&x), sev);
            }
        }
    }
    if let Ok(v) = std::env::var("HADOLINT_IGNORE") {
        for x in csv(&v) {
            s.ignored.insert(norm(&x));
        }
    }
    if let Ok(v) = std::env::var("HADOLINT_TRUSTED_REGISTRIES") {
        s.registries.extend(csv(&v));
    }
    if let Ok(v) = std::env::var("HADOLINT_REQUIRE_LABELS") {
        for x in csv(&v) {
            insert_label(&mut s.labels, &x)?;
        }
    }
    note_rule_coverage(s);
    Ok(())
}

fn apply_cli(s: &mut Settings, c: &CliOptions) -> anyhow::Result<()> {
    if let Some(v) = &c.format {
        s.formats.push(Format::parse(v)?);
    }
    if c.no_fail {
        s.no_fail = true;
    }
    if c.no_color {
        s.no_color = true;
    }
    if c.verbose {
        s.verbose = true;
    }
    if c.strict_labels {
        s.strict_labels = true;
    }
    if c.disable_ignore_pragma {
        s.disable_ignore = true;
    }
    if let Some(v) = &c.failure_threshold {
        s.threshold = Some(Threshold::parse(v)?);
    }
    for (values, sev) in [
        (&c.error, HSeverity::Error),
        (&c.warning, HSeverity::Warning),
        (&c.info, HSeverity::Info),
        (&c.style, HSeverity::Style),
    ] {
        for v in values {
            s.overrides.insert(norm(v), sev);
        }
    }
    if !c.ignore.is_empty() {
        s.ignored = c.ignore.iter().map(|v| norm(v)).collect();
    }
    s.registries.extend(c.trusted_registries.clone());
    for v in &c.required_labels {
        insert_label(&mut s.labels, v)?;
    }
    note_rule_coverage(s);
    Ok(())
}

fn insert_label(labels: &mut BTreeMap<String, String>, value: &str) -> anyhow::Result<()> {
    let (name, format) = value.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("Invalid Hadolint label schema '{value}'; expected LABEL:FORMAT")
    })?;
    labels.insert(name.into(), format.into());
    Ok(())
}
fn env_bool(name: &str, target: &mut bool) {
    if let Ok(v) = std::env::var(name) {
        *target = matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "y" | "yes" | "on" | "true"
        );
    }
}
fn csv(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}
fn norm(v: &str) -> String {
    v.to_ascii_uppercase()
}

fn note_rule_coverage(s: &mut Settings) {
    let configured = s
        .ignored
        .iter()
        .chain(s.overrides.keys())
        .cloned()
        .collect::<Vec<_>>();
    for rule in configured {
        match mapping_status(&rule) {
            None => {
                s.warnings.insert(format!("unmatched Hadolint rule {rule}"));
            }
            Some(false) => {
                s.warnings.insert(format!("Hadolint rule {rule} maps to a behaviorally different droast check; findings retain their DF identity"));
            }
            _ => {}
        }
    }
    if !s.labels.is_empty() || s.strict_labels {
        s.warnings.insert(
            "Hadolint label rules are behaviorally different in droast; findings retain DF074"
                .into(),
        );
    }
}
fn report_warnings(s: &Settings) {
    for warning in &s.warnings {
        eprintln!("droast: hadolint compatibility: {warning}");
    }
}

fn get<'a>(m: &'a Mapping, k: &str) -> Option<&'a Value> {
    m.get(Value::String(k.into()))
}
fn strings(m: &Mapping, k: &str) -> anyhow::Result<Vec<String>> {
    match get(m, k) {
        None => Ok(vec![]),
        Some(Value::String(v)) => Ok(vec![v.clone()]),
        Some(Value::Sequence(v)) => v
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{k}' must contain strings"))
            })
            .collect(),
        _ => bail!("Hadolint '{k}' must be a string or list of strings"),
    }
}
fn string_map(m: &Mapping, k: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let Some(v) = get(m, k) else {
        return Ok(BTreeMap::new());
    };
    v.as_mapping()
        .ok_or_else(|| anyhow::anyhow!("Hadolint '{k}' must be a mapping"))?
        .iter()
        .map(|(a, b)| {
            Ok((
                a.as_str()
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{k}' keys must be strings"))?
                    .into(),
                b.as_str()
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{k}' values must be strings"))?
                    .into(),
            ))
        })
        .collect()
}
fn set_bool(m: &Mapping, k: &str, target: &mut bool) -> anyhow::Result<()> {
    if let Some(v) = get(m, k) {
        *target = v
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("Hadolint '{k}' must be true or false"))?;
    }
    Ok(())
}

// true means output-compatible identity; false means only a broader/behaviorally different check exists.
fn mapping_status(dl: &str) -> Option<bool> {
    if dl.starts_with("SC") && dl[2..].chars().all(|character| character.is_ascii_digit()) {
        return Some(true);
    }
    Some(match dl {
        "DL1000" | "DL3000" | "DL3001" | "DL3002" | "DL3003" | "DL3004" | "DL3006" | "DL3007"
        | "DL3008" | "DL3011" | "DL3012" | "DL3013" | "DL3014" | "DL3015" | "DL3018" | "DL3019"
        | "DL3020" | "DL3021" | "DL3022" | "DL3023" | "DL3024" | "DL3025" | "DL3026" | "DL3027"
        | "DL3028" | "DL3029" | "DL3030" | "DL3032" | "DL3034" | "DL3035" | "DL3036" | "DL3040"
        | "DL3042" | "DL3043" | "DL3044" | "DL3045" | "DL3046" | "DL3047" | "DL3059" | "DL3060"
        | "DL3061" | "DL3062" | "DL4000" | "DL4001" | "DL4003" | "DL4004" | "DL4006" => true,
        "DL3009" | "DL3016" | "DL3033" | "DL3037" | "DL3041" => false,
        _ => return None,
    })
}
fn df_for_dl(dl: &str) -> Option<&'static [&'static str]> {
    crate::hadolint::aliases(dl)
}
fn all_mapped_df() -> BTreeSet<&'static str> {
    [
        "DL1000", "DL3000", "DL3001", "DL3002", "DL3003", "DL3004", "DL3006", "DL3007", "DL3008",
        "DL3009", "DL3011", "DL3012", "DL3013", "DL3014", "DL3015", "DL3016", "DL3018", "DL3019",
        "DL3020", "DL3021", "DL3022", "DL3023", "DL3024", "DL3025", "DL3026", "DL3027", "DL3028",
        "DL3029", "DL3030", "DL3032", "DL3033", "DL3034", "DL3035", "DL3036", "DL3037", "DL3040",
        "DL3041", "DL3042", "DL3043", "DL3044", "DL3045", "DL3046", "DL3047", "DL3059", "DL3060",
        "DL3061", "DL3062", "DL4000", "DL4001", "DL4003", "DL4004", "DL4006",
    ]
    .into_iter()
    .filter_map(df_for_dl)
    .flatten()
    .copied()
    .chain(["DF074"])
    .collect()
}
fn is_ignored(s: &Settings, id: &str, df: &str) -> bool {
    s.ignored.contains(id)
        || s.ignored
            .iter()
            .any(|dl| df_for_dl(dl).is_some_and(|ids| ids.contains(&df)))
}
fn configured_severity(s: &Settings, id: &str, df: &str) -> Option<HSeverity> {
    s.overrides.get(id).copied().or_else(|| {
        s.overrides.iter().find_map(|(dl, severity)| {
            df_for_dl(dl)
                .is_some_and(|ids| ids.contains(&df))
                .then_some(*severity)
        })
    })
}

fn compatible_id(f: &Finding) -> String {
    match f.rule.as_str() {
        "DF071" => "DL1000",
        "DF001" => {
            if f.message.to_ascii_lowercase().contains("latest") {
                "DL3007"
            } else {
                "DL3006"
            }
        }
        "DF005" => {
            if f.message.starts_with("apt-get") {
                "DL3008"
            } else {
                "DF005"
            }
        }
        "DF009" => "DL3000",
        "DF060" => "DL3001",
        "DF002" => "DL3002",
        "DF008" => "DL3003",
        "DF010" => "DL3004",
        "DF040" => "DL3011",
        "DF041" => "DL3012",
        "DF051" => "DL3013",
        "DF015" => "DL3014",
        "DF016" => "DL3015",
        "DF052" => "DL3018",
        "DF029" => "DL3019",
        "DF006" => "DL3020",
        "DF048" => "DL3021",
        "DF049" => "DL3022",
        "DF050" => "DL3023",
        "DF042" => "DL3024",
        "DF018" | "DF025" => "DL3025",
        "DF065" => "DL3026",
        "DF059" => "DL3027",
        "DF053" => "DL3028",
        "DF061" => "DL3029",
        "DF027" => "DL3030",
        "DF047" => "DL3032",
        "DF043" => "DL3034",
        "DF044" => "DL3035",
        "DF045" => "DL3036",
        "DF046" => "DL3040",
        "DF030" => "DL3042",
        "DF068" => "DL3043",
        "DF062" => "DL3044",
        "DF063" => "DL3045",
        "DF064" => "DL3046",
        "DF056" => "DL3047",
        "DF003" => "DL3059",
        "DF055" => "DL3060",
        "DF037" => "DL3061",
        "DF054" => "DL3062",
        "DF019" => "DL4000",
        "DF058" => "DL4001",
        "DF038" => "DL4003",
        "DF039" => "DL4004",
        "DF057" => "DL4006",
        _ => return f.rule.clone(),
    }
    .into()
}

fn default_hseverity(rule: &str, fallback: Severity) -> HSeverity {
    match rule {
        "DL1000" | "DL3000" | "DL3004" | "DL3011" | "DL3012" | "DL3020" | "DL3021" | "DL3023"
        | "DL3024" | "DL3026" | "DL3043" | "DL3044" | "DL3061" | "DL4000" | "DL4004" => {
            HSeverity::Error
        }
        "DL3001" | "DL3015" | "DL3019" | "DL3047" | "DL3059" | "DL3060" => HSeverity::Info,
        r if r.starts_with("DL") => HSeverity::Warning,
        _ => match fallback {
            Severity::Error => HSeverity::Error,
            Severity::Warning => HSeverity::Warning,
            Severity::Info => HSeverity::Info,
        },
    }
}

fn apply_hadolint_pragmas(source: &str, findings: &mut Vec<Finding>) {
    let mut global = BTreeSet::new();
    let mut next: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let lines = source.lines().collect::<Vec<_>>();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("# hadolint global ignore=") {
            global.extend(
                rest.split('#')
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .map(|x| norm(x.trim())),
            );
        } else if let Some(rest) = t.strip_prefix("# hadolint ignore=") {
            let ids = rest
                .split('#')
                .next()
                .unwrap_or("")
                .split(',')
                .map(|x| norm(x.trim()))
                .collect();
            let target = lines
                .iter()
                .enumerate()
                .skip(i + 1)
                .find(|(_, l)| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .map_or(i + 2, |(n, _)| n + 1);
            next.insert(target, ids);
        }
    }
    findings.retain(|f| {
        let dl = compatible_id(f);
        !global.contains(&dl)
            && !global.contains(&f.rule)
            && !next
                .get(&f.line)
                .is_some_and(|ids| ids.contains(&dl) || ids.contains(&f.rule))
    });
}

fn render(format: Format, f: &[CompatFinding], _no_color: bool) -> anyhow::Result<String> {
    Ok(match format{
    Format::Tty=>f.iter().map(|x|format!("{}:{} {} {}: {}\n",x.file,x.line,x.severity.text(),x.rule,x.message)).collect(),
    Format::Gnu=>f.iter().map(|x|format!("hadolint:{}:{}: {} {}: {}\n",x.file,x.line,x.rule,x.severity.text(),x.message)).collect(),
    Format::Json=>serde_json::to_string(&f.iter().map(json_issue).collect::<Vec<_>>())?,
    Format::Codacy=>f.iter().map(|x|serde_json::to_string(&serde_json::json!({"filename":x.file,"patternId":x.rule,"message":x.message,"line":x.line})).unwrap()).collect(),
    Format::CodeClimate=>f.iter().map(|x|format!("{}\0",serde_json::to_string(&climate_issue(x,false)).unwrap())).collect(),
    Format::GitLab=>serde_json::to_string(&f.iter().map(|x|climate_issue(x,true)).collect::<Vec<_>>())?,
    Format::SonarQube=>serde_json::to_string(&serde_json::json!({"issues":f.iter().map(sonar_issue).collect::<Vec<_>>() }))?,
    Format::Checkstyle=>checkstyle(f), Format::JUnit=>junit(f), Format::Sarif=>sarif(f),})
}
fn json_issue(x: &CompatFinding) -> serde_json::Value {
    serde_json::json!({"file":x.file,"line":x.line,"column":1,"level":x.severity.text(),"code":x.rule,"message":x.message})
}
fn climate_issue(x: &CompatFinding, fingerprint: bool) -> serde_json::Value {
    let severity = match x.severity {
        HSeverity::Error => "blocker",
        HSeverity::Warning => "major",
        HSeverity::Info => "info",
        HSeverity::Style => "minor",
        HSeverity::Ignore => "",
    };
    let mut v = serde_json::json!({"type":"issue","check_name":x.rule,"description":x.message,"categories":["Bug Risk"],"location":{"path":x.file,"lines":{"begin":x.line,"end":x.line}},"severity":severity});
    if fingerprint {
        v["fingerprint"] = serde_json::json!(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&v).unwrap())
        ));
    }
    v
}
fn sonar_issue(x: &CompatFinding) -> serde_json::Value {
    serde_json::json!({"engineId":"Hadolint","ruleId":x.rule,"severity":match x.severity{HSeverity::Error=>"CRITICAL",HSeverity::Warning=>"MAJOR",HSeverity::Info=>"MINOR",_=>"INFO"},"type":if x.severity==HSeverity::Error{"BUG"}else{"CODE_SMELL"},"primaryLocation":{"message":x.message,"filePath":x.file,"textRange":{"startLine":x.line,"endLine":x.line,"startColumn":0,"endColumn":1}}})
}
fn checkstyle(f: &[CompatFinding]) -> String {
    let mut s =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<checkstyle version=\"4.3\">".to_string();
    let mut by: BTreeMap<&str, Vec<&CompatFinding>> = BTreeMap::new();
    for x in f {
        by.entry(&x.file).or_default().push(x);
    }
    for (file, items) in by {
        s.push_str(&format!("\n  <file name=\"{}\">", xml(file)));
        for x in items {
            s.push_str(&format!("\n    <error line=\"{}\" column=\"1\" severity=\"{}\" message=\"{}\" source=\"{}\" />",x.line,x.severity.text(),xml(&x.message),x.rule));
        }
        s.push_str("\n  </file>");
    }
    s.push_str("\n</checkstyle>\n");
    s
}
fn junit(f: &[CompatFinding]) -> String {
    let mut by: BTreeMap<&str, Vec<&CompatFinding>> = BTreeMap::new();
    for x in f {
        by.entry(&x.file).or_default().push(x);
    }
    let mut s="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites id=\"droast\" name=\"Hadolint-compatible droast run\" time=\"0.001\">".to_string();
    for (file, items) in by {
        s.push_str(&format!("\n  <testsuite id=\"hadolint\" name=\"Hadolint-compatible droast\" time=\"0.001\" failures=\"{}\" errors=\"0\">",items.len()));
        for x in items {
            s.push_str(&format!("\n    <testcase id=\"hadolint.rule.{}\" time=\"0.001\"><failure type=\"{}\" message=\"{}\" id=\"{}\">File: {}\nLine: {}\nCategory: Hadolint - Dockerfile Static Analysis\n{}: {}</failure></testcase>",x.rule,x.severity.text(),xml(&x.message),x.rule,xml(file),x.line,x.severity.text(),xml(&x.message)));
        }
        s.push_str("\n  </testsuite>");
    }
    s.push_str("\n</testsuites>\n");
    s
}
fn sarif(f: &[CompatFinding]) -> String {
    let results=f.iter().map(|x|serde_json::json!({"ruleId":x.rule,"level":match x.severity{HSeverity::Error=>"error",HSeverity::Warning=>"warning",_=>"note"},"message":{"text":x.message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":x.file},"region":{"startLine":x.line,"startColumn":x.column}}}]})).collect::<Vec<_>>();
    serde_json::to_string_pretty(&serde_json::json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"droast (Hadolint compatibility mode)","informationUri":"https://github.com/immanuwell/dockerfile-roast"}},"results":results}]})).unwrap()
}
fn xml(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn print_report() {
    println!(
        "Hadolint compatibility matrix (droast {})",
        env!("CARGO_PKG_VERSION")
    );
    for dl in [
        "DL1000", "DL3000", "DL3001", "DL3002", "DL3003", "DL3004", "DL3006", "DL3007", "DL3008",
        "DL3009", "DL3011", "DL3012", "DL3013", "DL3014", "DL3015", "DL3016", "DL3018", "DL3019",
        "DL3020", "DL3021", "DL3022", "DL3023", "DL3024", "DL3025", "DL3026", "DL3027", "DL3028",
        "DL3029", "DL3030", "DL3032", "DL3033", "DL3034", "DL3035", "DL3036", "DL3037", "DL3040",
        "DL3041", "DL3042", "DL3043", "DL3044", "DL3045", "DL3046", "DL3047", "DL3059", "DL3060",
        "DL3061", "DL3062", "DL4000", "DL4001", "DL4003", "DL4004", "DL4006",
    ] {
        println!(
            "{dl}: {:<22} {}",
            df_for_dl(dl).unwrap().join(","),
            if mapping_status(dl) == Some(true) {
                "equivalent identity"
            } else {
                "behaviorally different"
            }
        );
    }
    println!("All other DL rules: unmatched");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_and_different_ids_are_distinguished() {
        let f = Finding {
            rule: "DF009".into(),
            severity: Severity::Warning,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            message: "x".into(),
            roast: "x".into(),
        };
        assert_eq!(compatible_id(&f), "DL3000");
        let f = Finding {
            rule: "DF005".into(),
            message: "yum install without pinned package versions".into(),
            ..f
        };
        assert_eq!(compatible_id(&f), "DF005");
    }
    #[test]
    fn xml_escapes_attributes() {
        assert_eq!(xml("a&\"<"), "a&amp;&quot;&lt;");
    }
}
