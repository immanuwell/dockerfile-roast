//! Offline, daemonless resolution of effective Docker build invocations.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use hcl::eval::{Context as HclContext, Evaluate};
use hcl::{BlockLabel, Body, Expression, Value as HclValue};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};

use crate::repository::{self, ContainerEngine};
use crate::rules::Finding;

pub const INVOCATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationKind {
    Direct,
    Compose,
    Bake,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueState {
    Resolved,
    Unresolved,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub kind: String,
    pub source: String,
    pub path: String,
    pub precedence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveValue {
    pub state: ValueState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationOrigin {
    pub kind: InvocationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub location: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredInput {
    pub id: EffectiveValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<EffectiveValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInvocation {
    pub schema_version: u32,
    pub id: String,
    pub origin: InvocationOrigin,
    pub dockerfile: EffectiveValue,
    pub context: EffectiveValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<EffectiveValue>,
    pub build_args: BTreeMap<String, EffectiveValue>,
    pub platforms: Vec<EffectiveValue>,
    pub named_contexts: BTreeMap<String, EffectiveValue>,
    pub secrets: Vec<DeclaredInput>,
    pub ssh: Vec<DeclaredInput>,
    pub cache_from: Vec<EffectiveValue>,
    pub cache_to: Vec<EffectiveValue>,
    pub exporters: Vec<EffectiveValue>,
    pub attestations: Vec<EffectiveValue>,
    pub effective_ignore_file: EffectiveValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationDocument {
    pub schema_version: u32,
    pub invocations: Vec<BuildInvocation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InvocationFinding {
    pub invocation_ids: Vec<String>,
    pub effective_inputs_hash: String,
    pub file: String,
    pub finding: Finding,
}

/// Run the existing rule engine once for every fully resolved invocation.
/// Findings collapse only when both their normal fingerprint and all effective
/// build inputs are identical; origin IDs are retained on the merged result.
pub fn lint(
    document: &InvocationDocument,
    options: &crate::linter::LintOptions,
) -> Result<Vec<InvocationFinding>> {
    let mut findings = BTreeMap::<(String, String), InvocationFinding>::new();
    for invocation in &document.invocations {
        let (Some(dockerfile), Some(context)) = (
            invocation.dockerfile.value.as_deref(),
            invocation.context.value.as_deref(),
        ) else {
            continue;
        };
        let linted = crate::linter::lint_file_with_context(
            Path::new(dockerfile),
            Path::new(context),
            options,
        )?;
        let effective_inputs_hash = effective_inputs_hash(invocation);
        for finding in linted.findings {
            let fingerprint = crate::output::finding_fingerprint(&linted.file, &finding);
            let key = (effective_inputs_hash.clone(), fingerprint);
            match findings.get_mut(&key) {
                Some(existing) => existing.invocation_ids.push(invocation.id.clone()),
                None => {
                    findings.insert(
                        key,
                        InvocationFinding {
                            invocation_ids: vec![invocation.id.clone()],
                            effective_inputs_hash: effective_inputs_hash.clone(),
                            file: linted.file.clone(),
                            finding,
                        },
                    );
                }
            }
        }
    }
    for finding in findings.values_mut() {
        finding.invocation_ids.sort();
    }
    Ok(findings.into_values().collect())
}

fn effective_inputs_hash(invocation: &BuildInvocation) -> String {
    let mut inputs = serde_json::json!({
        "dockerfile": invocation.dockerfile,
        "context": invocation.context,
        "target": invocation.target,
        "build_args": invocation.build_args,
        "platforms": invocation.platforms,
        "named_contexts": invocation.named_contexts,
        "secrets": invocation.secrets,
        "ssh": invocation.ssh,
        "cache_from": invocation.cache_from,
        "cache_to": invocation.cache_to,
        "exporters": invocation.exporters,
        "attestations": invocation.attestations,
        "effective_ignore_file": invocation.effective_ignore_file,
    });
    remove_nonsemantic_provenance(&mut inputs);
    let material =
        serde_json::to_vec(&inputs).expect("effective invocation inputs are serializable");
    format!("sha256:{:x}", Sha256::digest(material))
}

fn remove_nonsemantic_provenance(value: &mut JsonValue) {
    match value {
        JsonValue::Object(values) => {
            let redacted = values.get("state").and_then(JsonValue::as_str) == Some("redacted");
            if !redacted {
                values.remove("provenance");
            }
            for value in values.values_mut() {
                remove_nonsemantic_provenance(value);
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                remove_nonsemantic_provenance(value);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Default, Clone)]
struct RawBuild {
    context: Option<String>,
    dockerfile: Option<String>,
    target: Option<String>,
    args: BTreeMap<String, RawValue>,
    platforms: Vec<String>,
    contexts: BTreeMap<String, String>,
    secrets: Vec<(String, Option<String>)>,
    ssh: Vec<(String, Option<String>)>,
    cache_from: Vec<String>,
    cache_to: Vec<String>,
    outputs: Vec<String>,
    attestations: Vec<String>,
    inherits: Vec<String>,
    matrix: BTreeMap<String, Vec<String>>,
    inline: bool,
    source_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
enum RawValue {
    Value(String),
    Inherit,
    Unresolved(String),
}

pub fn discover(paths: &[PathBuf], engine: ContainerEngine) -> InvocationDocument {
    let repository = repository::discover(paths, engine);
    let mut warnings = repository.warnings;
    let definitions = definition_files(paths, &mut warnings);
    let mut invocations = Vec::new();

    for definition in definitions {
        if is_compose_file(&definition) {
            resolve_compose(&definition, engine, &mut invocations, &mut warnings);
        } else {
            resolve_bake(&definition, engine, &mut invocations, &mut warnings);
        }
    }

    let represented = invocations
        .iter()
        .filter_map(resolved_pair)
        .collect::<BTreeSet<_>>();
    for input in repository.inputs {
        let pair = (
            canonicalish(&input.dockerfile),
            canonicalish(&input.context),
        );
        if represented.contains(&pair) {
            continue;
        }
        invocations.push(direct_invocation(&input, engine));
    }

    for invocation in &mut invocations {
        invocation.id.clear();
        let material = serde_json::to_vec(invocation).expect("invocation schema is serializable");
        invocation.id = format!("sha256:{:x}", Sha256::digest(material));
    }
    invocations.sort_by(|left, right| left.id.cmp(&right.id));
    warnings.sort();
    warnings.dedup();
    InvocationDocument {
        schema_version: INVOCATION_SCHEMA_VERSION,
        invocations,
        warnings,
    }
}

fn direct_invocation(input: &repository::BuildInput, engine: ContainerEngine) -> BuildInvocation {
    let source = display_path(&input.dockerfile);
    let origin_location = provenance("discovery", &source, "dockerfile", 0);
    let dockerfile = resolved(display_path(&input.dockerfile), origin_location.clone());
    let context = resolved(
        display_path(&input.context),
        provenance("inferred", &source, "context", 0),
    );
    let ignore = ignore_file(&input.dockerfile, &input.context, engine, &source);
    empty_invocation(
        InvocationOrigin {
            kind: InvocationKind::Direct,
            name: None,
            location: origin_location,
        },
        dockerfile,
        context,
        ignore,
    )
}

fn empty_invocation(
    origin: InvocationOrigin,
    dockerfile: EffectiveValue,
    context: EffectiveValue,
    effective_ignore_file: EffectiveValue,
) -> BuildInvocation {
    BuildInvocation {
        schema_version: INVOCATION_SCHEMA_VERSION,
        id: String::new(),
        origin,
        dockerfile,
        context,
        target: None,
        build_args: BTreeMap::new(),
        platforms: Vec::new(),
        named_contexts: BTreeMap::new(),
        secrets: Vec::new(),
        ssh: Vec::new(),
        cache_from: Vec::new(),
        cache_to: Vec::new(),
        exporters: Vec::new(),
        attestations: Vec::new(),
        effective_ignore_file,
    }
}

fn resolve_compose(
    file: &Path,
    engine: ContainerEngine,
    output: &mut Vec<BuildInvocation>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(file) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Compose file '{}': {error}",
                file.display()
            ));
            return;
        }
    };
    let document: YamlValue = match serde_yaml::from_str(&content) {
        Ok(document) => document,
        Err(error) => {
            warnings.push(format!(
                "cannot parse Compose file '{}': {error}",
                file.display()
            ));
            return;
        }
    };
    let Some(services) = mapping_value(&document, "services").and_then(YamlValue::as_mapping)
    else {
        return;
    };
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let environment = compose_environment(base);
    for (name, service) in services {
        let Some(name) = name.as_str() else { continue };
        let Some(build) = mapping_value(service, "build") else {
            continue;
        };
        let raw = compose_build(build);
        if raw.inline {
            warnings.push(format!(
                "Compose service {name:?} in '{}' uses dockerfile_inline, which has no filesystem Dockerfile",
                file.display()
            ));
            continue;
        }
        let key_path = format!("services.{name}.build");
        output.push(materialize(
            raw,
            MaterializeContext {
                file,
                key_path: &key_path,
                kind: InvocationKind::Compose,
                name,
                base,
                environment: &environment,
                engine,
            },
        ));
    }
}

fn compose_build(value: &YamlValue) -> RawBuild {
    if let Some(context) = value.as_str() {
        return RawBuild {
            context: Some(context.to_string()),
            dockerfile: Some("Dockerfile".into()),
            ..RawBuild::default()
        };
    }
    let mut raw = RawBuild {
        context: mapping_value(value, "context")
            .and_then(YamlValue::as_str)
            .map(str::to_string)
            .or(Some(".".into())),
        dockerfile: mapping_value(value, "dockerfile")
            .and_then(YamlValue::as_str)
            .map(str::to_string)
            .or(Some("Dockerfile".into())),
        target: string_value(mapping_value(value, "target")),
        platforms: string_list(mapping_value(value, "platforms")),
        cache_from: string_or_object_list(mapping_value(value, "cache_from")),
        cache_to: string_or_object_list(mapping_value(value, "cache_to")),
        outputs: string_or_object_list(
            mapping_value(value, "outputs").or_else(|| mapping_value(value, "output")),
        ),
        inline: mapping_value(value, "dockerfile_inline").is_some(),
        ..RawBuild::default()
    };
    raw.args = yaml_key_values(mapping_value(value, "args"));
    raw.contexts = yaml_named_values(mapping_value(value, "additional_contexts"));
    raw.secrets = yaml_declarations(mapping_value(value, "secrets"));
    raw.ssh = yaml_declarations(mapping_value(value, "ssh"));
    if let Some(value) = mapping_value(value, "provenance") {
        raw.attestations
            .push(format!("type=provenance,{}", yaml_scalar(value)));
    }
    if let Some(value) = mapping_value(value, "sbom") {
        raw.attestations
            .push(format!("type=sbom,{}", yaml_scalar(value)));
    }
    raw
}

fn resolve_bake(
    file: &Path,
    engine: ContainerEngine,
    output: &mut Vec<BuildInvocation>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(file) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Bake file '{}': {error}",
                file.display()
            ));
            return;
        }
    };
    let targets = if file.extension().and_then(|value| value.to_str()) == Some("json") {
        parse_bake_json(&content)
    } else {
        parse_bake_hcl(&content)
    };
    let targets = match targets {
        Ok(targets) => targets,
        Err(error) => {
            warnings.push(format!(
                "cannot parse Bake file '{}': {error}",
                file.display()
            ));
            return;
        }
    };
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let environment = process_environment();
    for name in targets.keys() {
        if let Some(target) = targets.get(name) {
            let parents = target
                .inherits
                .iter()
                .filter_map(|parent| {
                    resolve_bake_target(parent, &targets, &mut HashSet::new())
                        .map(|resolved| (parent, resolved))
                })
                .collect::<Vec<_>>();
            for left in 0..parents.len() {
                for right in left + 1..parents.len() {
                    let conflicts = raw_conflicts(&parents[left].1, &parents[right].1);
                    if !conflicts.is_empty() {
                        warnings.push(format!(
                            "Bake target {name:?} in '{}' inherits conflicting definitions from {:?} and {:?}: {} (later inheritance wins)",
                            file.display(),
                            parents[left].0,
                            parents[right].0,
                            conflicts.join(", ")
                        ));
                    }
                }
            }
        }
        let mut visiting = HashSet::new();
        let Some(target) = resolve_bake_target(name, &targets, &mut visiting) else {
            warnings.push(format!(
                "Bake target {name:?} in '{}' has cyclic, missing, or conflicting inheritance",
                file.display()
            ));
            continue;
        };
        if target.inline {
            continue;
        }
        for (suffix, expanded) in expand_matrix(&target) {
            let key_path = format!("target.{name}{suffix}");
            let expanded_name = format!("{name}{suffix}");
            output.push(materialize(
                expanded,
                MaterializeContext {
                    file,
                    key_path: &key_path,
                    kind: InvocationKind::Bake,
                    name: &expanded_name,
                    base,
                    environment: &environment,
                    engine,
                },
            ));
        }
    }
}

fn raw_conflicts(left: &RawBuild, right: &RawBuild) -> Vec<String> {
    let mut conflicts = Vec::new();
    for (name, left, right) in [
        ("context", left.context.as_ref(), right.context.as_ref()),
        (
            "dockerfile",
            left.dockerfile.as_ref(),
            right.dockerfile.as_ref(),
        ),
        ("target", left.target.as_ref(), right.target.as_ref()),
    ] {
        if matches!((left, right), (Some(left), Some(right)) if left != right) {
            conflicts.push(name.to_string());
        }
    }
    for key in left.args.keys().filter(|key| right.args.contains_key(*key)) {
        let different = match (&left.args[key], &right.args[key]) {
            (RawValue::Value(left), RawValue::Value(right)) => left != right,
            (RawValue::Inherit, RawValue::Inherit) => false,
            (RawValue::Unresolved(left), RawValue::Unresolved(right)) => left != right,
            _ => true,
        };
        if different {
            conflicts.push(format!("args.{key}"));
        }
    }
    conflicts
}

struct MaterializeContext<'a> {
    file: &'a Path,
    key_path: &'a str,
    kind: InvocationKind,
    name: &'a str,
    base: &'a Path,
    environment: &'a BTreeMap<String, EnvValue>,
    engine: ContainerEngine,
}

fn materialize(raw: RawBuild, resolution: MaterializeContext<'_>) -> BuildInvocation {
    let MaterializeContext {
        file,
        key_path,
        kind,
        name,
        base,
        environment,
        engine,
    } = resolution;
    let source = display_path(file);
    let source_paths = raw.source_paths.clone();
    let path_for =
        |field: &str, default: String| source_paths.get(field).cloned().unwrap_or(default);
    let context_expression = raw.context.as_deref().unwrap_or(".");
    let context_interpolated = interpolate(context_expression, environment);
    let context = path_value(
        context_interpolated,
        base,
        &source,
        &path_for("context", format!("{key_path}.context")),
    );
    let dockerfile_expression = raw.dockerfile.as_deref().unwrap_or("Dockerfile");
    let dockerfile_interpolated = interpolate(dockerfile_expression, environment);
    let dockerfile = match (&context.value, dockerfile_interpolated) {
        (Some(context), Interpolation::Resolved(value, mut provenance_values)) => {
            let path = PathBuf::from(context).join(value);
            provenance_values.push(provenance(
                "definition",
                &source,
                &path_for("dockerfile", format!("{key_path}.dockerfile")),
                0,
            ));
            resolved_with(display_path(&path), provenance_values)
        }
        (_, Interpolation::Unresolved(expression, provenance_values)) => {
            unresolved_with(expression, provenance_values)
        }
        _ => unresolved(
            dockerfile_expression,
            provenance(
                "definition",
                &source,
                &path_for("dockerfile", format!("{key_path}.dockerfile")),
                0,
            ),
        ),
    };
    let ignore = match (dockerfile.value.as_deref(), context.value.as_deref()) {
        (Some(dockerfile), Some(context)) => {
            ignore_file(Path::new(dockerfile), Path::new(context), engine, &source)
        }
        _ => unresolved(
            "effective ignore file depends on unresolved build paths",
            provenance("derived", &source, &format!("{key_path}.ignore"), 0),
        ),
    };
    let mut invocation = empty_invocation(
        InvocationOrigin {
            kind,
            name: Some(name.to_string()),
            location: provenance("definition", &source, key_path, 0),
        },
        dockerfile,
        context,
        ignore,
    );
    invocation.target = raw.target.as_deref().map(|value| {
        effective_interpolation(
            value,
            environment,
            &source,
            &path_for("target", format!("{key_path}.target")),
        )
    });
    for (name, value) in raw.args {
        let path = path_for(&format!("args.{name}"), format!("{key_path}.args.{name}"));
        let value = match value {
            RawValue::Value(value) => {
                if sensitive_name(&name) {
                    redacted(&value, provenance("definition", &source, &path, 0))
                } else {
                    effective_interpolation(&value, environment, &source, &path)
                }
            }
            RawValue::Inherit => match environment.get(&name) {
                Some(value) if sensitive_name(&name) => redacted(&name, value.provenance.clone()),
                Some(value) => resolved_with(value.value.clone(), vec![value.provenance.clone()]),
                None => unresolved(&name, provenance("environment", &source, &path, 1)),
            },
            RawValue::Unresolved(expression) => {
                unresolved(expression, provenance("definition", &source, &path, 0))
            }
        };
        invocation.build_args.insert(name, value);
    }
    invocation.platforms = raw
        .platforms
        .iter()
        .map(|value| {
            effective_interpolation(
                value,
                environment,
                &source,
                &path_for("platforms", format!("{key_path}.platforms")),
            )
        })
        .collect();
    invocation.named_contexts = raw
        .contexts
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                named_context_value(
                    value,
                    environment,
                    base,
                    &source,
                    &path_for(
                        &format!("contexts.{name}"),
                        format!("{key_path}.contexts.{name}"),
                    ),
                ),
            )
        })
        .collect();
    invocation.secrets = declarations(
        raw.secrets,
        &source,
        &path_for("secrets", format!("{key_path}.secrets")),
    );
    invocation.ssh = declarations(
        raw.ssh,
        &source,
        &path_for("ssh", format!("{key_path}.ssh")),
    );
    invocation.cache_from = effective_list(
        raw.cache_from,
        environment,
        &source,
        &path_for("cache_from", format!("{key_path}.cache_from")),
    );
    invocation.cache_to = effective_list(
        raw.cache_to,
        environment,
        &source,
        &path_for("cache_to", format!("{key_path}.cache_to")),
    );
    invocation.exporters = effective_list(
        raw.outputs,
        environment,
        &source,
        &path_for("outputs", format!("{key_path}.outputs")),
    );
    invocation.attestations = effective_list(
        raw.attestations,
        environment,
        &source,
        &path_for("attestations", format!("{key_path}.attestations")),
    );
    invocation
}

fn named_context_value(
    expression: &str,
    environment: &BTreeMap<String, EnvValue>,
    base: &Path,
    source: &str,
    path: &str,
) -> EffectiveValue {
    let value = effective_interpolation(expression, environment, source, path);
    let Some(resolved_value) = value.value.as_deref() else {
        return value;
    };
    if resolved_value.contains("://")
        || resolved_value.starts_with("service:")
        || resolved_value.starts_with("target:")
        || resolved_value.starts_with("docker-image:")
    {
        value
    } else {
        resolved_with(display_path(&base.join(resolved_value)), value.provenance)
    }
}

#[derive(Debug, Clone)]
struct EnvValue {
    value: String,
    provenance: Provenance,
}

fn compose_environment(base: &Path) -> BTreeMap<String, EnvValue> {
    let mut environment = BTreeMap::new();
    let dotenv = base.join(".env");
    if let Ok(values) = dotenvy::from_path_iter(&dotenv) {
        for (name, value) in values.flatten() {
            environment.insert(
                name.clone(),
                EnvValue {
                    value,
                    provenance: provenance("dotenv", &display_path(&dotenv), &name, 10),
                },
            );
        }
    }
    for (name, value) in std::env::vars() {
        environment.insert(
            name.clone(),
            EnvValue {
                value,
                provenance: provenance("process_environment", "<environment>", &name, 20),
            },
        );
    }
    environment
}

fn process_environment() -> BTreeMap<String, EnvValue> {
    compose_environment(Path::new("/__droast_no_dotenv__"))
}

enum Interpolation {
    Resolved(String, Vec<Provenance>),
    Unresolved(String, Vec<Provenance>),
}

fn interpolate(expression: &str, environment: &BTreeMap<String, EnvValue>) -> Interpolation {
    let mut result = String::new();
    let mut provenance_values = Vec::new();
    let bytes = expression.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            let character = expression[index..].chars().next().unwrap();
            result.push(character);
            index += character.len_utf8();
            continue;
        }
        if bytes.get(index + 1) == Some(&b'$') {
            result.push('$');
            index += 2;
            continue;
        }
        let (name, operation, operand, end) = if bytes.get(index + 1) == Some(&b'{') {
            let Some(close) = expression[index + 2..].find('}') else {
                return Interpolation::Unresolved(expression.to_string(), provenance_values);
            };
            let end = index + 2 + close;
            let inner = &expression[index + 2..end];
            let parsed = [":-", ":+", ":?", "-", "+", "?"]
                .into_iter()
                .find_map(|operation| {
                    inner
                        .split_once(operation)
                        .map(|(name, operand)| (name, Some(operation), Some(operand)))
                })
                .unwrap_or((inner, None, None));
            (parsed.0, parsed.1, parsed.2, end + 1)
        } else {
            let start = index + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if end == start {
                result.push('$');
                index += 1;
                continue;
            }
            (&expression[start..end], None, None, end)
        };
        let environment_value = environment.get(name);
        let is_set = environment_value.is_some();
        let is_nonempty = environment_value.is_some_and(|value| !value.value.is_empty());
        let colon = operation.is_some_and(|operation| operation.starts_with(':'));
        let usable = is_set && (!colon || is_nonempty);
        match operation.map(|operation| operation.trim_start_matches(':')) {
            None if is_set => {
                let value = environment_value.unwrap();
                result.push_str(&value.value);
                provenance_values.push(value.provenance.clone());
            }
            Some("-") if usable => {
                let value = environment_value.unwrap();
                result.push_str(&value.value);
                provenance_values.push(value.provenance.clone());
            }
            Some("-") => result.push_str(operand.unwrap_or_default()),
            Some("+") if usable => result.push_str(operand.unwrap_or_default()),
            Some("+") => {}
            Some("?") if usable => {
                let value = environment_value.unwrap();
                result.push_str(&value.value);
                provenance_values.push(value.provenance.clone());
            }
            Some("?") | None => {
                return Interpolation::Unresolved(expression.to_string(), provenance_values)
            }
            _ => return Interpolation::Unresolved(expression.to_string(), provenance_values),
        }
        index = end;
    }
    Interpolation::Resolved(result, provenance_values)
}

fn effective_interpolation(
    expression: &str,
    environment: &BTreeMap<String, EnvValue>,
    source: &str,
    path: &str,
) -> EffectiveValue {
    match interpolate(expression, environment) {
        Interpolation::Resolved(value, mut values) => {
            values.push(provenance("definition", source, path, 0));
            resolved_with(value, values)
        }
        Interpolation::Unresolved(expression, mut values) => {
            values.push(provenance("definition", source, path, 0));
            unresolved_with(expression, values)
        }
    }
}

fn path_value(value: Interpolation, base: &Path, source: &str, path: &str) -> EffectiveValue {
    match value {
        Interpolation::Resolved(value, mut values) => {
            values.push(provenance("definition", source, path, 0));
            if value.contains("://") || value.starts_with("docker-image://") {
                unresolved_with(value, values)
            } else {
                resolved_with(display_path(&base.join(value)), values)
            }
        }
        Interpolation::Unresolved(expression, mut values) => {
            values.push(provenance("definition", source, path, 0));
            unresolved_with(expression, values)
        }
    }
}

fn declarations(
    values: Vec<(String, Option<String>)>,
    source: &str,
    path: &str,
) -> Vec<DeclaredInput> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, (id, target))| DeclaredInput {
            id: resolved(
                id,
                provenance("declaration", source, &format!("{path}[{index}].id"), 0),
            ),
            target: target.map(|target| {
                resolved(
                    target,
                    provenance("declaration", source, &format!("{path}[{index}].target"), 0),
                )
            }),
        })
        .collect()
}

fn effective_list(
    values: Vec<String>,
    env: &BTreeMap<String, EnvValue>,
    source: &str,
    path: &str,
) -> Vec<EffectiveValue> {
    values
        .iter()
        .map(|value| effective_interpolation(value, env, source, path))
        .collect()
}

fn ignore_file(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
    source: &str,
) -> EffectiveValue {
    let docker_specific = PathBuf::from(format!("{}.dockerignore", dockerfile.display()));
    let candidates = match engine {
        ContainerEngine::Docker => vec![docker_specific, context.join(".dockerignore")],
        ContainerEngine::Podman => vec![
            context.join(".containerignore"),
            context.join(".dockerignore"),
        ],
    };
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        resolved(
            display_path(path),
            provenance("filesystem", source, "effective_ignore_file", 0),
        )
    } else {
        unresolved(
            display_path(candidates.last().expect("ignore candidates are nonempty")),
            provenance("filesystem", source, "effective_ignore_file", 0),
        )
    }
}

fn parse_bake_json(content: &str) -> Result<BTreeMap<String, RawBuild>> {
    let document: JsonValue = serde_json::from_str(content)?;
    let mut result = BTreeMap::new();
    let Some(targets) = document.get("target").and_then(JsonValue::as_object) else {
        return Ok(result);
    };
    for (name, target) in targets {
        let mut raw = raw_from_json(target);
        annotate_bake_paths(&mut raw, name);
        result.insert(name.clone(), raw);
    }
    let variables = document
        .get("variable")
        .and_then(JsonValue::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, definition)| {
            std::env::var(name)
                .ok()
                .or_else(|| {
                    definition
                        .get("default")
                        .and_then(|value| value.as_str().map(str::to_string))
                })
                .map(|value| (name.clone(), value))
        })
        .collect::<BTreeMap<_, _>>();
    for target in result.values_mut() {
        substitute_raw(target, &variables);
    }
    Ok(result)
}

fn raw_from_json(value: &JsonValue) -> RawBuild {
    let mut raw = RawBuild {
        context: json_string(value.get("context")),
        dockerfile: json_string(value.get("dockerfile")),
        target: json_string(value.get("target")),
        platforms: json_strings(value.get("platforms")),
        contexts: json_named_values(value.get("contexts")),
        secrets: json_declarations(value.get("secret").or_else(|| value.get("secrets"))),
        ssh: json_declarations(value.get("ssh")),
        cache_from: json_strings(value.get("cache-from")),
        cache_to: json_strings(value.get("cache-to")),
        outputs: json_strings(value.get("output")),
        attestations: json_strings(value.get("attest")),
        inherits: json_strings(value.get("inherits")),
        matrix: json_matrix(value.get("matrix")),
        inline: value.get("dockerfile-inline").is_some(),
        ..RawBuild::default()
    };
    raw.args = json_key_values(value.get("args"));
    raw
}

fn parse_bake_hcl(content: &str) -> Result<BTreeMap<String, RawBuild>> {
    let body: Body = hcl::parse(content)?;
    let mut context = HclContext::new();
    for block in body
        .blocks()
        .filter(|block| block.identifier() == "variable")
    {
        let Some(name) = block_label(block.labels.first()) else {
            continue;
        };
        let value = std::env::var(name).ok().map(HclValue::from).or_else(|| {
            hcl_attribute(block, "default").and_then(|value| value.evaluate(&context).ok())
        });
        if let Some(value) = value {
            context.declare_var(name, value);
        }
    }
    let mut result = BTreeMap::new();
    for block in body.blocks().filter(|block| block.identifier() == "target") {
        let Some(name) = block_label(block.labels.first()) else {
            continue;
        };
        let matrix = hcl_attribute(block, "matrix")
            .and_then(|expression| expression.evaluate(&context).ok())
            .and_then(|value| serde_json::to_value(value).ok());
        let combinations = matrix_combinations(&json_matrix(matrix.as_ref()));
        for combination in combinations {
            let mut expanded_context = context.clone();
            for (key, value) in &combination {
                expanded_context.declare_var(key.as_str(), value.clone());
            }
            let value = |key: &str| {
                hcl_attribute(block, key).and_then(|expression| {
                    expression
                        .evaluate(&expanded_context)
                        .ok()
                        .and_then(|value| serde_json::to_value(value).ok())
                        .or_else(|| hcl::to_string(expression).ok().map(JsonValue::String))
                })
            };
            let object = [
                "context",
                "dockerfile",
                "target",
                "platforms",
                "contexts",
                "secret",
                "ssh",
                "cache-from",
                "cache-to",
                "output",
                "attest",
                "inherits",
                "args",
            ]
            .into_iter()
            .filter_map(|key| value(key).map(|value| (key.to_string(), value)))
            .collect::<serde_json::Map<_, _>>();
            let mut raw = raw_from_json(&JsonValue::Object(object));
            if let Some(Expression::Object(values)) = hcl_attribute(block, "args") {
                raw.args.clear();
                for (key, expression) in values {
                    let key = key.to_string().trim_matches('"').to_string();
                    let value = match expression.evaluate(&expanded_context) {
                        Ok(HclValue::Null) => RawValue::Inherit,
                        Ok(value) => {
                            RawValue::Value(value.as_str().map(str::to_string).unwrap_or_else(
                                || serde_json::to_string(&value).unwrap_or_default(),
                            ))
                        }
                        Err(_) => RawValue::Unresolved(
                            hcl::to_string(expression)
                                .unwrap_or_else(|_| "<unresolved HCL expression>".into()),
                        ),
                    };
                    raw.args.insert(key, value);
                }
            }
            raw.inline = hcl_attribute(block, "dockerfile-inline").is_some();
            annotate_bake_paths(&mut raw, name);
            let suffix = if combination.is_empty() {
                String::new()
            } else {
                format!(
                    "[{}]",
                    combination
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            result.insert(format!("{name}{suffix}"), raw);
        }
    }
    Ok(result)
}

fn resolve_bake_target(
    name: &str,
    targets: &BTreeMap<String, RawBuild>,
    visiting: &mut HashSet<String>,
) -> Option<RawBuild> {
    if !visiting.insert(name.to_string()) {
        return None;
    }
    let target = targets.get(name)?;
    let mut result = RawBuild::default();
    for parent in &target.inherits {
        merge_raw(&mut result, resolve_bake_target(parent, targets, visiting)?);
    }
    merge_raw(&mut result, target.clone());
    visiting.remove(name);
    Some(result)
}

fn merge_raw(base: &mut RawBuild, child: RawBuild) {
    base.source_paths.extend(child.source_paths.clone());
    if child.context.is_some() {
        base.context = child.context;
    }
    if child.dockerfile.is_some() {
        base.dockerfile = child.dockerfile;
        base.inline = false;
    }
    if child.target.is_some() {
        base.target = child.target;
    }
    base.args.extend(child.args);
    if !child.platforms.is_empty() {
        base.platforms = child.platforms;
    }
    base.contexts.extend(child.contexts);
    if !child.secrets.is_empty() {
        base.secrets = child.secrets;
    }
    if !child.ssh.is_empty() {
        base.ssh = child.ssh;
    }
    if !child.cache_from.is_empty() {
        base.cache_from = child.cache_from;
    }
    if !child.cache_to.is_empty() {
        base.cache_to = child.cache_to;
    }
    if !child.outputs.is_empty() {
        base.outputs = child.outputs;
    }
    if !child.attestations.is_empty() {
        base.attestations = child.attestations;
    }
    if !child.matrix.is_empty() {
        base.matrix = child.matrix;
    }
    if child.inline {
        base.inline = true;
        base.dockerfile = None;
    }
}

fn annotate_bake_paths(raw: &mut RawBuild, name: &str) {
    let base = format!("target.{name}");
    let mut add = |field: &str, present: bool, source_name: &str| {
        if present {
            raw.source_paths
                .insert(field.to_string(), format!("{base}.{source_name}"));
        }
    };
    add("context", raw.context.is_some(), "context");
    add("dockerfile", raw.dockerfile.is_some(), "dockerfile");
    add("target", raw.target.is_some(), "target");
    add("platforms", !raw.platforms.is_empty(), "platforms");
    add("secrets", !raw.secrets.is_empty(), "secret");
    add("ssh", !raw.ssh.is_empty(), "ssh");
    add("cache_from", !raw.cache_from.is_empty(), "cache-from");
    add("cache_to", !raw.cache_to.is_empty(), "cache-to");
    add("outputs", !raw.outputs.is_empty(), "output");
    add("attestations", !raw.attestations.is_empty(), "attest");
    for key in raw.args.keys() {
        raw.source_paths
            .insert(format!("args.{key}"), format!("{base}.args.{key}"));
    }
    for key in raw.contexts.keys() {
        raw.source_paths
            .insert(format!("contexts.{key}"), format!("{base}.contexts.{key}"));
    }
}

fn expand_matrix(raw: &RawBuild) -> Vec<(String, RawBuild)> {
    let combinations = matrix_combinations(&raw.matrix);
    if combinations.is_empty() {
        return Vec::new();
    }
    combinations
        .into_iter()
        .map(|values| {
            let mut expanded = raw.clone();
            expanded.matrix.clear();
            substitute_raw(&mut expanded, &values);
            let suffix = if values.is_empty() {
                String::new()
            } else {
                format!(
                    "[{}]",
                    values
                        .iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            (suffix, expanded)
        })
        .collect()
}

fn matrix_combinations(matrix: &BTreeMap<String, Vec<String>>) -> Vec<BTreeMap<String, String>> {
    let mut combinations = vec![BTreeMap::<String, String>::new()];
    for (name, values) in matrix {
        let mut next = Vec::new();
        for combination in &combinations {
            for value in values {
                let mut expanded = combination.clone();
                expanded.insert(name.clone(), value.clone());
                next.push(expanded);
            }
        }
        combinations = next;
    }
    combinations
}

fn substitute_raw(raw: &mut RawBuild, values: &BTreeMap<String, String>) {
    let substitute = |value: &mut String| {
        for (name, replacement) in values {
            *value = value.replace(&format!("${{{name}}}"), replacement);
        }
    };
    for value in [&mut raw.context, &mut raw.dockerfile, &mut raw.target]
        .into_iter()
        .flatten()
    {
        substitute(value);
    }
    for value in raw.args.values_mut() {
        if let RawValue::Value(value) = value {
            substitute(value);
        }
    }
    for value in raw
        .platforms
        .iter_mut()
        .chain(raw.contexts.values_mut())
        .chain(raw.cache_from.iter_mut())
        .chain(raw.cache_to.iter_mut())
        .chain(raw.outputs.iter_mut())
        .chain(raw.attestations.iter_mut())
    {
        substitute(value);
    }
}

fn definition_files(paths: &[PathBuf], warnings: &mut Vec<String>) -> BTreeSet<PathBuf> {
    let requested = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    let mut result = BTreeSet::new();
    let mut expanded = Vec::new();
    for path in requested {
        let pattern = path.to_string_lossy();
        if pattern.contains(['*', '?', '[']) {
            match glob::glob(&pattern) {
                Ok(matches) => expanded.extend(matches.flatten()),
                Err(error) => warnings.push(format!("invalid path pattern {pattern:?}: {error}")),
            }
        } else {
            expanded.push(path);
        }
    }
    for path in expanded {
        if path.is_file() && (is_compose_file(&path) || is_bake_file(&path)) {
            result.insert(path);
        } else if path.is_dir() {
            let mut walker = WalkBuilder::new(&path);
            walker
                .follow_links(false)
                .hidden(false)
                .ignore(true)
                .git_ignore(true)
                .parents(true);
            for entry in walker.build() {
                match entry {
                    Ok(entry) if entry.file_type().is_some_and(|value| value.is_file()) => {
                        let path = entry.into_path();
                        if is_compose_file(&path) || is_bake_file(&path) {
                            result.insert(path);
                        }
                    }
                    Err(error) => {
                        warnings.push(format!("cannot inspect invocation definition: {error}"))
                    }
                    _ => {}
                }
            }
        }
    }
    result
}

fn is_compose_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("compose.yaml" | "compose.yml" | "docker-compose.yaml" | "docker-compose.yml")
    )
}

fn is_bake_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("docker-bake.hcl" | "docker-bake.json")
    )
}

fn mapping_value<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    value.as_mapping()?.get(YamlValue::String(key.to_string()))
}

fn string_value(value: Option<&YamlValue>) -> Option<String> {
    value.and_then(YamlValue::as_str).map(str::to_string)
}
fn string_list(value: Option<&YamlValue>) -> Vec<String> {
    value
        .and_then(YamlValue::as_sequence)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
fn yaml_scalar(value: &YamlValue) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| {
        serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim()
            .to_string()
    })
}
fn string_or_object_list(value: Option<&YamlValue>) -> Vec<String> {
    value
        .map(|value| match value {
            YamlValue::Sequence(values) => values.iter().map(yaml_scalar).collect(),
            _ => vec![yaml_scalar(value)],
        })
        .unwrap_or_default()
}

fn yaml_key_values(value: Option<&YamlValue>) -> BTreeMap<String, RawValue> {
    let mut result = BTreeMap::new();
    match value {
        Some(YamlValue::Mapping(values)) => {
            for (key, value) in values {
                if let Some(key) = key.as_str() {
                    result.insert(
                        key.to_string(),
                        if value.is_null() {
                            RawValue::Inherit
                        } else {
                            RawValue::Value(yaml_scalar(value))
                        },
                    );
                }
            }
        }
        Some(YamlValue::Sequence(values)) => {
            for value in values.iter().filter_map(YamlValue::as_str) {
                if let Some((key, value)) = value.split_once('=') {
                    result.insert(key.to_string(), RawValue::Value(value.to_string()));
                } else {
                    result.insert(value.to_string(), RawValue::Inherit);
                }
            }
        }
        _ => {}
    }
    result
}

fn yaml_named_values(value: Option<&YamlValue>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    match value {
        Some(YamlValue::Mapping(values)) => {
            for (key, value) in values {
                if let Some(key) = key.as_str() {
                    result.insert(key.to_string(), yaml_scalar(value));
                }
            }
        }
        Some(YamlValue::Sequence(values)) => {
            for value in values.iter().filter_map(YamlValue::as_str) {
                if let Some((key, value)) = value.split_once('=') {
                    result.insert(key.to_string(), value.to_string());
                }
            }
        }
        _ => {}
    }
    result
}

fn yaml_declarations(value: Option<&YamlValue>) -> Vec<(String, Option<String>)> {
    value
        .and_then(YamlValue::as_sequence)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| match value {
                    YamlValue::String(id) => Some((id.clone(), None)),
                    YamlValue::Mapping(_) => {
                        let id = mapping_value(value, "source")
                            .or_else(|| mapping_value(value, "id"))
                            .and_then(YamlValue::as_str)?;
                        let target = mapping_value(value, "target")
                            .and_then(YamlValue::as_str)
                            .map(str::to_string);
                        Some((id.to_string(), target))
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn json_string(value: Option<&JsonValue>) -> Option<String> {
    value.and_then(JsonValue::as_str).map(str::to_string)
}
fn json_strings(value: Option<&JsonValue>) -> Vec<String> {
    match value {
        Some(JsonValue::String(value)) => vec![value.clone()],
        Some(JsonValue::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string())
            })
            .collect(),
        _ => Vec::new(),
    }
}
fn json_named_values(value: Option<&JsonValue>) -> BTreeMap<String, String> {
    value
        .and_then(JsonValue::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| value.to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}
fn json_key_values(value: Option<&JsonValue>) -> BTreeMap<String, RawValue> {
    value
        .and_then(JsonValue::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        if value.is_null() {
                            RawValue::Inherit
                        } else {
                            RawValue::Value(
                                value
                                    .as_str()
                                    .map(str::to_string)
                                    .unwrap_or_else(|| value.to_string()),
                            )
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}
fn json_matrix(value: Option<&JsonValue>) -> BTreeMap<String, Vec<String>> {
    value
        .and_then(JsonValue::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_strings(Some(value))))
                .collect()
        })
        .unwrap_or_default()
}
fn json_declarations(value: Option<&JsonValue>) -> Vec<(String, Option<String>)> {
    json_strings(value)
        .into_iter()
        .map(|value| {
            let mut id = value.clone();
            let mut target = None;
            for field in value.split(',') {
                if let Some(value) = field.strip_prefix("id=") {
                    id = value.to_string();
                }
                if let Some(value) = field.strip_prefix("target=") {
                    target = Some(value.to_string());
                }
            }
            (id, target)
        })
        .collect()
}

fn hcl_attribute<'a>(block: &'a hcl::Block, key: &str) -> Option<&'a Expression> {
    block
        .body
        .attributes()
        .find(|attribute| attribute.key() == key)
        .map(|attribute| attribute.expr())
}
fn block_label(label: Option<&BlockLabel>) -> Option<&str> {
    match label? {
        BlockLabel::Identifier(value) => Some(value.as_str()),
        BlockLabel::String(value) => Some(value),
    }
}

fn sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "token",
        "credential",
        "private_key",
        "auth",
    ]
    .iter()
    .any(|part| name.contains(part))
}
fn resolved(value: String, provenance: Provenance) -> EffectiveValue {
    resolved_with(value, vec![provenance])
}
fn resolved_with(value: String, provenance: Vec<Provenance>) -> EffectiveValue {
    EffectiveValue {
        state: ValueState::Resolved,
        value: Some(value),
        expression: None,
        provenance,
    }
}
fn unresolved(expression: impl Into<String>, provenance: Provenance) -> EffectiveValue {
    unresolved_with(expression.into(), vec![provenance])
}
fn unresolved_with(expression: String, provenance: Vec<Provenance>) -> EffectiveValue {
    EffectiveValue {
        state: ValueState::Unresolved,
        value: None,
        expression: Some(expression),
        provenance,
    }
}
fn redacted(_expression: &str, provenance: Provenance) -> EffectiveValue {
    EffectiveValue {
        state: ValueState::Redacted,
        value: None,
        expression: None,
        provenance: vec![provenance],
    }
}
fn provenance(kind: &str, source: &str, path: &str, precedence: u32) -> Provenance {
    Provenance {
        kind: kind.into(),
        source: source.into(),
        path: path.into(),
        precedence,
        line: None,
        column: None,
    }
}

fn display_path(path: &Path) -> String {
    let path = canonicalish(path);
    let display = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            path.strip_prefix(canonicalish(&cwd))
                .ok()
                .map(Path::to_path_buf)
        })
        .unwrap_or(path);
    let value = display.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        ".".into()
    } else {
        value
    }
}

fn canonicalish(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        }
    })
}

fn resolved_pair(invocation: &BuildInvocation) -> Option<(PathBuf, PathBuf)> {
    Some((
        canonicalish(Path::new(invocation.dockerfile.value.as_ref()?)),
        canonicalish(Path::new(invocation.context.value.as_ref()?)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_interpolation_is_not_replaced_with_empty_text() {
        match interpolate("images/${MISSING}/Dockerfile", &BTreeMap::new()) {
            Interpolation::Unresolved(expression, _) => {
                assert_eq!(expression, "images/${MISSING}/Dockerfile")
            }
            Interpolation::Resolved(..) => panic!("missing variable was resolved"),
        }
    }

    #[test]
    fn matrix_expansion_is_deterministic() {
        let raw = RawBuild {
            context: Some("${arch}".into()),
            matrix: BTreeMap::from([("arch".into(), vec!["amd64".into(), "arm64".into()])]),
            ..RawBuild::default()
        };
        let values = expand_matrix(&raw);
        assert_eq!(values[0].0, "[arch=amd64]");
        assert_eq!(values[1].1.context.as_deref(), Some("arm64"));
    }

    #[test]
    fn hcl_matrix_values_resolve_and_unknown_arguments_remain_unresolved() {
        let targets = parse_bake_hcl(
            r#"
target "release" {
  matrix = { arch = ["amd64", "arm64"] }
  platforms = ["linux/${arch}"]
  args = { ARCH = arch, UNKNOWN = missing_value }
}
"#,
        )
        .unwrap();
        let amd64 = &targets["release[arch=amd64]"];
        assert_eq!(amd64.platforms, vec!["linux/amd64"]);
        assert!(matches!(amd64.args["ARCH"], RawValue::Value(ref value) if value == "amd64"));
        assert!(matches!(amd64.args["UNKNOWN"], RawValue::Unresolved(_)));
    }

    #[test]
    fn invocation_lint_deduplicates_only_identical_effective_inputs() {
        let root =
            std::env::temp_dir().join(format!("droast-invocation-lint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Dockerfile"), "FROM alpine as build\n").unwrap();
        std::fs::write(
            root.join("compose.yaml"),
            "services:\n  one:\n    build: .\n  two:\n    build: .\n",
        )
        .unwrap();
        let mut document = discover(std::slice::from_ref(&root), ContainerEngine::Docker);
        assert_eq!(document.invocations.len(), 2);
        let options = crate::linter::LintOptions {
            only_rules: vec!["DF079".into()],
            check_dockerignore: false,
            ..crate::linter::LintOptions::default()
        };
        let identical = lint(&document, &options).unwrap();
        assert_eq!(identical.len(), 1);
        assert_eq!(identical[0].invocation_ids.len(), 2);

        document.invocations[0].build_args.insert(
            "MODE".into(),
            resolved("release".into(), provenance("test", "test", "MODE", 0)),
        );
        let different = lint(&document, &options).unwrap();
        assert_eq!(different.len(), 2);
        assert!(different
            .iter()
            .all(|finding| finding.invocation_ids.len() == 1));
        std::fs::remove_dir_all(root).unwrap();
    }
}
