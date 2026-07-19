//! Repository-aware Dockerfile and build-context discovery.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use hcl::eval::{Context, Evaluate};
use hcl::{BlockLabel, Body, Expression, Value as HclValue};
use ignore::WalkBuilder;
use serde_yaml::Value as YamlValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInput {
    pub dockerfile: PathBuf,
    pub context: PathBuf,
}

/// Selects build-context conventions without invoking a container engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerEngine {
    Docker,
    Podman,
}

impl ContainerEngine {
    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.unwrap_or("docker").to_ascii_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            other => anyhow::bail!("Unknown workflow engine '{other}'; expected docker or podman"),
        }
    }
}

#[derive(Debug, Default)]
pub struct Discovery {
    pub inputs: Vec<BuildInput>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerignoreProblem {
    Missing { expected: PathBuf },
    Empty { path: PathBuf },
}

/// Resolve CLI paths into local Dockerfiles and their effective build contexts.
pub fn discover(requested: &[PathBuf], engine: ContainerEngine) -> Discovery {
    let requested = if requested.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        requested.to_vec()
    };
    let mut discovery = Discovery::default();
    let mut inputs = BTreeMap::<(PathBuf, PathBuf), BuildInput>::new();

    for requested_path in requested {
        let pattern = requested_path.to_string_lossy();
        if contains_glob(&pattern) {
            match glob::glob(&pattern) {
                Ok(matches) => {
                    for path in matches.flatten() {
                        discover_path(&path, engine, &mut inputs, &mut discovery.warnings);
                    }
                }
                Err(error) => discovery
                    .warnings
                    .push(format!("invalid path pattern {pattern:?}: {error}")),
            }
        } else {
            discover_path(&requested_path, engine, &mut inputs, &mut discovery.warnings);
        }
    }

    discovery.inputs = inputs.into_values().collect();
    discovery
}

fn discover_path(
    path: &Path,
    engine: ContainerEngine,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    if path == Path::new("-") {
        insert_input(inputs, path.to_path_buf(), current_directory());
    } else if path.is_dir() {
        discover_directory(path, engine, inputs, warnings);
    } else if path.is_file() && is_compose_file(path) {
        discover_compose(path, inputs, warnings);
    } else if path.is_file() && is_bake_file(path) {
        discover_bake(path, inputs, warnings);
    } else {
        let context = path.parent().unwrap_or_else(|| Path::new("."));
        insert_input(inputs, path.to_path_buf(), absolute_path(context));
    }
}

fn discover_directory(
    root: &Path,
    engine: ContainerEngine,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let mut dockerfiles = Vec::new();
    let mut compose_files = Vec::new();
    let mut bake_files = Vec::new();

    let mut walker = WalkBuilder::new(root);
    walker
        .follow_links(false)
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true);
    for entry in walker.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!("cannot inspect repository entry: {error}"));
                continue;
            }
        };
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let path = entry.into_path();
        if is_dockerfile_name(&path) {
            dockerfiles.push(path);
        } else if is_compose_file(&path) {
            compose_files.push(path);
        } else if is_bake_file(&path) {
            bake_files.push(path);
        }
    }

    compose_files.sort();
    bake_files.sort();
    dockerfiles.sort();

    // Build definitions carry stronger context information than filename-only
    // discovery, so process them first. Pair-based deduplication preserves the
    // legitimate case where one Dockerfile is built from multiple contexts.
    for path in compose_files {
        discover_compose(&path, inputs, warnings);
    }
    for path in bake_files {
        discover_bake(&path, inputs, warnings);
    }
    for dockerfile in dockerfiles {
        if contains_dockerfile(inputs, &dockerfile) {
            continue;
        }
        let context = infer_context(&dockerfile, root, engine);
        insert_input(inputs, dockerfile, context);
    }
}

fn contains_dockerfile(
    inputs: &BTreeMap<(PathBuf, PathBuf), BuildInput>,
    dockerfile: &Path,
) -> bool {
    let dockerfile = absolute_path(dockerfile);
    inputs.keys().any(|(known, _)| known == &dockerfile)
}

fn infer_context(dockerfile: &Path, repository_root: &Path, engine: ContainerEngine) -> PathBuf {
    let root = absolute_path(repository_root);
    let mut directory = dockerfile
        .parent()
        .map(absolute_path)
        .unwrap_or_else(|| root.clone());
    loop {
        if has_context_ignore_file(&directory, engine) {
            return directory;
        }
        if directory == root || !directory.starts_with(&root) {
            return root;
        }
        let Some(parent) = directory.parent() else {
            return root;
        };
        directory = parent.to_path_buf();
    }
}

fn has_context_ignore_file(context: &Path, engine: ContainerEngine) -> bool {
    match engine {
        ContainerEngine::Docker => context.join(".dockerignore").is_file(),
        ContainerEngine::Podman => {
            context.join(".containerignore").is_file() || context.join(".dockerignore").is_file()
        }
    }
}

fn discover_compose(
    compose_file: &Path,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(compose_file) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Compose file '{}': {error}",
                compose_file.display()
            ));
            return;
        }
    };
    let document: YamlValue = match serde_yaml::from_str(&content) {
        Ok(document) => document,
        Err(error) => {
            warnings.push(format!(
                "cannot parse Compose file '{}': {error}",
                compose_file.display()
            ));
            return;
        }
    };
    let Some(services) = yaml_mapping_value(&document, "services").and_then(YamlValue::as_mapping)
    else {
        return;
    };
    let project_dir = compose_file.parent().unwrap_or_else(|| Path::new("."));
    let environment = compose_environment(project_dir);

    for (service_name, service) in services {
        let Some(build) = yaml_mapping_value(service, "build") else {
            continue;
        };
        let name = service_name.as_str().unwrap_or("<unnamed>");
        let (context_value, dockerfile_value) = match build {
            YamlValue::String(context) => (Some(context.as_str()), Some("Dockerfile")),
            YamlValue::Mapping(_) => {
                if yaml_mapping_value(build, "dockerfile_inline").is_some() {
                    continue;
                }
                (
                    yaml_mapping_value(build, "context").and_then(YamlValue::as_str),
                    yaml_mapping_value(build, "dockerfile")
                        .and_then(YamlValue::as_str)
                        .or(Some("Dockerfile")),
                )
            }
            _ => continue,
        };
        let Some(context_value) = interpolate_path(context_value.unwrap_or("."), &environment)
        else {
            warnings.push(format!(
                "Compose service {name:?} in '{}' has an unresolved build context",
                compose_file.display()
            ));
            continue;
        };
        let Some(dockerfile_value) =
            dockerfile_value.and_then(|value| interpolate_path(value, &environment))
        else {
            warnings.push(format!(
                "Compose service {name:?} in '{}' has an unresolved Dockerfile path",
                compose_file.display()
            ));
            continue;
        };
        let Some(context) = resolve_local_path(project_dir, &context_value) else {
            continue;
        };
        let dockerfile = resolve_path(&context, &dockerfile_value);
        insert_referenced(
            inputs,
            dockerfile,
            context,
            "Compose",
            compose_file,
            warnings,
        );
    }
}

fn yaml_mapping_value<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    value.as_mapping()?.get(YamlValue::String(key.to_string()))
}

#[derive(Debug, Default, Clone)]
struct BakeTarget {
    context: Option<String>,
    dockerfile: Option<String>,
    inherits: Vec<String>,
    inline: bool,
}

fn discover_bake(
    bake_file: &Path,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(bake_file) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Bake file '{}': {error}",
                bake_file.display()
            ));
            return;
        }
    };
    let targets = if bake_file.extension() == Some(OsStr::new("json")) {
        match parse_bake_json(&content) {
            Ok(targets) => targets,
            Err(error) => {
                warnings.push(format!(
                    "cannot parse Bake file '{}': {error}",
                    bake_file.display()
                ));
                return;
            }
        }
    } else {
        match parse_bake_hcl(&content) {
            Ok(targets) => targets,
            Err(error) => {
                warnings.push(format!(
                    "cannot parse Bake file '{}': {error}",
                    bake_file.display()
                ));
                return;
            }
        }
    };
    let base = bake_file.parent().unwrap_or_else(|| Path::new("."));

    for name in targets.keys() {
        let mut visiting = HashSet::new();
        let Some(target) = resolve_bake_target(name, &targets, &mut visiting) else {
            warnings.push(format!(
                "Bake target {name:?} in '{}' has cyclic or missing inheritance",
                bake_file.display()
            ));
            continue;
        };
        if target.inline {
            continue;
        }
        let context_value = target.context.as_deref().unwrap_or(".");
        let dockerfile_value = target.dockerfile.as_deref().unwrap_or("Dockerfile");
        let Some(context) = resolve_local_path(base, context_value) else {
            continue;
        };
        let dockerfile = resolve_path(&context, dockerfile_value);
        insert_referenced(inputs, dockerfile, context, "Bake", bake_file, warnings);
    }
}

fn parse_bake_json(content: &str) -> Result<HashMap<String, BakeTarget>, serde_json::Error> {
    let document: serde_json::Value = serde_json::from_str(content)?;
    let mut result = HashMap::new();
    let Some(targets) = document
        .get("target")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(result);
    };
    for (name, target) in targets {
        let inherits = target.get("inherits").map(json_strings).unwrap_or_default();
        result.insert(
            name.clone(),
            BakeTarget {
                context: target
                    .get("context")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                dockerfile: target
                    .get("dockerfile")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                inherits,
                inline: target.get("dockerfile-inline").is_some()
                    || target.get("dockerfile_inline").is_some(),
            },
        );
    }
    Ok(result)
}

fn json_strings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(value) => vec![value.clone()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_bake_hcl(content: &str) -> Result<HashMap<String, BakeTarget>, hcl::Error> {
    let body: Body = hcl::parse(content)?;
    let mut context = Context::new();
    for block in body
        .blocks()
        .filter(|block| block.identifier() == "variable")
    {
        let Some(name) = block_label(block.labels.first()) else {
            continue;
        };
        let value = std::env::var(name).ok().map(HclValue::from).or_else(|| {
            hcl_attribute(block, "default")
                .and_then(|expression| expression.evaluate(&context).ok())
        });
        if let Some(value) = value {
            context.declare_var(name, value);
        }
    }

    let mut result = HashMap::new();
    for block in body.blocks().filter(|block| block.identifier() == "target") {
        let Some(name) = block_label(block.labels.first()) else {
            continue;
        };
        let string_attribute = |key| {
            hcl_attribute(block, key)
                .and_then(|expression| expression.evaluate(&context).ok())
                .and_then(|value| value.as_str().map(str::to_string))
        };
        let inherits = hcl_attribute(block, "inherits")
            .and_then(|expression| expression.evaluate(&context).ok())
            .map(hcl_strings)
            .unwrap_or_default();
        result.insert(
            name.to_string(),
            BakeTarget {
                context: string_attribute("context"),
                dockerfile: string_attribute("dockerfile"),
                inherits,
                inline: hcl_attribute(block, "dockerfile-inline").is_some(),
            },
        );
    }
    Ok(result)
}

fn block_label(label: Option<&BlockLabel>) -> Option<&str> {
    match label? {
        BlockLabel::Identifier(value) => Some(value.as_str()),
        BlockLabel::String(value) => Some(value),
    }
}

fn hcl_attribute<'a>(block: &'a hcl::Block, key: &str) -> Option<&'a Expression> {
    block
        .body
        .attributes()
        .find(|attribute| attribute.key() == key)
        .map(|attribute| attribute.expr())
}

fn hcl_strings(value: HclValue) -> Vec<String> {
    match value {
        HclValue::String(value) => vec![value],
        HclValue::Array(values) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn resolve_bake_target(
    name: &str,
    targets: &HashMap<String, BakeTarget>,
    visiting: &mut HashSet<String>,
) -> Option<BakeTarget> {
    if !visiting.insert(name.to_string()) {
        return None;
    }
    let target = targets.get(name)?;
    let mut resolved = BakeTarget::default();
    for parent in &target.inherits {
        let inherited = resolve_bake_target(parent, targets, visiting)?;
        merge_bake_target(&mut resolved, inherited);
    }
    merge_bake_target(&mut resolved, target.clone());
    visiting.remove(name);
    Some(resolved)
}

fn merge_bake_target(base: &mut BakeTarget, override_target: BakeTarget) {
    if override_target.context.is_some() {
        base.context = override_target.context;
    }
    if override_target.dockerfile.is_some() {
        base.dockerfile = override_target.dockerfile;
        base.inline = false;
    }
    if override_target.inline {
        base.dockerfile = None;
        base.inline = true;
    }
}

fn insert_referenced(
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    dockerfile: PathBuf,
    context: PathBuf,
    kind: &str,
    definition: &Path,
    warnings: &mut Vec<String>,
) {
    if dockerfile.is_file() {
        insert_input(inputs, dockerfile, absolute_path(&context));
    } else {
        warnings.push(format!(
            "{kind} file '{}' references missing Dockerfile '{}'",
            definition.display(),
            dockerfile.display()
        ));
    }
}

fn insert_input(
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    dockerfile: PathBuf,
    context: PathBuf,
) {
    let dockerfile_key = if dockerfile == Path::new("-") {
        dockerfile.clone()
    } else {
        absolute_path(&dockerfile)
    };
    let context = absolute_path(&context);
    let display_path = relative_to_current_directory(&dockerfile_key);
    inputs
        .entry((dockerfile_key, context.clone()))
        .or_insert(BuildInput {
            dockerfile: display_path,
            context,
        });
}

/// Return the missing or ineffective ignore file for a build input.
pub fn ignorefile_problem(
    dockerfile: &Path,
    context: &Path,
) -> std::io::Result<Option<DockerignoreProblem>> {
    ignorefile_problem_for_engine(dockerfile, context, ContainerEngine::Docker)
}

/// Return the missing or ineffective ignore file selected by the chosen engine.
pub fn ignorefile_problem_for_engine(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
) -> std::io::Result<Option<DockerignoreProblem>> {
    let specific = dockerfile.parent().unwrap_or_else(|| Path::new(".")).join(format!(
        "{}.dockerignore",
        dockerfile.file_name().unwrap_or_else(|| OsStr::new("Dockerfile")).to_string_lossy()
    ));
    let root = context.join(".dockerignore");
    let container = context.join(".containerignore");
    let effective = match engine {
        ContainerEngine::Docker => {
            if specific.is_file() {
                specific
            } else if root.is_file() {
                root.clone()
            } else {
                return Ok(Some(DockerignoreProblem::Missing { expected: root }));
            }
        }
        ContainerEngine::Podman => {
            if container.is_file() {
                container
            } else if root.is_file() {
                root.clone()
            } else {
                return Ok(Some(DockerignoreProblem::Missing { expected: container }));
            }
        }
    };
    let content = std::fs::read_to_string(&effective)?;
    if has_exclusion_pattern(&content) {
        Ok(None)
    } else {
        Ok(Some(DockerignoreProblem::Empty { path: effective }))
    }
}

fn has_exclusion_pattern(content: &str) -> bool {
    content.lines().enumerate().any(|(index, line)| {
        let line = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        if line.starts_with('#') {
            return false;
        }
        let pattern = line.trim();
        !pattern.is_empty() && pattern != "." && !pattern.starts_with('!')
    })
}

fn is_dockerfile_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name == "Dockerfile"
        || name == "Containerfile"
        || name
            .strip_prefix("Dockerfile.")
            .is_some_and(|suffix| !suffix.is_empty())
        || name
            .strip_prefix("Containerfile.")
            .is_some_and(|suffix| !suffix.is_empty())
        || name
            .strip_suffix(".Dockerfile")
            .is_some_and(|prefix| !prefix.is_empty())
}

fn is_compose_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    (name == "compose.yaml"
        || name == "compose.yml"
        || name == "docker-compose.yaml"
        || name == "docker-compose.yml")
        || ((name.starts_with("compose.") || name.starts_with("docker-compose."))
            && (name.ends_with(".yaml") || name.ends_with(".yml")))
}

fn is_bake_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name.starts_with("docker-bake") && (name.ends_with(".hcl") || name.ends_with(".json"))
}

fn contains_glob(path: &str) -> bool {
    path.contains('*') || path.contains('?') || path.contains('[')
}

fn compose_environment(project_dir: &Path) -> HashMap<String, String> {
    let mut environment = HashMap::new();
    let dotenv = project_dir.join(".env");
    if dotenv.is_file() {
        if let Ok(entries) = dotenvy::from_path_iter(dotenv) {
            environment.extend(entries.flatten());
        }
    }
    environment.extend(std::env::vars());
    environment
}

fn interpolate_path(value: &str, environment: &HashMap<String, String>) -> Option<String> {
    let mut result = String::new();
    let chars = value.as_bytes();
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index] != b'$' {
            let character = value[index..].chars().next()?;
            result.push(character);
            index += character.len_utf8();
            continue;
        }
        if chars.get(index + 1) == Some(&b'$') {
            result.push('$');
            index += 2;
            continue;
        }
        if chars.get(index + 1) == Some(&b'{') {
            let end = value[index + 2..].find('}')? + index + 2;
            let expression = &value[index + 2..end];
            let name_end = expression
                .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .unwrap_or(expression.len());
            let name = &expression[..name_end];
            if name.is_empty() {
                return None;
            }
            let operator = &expression[name_end..];
            let current = environment.get(name);
            let replacement = if let Some(default) = operator.strip_prefix(":-") {
                current
                    .filter(|value| !value.is_empty())
                    .map(String::as_str)
                    .unwrap_or(default)
            } else if let Some(default) = operator.strip_prefix('-') {
                current.map(String::as_str).unwrap_or(default)
            } else if let Some(alternative) = operator.strip_prefix(":+") {
                if current.is_some_and(|value| !value.is_empty()) {
                    alternative
                } else {
                    ""
                }
            } else if let Some(alternative) = operator.strip_prefix('+') {
                if current.is_some() {
                    alternative
                } else {
                    ""
                }
            } else if operator.starts_with(":?") {
                current
                    .filter(|value| !value.is_empty())
                    .map(String::as_str)?
            } else if operator.starts_with('?') || operator.is_empty() {
                current.map(String::as_str)?
            } else {
                return None;
            };
            result.push_str(replacement);
            index = end + 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while chars
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            end += 1;
        }
        if end == start {
            return None;
        }
        result.push_str(environment.get(&value[start..end])?);
        index = end;
    }
    Some(expand_home(result))
}

fn expand_home(value: String) -> String {
    if value == "~" || value.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(value.strip_prefix("~/").unwrap_or(""))
                .to_string_lossy()
                .into_owned();
        }
    }
    value
}

fn resolve_local_path(base: &Path, value: &str) -> Option<PathBuf> {
    if value.contains("://") || value.starts_with("git@") || value.starts_with("target:") {
        return None;
    }
    Some(resolve_path(base, value))
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            current_directory().join(path)
        }
    })
}

fn current_directory() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn relative_to_current_directory(path: &Path) -> PathBuf {
    path.strip_prefix(current_directory())
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{has_exclusion_pattern, interpolate_path, is_dockerfile_name};
    use std::collections::HashMap;
    use std::path::Path;

    #[test]
    fn dockerfile_name_patterns_are_exact() {
        for name in [
            "Dockerfile",
            "Dockerfile.dev",
            "web.Dockerfile",
            "Containerfile",
            "Containerfile.release",
        ] {
            assert!(is_dockerfile_name(Path::new(name)), "{name}");
        }
        for name in [
            "dockerfile",
            "Dockerfile.",
            ".Dockerfile",
            "myContainerfile",
        ] {
            assert!(!is_dockerfile_name(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn dockerignore_needs_a_positive_pattern() {
        assert!(!has_exclusion_pattern("# comment\n\n!README.md\n.\n"));
        assert!(has_exclusion_pattern("# comment\nnode_modules\n"));
    }

    #[test]
    fn compose_path_defaults_are_interpolated() {
        let mut environment = HashMap::new();
        environment.insert("EMPTY".to_string(), String::new());
        assert_eq!(
            interpolate_path("${MISSING:-contexts/api}", &environment),
            Some("contexts/api".into())
        );
        assert_eq!(
            interpolate_path("${EMPTY-default}", &environment),
            Some(String::new())
        );
        assert_eq!(
            interpolate_path("${EMPTY:-default}", &environment),
            Some("default".into())
        );
        assert_eq!(
            interpolate_path("cost-$$5", &environment),
            Some("cost-$5".into())
        );
    }
}
