//! Repository-aware Dockerfile and build-context discovery.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use hcl::eval::{Context, Evaluate};
use hcl::{BlockLabel, Body, Expression, Value as HclValue};
use ignore::gitignore::GitignoreBuilder;
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
            discover_path(
                &requested_path,
                engine,
                &mut inputs,
                &mut discovery.warnings,
            );
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
    } else if engine == ContainerEngine::Podman && path.is_file() && is_quadlet_build_file(path) {
        discover_quadlet_build(path, inputs, warnings);
    } else if engine == ContainerEngine::Podman && path.is_file() && is_quadlet_kube_file(path) {
        discover_quadlet_kube(path, inputs, warnings);
    } else if engine == ContainerEngine::Podman && path.is_file() && is_kube_play_file(path) {
        discover_kube_play(path, inputs, warnings);
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
    let mut quadlet_build_files = Vec::new();
    let mut quadlet_kube_files = Vec::new();
    let mut kube_files = Vec::new();

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
        } else if engine == ContainerEngine::Podman && is_quadlet_build_file(&path) {
            quadlet_build_files.push(path);
        } else if engine == ContainerEngine::Podman && is_quadlet_kube_file(&path) {
            quadlet_kube_files.push(path);
        } else if engine == ContainerEngine::Podman && is_kube_play_file(&path) {
            kube_files.push(path);
        }
    }

    compose_files.sort();
    bake_files.sort();
    quadlet_build_files.sort();
    quadlet_kube_files.sort();
    kube_files.sort();
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
    for path in quadlet_build_files {
        discover_quadlet_build(&path, inputs, warnings);
    }
    for path in quadlet_kube_files {
        discover_quadlet_kube(&path, inputs, warnings);
    }
    for path in kube_files {
        discover_kube_play(&path, inputs, warnings);
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

fn discover_quadlet_build(
    unit: &Path,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(unit) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Quadlet build unit '{}': {error}",
                unit.display()
            ));
            return;
        }
    };
    if !quadlet_has_section(&content, "Build") {
        return;
    }
    let base = unit.parent().unwrap_or_else(|| Path::new("."));
    let files = quadlet_values(&content, "Build", "File");
    let working_directory = quadlet_values(&content, "Build", "SetWorkingDirectory")
        .into_iter()
        .last()
        .or_else(|| {
            quadlet_values(&content, "Service", "WorkingDirectory")
                .into_iter()
                .last()
        });

    if files.is_empty() {
        let Some(context) = quadlet_context(base, None, working_directory.as_deref()) else {
            warnings.push(format!(
                "Quadlet build unit '{}' has no local build context",
                unit.display()
            ));
            return;
        };
        if let Some(dockerfile) = default_containerfile(&context) {
            insert_referenced(inputs, dockerfile, context, "Quadlet build", unit, warnings);
        } else {
            warnings.push(format!(
                "Quadlet build unit '{}' has no Containerfile or Dockerfile in '{}'",
                unit.display(),
                context.display()
            ));
        }
        return;
    }

    for file in files {
        if file == "-" {
            warnings.push(format!(
                "Quadlet build unit '{}' reads its Containerfile from stdin and cannot be discovered",
                unit.display()
            ));
            continue;
        }
        let Some(dockerfile) = resolve_local_path(base, &file) else {
            warnings.push(format!(
                "Quadlet build unit '{}' references a non-local Containerfile '{file}'",
                unit.display()
            ));
            continue;
        };
        let Some(context) = quadlet_context(base, Some(&dockerfile), working_directory.as_deref())
        else {
            warnings.push(format!(
                "Quadlet build unit '{}' has a non-local build context",
                unit.display()
            ));
            continue;
        };
        insert_referenced(inputs, dockerfile, context, "Quadlet build", unit, warnings);
    }
}

fn discover_quadlet_kube(
    unit: &Path,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(unit) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Quadlet kube unit '{}': {error}",
                unit.display()
            ));
            return;
        }
    };
    if !quadlet_has_section(&content, "Kube") {
        return;
    }
    let base = unit.parent().unwrap_or_else(|| Path::new("."));
    for yaml in quadlet_values(&content, "Kube", "Yaml") {
        let Some(path) = resolve_local_path(base, &yaml) else {
            warnings.push(format!(
                "Quadlet kube unit '{}' references a non-local YAML source '{yaml}'",
                unit.display()
            ));
            continue;
        };
        if path.is_file() {
            discover_kube_play(&path, inputs, warnings);
        } else {
            warnings.push(format!(
                "Quadlet kube unit '{}' references missing YAML '{}'",
                unit.display(),
                path.display()
            ));
        }
    }
}

fn discover_kube_play(
    yaml_file: &Path,
    inputs: &mut BTreeMap<(PathBuf, PathBuf), BuildInput>,
    warnings: &mut Vec<String>,
) {
    let content = match std::fs::read_to_string(yaml_file) {
        Ok(content) => content,
        Err(error) => {
            warnings.push(format!(
                "cannot read Kubernetes YAML '{}': {error}",
                yaml_file.display()
            ));
            return;
        }
    };
    let document: YamlValue = match serde_yaml::from_str(&content) {
        Ok(document) => document,
        Err(error) => {
            warnings.push(format!(
                "cannot parse Kubernetes YAML '{}': {error}",
                yaml_file.display()
            ));
            return;
        }
    };
    let base = yaml_file.parent().unwrap_or_else(|| Path::new("."));
    for image in kube_image_values(&document) {
        let Some(image_dir) = local_kube_image_directory(&image) else {
            continue;
        };
        let context = base.join(image_dir);
        let Some(dockerfile) = default_containerfile(&context) else {
            continue;
        };
        insert_referenced(
            inputs,
            dockerfile,
            context,
            "Podman kube play",
            yaml_file,
            warnings,
        );
    }
}

fn quadlet_values(content: &str, target_section: &str, target_key: &str) -> Vec<String> {
    let mut section = "";
    let mut values = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
        {
            section = name.trim();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section.eq_ignore_ascii_case(target_section)
            && key.trim().eq_ignore_ascii_case(target_key)
        {
            values.push(value.trim().to_string());
        }
    }
    values
}

fn quadlet_has_section(content: &str, target_section: &str) -> bool {
    content.lines().any(|line| {
        line.trim()
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
            .is_some_and(|name| name.trim().eq_ignore_ascii_case(target_section))
    })
}

fn quadlet_context(base: &Path, dockerfile: Option<&Path>, value: Option<&str>) -> Option<PathBuf> {
    match value.unwrap_or("file") {
        "file" => dockerfile.and_then(Path::parent).map(Path::to_path_buf),
        "unit" => Some(base.to_path_buf()),
        value => resolve_local_path(base, value),
    }
}

fn default_containerfile(context: &Path) -> Option<PathBuf> {
    ["Containerfile", "Dockerfile"]
        .into_iter()
        .map(|name| context.join(name))
        .find(|path| path.is_file())
}

fn kube_image_values(document: &YamlValue) -> Vec<String> {
    let mut images = Vec::new();
    collect_kube_image_values(document, &mut images);
    images
}

fn collect_kube_image_values(value: &YamlValue, images: &mut Vec<String>) {
    match value {
        YamlValue::Mapping(entries) => {
            for (key, value) in entries {
                if key.as_str() == Some("image") {
                    if let Some(image) = value.as_str() {
                        images.push(image.to_string());
                    }
                }
                collect_kube_image_values(value, images);
            }
        }
        YamlValue::Sequence(values) => {
            for value in values {
                collect_kube_image_values(value, images);
            }
        }
        _ => {}
    }
}

fn local_kube_image_directory(image: &str) -> Option<&str> {
    if image.is_empty()
        || image.contains('/')
        || image.contains(':')
        || image.contains('@')
        || image == "latest"
    {
        return None;
    }
    Some(image)
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
    let effective = match effective_ignorefile(dockerfile, context, engine) {
        Some(path) => path,
        None => {
            return Ok(Some(DockerignoreProblem::Missing {
                expected: expected_ignorefile(dockerfile, context, engine),
            }))
        }
    };
    let content = std::fs::read_to_string(&effective)?;
    if has_exclusion_pattern(&content) {
        Ok(None)
    } else {
        Ok(Some(DockerignoreProblem::Empty { path: effective }))
    }
}

fn expected_ignorefile(_dockerfile: &Path, context: &Path, engine: ContainerEngine) -> PathBuf {
    match engine {
        ContainerEngine::Docker => context.join(".dockerignore"),
        ContainerEngine::Podman => context.join(".containerignore"),
    }
}

fn effective_ignorefile(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
) -> Option<PathBuf> {
    let specific = dockerfile
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(
            "{}.dockerignore",
            dockerfile
                .file_name()
                .unwrap_or_else(|| OsStr::new("Dockerfile"))
                .to_string_lossy()
        ));
    let root = context.join(".dockerignore");
    let container = context.join(".containerignore");
    match engine {
        ContainerEngine::Docker if specific.is_file() => Some(specific),
        ContainerEngine::Docker if root.is_file() => Some(root),
        ContainerEngine::Podman if container.is_file() => Some(container),
        ContainerEngine::Podman if root.is_file() => Some(root),
        _ => None,
    }
}

/// Return local COPY/ADD sources that are excluded by the effective ignore file.
/// This uses gitignore-compatible matching for Docker's documented pattern subset;
/// unusual Docker-only pattern behavior remains deliberately conservative.
pub fn ignored_copy_sources(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
) -> std::io::Result<Vec<(usize, String)>> {
    let Some(ignorefile) = effective_ignorefile(dockerfile, context, engine) else {
        return Ok(Vec::new());
    };
    let mut builder = GitignoreBuilder::new(context);
    builder.add(&ignorefile);
    let matcher = builder.build().map_err(std::io::Error::other)?;
    let ignorefile_content = std::fs::read_to_string(&ignorefile)?;
    let root_excluded = context_root_excluded(&ignorefile_content);
    let content = std::fs::read_to_string(dockerfile)?;
    let document = crate::parser::parse_document(&content);
    let mut ignored = Vec::new();
    for instruction in document
        .instructions
        .iter()
        .filter(|instruction| matches!(instruction.instruction.as_str(), "COPY" | "ADD"))
    {
        // Sources of a staged or named-context copy never come from the build
        // context, so the ignore file says nothing about them.
        if instruction
            .words
            .iter()
            .any(|word| word.value.to_ascii_lowercase().starts_with("--from="))
        {
            continue;
        }
        let words = instruction
            .words
            .iter()
            .filter(|word| !word.value.starts_with("--"))
            .collect::<Vec<_>>();
        let source_count = words.len().saturating_sub(1);
        for source in words.into_iter().take(source_count) {
            if source.value.contains("://")
                || source.value.contains('*')
                || source.value.contains('?')
            {
                continue;
            }
            let cleaned = clean_context_path(&source.value);
            if cleaned == "." || cleaned == "/" {
                // The build-context root is not a regular entry that a pattern
                // can exclude; only a catch-all leaves nothing to copy.
                if root_excluded {
                    ignored.push((instruction.line, source.value.clone()));
                }
                continue;
            }
            if cleaned.starts_with('/') {
                continue;
            }
            let candidate = context.join(&cleaned);
            if matcher
                .matched_path_or_any_parents(&candidate, false)
                .is_ignore()
                && !negation_may_rescue_children(&ignorefile_content, &cleaned)
            {
                ignored.push((instruction.line, source.value.clone()));
            }
        }
    }
    Ok(ignored)
}

/// Whether a negation pattern in the ignore file could still rescue some file
/// nested under `cleaned`. Unlike git, Docker's build-context filter does not
/// prune matching once an ancestor directory is excluded: patterns are
/// applied per file, so a later `!` pattern can re-include a file even though
/// an earlier pattern (such as a bare `*`) excluded one of its parent
/// directories. When such a pattern exists we cannot tell, without walking
/// the real build context, whether every file under a directory source ends
/// up excluded, so DF077 stays quiet rather than risk a false positive.
fn negation_may_rescue_children(content: &str, cleaned: &str) -> bool {
    let prefix = format!("{cleaned}/");
    for (index, line) in content.lines().enumerate() {
        let line = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let pattern = line.trim();
        let Some(negated) = pattern.strip_prefix('!') else {
            continue;
        };
        let negated = negated.trim();
        if negated.is_empty() {
            continue;
        }
        let target = clean_context_path(negated);
        let target = target.trim_start_matches('/');
        if target.starts_with("**") || target.starts_with(&prefix) || target == cleaned {
            return true;
        }
    }
    false
}

/// Whether the ignore file excludes every entry at the build-context root.
/// Docker cleans each pattern before matching, so `*`, `/*`, `./*`, and `*/`
/// are the same catch-all, while any negation can bring root entries back.
fn context_root_excluded(content: &str) -> bool {
    let mut catch_all = false;
    for (index, line) in content.lines().enumerate() {
        let line = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let pattern = line.trim();
        if pattern.is_empty() || pattern.starts_with('#') {
            continue;
        }
        if pattern.starts_with('!') {
            return false;
        }
        if matches!(
            clean_context_path(pattern).trim_start_matches('/'),
            "*" | "**" | "**/*"
        ) {
            catch_all = true;
        }
    }
    catch_all
}

/// Lexically clean a build-context path the way Docker does before matching it,
/// collapsing `.` and `..` components and redundant separators.
fn clean_context_path(value: &str) -> String {
    let rooted = value.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            part => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// The common broad-copy hazards used as a narrow signal for diagnostic wording.
const COMMON_COPY_ALL_HAZARDS: [(&str, bool); 4] = [
    (".git", true),
    ("node_modules", true),
    (".env", false),
    ("dist", true),
];

/// Whether the effective ignore file excludes the common broad-copy hazards
/// `.git`, `node_modules`, `.env`, and `dist`. This is deliberately a narrow
/// signal for diagnostic wording, not proof that `COPY .` is optimal.
pub fn ignores_common_copy_all_hazards(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
) -> std::io::Result<bool> {
    Ok(
        unignored_common_copy_all_hazards(dockerfile, context, engine)?
            .is_some_and(|unignored| unignored.is_empty()),
    )
}

/// The common broad-copy hazards that the effective ignore file does *not*
/// exclude. Returns `None` when there is no effective ignore file at all, so
/// callers can distinguish "no ignore file" from "ignore file misses some
/// hazards".
pub fn unignored_common_copy_all_hazards(
    dockerfile: &Path,
    context: &Path,
    engine: ContainerEngine,
) -> std::io::Result<Option<Vec<&'static str>>> {
    let Some(ignorefile) = effective_ignorefile(dockerfile, context, engine) else {
        return Ok(None);
    };
    let mut builder = GitignoreBuilder::new(context);
    builder.add(ignorefile);
    let matcher = builder.build().map_err(std::io::Error::other)?;
    Ok(Some(
        COMMON_COPY_ALL_HAZARDS
            .into_iter()
            .filter(|(path, is_dir)| {
                !matcher
                    .matched_path_or_any_parents(context.join(path), *is_dir)
                    .is_ignore()
            })
            .map(|(path, _)| path)
            .collect(),
    ))
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
    // Dockerfile-specific ignore files share the Dockerfile name prefix, but
    // are build-context metadata rather than Dockerfiles.
    if name.ends_with(".dockerignore") {
        return false;
    }
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
        || name
            .strip_suffix(".dockerfile")
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

fn is_quadlet_build_file(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("build"))
}

fn is_quadlet_kube_file(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("kube"))
}

fn is_kube_play_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name == "kube.yaml"
        || name == "kube.yml"
        || name.ends_with(".kube.yaml")
        || name.ends_with(".kube.yml")
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
    use super::{
        clean_context_path, context_root_excluded, has_exclusion_pattern, interpolate_path,
        is_dockerfile_name,
    };
    use std::collections::HashMap;
    use std::path::Path;

    #[test]
    fn dockerfile_name_patterns_are_exact() {
        for name in [
            "Dockerfile",
            "Dockerfile.dev",
            "web.Dockerfile",
            "web.dockerfile",
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
            "Dockerfile.dockerignore",
            "Containerfile.release.dockerignore",
        ] {
            assert!(!is_dockerfile_name(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn context_paths_are_cleaned_like_docker() {
        for (value, cleaned) in [
            (".", "."),
            ("./", "."),
            ("./.", "."),
            ("", "."),
            ("/", "/"),
            ("./src", "src"),
            ("src/", "src"),
            ("./src//app/", "src/app"),
            ("src/../app", "app"),
            ("../app", "../app"),
            ("./*", "*"),
            ("*/", "*"),
            ("/*", "/*"),
        ] {
            assert_eq!(clean_context_path(value), cleaned, "{value}");
        }
    }

    #[test]
    fn only_catch_all_patterns_exclude_the_context_root() {
        for content in [
            "*\n",
            "**\n",
            "**/*\n",
            "/*\n",
            "./*\n",
            "*/\n",
            "# c\nsrc\n*\n",
        ] {
            assert!(context_root_excluded(content), "{content:?}");
        }
        for content in [
            ".*\n",
            ".\n",
            "src\n",
            "*.txt\n",
            "**/*.txt\n",
            "*\n!src\n",
            "",
        ] {
            assert!(!context_root_excluded(content), "{content:?}");
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

    #[test]
    fn unignored_hazards_distinguish_missing_partial_and_complete_ignore_files() {
        use super::{unignored_common_copy_all_hazards, ContainerEngine};

        let root =
            std::env::temp_dir().join(format!("droast-unignored-hazards-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dockerfile = root.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM alpine:3.20\nCOPY . .\n").unwrap();

        // No ignore file at all: caller cannot re-word, gets None.
        assert_eq!(
            unignored_common_copy_all_hazards(&dockerfile, &root, ContainerEngine::Docker).unwrap(),
            None
        );

        // Partial ignore file: the missed hazards are reported.
        std::fs::write(root.join(".dockerignore"), "target/\nbin/\n").unwrap();
        assert_eq!(
            unignored_common_copy_all_hazards(&dockerfile, &root, ContainerEngine::Docker).unwrap(),
            Some(vec![".git", "node_modules", ".env", "dist"])
        );

        // Complete ignore file: nothing left unignored.
        std::fs::write(
            root.join(".dockerignore"),
            ".git\nnode_modules\n.env\ndist\n",
        )
        .unwrap();
        assert_eq!(
            unignored_common_copy_all_hazards(&dockerfile, &root, ContainerEngine::Docker).unwrap(),
            Some(Vec::new())
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
