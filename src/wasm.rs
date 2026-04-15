use wasm_bindgen::prelude::*;
use serde::Serialize;
use crate::{parser, rules};

#[derive(Serialize)]
struct WasmFinding {
    rule: String,
    severity: String,
    line: usize,
    message: String,
    roast: String,
}

#[derive(Serialize)]
struct WasmResult {
    total: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
    findings: Vec<WasmFinding>,
}

/// Lint a Dockerfile passed as a string; returns findings as a JSON string.
#[wasm_bindgen]
pub fn lint(content: &str) -> String {
    let instructions = parser::parse(content);

    let mut findings: Vec<rules::Finding> = Vec::new();
    for rule in rules::all_rules() {
        findings.extend((rule.func)(&instructions, content));
    }

    findings.sort_by(|a, b| {
        a.line.cmp(&b.line).then(b.severity.cmp(&a.severity))
    });

    let result = WasmResult {
        total: findings.len(),
        errors: findings.iter().filter(|f| f.severity == rules::Severity::Error).count(),
        warnings: findings.iter().filter(|f| f.severity == rules::Severity::Warning).count(),
        infos: findings.iter().filter(|f| f.severity == rules::Severity::Info).count(),
        findings: findings.iter().map(|f| WasmFinding {
            rule: f.rule.to_string(),
            severity: f.severity.to_string(),
            line: f.line,
            message: f.message.clone(),
            roast: f.roast.clone(),
        }).collect(),
    };

    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
