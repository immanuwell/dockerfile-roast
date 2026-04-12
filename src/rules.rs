use crate::parser::Instruction;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub line: usize,
    pub message: String,
    pub roast: String,
}

type RuleFn = fn(&[Instruction], &str) -> Vec<Finding>;

pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub func: RuleFn,
}

pub fn all_rules() -> Vec<Rule> {
    vec![
        Rule { id: "DF001", description: "Use specific base image tags instead of 'latest'", func: rule_latest_tag },
        Rule { id: "DF002", description: "Do not run as root", func: rule_running_as_root },
        Rule { id: "DF011", description: "Use multi-stage builds to reduce image size", func: rule_no_multistage },
        Rule { id: "DF020", description: "Set explicit non-root USER", func: rule_no_user_instruction },
    ]
}

fn instrs_of<'a>(instrs: &'a [Instruction], name: &str) -> Vec<&'a Instruction> {
    instrs.iter().filter(|i| i.instruction == name).collect()
}

fn has_instr(instrs: &[Instruction], name: &str) -> bool {
    instrs.iter().any(|i| i.instruction == name)
}

fn rule_latest_tag(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "FROM")
        .into_iter()
        .filter(|i| {
            let base = i.arguments.split_whitespace().next().unwrap_or("");
            if base.eq_ignore_ascii_case("scratch") { return false; }
            base.ends_with(":latest") || (!base.contains(':') && !base.contains('@'))
        })
        .map(|i| Finding {
            rule: "DF001",
            severity: Severity::Warning,
            line: i.line,
            message: format!("'{}' uses an unpinned image tag", i.arguments.split_whitespace().next().unwrap_or(&i.arguments)),
            roast: "Pinning to 'latest' is like ordering 'whatever' at a restaurant and then \
                    complaining when your image breaks in prod. Use a real tag.".to_string(),
        })
        .collect()
}

fn rule_running_as_root(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for u in instrs_of(instrs, "USER") {
        let val = u.arguments.trim().to_lowercase();
        if val == "root" || val == "0" || val == "0:0" || val == "root:root" {
            findings.push(Finding {
                rule: "DF002",
                severity: Severity::Error,
                line: u.line,
                message: "Container is explicitly set to run as root".to_string(),
                roast: "Congratulations, you're running as root. Your security team is crying, \
                        your CISO is drafting a strongly-worded email, and a hacker somewhere \
                        just smiled.".to_string(),
            });
        }
    }
    findings
}

fn rule_no_multistage(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let from_count = instrs_of(instrs, "FROM").len();
    if from_count > 1 { return vec![]; }
    let first_from = match instrs_of(instrs, "FROM").into_iter().next() {
        Some(f) => f,
        None => return vec![],
    };
    let build_images = ["golang", "node", "rust", "maven", "gradle", "openjdk", "python", "dotnet", "gcc"];
    let img = first_from.arguments.to_lowercase();
    if build_images.iter().any(|b| img.contains(b)) {
        return vec![Finding {
            rule: "DF011",
            severity: Severity::Warning,
            line: first_from.line,
            message: "Single-stage build with a heavy build image — consider multi-stage builds".to_string(),
            roast: "Shipping your entire build toolchain to production? Your 2GB Go image is \
                    basically a free gift to anyone who gets shell access. Multi-stage builds \
                    exist. They're fantastic. Use them.".to_string(),
        }];
    }
    vec![]
}

fn rule_no_user_instruction(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if has_instr(instrs, "USER") { return vec![]; }
    if !has_instr(instrs, "CMD") && !has_instr(instrs, "ENTRYPOINT") { return vec![]; }
    vec![Finding {
        rule: "DF020",
        severity: Severity::Warning,
        line: 0,
        message: "No USER instruction found — container will run as root by default".to_string(),
        roast: "No USER set? Bold strategy. Running everything as root in prod is a great way \
                to ensure job security — for your incident response team.".to_string(),
    }]
}
