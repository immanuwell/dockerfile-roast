use crate::parser::Instruction;
use regex::Regex;

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
        Rule { id: "DF011", description: "Use multi-stage builds to reduce image size", func: rule_no_multistage },
        Rule { id: "DF013", description: "Avoid storing secrets in ENV variables", func: rule_secrets_in_env },
        Rule { id: "DF014", description: "Avoid hardcoding passwords or tokens in ARG/ENV", func: rule_hardcoded_secrets },
        Rule { id: "DF020", description: "Set explicit non-root USER", func: rule_no_user_instruction },
        Rule { id: "DF021", description: "Avoid wget|sh pipe patterns (execute remote code)", func: rule_curl_pipe_sh },
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

fn rule_secrets_in_env(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let secret_patterns = ["password", "passwd", "secret", "token", "api_key", "apikey",
                           "private_key", "auth_token", "access_key", "secret_key",
                           "db_pass", "database_password"];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "ENV") {
        let lower = i.arguments.to_lowercase();
        for pat in &secret_patterns {
            if lower.contains(pat) {
                findings.push(Finding {
                    rule: "DF013",
                    severity: Severity::Error,
                    line: i.line,
                    message: format!("Potential secret in ENV variable (matched: '{}')", pat),
                    roast: format!(
                        "You put a '{}' in an ENV instruction. Congratulations — it's now \
                         immortalized in your image layers, your registry, your CI logs, \
                         and probably a security audit finding. Use Docker secrets or a vault.",
                        pat
                    ),
                });
                break;
            }
        }
    }
    findings
}

fn rule_hardcoded_secrets(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"(?i)(password|secret|token|key|passwd)\s*=\s*\S+").unwrap();
    let mut findings = Vec::new();
    for i in instrs.iter().filter(|i| i.instruction == "ARG" || i.instruction == "ENV") {
        if let Some(cap) = re.find(&i.arguments) {
            let parts: Vec<&str> = cap.as_str().splitn(2, '=').collect();
            if parts.len() == 2 {
                let val = parts[1].trim();
                if !val.is_empty() && !val.starts_with('$') && val != "\"\"" && val != "''" {
                    findings.push(Finding {
                        rule: "DF014",
                        severity: Severity::Error,
                        line: i.line,
                        message: "Hardcoded secret value detected in ARG/ENV".to_string(),
                        roast: "A hardcoded secret! How delightfully naive. It's in your git \
                                history forever now. Have fun rotating that. Maybe consider \
                                build secrets or runtime injection next time?".to_string(),
                    });
                }
            }
        }
    }
    findings
}

fn rule_curl_pipe_sh(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"(curl|wget)[^|]*\|\s*(bash|sh|ash|zsh|fish)").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            rule: "DF021",
            severity: Severity::Error,
            line: i.line,
            message: "Piping remote script directly to shell (curl/wget | sh)".to_string(),
            roast: "curl | sh: the technical equivalent of 'hold my beer'. You're downloading \
                    code from the internet and executing it blind, inside your container, \
                    and shipping it to prod. Your threat model is vibes.".to_string(),
        })
        .collect()
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
