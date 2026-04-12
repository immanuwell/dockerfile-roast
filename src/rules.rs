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
        Rule { id: "DF004", description: "Clean apt/yum/apk cache in the same RUN layer", func: rule_uncleaned_package_cache },
        Rule { id: "DF005", description: "Pin package versions for reproducibility", func: rule_unpinned_packages },
        Rule { id: "DF015", description: "Avoid using apt-get without -y flag", func: rule_apt_no_y },
        Rule { id: "DF016", description: "Use --no-install-recommends with apt-get", func: rule_apt_recommends },
        Rule { id: "DF021", description: "Avoid wget|sh pipe patterns (execute remote code)", func: rule_curl_pipe_sh },
        Rule { id: "DF027", description: "Do not use yum without -y flag", func: rule_yum_no_y },
        Rule { id: "DF028", description: "Cache-bust apt-get update", func: rule_apt_get_update_alone },
        Rule { id: "DF029", description: "Avoid apk add without --no-cache", func: rule_apk_no_cache },
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

fn rule_uncleaned_package_cache(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        let arg = &i.arguments;
        let has_apt = arg.contains("apt-get install") || arg.contains("apt install");
        let has_yum = arg.contains("yum install") || arg.contains("dnf install");
        let has_apk = arg.contains("apk add") && !arg.contains("--no-cache");
        if has_apt && !arg.contains("rm -rf /var/lib/apt/lists") {
            findings.push(Finding {
                rule: "DF004",
                severity: Severity::Warning,
                line: i.line,
                message: "apt cache not cleaned after install — adds unnecessary layer size".to_string(),
                roast: "Not cleaning the apt cache is like finishing a meal and leaving all the \
                        wrappers in the container. Your image is now a trash can. A very expensive \
                        trash can stored in ECR.".to_string(),
            });
        }
        if has_yum && !arg.contains("yum clean all") && !arg.contains("dnf clean all") {
            findings.push(Finding {
                rule: "DF004",
                severity: Severity::Warning,
                line: i.line,
                message: "yum/dnf cache not cleaned after install".to_string(),
                roast: "You installed packages with yum but didn't clean up. Every megabyte of \
                        cache you leave is a megabyte of shame floating in your registry.".to_string(),
            });
        }
        if has_apk {
            findings.push(Finding {
                rule: "DF029",
                severity: Severity::Warning,
                line: i.line,
                message: "apk add without --no-cache flag".to_string(),
                roast: "Using `apk add` without `--no-cache`? You chose Alpine to save space and \
                        then immediately gained it all back. That's impressive, in a bad way.".to_string(),
            });
        }
    }
    findings
}

fn rule_unpinned_packages(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re_apt = Regex::new(r"apt-get install[^&|;]*").unwrap();
    let re_yum = Regex::new(r"yum install[^&|;]*").unwrap();
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        for cap in re_apt.find_iter(&i.arguments) {
            if !cap.as_str().contains('=') && !cap.as_str().contains("--only-upgrade") {
                findings.push(Finding {
                    rule: "DF005",
                    severity: Severity::Info,
                    line: i.line,
                    message: "apt-get install without pinned package versions".to_string(),
                    roast: "Unpinned packages: a bold way to ensure your build is different \
                            every single time. 'It worked on my machine' is a lifestyle choice, \
                            not a deployment strategy.".to_string(),
                });
                break;
            }
        }
        for _cap in re_yum.find_iter(&i.arguments) {
            findings.push(Finding {
                rule: "DF005",
                severity: Severity::Info,
                line: i.line,
                message: "yum install without pinned package versions".to_string(),
                roast: "Your yum packages are pinned to 'whatever yum feels like today'. \
                        Reproducibility called — it's going to voicemail.".to_string(),
            });
            break;
        }
    }
    findings
}

fn rule_apt_no_y(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("apt-get install") || a.contains("apt install"))
                && !a.contains("-y") && !a.contains("--yes") && !a.contains("--assume-yes")
                && !a.contains("DEBIAN_FRONTEND=noninteractive")
        })
        .map(|i| Finding {
            rule: "DF015",
            severity: Severity::Error,
            line: i.line,
            message: "apt-get install without -y flag will hang waiting for user input".to_string(),
            roast: "apt-get install without -y? Your build is going to sit there, patiently \
                    waiting for a 'yes' that will never come, like a golden retriever waiting \
                    for an owner who's on a cruise ship.".to_string(),
        })
        .collect()
}

fn rule_apt_recommends(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("apt-get install") || a.contains("apt install"))
                && !a.contains("--no-install-recommends")
        })
        .map(|i| Finding {
            rule: "DF016",
            severity: Severity::Info,
            line: i.line,
            message: "apt-get install without --no-install-recommends installs extra packages".to_string(),
            roast: "Installing without --no-install-recommends? apt is now installing packages \
                    you didn't ask for, like a waiter who brings you a full bread basket when \
                    you said you're gluten-free. `--no-install-recommends` is right there.".to_string(),
        })
        .collect()
}

fn rule_yum_no_y(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("yum install") || a.contains("dnf install"))
                && !a.contains("-y") && !a.contains("--assumeyes")
        })
        .map(|i| Finding {
            rule: "DF027",
            severity: Severity::Error,
            line: i.line,
            message: "yum/dnf install without -y flag will hang waiting for user input".to_string(),
            roast: "yum install without -y. Your build will hang indefinitely, \
                    waiting for input in a non-interactive environment. \
                    It's not coming. Add -y and move on.".to_string(),
        })
        .collect()
}

fn rule_apt_get_update_alone(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut prev_was_update = false;
    let mut update_line = 0;
    for i in instrs {
        if i.instruction == "RUN" {
            let a = &i.arguments;
            let has_update = a.contains("apt-get update") || a.contains("apt update");
            let has_install = a.contains("apt-get install") || a.contains("apt install");
            if has_update && !has_install {
                prev_was_update = true;
                update_line = i.line;
            } else if has_install && !has_update && prev_was_update {
                findings.push(Finding {
                    rule: "DF028",
                    severity: Severity::Warning,
                    line: update_line,
                    message: "apt-get update in a separate RUN from apt-get install causes cache poisoning".to_string(),
                    roast: "Splitting `apt-get update` and `apt-get install` into separate RUN \
                            layers is a classic mistake. Docker caches the update layer and \
                            your install may use a stale index. Combine them with && or enjoy \
                            mysterious 404 errors.".to_string(),
                });
                prev_was_update = false;
            } else {
                prev_was_update = false;
            }
        }
    }
    findings
}

fn rule_apk_no_cache(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // handled inside rule_uncleaned_package_cache to avoid duplicate findings
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
