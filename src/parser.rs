/// Dockerfile parser — produces a list of instructions with line numbers.

#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub line: usize,
    pub instruction: String,
    pub arguments: String,
    pub raw: String,
}

pub fn parse(content: &str) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut pending_line: Option<usize> = None;
    let mut pending_parts: Vec<String> = Vec::new();
    let mut pending_instr: Option<String> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();

        // If we're inside a continuation, collect
        if let Some(ref instr) = pending_instr.clone() {
            // Strip trailing backslash
            let continued = if trimmed.ends_with('\\') {
                &trimmed[..trimmed.len() - 1]
            } else {
                trimmed
            };
            pending_parts.push(continued.trim().to_string());

            if !trimmed.ends_with('\\') {
                let args = pending_parts.join(" ").trim().to_string();
                let first_line = pending_line.unwrap();
                instructions.push(Instruction {
                    line: first_line,
                    instruction: instr.to_uppercase(),
                    arguments: args,
                    raw: raw_line.to_string(),
                });
                pending_instr = None;
                pending_line = None;
                pending_parts.clear();
            }
            continue;
        }

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split instruction keyword from arguments
        let (kw, rest) = match trimmed.split_once(|c: char| c.is_whitespace()) {
            Some((k, r)) => (k.to_uppercase(), r.trim().to_string()),
            None => (trimmed.to_uppercase(), String::new()),
        };

        if rest.ends_with('\\') {
            // Multi-line instruction
            pending_instr = Some(kw);
            pending_line = Some(line_no);
            pending_parts.push(rest[..rest.len() - 1].trim().to_string());
        } else {
            instructions.push(Instruction {
                line: line_no,
                instruction: kw,
                arguments: rest,
                raw: trimmed.to_string(),
            });
        }
    }

    // Handle unterminated continuation at EOF
    if let Some(instr) = pending_instr {
        let args = pending_parts.join(" ").trim().to_string();
        instructions.push(Instruction {
            line: pending_line.unwrap(),
            instruction: instr,
            arguments: args,
            raw: String::new(),
        });
    }

    instructions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parse() {
        let df = "FROM ubuntu:latest\nRUN apt-get install curl\n";
        let instrs = parse(df);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].instruction, "FROM");
        assert_eq!(instrs[0].arguments, "ubuntu:latest");
        assert_eq!(instrs[1].instruction, "RUN");
    }

    #[test]
    fn test_skip_comments() {
        let df = "# comment\nFROM alpine\n";
        let instrs = parse(df);
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_multiline() {
        let df = "RUN apt-get install \\\n    curl \\\n    wget\n";
        let instrs = parse(df);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].instruction, "RUN");
    }
}
