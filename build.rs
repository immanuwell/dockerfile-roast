use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=DROAST_VERSION");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    // 1. Explicit env var — used by CI and manual builds.
    if let Ok(v) = std::env::var("DROAST_VERSION") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            println!("cargo:rustc-env=DROAST_VERSION={v}");
            return;
        }
    }

    // 2. Git tag — works for local builds where full history is available.
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let tag = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !tag.is_empty() {
                println!("cargo:rustc-env=DROAST_VERSION={tag}");
                return;
            }
        }
    }

    panic!(
        "\n\nERROR: could not determine droast version.\n\
         Either push a git tag, or set DROAST_VERSION before building:\n\
         \n    DROAST_VERSION=1.3.0 cargo build --release\n\n"
    );
}
