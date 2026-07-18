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

    // 3. Cargo package version — used by registry and Git installs where the
    // source checkout does not contain Git metadata.
    let package_version = std::env::var("CARGO_PKG_VERSION")
        .expect("Cargo must provide CARGO_PKG_VERSION to build scripts");
    println!("cargo:rustc-env=DROAST_VERSION={package_version}");
}
