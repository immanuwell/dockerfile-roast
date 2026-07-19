pub mod parser;
pub mod rules;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod config;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod hadolint;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod linter;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod output;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod policy;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod repository;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod wasm;
