pub mod parser;
pub mod rules;

#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod linter;
#[cfg(not(target_arch = "wasm32"))]
pub mod output;
#[cfg(not(target_arch = "wasm32"))]
pub mod repository;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
