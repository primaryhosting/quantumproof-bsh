//! BSH — Brockian Secure Hash Library
//! 
//! Post-quantum hash function using D₅ pentagonal symmetry.
//! Can be compiled to WebAssembly for browser use.

mod bsh;

pub use bsh::{hash, DIGEST_SIZE, run_tests, run_bench};

/// Hash data and return hex string (convenience function)
pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

/// Hash a string and return hex (convenience for WASM)
pub fn hash_string(input: &str) -> String {
    hash_hex(input.as_bytes())
}
