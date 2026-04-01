use wasm_bindgen::prelude::*;

/// Hash raw bytes and return the 32-byte digest as a Vec<u8>.
#[wasm_bindgen]
pub fn bsh_hash(input: &[u8]) -> Vec<u8> {
    bsh_core::hash(input).to_vec()
}

/// Hash raw bytes and return the hex-encoded digest string.
#[wasm_bindgen]
pub fn bsh_hash_hex(input: &[u8]) -> String {
    bsh_core::hash_hex(input)
}

/// Hash a UTF-8 string and return the hex-encoded digest.
#[wasm_bindgen]
pub fn bsh_hash_string(input: &str) -> String {
    bsh_core::hash_string(input)
}
