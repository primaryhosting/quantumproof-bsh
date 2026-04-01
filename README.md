# QuantumProof BSH — Brockian Secure Hash

Post-quantum hash function using D₅ pentagonal symmetry and golden ratio constants.

## Structure

- `bsh-core/` — Reference Rust implementation (256-bit digest, 24 rounds, D₅ sponge)
- `bsh-wasm/` — WebAssembly bindings via wasm-bindgen

## Build WASM

```bash
cd bsh-wasm
wasm-pack build --target web --release --out-dir ../pkg
```

Output in `pkg/`: `bsh_wasm_bg.wasm`, `bsh_wasm.js`, `bsh_wasm.d.ts`

## Usage (Rust)

```rust
let digest = bsh_core::hash(b"hello world");
let hex = bsh_core::hash_hex(b"hello world");
```

## Usage (JavaScript / WASM)

```javascript
import init, { bsh_hash_string } from './pkg/bsh_wasm.js';
await init();
const hex = bsh_hash_string("hello world");
```

## CI

GitHub Actions builds WASM on every push to `bsh-core/` or `bsh-wasm/` and publishes release artifacts on main.

## License

Apache-2.0 — Christopher Brock
