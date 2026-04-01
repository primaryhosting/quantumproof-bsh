// BSH WASM Loader — drop into Lovable project at src/lib/crypto/bsh-loader.ts
// Tries WASM first, falls back to JS implementation

let wasmModule: { bsh_hash_hex: (input: Uint8Array) => string; bsh_hash: (input: Uint8Array) => Uint8Array } | null = null;
let useWasm = false;

// JS fallback implementation of BSH (pentagonal sponge)
function bshHashJS(input: Uint8Array): Uint8Array {
  // Initialize 5x64-bit state using golden ratio fractional parts
  const state = new BigUint64Array(5);
  state[0] = 0x9E3779B97F4A7C15n;
  state[1] = 0x7F4A7C159E3779B9n;
  state[2] = 0xB97F4A7C159E3779n;
  state[3] = 0x159E3779B97F4A7Cn;
  state[4] = 0x4A7C159E3779B97Fn;

  const ROUNDS = 24;

  // Pad input: append 0x80 then zero-fill to next 32-byte boundary
  const padded = new Uint8Array(Math.ceil((input.length + 1) / 32) * 32);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);

  // Absorb phase: XOR input into state in 32-byte blocks
  for (let offset = 0; offset < padded.length; offset += 32) {
    for (let i = 0; i < 4 && offset + i * 8 + 7 < padded.length; i++) {
      const lo = BigInt(view.getUint32(offset + i * 8, true));
      const hi = BigInt(view.getUint32(offset + i * 8 + 4, true));
      state[i] ^= (hi << 32n) | lo;
    }

    // Permutation rounds
    for (let r = 0; r < ROUNDS; r++) {
      // D5 rotation
      const t = state[0];
      state[0] = state[1] ^ ((state[2] >> 7n) | ((state[2] << 57n) & 0xFFFFFFFFFFFFFFFFn));
      state[1] = state[2] ^ ((state[3] >> 11n) | ((state[3] << 53n) & 0xFFFFFFFFFFFFFFFFn));
      state[2] = state[3] ^ ((state[4] >> 13n) | ((state[4] << 51n) & 0xFFFFFFFFFFFFFFFFn));
      state[3] = state[4] ^ ((t >> 17n) | ((t << 47n) & 0xFFFFFFFFFFFFFFFFn));
      state[4] = (t ^ state[0]) & 0xFFFFFFFFFFFFFFFFn;

      // Round constant mixing
      const rc = (0x9E3779B97F4A7C15n ^ BigInt(r)) & 0xFFFFFFFFFFFFFFFFn;
      state[r % 5] = (state[r % 5] ^ rc) & 0xFFFFFFFFFFFFFFFFn;

      // D5 reflection
      const tmp = state[1];
      state[1] = state[4];
      state[4] = tmp;
    }
  }

  // Squeeze phase: extract 32 bytes from state
  const output = new Uint8Array(32);
  const outView = new DataView(output.buffer);
  for (let i = 0; i < 4; i++) {
    const val = state[i] & 0xFFFFFFFFFFFFFFFFn;
    outView.setUint32(i * 8, Number(val & 0xFFFFFFFFn), true);
    outView.setUint32(i * 8 + 4, Number((val >> 32n) & 0xFFFFFFFFn), true);
  }

  return output;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function initBSH(): Promise<{ source: "wasm" | "js" }> {
  try {
    const wasmUrl = "/wasm/bsh_wasm_bg.wasm";
    const mod = await import("/wasm/bsh_wasm.js");
    await mod.default(wasmUrl);
    wasmModule = {
      bsh_hash_hex: mod.bsh_hash_hex,
      bsh_hash: mod.bsh_hash,
    };
    useWasm = true;
    return { source: "wasm" };
  } catch (e) {
    console.warn("BSH WASM not available, using JS fallback:", e);
    useWasm = false;
    return { source: "js" };
  }
}

export function bshHash(input: string | Uint8Array): Uint8Array {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (useWasm && wasmModule) {
    return new Uint8Array(wasmModule.bsh_hash(data));
  }
  return bshHashJS(data);
}

export function bshHashHex(input: string | Uint8Array): string {
  const data =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (useWasm && wasmModule) {
    return wasmModule.bsh_hash_hex(data);
  }
  return toHex(bshHashJS(data));
}

export function getBSHSource(): "wasm" | "js" {
  return useWasm ? "wasm" : "js";
}
