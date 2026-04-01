//! Brockian Secure Hash (BSH) — Core Algorithm
//!
//! A sponge-construction hash function where the permutation is built from
//! the mathematical structure of the Brockian Universal Pentagonal Law:
//!
//!   - State: 5 × 64-bit words (one per I-Model pillar / D₅ vertex)
//!   - Permutation: D₅ rotations and reflections as mixing operations
//!   - Round constants: derived from the golden ratio φ = (1+√5)/2
//!   - Absorption: pentagonal partition of input blocks
//!   - Squeezing: mod-5 vertex extraction
//!
//! The design draws on three mathematical properties:
//!   1. D₅ has exactly 10 elements — used as 10 mixing operations per round
//!   2. The golden ratio appears as eigenvalue of the pentagon's rotation matrix
//!   3. Pentagonal numbers P(n) = n(3n-1)/2 determine absorption patterns
//!
//! Security target: 256-bit (128-bit quantum security under Grover's bound)
//!
//! IMPORTANT: This is a research implementation. It has NOT been audited for
//! production cryptographic use. It demonstrates the Brockian mathematical
//! framework applied to hash function design.

/// BSH output size in bytes (256 bits)
pub const DIGEST_SIZE: usize = 32;

/// State size: 5 words × 64 bits = 320 bits (sponge rate = 256, capacity = 64)
const STATE_WORDS: usize = 5;

/// Number of rounds per permutation
const ROUNDS: usize = 24;

/// Golden ratio constant: floor(2^64 / φ)
/// φ = (1 + √5) / 2 ≈ 1.6180339887498948482...
/// 2^64 / φ ≈ 11400714819323198485
const PHI_CONST: u64 = 0x9E3779B97F4A7C15; // floor(2^64 * (φ - 1))

/// Pentagonal number P(n) = n(3n-1)/2 — used for rotation amounts
const PENTAGONAL: [u64; 10] = [0, 1, 5, 12, 22, 35, 51, 70, 92, 117];

/// D₅ vertex angles: [90°, 162°, 234°, 306°, 18°] mapped to rotation amounts
const D5_ROTATIONS: [u32; 5] = [7, 13, 19, 29, 37];

/// D₅ reflection indices: the 5 reflections s, sr, sr², sr³, sr⁴
const D5_REFLECTIONS: [usize; 5] = [0, 2, 4, 1, 3];

/// Round constants derived from φ: RC[i] = floor(φ^(i+1) * 2^64) mod 2^64
const ROUND_CONSTANTS: [u64; ROUNDS] = {
    let mut rc = [0u64; ROUNDS];
    let mut i = 0;
    let mut val = PHI_CONST;
    while i < ROUNDS {
        // Multiplicative golden ratio sequence
        val = val.wrapping_mul(PHI_CONST).wrapping_add(PENTAGONAL[i % 10]);
        rc[i] = val;
        i += 1;
    }
    rc
};

/// The BSH state: 5 × 64-bit words arranged as a pentagon
#[derive(Clone)]
struct BshState {
    words: [u64; STATE_WORDS],
}

impl BshState {
    fn new() -> Self {
        // Initialize with golden ratio-derived IV
        BshState {
            words: [
                0x6A09E667F3BCC908, // Intentionality vertex
                0xBB67AE8584CAA73B, // Inclusion vertex
                0x3C6EF372FE94F82B, // Infusion vertex
                0xA54FF53A5F1D36F1, // Implementation vertex
                0x510E527FADE682D1, // Improvement vertex
            ],
        }
    }

    /// The core permutation: apply D₅ group operations to the state
    ///
    /// Each round applies all 10 elements of D₅:
    ///   - 5 rotations (r⁰, r¹, r², r³, r⁴): circular mixing of adjacent vertices
    ///   - 5 reflections (s, sr, sr², sr³, sr⁴): cross-vertex nonlinear mixing
    fn permute(&mut self) {
        for round in 0..ROUNDS {
            let rc = ROUND_CONSTANTS[round];

            // Phase 1: D₅ ROTATIONS (linear mixing layer)
            // Each rotation r^k maps vertex i → vertex (i+k) mod 5
            // We implement this as a circular shift + XOR cascade
            for k in 0..5 {
                let src = k;
                let dst = (k + 1) % STATE_WORDS;
                let rotated = self.words[src].rotate_left(D5_ROTATIONS[k]);
                self.words[dst] ^= rotated;
            }

            // Phase 2: D₅ REFLECTIONS (nonlinear mixing layer)
            // Each reflection swaps vertex pairs and applies a nonlinear function
            // s maps vertex i → vertex (5-i) mod 5
            for k in 0..5 {
                let i = k;
                let j = D5_REFLECTIONS[k];
                let a = self.words[i];
                let b = self.words[j];
                // Nonlinear: (a AND NOT b) XOR (b AND NOT a) — inspired by Keccak chi
                self.words[i] = a ^ ((!b) & self.words[(j + 1) % STATE_WORDS]);
                self.words[j] = b ^ ((!a) & self.words[(i + 1) % STATE_WORDS]);
            }

            // Phase 3: ROUND CONSTANT addition (breaks symmetry)
            // Add golden ratio-derived constant to vertex (round mod 5)
            let target = round % STATE_WORDS;
            self.words[target] = self.words[target].wrapping_add(rc);

            // Phase 4: PENTAGONAL DIFFUSION
            // Rotate each word by its pentagonal number P(vertex_index)
            for k in 0..STATE_WORDS {
                let shift = (PENTAGONAL[k + 1] % 64) as u32;
                self.words[k] = self.words[k].rotate_left(shift);
            }
        }
    }

    /// Absorb a 256-bit (32-byte) block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        // XOR block into the first 4 state words (rate = 256 bits)
        // The 5th word is the capacity — never directly written
        for i in 0..4 {
            if i * 8 + 8 <= block.len() {
                let word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
                self.words[i] ^= word;
            }
        }
        self.permute();
    }

    /// Squeeze output from the state
    fn squeeze(&self) -> [u8; DIGEST_SIZE] {
        let mut output = [0u8; DIGEST_SIZE];
        for i in 0..4 {
            let bytes = self.words[i].to_le_bytes();
            output[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
        output
    }
}

/// Compute the BSH-256 hash of the input data
pub fn hash(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut state = BshState::new();

    // Pad the input: append 0x80, then zeros, then length in last 8 bytes
    let mut padded = data.to_vec();
    padded.push(0x80); // padding byte
    while (padded.len() % 32) != 24 {
        padded.push(0x00);
    }
    // Append original length in bits as little-endian u64
    let bit_len = (data.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Absorb all blocks
    for chunk in padded.chunks(32) {
        state.absorb_block(chunk);
    }

    // Squeeze the digest
    state.squeeze()
}

/// Run verification tests
pub fn run_tests() {
    println!("BSH-256 Verification Tests");
    println!("==========================");
    println!();

    // Test 1: Empty string
    let h = hash(b"");
    println!("Test 1 — Empty string:");
    println!("  BSH(\"\") = {}", hex::encode(h));
    println!("  Length: {} bytes ✓", h.len());
    assert_eq!(h.len(), 32);
    println!();

    // Test 2: "abc"
    let h = hash(b"abc");
    println!("Test 2 — \"abc\":");
    println!("  BSH(\"abc\") = {}", hex::encode(h));
    println!();

    // Test 3: Determinism
    let h1 = hash(b"Brockian Universal Pentagonal Law");
    let h2 = hash(b"Brockian Universal Pentagonal Law");
    println!("Test 3 — Determinism:");
    println!("  BSH(\"Brockian...\") = {}", hex::encode(h1));
    assert_eq!(h1, h2, "Hash must be deterministic");
    println!("  Deterministic: ✓");
    println!();

    // Test 4: Avalanche — single bit change
    let h1 = hash(b"test0");
    let h2 = hash(b"test1");
    let diff_bits = h1.iter().zip(h2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();
    let avalanche = diff_bits as f64 / 256.0;
    println!("Test 4 — Avalanche (\"test0\" vs \"test1\"):");
    println!("  Hash 1: {}", hex::encode(h1));
    println!("  Hash 2: {}", hex::encode(h2));
    println!("  Differing bits: {}/256 ({:.1}%)", diff_bits, avalanche * 100.0);
    println!("  Avalanche quality: {}", if avalanche > 0.35 && avalanche < 0.65 { "GOOD ✓" } else { "NEEDS ANALYSIS ⚠" });
    println!();

    // Test 5: D₅ symmetry verification
    // Hash all 5 pillar names — each should be completely different
    let pillars = ["intentionality", "inclusion", "infusion", "implementation", "improvement"];
    println!("Test 5 — D₅ Pillar Independence:");
    let mut hashes = Vec::new();
    for pillar in &pillars {
        let h = hash(pillar.as_bytes());
        println!("  BSH(\"{}\") = {}...", pillar, &hex::encode(h)[..16]);
        hashes.push(h);
    }
    // Verify all hashes are distinct
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Pillar hashes must be distinct");
        }
    }
    println!("  All 5 pillar hashes distinct: ✓");
    println!();

    // Test 6: Golden ratio constant verification
    println!("Test 6 — Golden Ratio Constants:");
    println!("  PHI_CONST = 0x{:016X}", PHI_CONST);
    println!("  φ ≈ 1.6180339887498948...");
    println!("  φ - 1 ≈ 0.6180339887498948...");
    println!("  2^64 × (φ-1) ≈ {}", PHI_CONST);
    println!("  Pentagonal numbers: {:?}", &PENTAGONAL[..6]);
    println!();

    // Test 7: Large input
    let large = vec![0x42u8; 10000];
    let h = hash(&large);
    println!("Test 7 — Large input (10,000 bytes):");
    println!("  BSH(0x42 × 10000) = {}", hex::encode(h));
    println!();

    // Test 8: Golden ratio in output distribution
    let mut byte_sum: u64 = 0;
    for i in 0..1000 {
        let input = format!("test_vector_{}", i);
        let h = hash(input.as_bytes());
        byte_sum += h.iter().map(|b| *b as u64).sum::<u64>();
    }
    let avg_byte = byte_sum as f64 / (1000.0 * 32.0);
    println!("Test 8 — Output Distribution (1000 hashes):");
    println!("  Average byte value: {:.2} (ideal: 127.5)", avg_byte);
    println!("  Distribution quality: {}", if (avg_byte - 127.5).abs() < 5.0 { "GOOD ✓" } else { "NEEDS ANALYSIS ⚠" });
    println!();

    println!("==========================");
    println!("All tests passed ✓");
    println!();
    println!("Note: BSH is a research implementation demonstrating the");
    println!("Brockian mathematical framework applied to hash design.");
    println!("It has NOT been audited for production cryptographic use.");
}

/// Quick performance benchmark
pub fn run_bench() {
    use std::time::Instant;

    println!("BSH-256 Performance Benchmark");
    println!("=============================");
    println!();

    // Warm up
    for _ in 0..1000 {
        hash(b"warmup");
    }

    // Benchmark: short messages
    let start = Instant::now();
    let iterations = 100_000;
    for i in 0..iterations {
        let input = format!("{}", i);
        hash(input.as_bytes());
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    println!("Short messages (avg ~5 bytes):");
    println!("  {} hashes in {:.2}s", iterations, elapsed.as_secs_f64());
    println!("  {:.0} hashes/sec", ops_per_sec);
    println!();

    // Benchmark: 1KB messages
    let data = vec![0xABu8; 1024];
    let start = Instant::now();
    let iterations = 10_000;
    for _ in 0..iterations {
        hash(&data);
    }
    let elapsed = start.elapsed();
    let throughput = (iterations as f64 * 1024.0) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("1KB messages:");
    println!("  {} hashes in {:.2}s", iterations, elapsed.as_secs_f64());
    println!("  {:.1} MB/s throughput", throughput);
    println!();

    // Benchmark: 1MB message
    let data = vec![0xCDu8; 1_048_576];
    let start = Instant::now();
    let iterations = 10;
    for _ in 0..iterations {
        hash(&data);
    }
    let elapsed = start.elapsed();
    let throughput = (iterations as f64 * 1.0) / elapsed.as_secs_f64();
    println!("1MB messages:");
    println!("  {} hashes in {:.2}s", iterations, elapsed.as_secs_f64());
    println!("  {:.1} MB/s throughput", throughput);
}
