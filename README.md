# Pico Wasm Stark Verifier

WebAssembly bindings for the Pico STARK verifier.

## Overview

This module compiles the `verify` function from `pico-vm`'s `CombineProver` to WebAssembly, allowing STARK proof verification in web browsers and Node.js environments.

It verifies four kinds of Pico proofs:

- Pico (FRI, single GPU), under the `'Pico'` type
- Pico Prism (FRI, multiple GPUs), under the `'PicoPrism'` type
- Pico 3.0 (MLE), also under the `'Pico'` type; see [Pico 3.0 (MLE) proofs](#pico-30-mle-proofs)
- Pico 3.1 (MLE compress), also under the `'Pico'` type; see [Pico 3.1 compress proofs](#pico-31-compress-proofs)

For the Pico STARK verifier to work, the env variable `VK_VERIFICATION` needs be set to `false`, but this is challenging when compiling to WASM. Therefore, as a temporary solution, this pkg uses a fork of Pico which bypasses a `vk_verification_enabled` check in the `verify` function and assumes it is disabled.

## Usage

### Installation

```bash
npm install @ethproofs/pico-wasm-stark-verifier
```

### React Integration

```typescript
import init, { main, verify_stark } from '@ethproofs/pico-wasm-stark-verifier';

await init(); // Initialize WASM (if needed)
main(); // Initialize panic hook

// Verify a Pico proof (single GPU)
const isValid = verify_stark('Pico', proofBytes, vkBytes);

// Verify a Pico Prism proof (multi GPUs)
const isValid = verify_stark('PicoPrism', proofBytes, vkBytes);

// Verify a Pico 3.0 proof: same type as Pico, told apart by its format
const isValid = verify_stark('Pico', proofBytes, vkBytes);

// Verify a Pico 3.1 compress proof: same type again, told apart by its format version
const isValid = verify_stark('Pico', proofBytes, vkBytes);
```

For complete React integration examples, see [REACT_INTEGRATION.md](./REACT_INTEGRATION.md).

### Node.js Usage

```javascript
const { main, verify_stark } = require('@ethproofs/pico-wasm-stark-verifier');

// The Node.js version initializes automatically

main(); // Initialize panic hook
const result = verify_stark('PicoPrism', proofBytes, vkBytes);
```

## Pico 3.0 (MLE) proofs

Pico 3.0 proofs use the `'Pico'` type. The verifier recognizes them by the magic their bytes start with (`PICOMLE\0`); every other `'Pico'` proof takes the FRI path as before. A Pico 3.0 proof that does not verify throws an error with the reason, where the FRI paths return `false`.

Both files have the same framing, `magic (8 bytes) | format version (u32 LE) | zstd(bincode(body))`:

| File | Magic | Version | Body |
|---|---|---|---|
| Proof (what the prover submits) | `PICOMLE\0` | 3 | The root proof and the verifying key it was proved under |
| VK (uploaded for the cluster version) | `PICOMLEV` | 2 | The guest identity, the whitelist root, and Merkle memberships under that root of the keys a root proof can be proved under |

The verifier trusts only the VK. It accepts the key inside a proof only if the key's body hashes to its identity and that identity is one of the VK's members. Each member's path must reach the VK's whitelist root. The proof must then verify under that key, its recursion tree must be complete, and its public values must name the VK's guest and whitelist root. Every inner key of the tree is checked against the same root in circuit, so the root pins the whole tree.

The VK depends only on the guest program and on the whitelist the prover runs with. A new guest or a new whitelist needs a new VK, not a new verifier.

The Pico 3.0 crates come from the [`v3.0.0`](https://github.com/brevis-network/pico/releases/tag/v3.0.0) release of Pico; see `Cargo.toml`.

## Pico 3.1 compress proofs

From Pico 3.1 on, a cluster submits its compress proof: the complete root proof re-proved under the compress preset, at 128-bit security. It uses the `'Pico'` type and the Pico 3.0 magic, with format version 4:

| File | Magic | Version | Body |
|---|---|---|---|
| Proof (what the prover submits) | `PICOMLE\0` | 4 | The compress proof alone |
| VK (uploaded for the cluster version) | `PICOMLEV` | 2 | As for Pico 3.0: the guest identity, the whitelist root, and Merkle memberships under that root of the keys a root or a compress proof can be proved under |

The proof carries no key, because every compress proof is proved under the whitelist's one compress key. This package carries that key: `keys/pico-v3.1.2-compress-vk.bin` is the `mle_compress_vk.bin` of Pico v3.1.2.

The checks are those for Pico 3.0, with that key in place of a key inside the proof. The key must hash to its identity, and the identity must be one of the VK's members, whose paths must reach the VK's whitelist root. The proof must verify under the key, and its public values must say the recursion is complete and name the VK's guest and whitelist root. The VK is still all the verifier trusts.

A new guest or a new whitelist needs a new VK, not a new verifier, as long as the compress key is the same. A new compress key needs a new release of this package.

The checks are `pico-verifier`'s, from the [`v3.1.2`](https://github.com/brevis-network/pico/tree/v3.1.2) tag of Pico, without its default features, so the package still builds without C; see `Cargo.toml`.

## Testing

### Installation

```bash
npm install
```

### Prerequisites

- [Rust (Nightly)](https://pico-docs.brevis.network/getting-started/installation#rust-toolchain)
- [wasm-pack](https://github.com/drager/wasm-pack)

### Building

```bash
# Build for all targets
npm run build:all
```

### Node.js Example

```bash
npm run test:node
```

This runs the Node.js example that loads the proof and verification key files in `proofs/` and `riscv-vks/` (one per kind of proof) and verifies each of them.

`cargo test` runs the same fixtures natively, and the Pico 3.0 and 3.1 tests also check that tampered proofs, a VK for another guest and a VK that does not cover the proof's key are rejected.

### Browser Example

```bash
npm run test
```

This starts a local HTTP server at `http://localhost:8080` with a browser example that demonstrates:

- Loading the WASM module in a browser environment
- File upload interface for proof and verification key files
- Interactive STARK proof verification
- Performance metrics and detailed logging
- Error handling and user feedback

The browser example provides a complete UI for testing the WASM verifier with drag-and-drop file selection and real-time verification results.

**Note:** The browser example requires files to be served over HTTP due to WASM CORS restrictions. The included server script handles this automatically.
