//! Pico 3.1 compress proofs (MLE/WHIR, 128-bit security).
//!
//! From Pico 3.1 on, a cluster submits its compress proof: the complete root proof re-proved under
//! the compress preset. It is framed like a Pico 3.0 proof ([`crate::pico_mle`]), under its own
//! format version:
//!
//! - the proof, `PICOMLE\0` version 4 ([`CompressProofV4`]): the compress proof alone, without a
//!   key, since it is proved under the whitelist's one compress key;
//! - the VK, `PICOMLEV` version 2, the bundle format of Pico 3.0: the guest identity, the whitelist
//!   root, and Merkle memberships under that root of the keys a root or a compress proof can be
//!   proved under.
//!
//! The proof carries no key, so this verifier carries the compress key: [`COMPRESS_VK`], the
//! `mle_compress_vk.bin` of Pico v3.1.2. The VK bundle is still what this verifier trusts. The key
//! is accepted only if its body hashes to its identity and that identity is one of the bundle's
//! members, whose paths must reach the bundle's whitelist root. The proof must then verify under
//! the key, and its public values must say the recursion is complete and name the bundle's guest
//! and whitelist root.
//!
//! The checks are `pico-verifier`'s, from the same Pico release. Without its default features it
//! builds without zstd's C library; the framing here uses `ruzstd`, as for Pico 3.0.

use std::{
    io::Cursor,
    sync::{Arc, OnceLock},
};

use bincode::Options;
use pico_mle_core_31::{
    codec::Decode, config::recursion_params_with_128_bits_security,
    keygen::types::MultiStarkVerifyingKey, proof::Proof,
};
use pico_verifier::{hash::digest_from_u32s, whitelist::VkMembership, MleApexVerifier, Sc, VmVk};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::pico_mle::{bincode_capped, unframe, VkBundleV2, PROOF_MAGIC, VK_MAGIC, VK_VERSION};

const PROOF_VERSION: u32 = 4;

/// The compress key of Pico v3.1.2's whitelist, `vm/src/mle/shape_vk_bins/mle_compress_vk.bin` at
/// that tag: bincode of its `MultiStarkVerifyingKey`, with fixed-width integers.
const COMPRESS_VK: &[u8] = include_bytes!("../keys/pico-v3.1.2-compress-vk.bin");

/// A compress proof, without its key.
#[derive(Deserialize)]
struct CompressProofV4 {
    /// The compress proof, in mle-core's versioned wire codec.
    proof: Vec<u8>,
}

/// Whether `bytes` is framed as a compress proof: the Pico MLE magic, then format version 4.
pub(crate) fn is_compress_proof(bytes: &[u8]) -> bool {
    bytes.starts_with(&PROOF_MAGIC) && bytes.get(8..12) == Some(&PROOF_VERSION.to_le_bytes()[..])
}

/// `Ok(true)` if `proof_bytes` is a compress proof of the guest `vk_bytes` names, under the
/// whitelist it pins. Anything else is an error carrying the reason.
pub(crate) fn verify_proof(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<bool, JsValue> {
    verify(proof_bytes, vk_bytes)
        .map(|()| true)
        .map_err(|e| JsValue::from_str(&e))
}

fn verify(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<(), String> {
    let bundle = unframe(vk_bytes, &VK_MAGIC, VK_VERSION, "vk")?;
    let body = unframe(proof_bytes, &PROOF_MAGIC, PROOF_VERSION, "proof")?;
    verify_decoded(&bundle, &body)
}

fn verify_decoded(bundle: &VkBundleV2, body: &CompressProofV4) -> Result<(), String> {
    let members = bundle
        .members
        .iter()
        .map(|m| VkMembership {
            identity: (
                digest_from_u32s(&m.pre_hash),
                digest_from_u32s(&m.merged_commit),
            ),
            index: m.index as usize,
            siblings: m.siblings.iter().map(digest_from_u32s).collect(),
        })
        .collect();
    let vm_vk = VmVk::from_u32s(&bundle.vm_vk).map_err(|e| format!("vk: {e}"))?;
    let apex = MleApexVerifier::with_members(
        recursion_params_with_128_bits_security(),
        members,
        vm_vk,
        digest_from_u32s(&bundle.vk_root),
    )
    .map_err(|e| format!("vk: {e}"))?;

    let proof = decode_proof(&body.proof)?;
    apex.verify_compress(&(proof, compress_vk()?))
        .map_err(|e| e.to_string())
}

/// The proof the bytes hold, and nothing after it.
fn decode_proof(bytes: &[u8]) -> Result<Proof<Sc>, String> {
    let mut reader = Cursor::new(bytes);
    let proof = Proof::<Sc>::decode(&mut reader).map_err(|e| format!("proof: {e:?}"))?;
    if reader.position() != bytes.len() as u64 {
        return Err("proof: trailing bytes after the compress proof".into());
    }
    Ok(proof)
}

/// [`COMPRESS_VK`], decoded on first use.
fn compress_vk() -> Result<Arc<MultiStarkVerifyingKey<Sc>>, String> {
    static VK: OnceLock<Arc<MultiStarkVerifyingKey<Sc>>> = OnceLock::new();
    if let Some(vk) = VK.get() {
        return Ok(vk.clone());
    }
    let vk: MultiStarkVerifyingKey<Sc> = bincode_capped()
        .deserialize(COMPRESS_VK)
        .map_err(|e| format!("compress key: {e}"))?;
    Ok(VK.get_or_init(|| Arc::new(vk)).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_verifier::whitelist::vk_identity;
    use std::fs;

    // A Pico v3.1.2 compress proof of mainnet block 26384200, proved by Brevis's ethproofs prover,
    // and the VK bundle for its guest and whitelist.
    const PROOF_FILE_PATH: &str = "proofs/pico-mle-compress-eth-proof.bin";
    const VK_FILE_PATH: &str = "riscv-vks/pico-mle-compress-vk-kb.bin";

    fn fixtures() -> (VkBundleV2, CompressProofV4) {
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        (
            unframe(&vk, &VK_MAGIC, VK_VERSION, "vk").unwrap(),
            unframe(&proof, &PROOF_MAGIC, PROOF_VERSION, "proof").unwrap(),
        )
    }

    #[test]
    fn test_pico_mle_compress_verification() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        assert!(is_compress_proof(&proof));
        verify(&proof, &vk).unwrap();
    }

    #[test]
    fn rejects_a_tampered_proof() {
        let (bundle, mut body) = fixtures();
        let last = body.proof.len() - 1;
        body.proof[last] ^= 1;
        assert!(verify_decoded(&bundle, &body).is_err());
    }

    #[test]
    fn rejects_another_guest() {
        let (mut bundle, body) = fixtures();
        bundle.vm_vk[0] ^= 1;
        let err = verify_decoded(&bundle, &body).unwrap_err();
        assert!(err.contains("riscv_vk_digest"), "{err}");
    }

    #[test]
    fn rejects_a_bundle_without_the_compress_key() {
        let (mut bundle, body) = fixtures();
        let compress = vk_identity(&compress_vk().unwrap());
        let before = bundle.members.len();
        bundle.members.retain(|m| {
            (
                digest_from_u32s(&m.pre_hash),
                digest_from_u32s(&m.merged_commit),
            ) != compress
        });
        assert_eq!(bundle.members.len(), before - 1);
        let err = verify_decoded(&bundle, &body).unwrap_err();
        assert!(err.contains("not in the whitelist"), "{err}");
    }

    #[test]
    fn rejects_members_off_the_root() {
        let (mut bundle, body) = fixtures();
        bundle.vk_root[0] ^= 1;
        let err = verify_decoded(&bundle, &body).unwrap_err();
        assert!(
            err.contains("does not verify against the trusted root"),
            "{err}"
        );
    }

    #[test]
    fn rejects_the_pico_3_0_vk() {
        // Another guest build and another whitelist, without this compress key.
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read("riscv-vks/pico-mle-vk-kb.bin").unwrap();
        assert!(verify(&proof, &vk).is_err());
    }

    #[test]
    fn refuses_other_formats() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let root_proof = fs::read("proofs/pico-mle-eth-proof.bin").unwrap();
        let fri_proof = fs::read("proofs/pico-eth-proof.bin").unwrap();
        let fri_vk = fs::read("riscv-vks/pico-vk-kb.bin").unwrap();
        assert!(!is_compress_proof(&root_proof));
        assert!(!is_compress_proof(&fri_proof));
        assert!(verify(&root_proof, &vk)
            .unwrap_err()
            .contains("format version 3"));
        assert!(verify(&fri_proof, &vk).is_err());
        assert!(verify(&proof, &fri_vk).is_err());
        assert!(verify(&vk, &proof).is_err());
    }
}
