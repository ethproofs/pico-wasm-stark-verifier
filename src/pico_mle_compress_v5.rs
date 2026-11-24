//! Pico compress proofs in format version 5 (MLE/WHIR, 128-bit security), from Pico 3.2.
//!
//! The same two files as for Pico 3.1 ([`crate::pico_mle_compress`]), in new versions:
//!
//! - the proof, `PICOMLE\0` version 5 ([`CompressProofV5`]): the compress proof alone, without a
//!   key, its WHIR Merkle openings as multiproofs. The paths of a round's queries share their upper
//!   nodes, which travel once; the decoder rebuilds the flat proof, which is verified as any other.
//!   Version 4 sent the flat proof; a version 5 prover no longer writes it.
//! - the VK, `PICOMLEV` version 3 ([`VkBundleV3`]): as version 2 except for the guest identity,
//!   which is 20 field elements: program commitment (8), entry pc (3), the memory image's
//!   commitment (8) and its tier (1). Version 2 carried the initial global cumulative sum instead.
//!
//! The proof carries no key, so this verifier carries the compress key, [`COMPRESS_VK`]. The VK
//! bundle is still what this verifier trusts. The key is accepted only if its body hashes to its
//! identity and that identity is one of the bundle's members, whose paths must reach the bundle's
//! whitelist root. The proof must then verify under the key, and its public values must say the
//! recursion is complete and name the bundle's guest and whitelist root.
//!
//! The checks are `pico-verifier`'s, from the same Pico tag. Without its default features it
//! builds without zstd's C library; the framing here uses `ruzstd`, as for the other Pico formats.

use std::{
    io::Cursor,
    sync::{Arc, OnceLock},
};

use bincode::Options;
use pico_mle_core_v5::{
    config::{
        koala_bear_poseidon2::default_koalabear_hasher, recursion_params_with_128_bits_security,
    },
    keygen::types::MultiStarkVerifyingKey,
    proof::Proof,
    protocol::multiproof::decode_multiproof,
};
use pico_verifier_v5::{
    hash::digest_from_u32s, whitelist::VkMembership, MleApexVerifier, Sc, VmVk,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::pico_mle::{bincode_capped, unframe, PROOF_MAGIC, VK_MAGIC};

const PROOF_VERSION: u32 = 5;
const VK_VERSION: u32 = 3;

/// The compress key of the whitelist these proofs are made under,
/// `vm/src/mle/shape_vk_bins/mle_compress_vk.bin` at the Pico tag in `Cargo.toml`: bincode of
/// its `MultiStarkVerifyingKey`, with fixed-width integers.
const COMPRESS_VK: &[u8] = include_bytes!("../keys/pico-v3.2.0-compress-vk.bin");

/// A compress proof, without its key.
#[derive(Deserialize)]
struct CompressProofV5 {
    /// The compress proof, in mle-core's multiproof form.
    proof: Vec<u8>,
}

/// What a cluster version's VK holds: Pico's `pico_verifier::bundle::MleVkBundleV3`.
#[derive(Deserialize)]
struct VkBundleV3 {
    /// The guest identity: program commitment (8), entry pc (3), memory image commitment (8) and
    /// tier (1), as canonical u32s.
    vm_vk: Vec<u32>,
    /// The whitelist root.
    vk_root: [u32; 8],
    /// The keys a root or a compress proof can be proved under, with their paths to `vk_root`.
    members: Vec<MemberV3>,
}

#[derive(Deserialize)]
struct MemberV3 {
    pre_hash: [u32; 8],
    merged_commit: [u32; 8],
    index: u32,
    /// One sibling per tree level, bottom-up.
    siblings: Vec<[u32; 8]>,
}

/// Whether `bytes` is framed as a format version 5 compress proof: the Pico MLE magic, then 5.
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

fn verify_decoded(bundle: &VkBundleV3, body: &CompressProofV5) -> Result<(), String> {
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

/// The proof the multiproof bytes hold, its flat Merkle paths rebuilt, and nothing after it. The
/// rebuilt proof is not trusted: the apex verifies it as any decoded proof.
fn decode_proof(bytes: &[u8]) -> Result<Proof<Sc>, String> {
    let mut reader = Cursor::new(bytes);
    let proof = decode_multiproof::<Sc, _>(&default_koalabear_hasher(), &mut reader)
        .map_err(|e| format!("proof: {e}"))?;
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
    use pico_verifier_v5::whitelist::vk_identity;
    use std::fs;

    // A compress proof of mainnet block 24006677, proved by Pico's GPU prover under the whitelist
    // of the tag in `Cargo.toml` and framed as the ethproofs prover frames it, and the VK bundle
    // for its guest and whitelist.
    const PROOF_FILE_PATH: &str = "proofs/pico-mle-compress-v5-eth-proof.bin";
    const VK_FILE_PATH: &str = "riscv-vks/pico-mle-compress-v5-vk-kb.bin";

    fn fixtures() -> (VkBundleV3, CompressProofV5) {
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        (
            unframe(&vk, &VK_MAGIC, VK_VERSION, "vk").unwrap(),
            unframe(&proof, &PROOF_MAGIC, PROOF_VERSION, "proof").unwrap(),
        )
    }

    #[test]
    fn test_pico_mle_compress_v5_verification() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        assert!(is_compress_proof(&proof));
        // The Pico 3.1 module does not claim it; the Pico 3.0 one would, by its magic alone, which
        // is why `verify_stark` asks this module first.
        assert!(!crate::pico_mle_compress::is_compress_proof(&proof));
        assert!(crate::pico_mle::is_mle_proof(&proof));
        verify(&proof, &vk).unwrap();
    }

    #[test]
    fn rejects_flipped_bits() {
        // One bit flipped anywhere in the proof: a decode failure or a failed verify, never an
        // acceptance.
        let (bundle, body) = fixtures();
        let n = body.proof.len();
        for pos in [0, 4, n / 7, n / 3, n / 2, 2 * n / 3, n - 33, n - 1] {
            let mut proof = body.proof.clone();
            proof[pos] ^= 0x10;
            assert!(
                verify_decoded(&bundle, &CompressProofV5 { proof }).is_err(),
                "a flipped bit at proof byte {pos} of {n} was accepted"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let (bundle, mut body) = fixtures();
        body.proof.push(0);
        let err = verify_decoded(&bundle, &body).unwrap_err();
        assert!(err.contains("trailing bytes"), "{err}");
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
    fn rejects_the_pico_3_1_vk() {
        // Version 2: another guest identity, another whitelist and compress key.
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read("riscv-vks/pico-mle-compress-vk-kb.bin").unwrap();
        let err = verify(&proof, &vk).unwrap_err();
        assert!(err.contains("format version 2"), "{err}");
    }

    #[test]
    fn refuses_other_formats() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let v4_proof = fs::read("proofs/pico-mle-compress-eth-proof.bin").unwrap();
        let root_proof = fs::read("proofs/pico-mle-eth-proof.bin").unwrap();
        let fri_proof = fs::read("proofs/pico-eth-proof.bin").unwrap();
        let fri_vk = fs::read("riscv-vks/pico-vk-kb.bin").unwrap();
        assert!(!is_compress_proof(&v4_proof));
        assert!(!is_compress_proof(&root_proof));
        assert!(!is_compress_proof(&fri_proof));
        assert!(verify(&v4_proof, &vk)
            .unwrap_err()
            .contains("format version 4"));
        assert!(verify(&root_proof, &vk)
            .unwrap_err()
            .contains("format version 3"));
        assert!(verify(&fri_proof, &vk).is_err());
        assert!(verify(&proof, &fri_vk).is_err());
        assert!(verify(&vk, &proof).is_err());
    }
}
