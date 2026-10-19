//! Pico 3.0 (MLE/WHIR) root proofs.
//!
//! ethproofs stores two byte strings for a Pico 3.0 cluster, both framed the same way:
//!
//! ```text
//! magic (8 bytes) | format version (u32 LE) | zstd(bincode(body))
//! ```
//!
//! - the proof, `PICOMLE\0` version 3 ([`ProofV3`]): the root proof and the verifying key it was
//!   proved under;
//! - the VK, `PICOMLEV` version 2 ([`VkBundleV2`]): the guest identity, the whitelist root, and
//!   Merkle memberships under that root of the keys a root proof can be proved under.
//!
//! The proof's magic is what routes it here from `verify_stark("Pico", ..)`; the FRI proofs that
//! share that type are bincode and never start with it.
//!
//! The VK bundle is everything this verifier trusts. The key inside the proof is not trusted:
//! pico-vm's `MleApexVerifier` accepts the proof only if that key's body hashes to its identity
//! and the identity is one of the bundle's members, the root proof verifies under it, the
//! recursion tree is complete, and its public values name the bundle's guest and whitelist root.
//! Every inner key of the tree was checked against that same root in circuit.
//!
//! Both formats are written by Brevis's ethproofs prover; the structs here mirror its own.

use std::{io::Read, sync::Arc};

use bincode::Options;
use pico_mle_core::{
    codec::Decode, config::recursion_params_with_100_bits_security,
    keygen::types::MultiStarkVerifyingKey, p3_field::PrimeCharacteristicRing, proof::Proof,
};
use pico_mle_vm::{
    machine::septic::{SepticCurve, SepticDigest, SepticExtension},
    mle::machine::{
        apex::MleApexVerifier, exe::RiscvVmVk, recursion::Kb, riscv::Sc, vk_map::VkMembership,
    },
};
use serde::{de::DeserializeOwned, Deserialize};
use wasm_bindgen::prelude::*;

const PROOF_MAGIC: [u8; 8] = *b"PICOMLE\0";
const PROOF_VERSION: u32 = 3;
const VK_MAGIC: [u8; 8] = *b"PICOMLEV";
const VK_VERSION: u32 = 2;

/// Bounds what hostile bytes can make the verifier allocate, in the zstd stream and in every
/// bincode length prefix. A real proof body is under 1 MB and a VK bundle about 20 KB.
const MAX_BODY: u64 = 16 << 20;

/// A root proof and the key it was proved under.
#[derive(Deserialize)]
struct ProofV3 {
    /// The root proof, in mle-core's versioned wire codec.
    proof: Vec<u8>,
    /// bincode of the root's `MultiStarkVerifyingKey`.
    root_vk: Vec<u8>,
}

/// What a cluster version's VK holds.
#[derive(Deserialize)]
struct VkBundleV2 {
    /// The guest identity: program commitment (8), entry pc (3), and the initial global
    /// cumulative sum's x (7) and y (7), as canonical u32s.
    vm_vk: Vec<u32>,
    /// The whitelist root.
    vk_root: [u32; 8],
    /// The keys a root proof can be proved under, with their paths to `vk_root`.
    members: Vec<MemberV2>,
}

#[derive(Deserialize)]
struct MemberV2 {
    pre_hash: [u32; 8],
    merged_commit: [u32; 8],
    index: u32,
    /// One sibling per tree level, bottom-up.
    siblings: Vec<[u32; 8]>,
}

pub(crate) fn is_mle_proof(bytes: &[u8]) -> bool {
    bytes.starts_with(&PROOF_MAGIC)
}

/// `Ok(true)` if `proof_bytes` is a complete root proof of the guest `vk_bytes` names, under the
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

fn verify_decoded(bundle: &VkBundleV2, body: &ProofV3) -> Result<(), String> {
    let members = bundle
        .members
        .iter()
        .map(|m| VkMembership {
            identity: (field(&m.pre_hash), field(&m.merged_commit)),
            index: m.index as usize,
            siblings: m.siblings.iter().map(field).collect(),
        })
        .collect();
    let apex = MleApexVerifier::with_members(
        recursion_params_with_100_bits_security(),
        members,
        vm_vk(&bundle.vm_vk)?,
        field(&bundle.vk_root),
    )
    .map_err(|e| format!("vk: {e}"))?;

    let proof = Proof::<Sc>::decode_from_bytes(&body.proof).map_err(|e| format!("proof: {e:?}"))?;
    let root_vk: MultiStarkVerifyingKey<Sc> = bincode_capped()
        .deserialize(&body.root_vk)
        .map_err(|e| format!("proof: root vk: {e}"))?;
    apex.verify(&(proof, Arc::new(root_vk)))
        .map_err(|e| e.to_string())
}

/// The inverse of the prover's framing, bounded against hostile input.
fn unframe<T: DeserializeOwned>(
    bytes: &[u8],
    magic: &[u8; 8],
    version: u32,
    what: &str,
) -> Result<T, String> {
    let rest = bytes
        .strip_prefix(magic.as_slice())
        .ok_or_else(|| format!("{what}: not a Pico 3.0 {what}"))?;
    let (v, mut body) = rest
        .split_at_checked(4)
        .ok_or_else(|| format!("{what}: truncated"))?;
    let v = u32::from_le_bytes(v.try_into().expect("4 bytes"));
    if v != version {
        return Err(format!(
            "{what}: format version {v}, this verifier reads {version}"
        ));
    }
    let mut raw = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(&mut body)
        .map_err(|e| format!("{what}: zstd: {e}"))?
        .take(MAX_BODY + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("{what}: zstd: {e}"))?;
    if raw.len() as u64 > MAX_BODY {
        return Err(format!("{what}: body over {MAX_BODY} bytes"));
    }
    bincode_capped()
        .deserialize(&raw)
        .map_err(|e| format!("{what}: {e}"))
}

/// bincode as the prover's `bincode::serialize` writes it (fixed-width integers), with every
/// length prefix checked against [`MAX_BODY`] before anything is allocated.
fn bincode_capped() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY)
}

fn field(limbs: &[u32; 8]) -> [Kb; 8] {
    limbs.map(Kb::from_u32)
}

fn vm_vk(e: &[u32]) -> Result<RiscvVmVk, String> {
    if e.len() != 25 {
        return Err(format!(
            "vk: the guest identity needs 25 field elements, got {}",
            e.len()
        ));
    }
    let k = |i: usize| Kb::from_u32(e[i]);
    Ok(RiscvVmVk {
        program_commit: std::array::from_fn(k),
        pc_start: [k(8), k(9), k(10)],
        initial_gcs: SepticDigest(SepticCurve {
            x: SepticExtension(std::array::from_fn(|i| k(11 + i))),
            y: SepticExtension(std::array::from_fn(|i| k(18 + i))),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // A Pico 3.0 proof of mainnet block 26202136, downloaded from ethproofs staging, and the VK
    // bundle for that cluster's guest and whitelist.
    const PROOF_FILE_PATH: &str = "proofs/pico-mle-eth-proof.bin";
    const VK_FILE_PATH: &str = "riscv-vks/pico-mle-vk-kb.bin";

    fn fixtures() -> (VkBundleV2, ProofV3) {
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        (
            unframe(&vk, &VK_MAGIC, VK_VERSION, "vk").unwrap(),
            unframe(&proof, &PROOF_MAGIC, PROOF_VERSION, "proof").unwrap(),
        )
    }

    #[test]
    fn test_pico_mle_verification() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        assert!(is_mle_proof(&proof));
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
    fn rejects_a_tampered_root_vk() {
        let (bundle, mut body) = fixtures();
        let last = body.root_vk.len() - 1;
        body.root_vk[last] ^= 1;
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
    fn rejects_a_key_the_bundle_does_not_vouch_for() {
        let (mut bundle, body) = fixtures();
        bundle.members.clear();
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
    fn refuses_other_formats() {
        let proof = fs::read(PROOF_FILE_PATH).unwrap();
        let vk = fs::read(VK_FILE_PATH).unwrap();
        let fri_proof = fs::read("proofs/pico-eth-proof.bin").unwrap();
        let fri_vk = fs::read("riscv-vks/pico-vk-kb.bin").unwrap();
        assert!(!is_mle_proof(&fri_proof));
        assert!(verify(&fri_proof, &vk).is_err());
        assert!(verify(&proof, &fri_vk).is_err());
        assert!(verify(&vk, &proof).is_err());
        let mut v1 = vk.clone();
        v1[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify(&proof, &v1)
            .unwrap_err()
            .contains("format version 1"));
    }
}
