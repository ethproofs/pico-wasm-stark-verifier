use pico_prism_vm::{
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::KoalaBearPoseidon2,
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::{BaseProof, MetaProof},
    },
    primitives::consts::RECURSION_NUM_PVS,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Serializable wrappers for MetaProof
#[derive(Serialize, Deserialize)]
struct SerializableKoalaBearMetaProof {
    proofs: Vec<BaseProof<KoalaBearPoseidon2>>,
    vks: Vec<BaseVerifyingKey<KoalaBearPoseidon2>>,
    pv_stream: Option<Vec<u8>>,
}

impl SerializableKoalaBearMetaProof {
    fn to_meta_proof(self) -> MetaProof<KoalaBearPoseidon2> {
        MetaProof::new(self.proofs.into(), self.vks.into(), self.pv_stream)
    }
}

struct KoalaBearCombineVerifier {
    machine: CombineMachine<KoalaBearPoseidon2, RecursionChipType<Val<KoalaBearPoseidon2>>>,
}

impl KoalaBearCombineVerifier {
    fn new() -> Self {
        let machine = CombineMachine::new(
            KoalaBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        Self { machine }
    }

    fn verify(
        &self,
        proof: &MetaProof<KoalaBearPoseidon2>,
        riscv_vk: &BaseVerifyingKey<KoalaBearPoseidon2>,
    ) -> bool {
        self.machine.verify(proof, riscv_vk).is_ok()
    }
}

// Verify the KoalaBear proof
pub(crate) fn verify_kb_proof(proof_bytes: &[u8], riscv_vk_bytes: &[u8]) -> Result<bool, JsValue> {
    // Deserialize KoalaBear proof wrapper
    let serializable_proof: SerializableKoalaBearMetaProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KoalaBear proof: {e}")))?;
    let proof = serializable_proof.to_meta_proof();

    // Deserialize KoalaBear verification key
    let riscv_vk: BaseVerifyingKey<KoalaBearPoseidon2> = bincode::deserialize(riscv_vk_bytes)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize KoalaBear riscv verification key: {e}",
            ))
        })?;

    // Create and run verifier
    let verifier = KoalaBearCombineVerifier::new();
    let result = verifier.verify(&proof, &riscv_vk);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use std::{env, fs};

    // RiscV VK for Pico Prism
    const PICO_PRISM_KB_VK_FILE_PATH: &str = "riscv-vks/pico-prism-vk-kb.bin";

    // Test Pico Prism proof downloading from eth-proofs:
    // <https://ethproofs.org/clusters/79041a5b-ee8d-49b3-8207-86c7debf8e13>
    const PICO_PRISM_TEST_PROOF_FILE_PATH: &str = "proofs/pico-prism-eth-proof.bin";

    // RiscV VK for Pico Prism of simple 5090
    const PICO_PRISM_SIMPLE_5090_KB_VK_FILE_PATH: &str =
        "riscv-vks/pico-prism-simple-5090-vk-kb.bin";

    // Test Pico Prism proof downloading from eth-proofs:
    // <https://ethproofs.org/clusters/a417ab66-2902-43e0-9611-0d4c77872775>
    const PICO_PRISM_SIMPLE_5090_TEST_PROOF_FILE_PATH: &str =
        "proofs/pico-prism-simple-5090-eth-proof.bin";

    #[test]
    fn test_pico_prism_verification() -> Result<()> {
        env::set_var("VK_VERIFICATION", "false");

        let vk: Vec<u8> = fs::read(PICO_PRISM_KB_VK_FILE_PATH)?;
        let proof: Vec<u8> = fs::read(PICO_PRISM_TEST_PROOF_FILE_PATH)?;

        let is_verified = verify_kb_proof(&proof, &vk)
            .map_err(|e| anyhow!("Failed to verify KoalaBear proof: {e:?}"))?;
        assert!(is_verified, "Cannot verify KoalaBear proof");

        Ok(())
    }

    #[test]
    fn test_pico_prism_simple_5090_verification() -> Result<()> {
        env::set_var("VK_VERIFICATION", "false");

        let vk: Vec<u8> = fs::read(PICO_PRISM_SIMPLE_5090_KB_VK_FILE_PATH)?;
        let proof: Vec<u8> = fs::read(PICO_PRISM_SIMPLE_5090_TEST_PROOF_FILE_PATH)?;

        let is_verified = verify_kb_proof(&proof, &vk)
            .map_err(|e| anyhow!("Failed to verify KoalaBear proof: {e:?}"))?;
        assert!(is_verified, "Cannot verify KoalaBear proof");

        Ok(())
    }
}
