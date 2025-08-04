use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
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

// Enable console.log! macro for debugging
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

// Set up panic hook for better error messages
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// Serializable wrappers for MetaProof for specific field configurations
#[derive(Serialize, Deserialize)]
struct SerializableBabyBearMetaProof {
    proofs: Vec<BaseProof<BabyBearPoseidon2>>,
    vks: Vec<BaseVerifyingKey<BabyBearPoseidon2>>,
    pv_stream: Option<Vec<u8>>,
}

impl SerializableBabyBearMetaProof {
    fn to_meta_proof(self) -> MetaProof<BabyBearPoseidon2> {
        MetaProof::new(self.proofs.into(), self.vks.into(), self.pv_stream)
    }
}

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

// Combine machine wrappers for verification
struct BabyBearCombineVerifier {
    machine: CombineMachine<
        BabyBearPoseidon2,
        RecursionChipType<pico_vm::configs::config::Val<BabyBearPoseidon2>>,
    >,
}

impl BabyBearCombineVerifier {
    fn new() -> Self {
        let machine = CombineMachine::new(
            BabyBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        Self { machine }
    }

    fn verify(
        &self,
        proof: &MetaProof<BabyBearPoseidon2>,
        riscv_vk: &BaseVerifyingKey<BabyBearPoseidon2>,
    ) -> bool {
        self.machine.verify(proof, riscv_vk).is_ok()
    }
}

struct KoalaBearCombineVerifier {
    machine: CombineMachine<
        KoalaBearPoseidon2,
        RecursionChipType<pico_vm::configs::config::Val<KoalaBearPoseidon2>>,
    >,
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

// BabyBear field verification using CombineProver.verify()
// Expects a single serialized MetaProof and verification key
#[wasm_bindgen]
pub fn verify_babybear(proof_bytes: &[u8], riscv_vk_bytes: &[u8]) -> Result<bool, JsValue> {
    console_log!(
        "Starting BabyBear verification with proof size: {}, riscv_vk size: {}",
        proof_bytes.len(),
        riscv_vk_bytes.len()
    );

    // Deserialize the proof wrapper
    let serializable_proof: SerializableBabyBearMetaProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof: {}", e)))?;

    // Convert to MetaProof
    let proof = serializable_proof.to_meta_proof();

    // Deserialize the RISCV verification key
    let riscv_vk: BaseVerifyingKey<BabyBearPoseidon2> = bincode::deserialize(riscv_vk_bytes)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize riscv verification key: {}",
                e
            ))
        })?;

    // Create a combine verifier
    let verifier = BabyBearCombineVerifier::new();

    // Perform verification
    let result = verifier.verify(&proof, &riscv_vk);
    console_log!("Verification result: {}", result);

    Ok(result)
}

// KoalaBear field verification using CombineProver.verify()
// Expects a single serialized MetaProof and verification key
#[wasm_bindgen]
pub fn verify_koalabear(proof_bytes: &[u8], riscv_vk_bytes: &[u8]) -> Result<bool, JsValue> {
    console_log!(
        "Starting KoalaBear verification with proof size: {}, riscv_vk size: {}",
        proof_bytes.len(),
        riscv_vk_bytes.len()
    );

    // Deserialize the proof wrapper
    let serializable_proof: SerializableKoalaBearMetaProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof: {}", e)))?;

    // Convert to MetaProof
    let proof = serializable_proof.to_meta_proof();

    // Deserialize the RISCV verification key
    let riscv_vk: BaseVerifyingKey<KoalaBearPoseidon2> = bincode::deserialize(riscv_vk_bytes)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to deserialize riscv verification key: {}",
                e
            ))
        })?;

    // Create a combine verifier
    let verifier = KoalaBearCombineVerifier::new();

    // Perform verification
    let result = verifier.verify(&proof, &riscv_vk);
    console_log!("Verification result: {}", result);

    Ok(result)
}
