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

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum FieldType {
    BabyBear,
    KoalaBear,
}

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

// Serializable wrappers for MetaProof
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

// Wrapper function for the pico-vm CombineProver 'verify' function
// Expects a field type, serialized MetaProof, and verification key
#[wasm_bindgen]
pub fn verify_stark(
    field_type: &str,
    proof_bytes: &[u8],
    riscv_vk_bytes: &[u8],
) -> Result<bool, JsValue> {
    let field_type: FieldType = match field_type {
        "BabyBear" => FieldType::BabyBear,
        "KoalaBear" => FieldType::KoalaBear,
        _ => {
            return Err(JsValue::from_str(
                "Invalid field type. Use 'BabyBear' or 'KoalaBear'",
            ))
        }
    };

    console_log!(
        "Starting {:?} verification with proof size: {}, riscv_vk size: {}",
        field_type,
        proof_bytes.len(),
        riscv_vk_bytes.len()
    );

    match field_type {
        FieldType::BabyBear => {
            // Deserialize BabyBear proof wrapper
            let serializable_proof: SerializableBabyBearMetaProof =
                bincode::deserialize(proof_bytes).map_err(|e| {
                    JsValue::from_str(&format!("Failed to deserialize BabyBear proof: {}", e))
                })?;
            let proof = serializable_proof.to_meta_proof();

            // Deserialize BabyBear verification key
            let riscv_vk: BaseVerifyingKey<BabyBearPoseidon2> =
                bincode::deserialize(riscv_vk_bytes).map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to deserialize BabyBear riscv verification key: {}",
                        e
                    ))
                })?;

            let verifier = BabyBearCombineVerifier::new();
            let result = verifier.verify(&proof, &riscv_vk);
            console_log!("BabyBear verification result: {}", result);
            Ok(result)
        }
        FieldType::KoalaBear => {
            // Deserialize KoalaBear proof wrapper
            let serializable_proof: SerializableKoalaBearMetaProof =
                bincode::deserialize(proof_bytes).map_err(|e| {
                    JsValue::from_str(&format!("Failed to deserialize KoalaBear proof: {}", e))
                })?;
            let proof = serializable_proof.to_meta_proof();

            // Deserialize KoalaBear verification key
            let riscv_vk: BaseVerifyingKey<KoalaBearPoseidon2> =
                bincode::deserialize(riscv_vk_bytes).map_err(|e| {
                    JsValue::from_str(&format!(
                        "Failed to deserialize KoalaBear riscv verification key: {}",
                        e
                    ))
                })?;

            // Create and run verifier
            let verifier = KoalaBearCombineVerifier::new();
            let result = verifier.verify(&proof, &riscv_vk);
            console_log!("KoalaBear verification result: {}", result);
            Ok(result)
        }
    }
}
