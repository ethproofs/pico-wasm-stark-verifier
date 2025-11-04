use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

mod pico;
mod pico_prism;

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum VMType {
    Pico,
    PicoPrism,
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

// Wrapper function for the pico-vm CombineProver 'verify' function
// Expects a vm type, serialized MetaProof, and verification key
#[wasm_bindgen]
pub fn verify_stark(
    vm_type: &str,
    proof_bytes: &[u8],
    riscv_vk_bytes: &[u8],
) -> Result<bool, JsValue> {
    let vm_type = match vm_type {
        "Pico" => VMType::Pico,
        "PicoPrism" => VMType::PicoPrism,
        _ => {
            return Err(JsValue::from_str(
                "Invalid VM type. Use 'Pico' or 'PicoPrism'",
            ))
        }
    };

    console_log!(
        "Starting {:?} verification with proof size: {}, riscv_vk size: {}",
        vm_type,
        proof_bytes.len(),
        riscv_vk_bytes.len(),
    );

    match vm_type {
        VMType::Pico => {
            let result = pico::verify_kb_proof(proof_bytes, riscv_vk_bytes);
            console_log!("Pico single GPU verification result: {result:?}");
            result
        }
        VMType::PicoPrism => {
            let result = pico_prism::verify_kb_proof(proof_bytes, riscv_vk_bytes);
            console_log!("Pico Prism multi GPUs verification result: {result:?}");
            result
        }
    }
}
