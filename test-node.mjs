import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { main, verify_stark } from './pkg-node/pico_wasm_stark_verifier.js';

// Every proof here is a real ethproofs block proof and must verify.
const CASES = [
  {
    name: 'Pico (FRI, single GPU)',
    vmType: 'Pico',
    proof: 'pico-eth-proof.bin',
    vk: 'pico-vk-kb.bin',
  },
  {
    name: 'Pico Prism (FRI, multi GPUs)',
    vmType: 'PicoPrism',
    proof: 'pico-prism-eth-proof.bin',
    vk: 'pico-prism-vk-kb.bin',
  },
  {
    // Shares the 'Pico' type; the verifier recognizes the proof format by its magic.
    name: 'Pico 3.0 (MLE)',
    vmType: 'Pico',
    proof: 'pico-mle-eth-proof.bin',
    vk: 'pico-mle-vk-kb.bin',
  },
];

async function testVerification() {
  console.log('🧪 Testing Pico WASM STARK Verifier\n');

  main();
  console.log('✅ WASM module initialized\n');

  let failed = 0;
  for (const c of CASES) {
    const proofBytes = fs.readFileSync(path.join(__dirname, 'proofs', c.proof));
    const vkBytes = fs.readFileSync(path.join(__dirname, 'riscv-vks', c.vk));
    console.log(`🔍 ${c.name}: proof ${proofBytes.length} bytes, VK ${vkBytes.length} bytes`);

    const start = performance.now();
    let result;
    try {
      result = verify_stark(c.vmType, proofBytes, vkBytes);
    } catch (error) {
      result = false;
      console.error(`   ❌ Error: ${error?.message ?? error}`);
    }
    const ms = Math.round(performance.now() - start);
    console.log(`   ${result ? '✅ VALID' : '❌ INVALID'} in ${ms} milliseconds\n`);
    if (!result) failed += 1;
  }

  console.log('📊 Verification Summary:');
  console.log(`  ${CASES.length - failed}/${CASES.length} proofs verified`);
  if (failed) process.exit(1);
}

testVerification();
