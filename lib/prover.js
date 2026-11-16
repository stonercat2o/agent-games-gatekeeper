// Thin wrapper around snarkjs for the official gatekeeper artifacts.
// The verification key is exported from the .zkey itself (there is no
// separate official verification_key.json download), so local verification
// always uses exactly the key the proving key commits to.
const path = require('path');
const snarkjs = require('snarkjs');

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');

let vkPromise = null;
function loadVerificationKey() {
  if (!vkPromise) vkPromise = snarkjs.zKey.exportVerificationKey(ZKEY_PATH);
  return vkPromise;
}

// Returns { proof, publicSignals }. Throws when the witness calculation
// rejects the inputs — i.e. when the decision we feed in disagrees with the
// circuit's own evaluation of the condition.
async function generateProof(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  return { proof, publicSignals };
}

async function verifyProof(publicSignals, proof) {
  const vk = await loadVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { WASM_PATH, ZKEY_PATH, loadVerificationKey, generateProof, verifyProof };
