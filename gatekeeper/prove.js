// Builds the gatekeeper circuit input for a decided task and generates
// its Groth16 proof.
//
// Circuit inputs (13): the ten condition fields, the decision bit
// (1 = APPROVE, 0 = REJECT), the task id mapped to a field element, and a
// fresh random 32-byte salt that stays private.
// Public signals (13): a salt-dependent binding hash first, then the twelve
// non-salt inputs in circuit order — the platform checks those twelve
// against the envelope it sent, and the binding hash stops proofs from
// being precomputed or replayed across tasks.
const crypto = require('crypto');
const { taskIdToFieldElement } = require('../lib/field');
const { generateProof } = require('../lib/prover');

function buildCircuitInput(task, decision, taskIdMode) {
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToFieldElement(task.task_id, taskIdMode).toString(10),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
}

async function proveDecision(task, decision, taskIdMode) {
  return generateProof(buildCircuitInput(task, decision, taskIdMode));
}

module.exports = { buildCircuitInput, proveDecision };
