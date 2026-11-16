// The gatekeeper checklist.
//
// The circuit re-evaluates the same condition from the same inputs and
// refuses to produce a witness for a decision it disagrees with, so this
// evaluation has to mirror the circuit exactly — including the boundary
// rules, which are NOT uniform:
//   public_balance == minimum  -> still valid  (threshold is inclusive)
//   amount == max_transfer     -> still valid  (cap is inclusive)
//   current_block == expiry    -> EXPIRED      (the condition is only alive
//                                               while current < expiry)
// Checks run in the fixed order below and the first failure names the
// outcome; if nothing fails, the transfer is approved.
//
// PROOF_REUSED is the one check the circuit cannot make: it depends on what
// this process has seen before, not on the task's inputs. We track the
// first task_id that presented each proof_tx. A platform redelivery of the
// SAME task_id is a retry, not a reuse.

// proof_tx (lowercased) -> task_id that presented it first
const firstSeenTaskByProofTx = new Map();

function asInteger(value, fieldName) {
  try {
    return BigInt(value);
  } catch {
    throw new TypeError(
      `task field "${fieldName}" is not an integer (got ${JSON.stringify(value)})`
    );
  }
}

// task: flat object with the envelope's condition fields plus task_id.
// Returns { decision: 'APPROVE'|'REJECT', reason_code }.
// Throws TypeError on non-integer numeric fields (the caller maps that to
// a fail-closed INVALID_TASK reject).
function evaluateTask(task) {
  const registeredVk = String(task.registered_vk ?? '').toLowerCase();
  const proofVk = String(task.proof_vk ?? '').toLowerCase();
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }

  const proofTx = String(task.proof_tx ?? '').toLowerCase();
  const taskId = String(task.task_id ?? '');
  if (proofTx !== '') {
    const firstTask = firstSeenTaskByProofTx.get(proofTx);
    if (firstTask !== undefined && firstTask !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (firstTask === undefined) firstSeenTaskByProofTx.set(proofTx, taskId);
  }

  if (asInteger(task.public_balance, 'public_balance') < asInteger(task.minimum, 'minimum')) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (asInteger(task.current_block, 'current_block') >= asInteger(task.expiry_block, 'expiry_block')) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (
    String(task.recipient ?? '').toLowerCase() !==
    String(task.condition_recipient ?? '').toLowerCase()
  ) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (asInteger(task.amount, 'amount') > asInteger(task.max_transfer, 'max_transfer')) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function resetSeenProofs() {
  firstSeenTaskByProofTx.clear();
}

module.exports = { evaluateTask, resetSeenProofs, firstSeenTaskByProofTx };
