// Field arithmetic helpers for the gatekeeper circuit (BN254 scalar field),
// and the mapping from the envelope's string task_id to a field element.

// Order of the BN254 (alt_bn128) scalar field.
const BN254_SCALAR_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Reduce any integer-like value (BigInt, number, decimal string, or
// 0x-prefixed hex string) into the field.
function reduceToField(value) {
  let v;
  if (typeof value === 'bigint') v = value;
  else if (typeof value === 'number') v = BigInt(value);
  else v = BigInt(String(value));
  const r = v % BN254_SCALAR_ORDER;
  return r >= 0n ? r : r + BN254_SCALAR_ORDER;
}

// True Keccak-256 (not the FIPS SHA3-256 variant — different padding).
// Implemented in pure JS via js-sha3: OpenSSL builds differ (Railway's Node
// has no keccak digest — "Digest method not supported"), so the hash must not
// depend on the platform's crypto provider. The test harness pins the output
// against the published empty-string/"abc" digests.
const { keccak256: keccak256Hex } = require('js-sha3');
function keccak256(data) {
  return Buffer.from(keccak256Hex.array(data));
}

// The envelope's task_id is a free-form string (e.g. "gk_24_9d1") but the
// circuit consumes a field element. Default mapping ("keccak"): hash the
// UTF-8 bytes of the id with Keccak-256 and reduce mod p. The "numeric" and
// "hex" modes are fallbacks (digits / hex characters of the id read as an
// integer) in case a practice round ever proves the default wrong; switch
// with GATEKEEPER_TASK_ID_MODE, nothing else changes.
function taskIdToFieldElement(taskId, mode = 'keccak') {
  const id = String(taskId ?? '');
  if (mode === 'numeric') {
    const digits = id.replace(/[^0-9]/g, '');
    return digits ? reduceToField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hexDigits = id.replace(/[^0-9a-fA-F]/g, '');
    return hexDigits ? reduceToField(BigInt('0x' + hexDigits)) : 0n;
  }
  return reduceToField(BigInt('0x' + keccak256(Buffer.from(id, 'utf8')).toString('hex')));
}

module.exports = { BN254_SCALAR_ORDER, reduceToField, keccak256, taskIdToFieldElement };
