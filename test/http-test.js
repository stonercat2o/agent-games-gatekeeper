// HTTP-level test harness for the Proof Gatekeeper agent.
//
// Boots the real server as a child process with a throwaway HMAC secret,
// waits for its boot self-test to PASS, then drives signed task envelopes
// over HTTP — the same wire shape the platform uses (condition fields
// wrapped in `input`, task_id on the envelope). Proofs returned by the
// server are verified locally with snarkjs against the verification key
// exported from the official .zkey, and every response's HMAC signature
// header is checked.
//
// Run: npm test   (or: node test/http-test.js)
const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');

const { keccak256 } = require('../lib/field');

const ROOT = path.join(__dirname, '..');
const PORT = 18741;
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = 'local-harness-secret-not-for-production';

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER_ADDR = '0x2222222222222222222222222222222222222222';

let passed = 0;
let failed = 0;
function report(ok, name, detail = '') {
  if (ok) passed++;
  else failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
}

function sign(text, secret = TEST_SECRET) {
  return crypto.createHmac('sha256', secret).update(text).digest('hex');
}

async function postEnvelope(envelope, { secret = TEST_SECRET, signIt = true } = {}) {
  const bodyText = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
  const headers = { 'content-type': 'application/json' };
  if (signIt) headers['x-agent-games-signature'] = sign(bodyText, secret);
  const t0 = Date.now();
  const res = await fetch(BASE + '/gatekeeper', { method: 'POST', headers, body: bodyText });
  const text = await res.text();
  const ms = Date.now() - t0;
  let json = null;
  try {
    json = JSON.parse(text);
  } catch { /* leave null */ }
  return { status: res.status, text, json, ms, signature: res.headers.get('x-agent-games-signature') };
}

function responseSignatureValid(r) {
  return r.signature === sign(r.text);
}

// Envelope in the platform's wire shape: condition fields inside `input`.
function envelope(taskId, input) {
  return { task_id: taskId, input };
}

function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: '8430000',
    current_block: '8420000',
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xproof0001',
    ...overrides,
  };
}

async function waitForSelfTest(child) {
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited early with code ${child.exitCode}`);
    try {
      const res = await fetch(BASE + '/health');
      const json = await res.json();
      if (json.selfTest && json.selfTest.startsWith('PASS')) return json;
      if (json.selfTest && json.selfTest.startsWith('FAIL')) {
        throw new Error('server self-test failed: ' + json.selfTest);
      }
    } catch (err) {
      if (err.message.startsWith('server self-test')) throw err;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('timed out waiting for the server self-test');
}

async function main() {
  // Pin the Keccak-256 used for the taskId mapping against published vectors.
  report(
    keccak256(Buffer.from('')).toString('hex') ===
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' &&
      keccak256(Buffer.from('abc')).toString('hex') ===
        '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    'keccak-256 matches published test vectors'
  );

  const child = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_SECRET: TEST_SECRET,
      GATEKEEPER_TASK_ID_MODE: 'keccak',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  child.stderr.on('data', (d) => process.stderr.write('[server] ' + d));

  try {
    const health = await waitForSelfTest(child);
    report(true, 'boot self-test (synthetic task -> proof -> local verify)', health.selfTest);

    const vk = await snarkjs.zKey.exportVerificationKey(
      path.join(ROOT, 'circuits', 'gatekeeper_final.zkey')
    );
    const proofVerifies = async (r) =>
      Boolean(r.json && r.json.proof) &&
      (await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof));

    // --- the happy path -------------------------------------------------
    const validBody = JSON.stringify(envelope('gk_case_valid', baseInput()));
    const valid = await postEnvelope(validBody);
    report(
      valid.status === 200 &&
        valid.json.decision === 'APPROVE' &&
        valid.json.reason_code === 'VALID_CONDITION' &&
        valid.json.public_signals.length === 13,
      'valid task -> APPROVE/VALID_CONDITION with 13 public signals',
      `${valid.ms}ms`
    );
    report(await proofVerifies(valid), 'valid task proof verifies locally', `${valid.ms}ms`);
    report(responseSignatureValid(valid), 'valid task response is correctly HMAC-signed');

    // --- the six traps ----------------------------------------------------
    const traps = [
      ['VK_SUBSTITUTION', { proof_vk: OTHER_VK, proof_tx: '0xproof0002' }],
      ['THRESHOLD_MISMATCH', { public_balance: '999', proof_tx: '0xproof0003' }],
      ['EXPIRED_CONDITION', { current_block: '8430001', proof_tx: '0xproof0004' }],
      ['RECIPIENT_MISMATCH', { recipient: OTHER_ADDR, proof_tx: '0xproof0005' }],
      ['AMOUNT_OVERFLOW', { amount: '1001', proof_tx: '0xproof0006' }],
    ];
    for (const [reason, patch] of traps) {
      const r = await postEnvelope(envelope('gk_case_' + reason.toLowerCase(), baseInput(patch)));
      const okDecision =
        r.status === 200 && r.json.decision === 'REJECT' && r.json.reason_code === reason;
      report(okDecision, `trap ${reason} -> REJECT/${reason}`, `${r.ms}ms`);
      report(await proofVerifies(r), `trap ${reason} proof verifies (circuit agrees)`, `${r.ms}ms`);
    }

    // --- boundaries -------------------------------------------------------
    const boundaries = [
      [
        'balance == minimum approves',
        { public_balance: '1000', proof_tx: '0xproof0007' },
        'APPROVE',
        'VALID_CONDITION',
      ],
      [
        'amount == max approves',
        { amount: '1000', proof_tx: '0xproof0008' },
        'APPROVE',
        'VALID_CONDITION',
      ],
      [
        'current_block == expiry_block is EXPIRED',
        { current_block: '8430000', proof_tx: '0xproof0009' },
        'REJECT',
        'EXPIRED_CONDITION',
      ],
      [
        'recipient match is case-insensitive',
        {
          recipient: '0xaBcDeF1111111111111111111111111111111111',
          condition_recipient: '0xABCDEF1111111111111111111111111111111111',
          proof_tx: '0xproof0010',
        },
        'APPROVE',
        'VALID_CONDITION',
      ],
    ];
    for (const [name, patch, wantDecision, wantReason] of boundaries) {
      const r = await postEnvelope(
        envelope('gk_case_boundary_' + Math.random().toString(36).slice(2, 8), baseInput(patch))
      );
      report(
        r.status === 200 && r.json.decision === wantDecision && r.json.reason_code === wantReason,
        'boundary: ' + name,
        `${r.ms}ms`
      );
      report(await proofVerifies(r), 'boundary proof verifies: ' + name, `${r.ms}ms`);
    }

    // --- transport auth -----------------------------------------------------
    const badSig = await postEnvelope(envelope('gk_case_badsig', baseInput()), {
      secret: 'the-wrong-secret',
    });
    report(badSig.status === 401, 'bad signature -> 401', `${badSig.ms}ms`);
    const noSig = await postEnvelope(envelope('gk_case_nosig', baseInput()), { signIt: false });
    report(noSig.status === 401, 'missing signature -> 401', `${noSig.ms}ms`);

    // --- proof reuse + idempotent redelivery --------------------------------
    const reuse = await postEnvelope(
      envelope('gk_case_someone_else', baseInput({ proof_tx: '0xproof0001' }))
    );
    report(
      reuse.status === 200 &&
        reuse.json.decision === 'REJECT' &&
        reuse.json.reason_code === 'PROOF_REUSED' &&
        reuse.json.proof === undefined,
      'proof_tx reused under a second task_id -> PROOF_REUSED (no proof)',
      `${reuse.ms}ms`
    );

    const redelivered = await postEnvelope(validBody);
    report(
      redelivered.status === 200 && redelivered.text === valid.text,
      'same task_id redelivered -> cached response, byte-identical (not reuse)',
      `${redelivered.ms}ms`
    );

    // --- preflight ----------------------------------------------------------
    const preflight = await postEnvelope({ type: 'agent-games.preflight.v1' });
    report(
      preflight.status === 200 && preflight.json.ok === true && preflight.json.protocolVersion === 'v1',
      'preflight envelope -> {ok:true, protocolVersion:"v1"}',
      `${preflight.ms}ms`
    );

    // --- flat envelope tolerance ---------------------------------------------
    const flat = await postEnvelope({ task_id: 'gk_case_flat', ...baseInput({ proof_tx: '0xproof0011' }) });
    report(
      flat.status === 200 && flat.json.decision === 'APPROVE' && (await proofVerifies(flat)),
      'flat envelope (no `input` wrapper) -> APPROVE + verifying proof',
      `${flat.ms}ms`
    );
  } finally {
    child.kill('SIGTERM');
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('HARNESS ERROR:', err);
  process.exit(1);
});
