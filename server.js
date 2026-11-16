// Proof Gatekeeper agent — zkVerify Agent Games, Season 01.
//
// Plain node:http server, no framework:
//   GET  /health     readiness, including the boot-time proof self-test
//   POST /gatekeeper signed task envelope in -> signed decision + proof out
//
// Protocol behaviour:
// - Requests and responses are authenticated with HMAC-SHA256 over the raw
//   body bytes (`x-agent-games-signature` header; secret from the Agent
//   Games dashboard). Inbound signatures are verified BEFORE JSON parsing.
//   Without a configured secret, inbound verification is skipped (local
//   development only) and /health says so.
// - A preflight envelope {"type":"agent-games.preflight.v1"} is answered
//   {"ok":true,"protocolVersion":"v1"}.
// - Task condition fields arrive wrapped in an `input` object on the
//   envelope, with task_id on the envelope itself. A flat envelope (fields
//   at top level) is accepted too — the merge below tolerates both, and
//   proof_tx is read from either level.
// - Responses are cached per task_id: a platform redelivery of the same
//   task gets the original response back byte-for-byte (and is NOT treated
//   as proof reuse).
// - PROOF_REUSED decisions carry no proof: reuse is a fact about this
//   process's history, not about the task inputs, so the circuit cannot
//   attest to it. The same applies to malformed tasks (INVALID_TASK).
// - If proof generation fails for any other decision, the signed decision
//   is still returned, without a proof — a visible miss beats a timeout.
const http = require('http');
const { SIGNATURE_HEADER, signBody, verifyBody } = require('./lib/hmac');
const { evaluateTask } = require('./gatekeeper/decide');
const { proveDecision } = require('./gatekeeper/prove');
const { verifyProof } = require('./lib/prover');
const { ensureCircuits } = require('./scripts/fetch-circuits');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const SECRET =
  process.env.AGENT_GAMES_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || '';
const SIGN_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';
const MAX_BODY_BYTES = 1024 * 1024;

// Registered verification-key hash of the official gatekeeper circuit.
const REGISTERED_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

let selfTest = 'pending';

// task_id -> response body object (idempotent redelivery)
const responseCache = new Map();

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (SECRET) headers[SIGNATURE_HEADER] = signBody(SECRET, body, SIGN_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Merge the envelope into the flat task shape the checklist works on.
// Condition fields live in `input` when the platform wraps them; task_id
// belongs to the envelope level and wins over any copy inside `input`.
function unwrapTask(envelope) {
  const wrapped =
    envelope && typeof envelope.input === 'object' && envelope.input !== null
      ? envelope.input
      : {};
  const task = { ...envelope, ...wrapped };
  if (envelope && envelope.task_id !== undefined) task.task_id = envelope.task_id;
  delete task.input;
  return task;
}

async function handleTask(envelope) {
  const task = unwrapTask(envelope);
  const cacheKey =
    typeof task.task_id === 'string' && task.task_id !== '' ? task.task_id : null;
  if (cacheKey && responseCache.has(cacheKey)) {
    return responseCache.get(cacheKey);
  }

  let outcome;
  try {
    outcome = evaluateTask(task);
  } catch (err) {
    if (!(err instanceof TypeError)) throw err;
    // Fail closed: a task we cannot even parse is rejected, never approved.
    outcome = { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }

  const body = { decision: outcome.decision, reason_code: outcome.reason_code };
  if (task.proof_tx !== undefined && task.proof_tx !== null && task.proof_tx !== '') {
    body.proof_tx = String(task.proof_tx);
  }

  const proofless = outcome.reason_code === 'PROOF_REUSED' || outcome.reason_code === 'INVALID_TASK';
  if (!proofless) {
    try {
      const { proof, publicSignals } = await proveDecision(task, outcome.decision, TASK_ID_MODE);
      body.proof = proof;
      body.public_signals = publicSignals;
    } catch (err) {
      console.error(`[gatekeeper] proof failed for task ${task.task_id}: ${err.message}`);
      body.proof_error = 'proof generation failed';
    }
  }

  if (cacheKey) responseCache.set(cacheKey, body);
  return body;
}

// Boot self-test: decide a synthetic valid task, generate a real proof and
// verify it against the verification key exported from the official .zkey.
// The synthetic task carries an empty proof_tx so it never pollutes the
// proof-reuse bookkeeping (proof_tx is not a circuit input).
async function runSelfTest() {
  const task = {
    task_id: 'gk_selftest_boot',
    registered_vk: REGISTERED_VK_HASH,
    proof_vk: REGISTERED_VK_HASH,
    minimum: '1000',
    public_balance: '1500',
    expiry_block: '9000000',
    current_block: '8999999',
    recipient: '0x1111111111111111111111111111111111111111',
    condition_recipient: '0x1111111111111111111111111111111111111111',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '',
  };
  try {
    const { decision, reason_code } = evaluateTask(task);
    if (decision !== 'APPROVE') {
      throw new Error(`synthetic task decided ${decision}/${reason_code}, expected APPROVE`);
    }
    const { proof, publicSignals } = await proveDecision(task, decision, TASK_ID_MODE);
    if (publicSignals.length !== 13) {
      throw new Error(`expected 13 public signals, got ${publicSignals.length}`);
    }
    const ok = await verifyProof(publicSignals, proof);
    selfTest = ok ? 'PASS' : 'FAIL (proof did not verify against the official verification key)';
  } catch (err) {
    selfTest = 'FAIL (' + err.message + ')';
  }
  console.log('[self-test]', selfTest);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendSigned(res, 200, {
        ok: true,
        service: 'proof-gatekeeper',
        hmacConfigured: Boolean(SECRET),
        taskIdMode: TASK_ID_MODE,
        selfTest,
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === 'GET' && req.url === '/') {
      return sendSigned(res, 200, {
        service: 'proof-gatekeeper',
        endpoints: ['POST /gatekeeper', 'GET /health'],
      });
    }
    if (req.method !== 'POST' || req.url !== '/gatekeeper') {
      return sendSigned(res, 404, { ok: false, error: 'not found' });
    }

    const raw = await readRawBody(req);
    if (SECRET && !verifyBody(SECRET, raw, req.headers[SIGNATURE_HEADER])) {
      return sendSigned(res, 401, { ok: false, error: 'bad signature' });
    }

    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendSigned(res, 400, { ok: false, error: 'invalid json' });
    }

    if (envelope && envelope.type === 'agent-games.preflight.v1') {
      return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    }

    const started = Date.now();
    const body = await handleTask(envelope);
    console.log(
      `[gatekeeper] task ${envelope && envelope.task_id} -> ${body.decision}/${body.reason_code} in ${Date.now() - started}ms`
    );
    return sendSigned(res, 200, body);
  } catch (err) {
    console.error('[server] unhandled error:', err);
    if (!res.headersSent) return sendSigned(res, 500, { ok: false, error: 'internal error' });
    res.end();
  }
});

ensureCircuits()
  .then(() => {
    server.listen(PORT, HOST, () => {
      console.log(
        `[gatekeeper] listening on ${HOST}:${PORT} (HMAC ${SECRET ? 'on' : 'OFF — set AGENT_GAMES_SECRET before going live'}, taskId mode ${TASK_ID_MODE})`
      );
      runSelfTest();
    });
  })
  .catch((err) => {
    console.error('[circuits] could not prepare circuit artifacts:', err.message);
    process.exit(1);
  });
