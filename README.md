# Proof Gatekeeper agent — zkVerify Agent Games, Season 01

An agent for the **Proof Gatekeeper** track of zkVerify's Agent Games
(21 Oct – 21 Nov 2026; 100,000 VFY for the track, split 50/30/20 across the
top three). The platform sends signed transfer tasks; the agent answers
APPROVE or REJECT and attaches a Groth16 proof — generated locally with the
official circuit — that the decision follows the registered condition. The
platform verifies the proof instead of trusting the answer.

Scoring: correct decision **+12**, wrong APPROVE **−6**, wrong REJECT **−3**,
timeout or missing proof **−2**, plus a reliability bonus. Rounds: 8 tasks
per agent per daily round, 13–20 Nov; everything closes 21 Nov 22:00 UTC.

## How it works

`POST /gatekeeper` receives a task envelope:

- **Transport auth** — HMAC-SHA256 over the *raw* request body, hex digest in
  the `x-agent-games-signature` header, keyed with the secret the dashboard
  issues at agent registration. Verified before JSON parsing; a bad or
  missing signature gets a 401 and nothing else. Every response, errors
  included, is signed the same way.
- **Envelope shape** — condition fields arrive wrapped in an `input` object;
  `task_id` sits on the envelope itself. (A flat envelope is also accepted.)
- **Decision** — a fixed checklist, first failure wins:
  1. `VK_SUBSTITUTION` — `proof_vk != registered_vk`
  2. `PROOF_REUSED` — `proof_tx` already seen under a *different* task_id
     (a redelivery of the same task_id is a retry, not a reuse)
  3. `THRESHOLD_MISMATCH` — `public_balance < minimum` (equality is valid)
  4. `EXPIRED_CONDITION` — `current_block >= expiry_block` (equality is expired)
  5. `RECIPIENT_MISMATCH` — recipients differ (compared case-insensitively)
  6. `AMOUNT_OVERFLOW` — `amount > max_transfer` (equality is valid)
  7. otherwise APPROVE with `VALID_CONDITION`
- **Proof** — snarkjs `groth16.fullProve` with the official artifacts
  (`gatekeeper.wasm`, `gatekeeper_final.zkey`). Circuit inputs: the ten
  condition fields, the decision bit, the task id as a field element
  (`keccak256(utf8(task_id)) mod p`, BN254), and a fresh random 32-byte salt
  kept private. Output: 13 public signals — a salt-dependent binding hash,
  then the twelve non-salt inputs. The circuit re-evaluates the condition
  itself, so a decision it disagrees with fails witness generation; the
  checklist above mirrors it bit-exactly (the test harness proves this:
  every trap's REJECT proof verifies).
- **Idempotency** — responses are cached per `task_id`; a redelivered task
  returns the original response byte-for-byte.
- **Fail visible, never hang** — if proof generation throws, the signed
  decision is still returned without a proof. `PROOF_REUSED` and malformed
  tasks (`INVALID_TASK`) carry no proof by design: reuse is a fact about
  this process's history, not about the task inputs, so the circuit cannot
  attest to it.
- **Self-test** — at boot the agent decides a synthetic valid task,
  generates a real proof and verifies it against the verification key
  exported from the official `.zkey`. `GET /health` reports the result.

Response shape:

```json
{ "decision": "APPROVE", "reason_code": "VALID_CONDITION", "proof_tx": "0x…",
  "proof": { "pi_a": ["…"], "pi_b": [["…"]], "pi_c": ["…"],
             "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["…13 values…"] }
```

## Run locally

```bash
npm install
npm run fetch-circuits   # downloads the official artifacts into circuits/
cp .env.example .env     # fill AGENT_GAMES_SECRET after dashboard registration
npm start                # listens on PORT (default 8080)
npm test                 # HTTP harness: all traps, boundaries, auth, reuse
```

Without a secret the server still runs (for local development) but inbound
signature verification is disabled — `/health` reports `hmacConfigured:
false`. Never deploy it that way.

## Deploy (Railway)

1. Create the Railway service from this repo; the start command is
   `npm start` (Railway injects `PORT`; the server binds `0.0.0.0:$PORT`).
2. Set environment variables on the service:
   - `AGENT_GAMES_SECRET` — the HMAC secret from the Agent Games dashboard
     (set it after registering the agent there; `AGENT_GAMES_HMAC_SECRET`
     is accepted as an alias).
   - `AGENT_GAMES_HMAC_FORMAT` — leave unset (`hex`); switch to `sha256=`
     only if the platform's preflight rejects the default.
   - `GATEKEEPER_TASK_ID_MODE` — leave unset (`keccak`); `numeric`/`hex`
     are fallbacks if a practice round ever rejects the proof's taskId.
3. Circuit binaries are **not** in git (see `.gitignore`); the server
   downloads them from `https://agentgames.zkverify.io/circuits` at boot
   when missing, then runs the proof self-test. Check `/health` after the
   deploy: `selfTest` must read `PASS` before entering the agent.
4. Register the deployed base URL + `/gatekeeper` as the agent endpoint in
   the dashboard, run the platform preflight, then a practice task, before
   the first scored round.

## Protocol notes — confirmed vs. open

Confirmed from the official artifacts and two independent entrant codebases
(cross-checked against each other and against the circuit itself):

- Artifact integrity: `gatekeeper.wasm` md5 `8f3a1d55cc0ac9d0176846ad6536c3c4`
  (1,755,820 bytes), `gatekeeper_final.zkey` md5 `086656cb4ead752f9a9374d2a5af706b`
  (309,750 bytes), both served from `agentgames.zkverify.io/circuits`;
  registered VK hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
  There is no separate `verification_key.json` download (all plausible names
  404) — the key is exported from the `.zkey` locally.
- Circuit input names and public-signal order, the seven-check list with its
  boundary rules, the preflight envelope (`{"type":"agent-games.preflight.v1"}`
  → `{ok:true, protocolVersion:"v1"}`), the response field names, and the
  HMAC header/format — all consistent across sources, and every locally
  generated proof (APPROVE and each REJECT trap) verifies against the
  official key, which pins the decision semantics empirically.

Open items to confirm against a live practice round after registration:

- **taskId mapping** — `keccak256(utf8(task_id)) mod p` is the default both
  entrant codebases settled on (one reports practice tasks confirmed it),
  but the platform does not document it; if a practice proof is rejected,
  flip `GATEKEEPER_TASK_ID_MODE` and retry.
- **proof_tx placement** — read from `input` or the envelope level,
  whichever carries it; the merge tolerates both.
- **Recipient encoding** — fixtures show hex addresses (or small decimal
  ids); values are passed to the circuit as-is. A non-numeric recipient
  string would make proof generation fail (the decision would still be
  returned, without a proof).
- **Proof-less PROOF_REUSED responses** — both reference entrants answer
  reuse without a proof; the platform's exact scoring treatment of that
  case is not documented in anything we could read.
