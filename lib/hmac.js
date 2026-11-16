// HMAC-SHA256 authentication for Agent Games envelopes.
//
// The platform signs every request body with the shared secret and sends
// the digest in the `x-agent-games-signature` header; our responses are
// signed the same way over their raw body bytes. Verification must happen
// on the raw bytes BEFORE any JSON parsing: re-serialising a parsed body
// would not reproduce the exact bytes that were signed.
const crypto = require('crypto');

const SIGNATURE_HEADER = 'x-agent-games-signature';

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

// Outbound encoding: bare lowercase hex by default; the "sha256=" form is
// available via AGENT_GAMES_HMAC_FORMAT if the platform ever asks for it.
function signBody(secret, rawBody, format = 'hex') {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

// Inbound, both encodings of the same digest are accepted — there is no
// security difference, and failing a preflight over the prefix alone would
// be a pointless own goal. Comparison is constant-time.
function verifyBody(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== 'string' || headerValue.length === 0) return false;
  const presented = headerValue.startsWith('sha256=')
    ? headerValue.slice('sha256='.length)
    : headerValue;
  const expected = Buffer.from(hmacHex(secret, rawBody), 'utf8');
  const actual = Buffer.from(presented, 'utf8');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

module.exports = { SIGNATURE_HEADER, signBody, verifyBody };
