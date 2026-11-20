import test from 'node:test';
import assert from 'node:assert/strict';
import {
  base64UrlEncode,
  base64UrlDecode,
  simulateHmacSha256,
  parseJwt,
  generateJwt,
  verifyJwt,
  crackHmacSecret,
  calculateKeyEntropy,
  lookupRainbowTable,
  evaluateApiChallenge,
} from './apiSecurityEngine.js';

test('base64UrlEncode and base64UrlDecode handle round trips and special characters', () => {
  const sample = '{"alg":"HS256","typ":"JWT","test":"hello+world/foo=bar"}';
  const encoded = base64UrlEncode(sample);

  assert.ok(!encoded.includes('+'));
  assert.ok(!encoded.includes('/'));
  assert.ok(!encoded.includes('='));

  const decoded = base64UrlDecode(encoded);
  assert.equal(decoded, sample);

  // Safe empty handling
  assert.equal(base64UrlDecode(''), '');
  assert.equal(base64UrlDecode(null), '');
});

test('simulateHmacSha256 generates deterministic tamper-evident signatures', () => {
  const data = 'header.payload';
  const sig1 = simulateHmacSha256(data, 'secret123');
  const sig2 = simulateHmacSha256(data, 'secret123');
  const sigDifferentKey = simulateHmacSha256(data, 'different-key');
  const sigTamperedData = simulateHmacSha256('header.tampered', 'secret123');

  assert.ok(sig1.startsWith('sig_'));
  assert.equal(sig1, sig2);
  assert.notEqual(sig1, sigDifferentKey);
  assert.notEqual(sig1, sigTamperedData);
  assert.equal(simulateHmacSha256(data, ''), '');
});

test('parseJwt parses valid tokens and detects malformed inputs', () => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: '123', name: 'Alice' };
  const validToken = generateJwt(header, payload, 'mykey');

  const parsed = parseJwt(validToken);
  assert.equal(parsed.validFormat, true);
  assert.equal(parsed.header.alg, 'HS256');
  assert.equal(parsed.payload.sub, '123');
  assert.equal(parsed.payload.name, 'Alice');
  assert.ok(parsed.signature.startsWith('sig_'));

  // Invalid formats
  assert.equal(parseJwt('not-a-jwt').validFormat, false);
  assert.equal(parseJwt('').validFormat, false);
  assert.equal(parseJwt('a.b').validFormat, false);
  assert.equal(parseJwt('a.b.c.d').validFormat, false);
  assert.equal(parseJwt('invalid_json.payload.sig').validFormat, false);
});

test('verifyJwt detects tampering and validates signatures correctly', () => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: 'user_1', role: 'user', exp: Math.floor(Date.now() / 1000) + 3600 };
  const token = generateJwt(header, payload, 'secret123');

  // Valid verification
  const validResult = verifyJwt(token, 'secret123');
  assert.equal(validResult.valid, true);
  assert.equal(validResult.payload.role, 'user');
  assert.equal(validResult.expired, false);

  // Wrong secret key
  const invalidKeyResult = verifyJwt(token, 'wrong-secret');
  assert.equal(invalidKeyResult.valid, false);
  assert.ok(invalidKeyResult.error.includes('Invalid signature'));

  // Tampered payload
  const tamperedPayloadB64 = base64UrlEncode(JSON.stringify({ sub: 'user_1', role: 'admin' }));
  const [headerB64, , sig] = token.split('.');
  const tamperedToken = `${headerB64}.${tamperedPayloadB64}.${sig}`;

  const tamperedResult = verifyJwt(tamperedToken, 'secret123');
  assert.equal(tamperedResult.valid, false);
  assert.ok(tamperedResult.error.includes('Invalid signature'));
});

test('verifyJwt enforces algorithm whitelisting and blocks alg: none', () => {
  const noneHeader = { alg: 'none', typ: 'JWT' };
  const payload = { sub: 'user_1', role: 'admin' };
  const noneToken = generateJwt(noneHeader, payload);

  // Defense active: alg 'none' blocked
  const blockedResult = verifyJwt(noneToken, 'any-secret', {
    allowedAlgorithms: ['HS256', 'RS256'],
  });
  assert.equal(blockedResult.valid, false);
  assert.equal(blockedResult.algBypassDetected, true);
  assert.ok(blockedResult.error.includes('Insecure algorithm'));

  // Insecure mode: alg 'none' explicitly allowed
  const allowedResult = verifyJwt(noneToken, 'any-secret', {
    allowedAlgorithms: ['HS256', 'none'],
  });
  assert.equal(allowedResult.valid, true);
  assert.equal(allowedResult.payload.role, 'admin');
});

test('verifyJwt enforces expiration timestamps', () => {
  const currentEpoch = 1700000000;
  const expiredPayload = { sub: 'user_1', exp: 1699990000 }; // in the past
  const expiredToken = generateJwt({ alg: 'HS256' }, expiredPayload, 'key');

  const res = verifyJwt(expiredToken, 'key', {
    currentTime: currentEpoch,
    enforceExp: true,
  });
  assert.equal(res.valid, false);
  assert.equal(res.expired, true);
  assert.ok(res.error.includes('Token expired'));

  // When exp verification is disabled
  const uncheckRes = verifyJwt(expiredToken, 'key', {
    currentTime: currentEpoch,
    enforceExp: false,
  });
  assert.equal(uncheckRes.valid, true);
});

test('crackHmacSecret discovers weak dictionary keys', () => {
  const token = generateJwt({ alg: 'HS256' }, { user: 'guest' }, 'secret123');
  const crackRes = crackHmacSecret(token, ['123456', 'admin', 'secret123', 'password']);

  assert.equal(crackRes.cracked, true);
  assert.equal(crackRes.secret, 'secret123');
  assert.equal(crackRes.attempts, 3);
  assert.ok(crackRes.timeMs >= 0);

  // Key not in dictionary
  const secureToken = generateJwt({ alg: 'HS256' }, { user: 'guest' }, 'random-unbreakable-key-9824');
  const failRes = crackHmacSecret(secureToken, ['123456', 'admin']);
  assert.equal(failRes.cracked, false);
  assert.equal(failRes.secret, null);
});

test('calculateKeyEntropy calculates bit-strength and ratings accurately', () => {
  const weak = calculateKeyEntropy('123456');
  assert.equal(weak.rating, 'Weak');
  assert.ok(weak.bits < 36);

  const moderate = calculateKeyEntropy('secret_key_123');
  assert.ok(['Moderate', 'Strong'].includes(moderate.rating));

  const strong = calculateKeyEntropy('d8F#k9!zL2@mQ4$vP7*wE1&rT5^yU3(oI6)aS0_dF');
  assert.equal(strong.rating, 'Cryptographic Grade');
  assert.ok(strong.bits >= 128);

  // Safe empty handling
  const empty = calculateKeyEntropy('');
  assert.equal(empty.entropy, 0);
  assert.equal(empty.rating, 'None');
});

test('lookupRainbowTable returns plaintext for known weak hashes', () => {
  // MD5 of 'password'
  const hit = lookupRainbowTable('5f4dcc3b5aa765d61d8327deb882cf99');
  assert.equal(hit.cracked, true);
  assert.equal(hit.plaintext, 'password');
  assert.equal(hit.algorithm, 'MD5');

  // Unknown random hash
  const miss = lookupRainbowTable('00000000000000000000000000000000');
  assert.equal(miss.cracked, false);
  assert.equal(miss.plaintext, null);
});

test('evaluateApiChallenge processes jwt_alg_none scenario end-to-end', () => {
  // Valid exploit token with alg: none and role: admin
  const exploitToken = generateJwt({ alg: 'none', typ: 'JWT' }, { sub: 'attacker', role: 'admin' });

  // 1. Without defense (Vulnerable Gateway) -> Exploit succeeds
  const run1 = evaluateApiChallenge('jwt_alg_none', exploitToken, { defenseActive: false });
  assert.equal(run1.passed, true);
  assert.equal(run1.statusCode, 200);
  assert.equal(run1.responseBody.status, 'ACCESS_GRANTED');
  assert.ok(run1.explanation.includes('EXPLOIT SUCCESSFUL'));

  // 2. With defense active (Secure Gateway) -> Exploit blocked
  const run2 = evaluateApiChallenge('jwt_alg_none', exploitToken, { defenseActive: true });
  assert.equal(run2.passed, true);
  assert.equal(run2.statusCode, 401);
  assert.equal(run2.responseBody.code, 'INSECURE_ALGORITHM');
  assert.ok(run2.explanation.includes('DEFENSE ACTIVATED'));
});

test('evaluateApiChallenge processes jwt_weak_secret and jwt_expired_replay', () => {
  // Weak secret forgery
  const forgedToken = generateJwt({ alg: 'HS256' }, { role: 'superuser' }, 'secret123');
  const resSecret = evaluateApiChallenge('jwt_weak_secret', forgedToken, { defenseActive: false });
  assert.equal(resSecret.passed, true);
  assert.equal(resSecret.statusCode, 200);

  // Expired replay
  const expiredToken = generateJwt({ alg: 'HS256' }, { sub: 'cfo', exp: 1000000 }, 'cluster');
  const resReplayExploit = evaluateApiChallenge('jwt_expired_replay', expiredToken, { defenseActive: false });
  assert.equal(resReplayExploit.passed, true);
  assert.equal(resReplayExploit.statusCode, 200);
  assert.equal(resReplayExploit.responseBody.status, 'WIRE_TRANSFER_EXECUTED');

  const resReplayBlocked = evaluateApiChallenge('jwt_expired_replay', expiredToken, { defenseActive: true });
  assert.equal(resReplayBlocked.passed, true);
  assert.equal(resReplayBlocked.statusCode, 401);
  assert.equal(resReplayBlocked.responseBody.error, 'TokenExpiredError');
});

test('API security scenarios have cryptographically valid initial tokens and crackable dictionary targets', async () => {
  const { API_SECURITY_SCENARIOS, COMMON_WEAK_SECRETS } = await import('../data/apiSecurityScenarios.js');

  // Verify jwt_alg_none
  const noneScenario = API_SECURITY_SCENARIOS.find((s) => s.id === 'jwt_alg_none');
  const noneVerify = verifyJwt(noneScenario.initialToken, noneScenario.initialSecret, { enforceExp: false });
  assert.equal(noneVerify.valid, true);

  // Verify jwt_weak_secret
  const weakScenario = API_SECURITY_SCENARIOS.find((s) => s.id === 'jwt_weak_secret');
  const weakVerify = verifyJwt(weakScenario.initialToken, weakScenario.initialSecret, { enforceExp: false });
  assert.equal(weakVerify.valid, true);

  // Verify jwt_expired_replay
  const expiredScenario = API_SECURITY_SCENARIOS.find((s) => s.id === 'jwt_expired_replay');
  const expiredVerify = verifyJwt(expiredScenario.initialToken, expiredScenario.initialSecret, { enforceExp: false });
  assert.equal(expiredVerify.valid, true);

  // Verify default cracker token
  const defaultCrackerToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzIwOTEiLCJuYW1lIjoiTWFyayBTbG9hbiIsInJvbGUiOiJ2aWV3ZXIifQ.sig_c16601c6b447d25e';
  const crack = crackHmacSecret(defaultCrackerToken, COMMON_WEAK_SECRETS);
  assert.equal(crack.cracked, true);
  assert.equal(crack.secret, 'secret123');
});

