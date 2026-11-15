/**
 * Predefined API Security and Token Vulnerability Scenarios
 * Covers OWASP API Security Top 10 vulnerabilities including:
 * - Broken Authentication & Algorithm Confusion (alg: none)
 * - Weak HMAC Secret Cracking & Token Forgery
 * - Expiration Validation & Replay Attacks
 * - Cryptographic Storage & Salt Deficiency
 */

export const API_SECURITY_SCENARIOS = [
  {
    id: 'jwt_alg_none',
    title: 'JWT Signature Bypass via `alg: none`',
    category: 'Broken Authentication',
    owaspTag: 'API2:2023 Broken Authentication',
    difficulty: 'Hard',
    summary:
      'Exploit an insecure API gateway that accepts the deprecated "none" algorithm, allowing privilege escalation from a standard user to system administrator without knowing the secret signing key.',
    initialToken:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEwNDIiLCJuYW1lIjoiQWxleCBWYW5jZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.d41d8cd98f00b204e9800998ecf8427e',
    initialSecret: 'super-secret-hmac-key',
    targetEndpoint: '/api/v1/admin/financial-records',
    targetObjective:
      'Modify the JWT header to {"alg": "none", "typ": "JWT"}, change payload "role" to "admin", and clear the signature to bypass authentication and retrieve restricted financial records.',
    vulnerableSnippet: `// INSECURE: Accepts any algorithm declared in token header
function verifyToken(token) {
  const [headerB64, payloadB64, signature] = token.split('.');
  const header = JSON.parse(base64UrlDecode(headerB64));
  const payload = JSON.parse(base64UrlDecode(payloadB64));

  // VULNERABILITY: If alg is 'none', signature check is skipped!
  if (header.alg === 'none' || !signature) {
    return { authenticated: true, user: payload };
  }

  return hmacSha256(headerB64 + '.' + payloadB64, SECRET) === signature
    ? { authenticated: true, user: payload }
    : { authenticated: false };
}`,
    secureSnippet: `// SECURE: Enforces strict algorithm whitelist and rejects 'none'
function verifyToken(token) {
  const ALLOWED_ALGORITHMS = ['HS256', 'RS256'];
  const [headerB64, payloadB64, signature] = token.split('.');
  const header = JSON.parse(base64UrlDecode(headerB64));

  // DEFENSE: Explicitly reject unverified algorithms
  if (!ALLOWED_ALGORITHMS.includes(header.alg) || !signature) {
    throw new SecurityException('Rejected: Insecure or unsupported algorithm');
  }

  const expectedSig = hmacSha256(headerB64 + '.' + payloadB64, SECRET);
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
    throw new SecurityException('Signature verification failed');
  }

  return JSON.parse(base64UrlDecode(payloadB64));
}`,
    hints: [
      'Decode the token header and change "alg": "HS256" to "alg": "none".',
      'In the payload, elevate the "role" claim from "user" to "admin".',
      'A token with alg: none must have an empty signature (format: header.payload.).',
    ],
  },
  {
    id: 'jwt_weak_secret',
    title: 'Weak HMAC Key Offline Cracking & Forgery',
    category: 'Cryptographic Failure',
    owaspTag: 'API2:2023 Cryptographic Failure & Token Forgery',
    difficulty: 'Hard',
    summary:
      'Crack a symmetric JWT signing key using dictionary brute-force against a weak secret, then forge a high-privilege token to invoke protected backend endpoints.',
    initialToken:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzIwOTEiLCJuYW1lIjoiTWFyayBTbG9hbiIsInJvbGUiOiJ2aWV3ZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnByb2ZpbGUiXSwiaWF0IjoxNzAwMDAwMDAwfQ.sim_secret123_sig',
    initialSecret: 'secret123',
    targetEndpoint: '/api/v1/management/system-audit',
    targetObjective:
      'Run a dictionary attack against the token to recover the signing secret, elevate permissions to ["*"] with role "superuser", and generate a valid HMAC-SHA256 signature.',
    vulnerableSnippet: `// INSECURE: Uses a predictable, low-entropy dictionary word as secret
const JWT_SECRET = process.env.JWT_SECRET || 'secret123'; // Weak secret!

app.post('/api/v1/auth/login', (req, res) => {
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256'
  });
  res.json({ token });
});`,
    secureSnippet: `// SECURE: Enforces a high-entropy 256-bit CSPRNG secret key
const crypto = require('crypto');
// 256-bit (32 bytes) cryptographically secure pseudorandom key
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || Buffer.from(JWT_SECRET, 'hex').length < 32) {
  throw new Error('FATAL: JWT_SECRET must be at least 256 bits of entropy');
}

app.post('/api/v1/auth/login', (req, res) => {
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m'
  });
  res.json({ token });
});`,
    hints: [
      'Use the Token Cracker tab to test the signature against common dictionary passwords.',
      'Notice how fast low-entropy keys (under 40 bits of entropy) are broken offline without triggering API rate limits.',
      'Once cracked, resign the tampered payload with the discovered secret.',
    ],
  },
  {
    id: 'jwt_expired_replay',
    title: 'Token Expiration Bypass & Replay Vulnerability',
    category: 'Broken Authentication',
    owaspTag: 'API2:2023 Broken Authentication & Replay Attacks',
    difficulty: 'Hard',
    summary:
      'Exploit an API service that verifies cryptographic signatures but neglects validating token expiration (`exp`), enabling indefinitely captured tokens to be replayed.',
    initialToken:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzUwMTIiLCJlbWFpbCI6ImV4ZWN1dGl2ZUBjb3JwLmxvY2FsIiwicm9sZSI6ImNmb19hZG1pbiIsImlhdCI6MTY5MDAwMDAwMCwiZXhwIjoxNjkwMDAzNjAwfQ.sim_securekey_sig',
    initialSecret: 'high-entropy-secure-cluster-key-2026',
    targetEndpoint: '/api/v1/treasury/wire-transfer',
    targetObjective:
      'Analyze the expired CFO token, identify the missing server-side expiration validation check, and apply the strict timestamp verification middleware patch.',
    vulnerableSnippet: `// INSECURE: Signature verified, but expiration timestamp ignored
function authenticateSession(token) {
  const decoded = verifySignature(token, CLUSTER_SECRET);
  if (!decoded) return null;

  // VULNERABILITY: Missing expiration check!
  // The token expired months ago, but is still treated as valid.
  return { authorized: true, user: decoded.sub, role: decoded.role };
}`,
    secureSnippet: `// SECURE: Strict expiration and clock skew verification
function authenticateSession(token) {
  const decoded = verifySignature(token, CLUSTER_SECRET);
  if (!decoded) return null;

  const currentEpoch = Math.floor(Date.now() / 1000);
  const CLOCK_TOLERANCE_SECONDS = 30; // Accommodate slight server time drift

  // DEFENSE: Strictly enforce expiration timestamp
  if (!decoded.exp || (currentEpoch - CLOCK_TOLERANCE_SECONDS) >= decoded.exp) {
    throw new SecurityException('Token has expired. Re-authentication required.');
  }

  return { authorized: true, user: decoded.sub, role: decoded.role };
}`,
    hints: [
      'Check the "exp" claim value against the current epoch timestamp.',
      'In a replay attack, stolen tokens with no expiration or revoked status remain valid forever.',
      'Activate the Expiration Defense to reject tokens whose exp timestamp has passed.',
    ],
  },
  {
    id: 'crypto_unsalted_hashes',
    title: 'Unsalted Hash Exposure vs Key Derivation (bcrypt)',
    category: 'Cryptographic Storage',
    owaspTag: 'API2:2023 Security Misconfiguration & Password Storage',
    difficulty: 'Hard',
    summary:
      'Demonstrate how fast unsalted hashes (MD5 / SHA-1) in leaked credential databases can be instantly reverse-looked up using precomputed rainbow tables, and upgrade the storage engine to salted bcrypt.',
    initialHash: '5f4dcc3b5aa765d61d8327deb882cf99', // MD5 of "password"
    initialSalt: null,
    targetEndpoint: '/api/v1/auth/hash-audit',
    targetObjective:
      'Examine the leaked MD5 hash database, execute a simulated rainbow table lookup to expose plaintext passwords, and verify the mitigation using bcrypt with salt and work factor 12.',
    vulnerableSnippet: `// INSECURE: Fast unsalted MD5 hashing for password storage
const crypto = require('crypto');

function storePassword(password) {
  // VULNERABILITY: MD5 can compute billions of hashes/second.
  // Precomputed rainbow tables allow instant reverse lookup.
  return crypto.createHash('md5').update(password).digest('hex');
}`,
    secureSnippet: `// SECURE: Adaptive salted key derivation with bcrypt / Argon2id
const bcrypt = require('bcrypt');

async function storePassword(password) {
  const SALT_ROUNDS = 12; // Computationally expensive work factor
  // DEFENSE: Generates a unique 128-bit salt and runs 4096 hashing rounds
  return await bcrypt.hash(password, SALT_ROUNDS);
}`,
    hints: [
      'Fast cryptographic hashes (MD5, SHA-256) were designed for message integrity, NOT password storage.',
      'Without a random salt, identical passwords produce identical hashes across all accounts.',
      'Work factors ensure brute-force attacks take millennia rather than seconds.',
    ],
  },
];

export const COMMON_WEAK_SECRETS = [
  'secret',
  'password',
  '123456',
  'secret123',
  'admin',
  'jwtsecret',
  'supersecret',
  'qwerty',
  'letmein',
  'welcome',
  'api-secret',
];

export const RAINBOW_TABLE_LOOKUP = {
  '5f4dcc3b5aa765d61d8327deb882cf99': { plaintext: 'password', algorithm: 'MD5' },
  '21232f297a57a5a743894a0e4a801fc3': { plaintext: 'admin', algorithm: 'MD5' },
  'e10adc3949ba59abbe56e057f20f883e': { plaintext: '123456', algorithm: 'MD5' },
  '827ccb0eea8a706c4c34a16891f84e7b': { plaintext: '12345', algorithm: 'MD5' },
  '098f6bcd4621d373cade4e832627b4f6': { plaintext: 'test', algorithm: 'MD5' },
  'd41d8cd98f00b204e9800998ecf8427e': { plaintext: '', algorithm: 'MD5 (empty)' },
};
