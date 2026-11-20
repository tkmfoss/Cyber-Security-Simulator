/**
 * API Security & Token Vulnerability Evaluation Engine
 * Pure, deterministic cryptographic simulation for:
 * - JWT parsing, encoding, decoding, and signature validation
 * - Algorithm confusion and `alg: none` exploit verification
 * - Weak HMAC secret dictionary cracking
 * - Key entropy and bit-strength analysis
 * - Expiration validation and replay attack detection
 * - Rainbow table hash lookup
 */

import { COMMON_WEAK_SECRETS, RAINBOW_TABLE_LOOKUP } from '../data/apiSecurityScenarios.js';

/**
 * Base64URL encode a UTF-8 string (RFC 7515 compliant)
 */
export function base64UrlEncode(str) {
  if (typeof str !== 'string') {
    str = JSON.stringify(str);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf-8').toString('base64url');
  }
  // Browser fallback
  const b64 = btoa(unescape(encodeURIComponent(str)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode a string to UTF-8
 */
export function base64UrlDecode(str) {
  if (!str || typeof str !== 'string') return '';
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'base64url').toString('utf-8');
  }
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  return decodeURIComponent(escape(atob(b64)));
}

/**
 * Deterministic simulated HMAC-SHA256 signature generator.
 * Produces reproducible, tamper-evident hash digests across environments.
 */
export function simulateHmacSha256(data, secret) {
  if (!secret || typeof secret !== 'string') return '';
  if (typeof data !== 'string') data = String(data);

  let h1 = 0x811c9dc5;
  const combined = `${secret}:${data}:${secret}`;
  for (let i = 0; i < combined.length; i++) {
    h1 ^= combined.charCodeAt(i);
    h1 = Math.imul(h1, 0x01000193);
  }
  const hex1 = (h1 >>> 0).toString(16).padStart(8, '0');

  let h2 = 0x9e3779b9;
  for (let i = combined.length - 1; i >= 0; i--) {
    h2 ^= combined.charCodeAt(i);
    h2 = Math.imul(h2, 0x5bd1e995);
  }
  const hex2 = (h2 >>> 0).toString(16).padStart(8, '0');

  return `sig_${hex1}${hex2}`;
}

/**
 * Parse and validate a 3-part JSON Web Token string
 */
export function parseJwt(tokenString) {
  if (!tokenString || typeof tokenString !== 'string') {
    return {
      validFormat: false,
      header: null,
      payload: null,
      signature: null,
      rawHeader: '',
      rawPayload: '',
      error: 'Token must be a non-empty string',
    };
  }

  const parts = tokenString.trim().split('.');
  if (parts.length !== 3) {
    return {
      validFormat: false,
      header: null,
      payload: null,
      signature: null,
      rawHeader: '',
      rawPayload: '',
      error: `Invalid JWT structure: Expected 3 period-separated parts, found ${parts.length}`,
    };
  }

  const [rawHeader, rawPayload, signature] = parts;
  let header = null;
  let payload = null;

  try {
    const decodedHeader = base64UrlDecode(rawHeader);
    header = JSON.parse(decodedHeader);
  } catch (err) {
    return {
      validFormat: false,
      header: null,
      payload: null,
      signature,
      rawHeader,
      rawPayload,
      error: `Malformed JWT Header JSON: ${err.message}`,
    };
  }

  try {
    const decodedPayload = base64UrlDecode(rawPayload);
    payload = JSON.parse(decodedPayload);
  } catch (err) {
    return {
      validFormat: false,
      header,
      payload: null,
      signature,
      rawHeader,
      rawPayload,
      error: `Malformed JWT Payload JSON: ${err.message}`,
    };
  }

  return {
    validFormat: true,
    header,
    payload,
    signature,
    rawHeader,
    rawPayload,
    error: null,
  };
}

/**
 * Generate a complete JWT from Header and Payload objects
 */
export function generateJwt(headerObj, payloadObj, secret = '') {
  const rawHeader = base64UrlEncode(JSON.stringify(headerObj));
  const rawPayload = base64UrlEncode(JSON.stringify(payloadObj));

  if (!headerObj || headerObj.alg === 'none') {
    return `${rawHeader}.${rawPayload}.`;
  }

  const signature = simulateHmacSha256(`${rawHeader}.${rawPayload}`, secret);
  return `${rawHeader}.${rawPayload}.${signature}`;
}

/**
 * Verify a JWT against algorithms, secret key, and expiration
 */
export function verifyJwt(tokenString, secret, options = {}) {
  const {
    allowedAlgorithms = ['HS256', 'RS256'],
    enforceExp = true,
    currentTime = Math.floor(Date.now() / 1000),
    clockTolerance = 30,
  } = options;

  const parsed = parseJwt(tokenString);
  if (!parsed.validFormat) {
    return {
      valid: false,
      error: parsed.error,
      payload: null,
      expired: false,
      algBypassDetected: false,
    };
  }

  const { header, payload, signature, rawHeader, rawPayload } = parsed;

  // 1. Check Algorithm Whitelist
  if (!header || !header.alg) {
    return {
      valid: false,
      error: 'Missing required "alg" declaration in JWT Header',
      payload: null,
      expired: false,
      algBypassDetected: false,
    };
  }

  const algLower = header.alg.toLowerCase();
  if (algLower === 'none') {
    if (!allowedAlgorithms.map(a => a.toLowerCase()).includes('none')) {
      return {
        valid: false,
        error: 'Rejected: Insecure algorithm "none" is not permitted by API gateway policy',
        payload: null,
        expired: false,
        algBypassDetected: true,
      };
    }
    // If 'none' is explicitly allowed (vulnerable mode)
    return {
      valid: true,
      error: null,
      payload,
      expired: false,
      algBypassDetected: true,
    };
  }

  if (!allowedAlgorithms.includes(header.alg)) {
    return {
      valid: false,
      error: `Unsupported algorithm: ${header.alg}. Allowed: ${allowedAlgorithms.join(', ')}`,
      payload: null,
      expired: false,
      algBypassDetected: false,
    };
  }

  // 2. Cryptographic Signature Verification
  if (!signature) {
    return {
      valid: false,
      error: 'Missing cryptographic signature',
      payload: null,
      expired: false,
      algBypassDetected: false,
    };
  }

  const expectedSignature = simulateHmacSha256(`${rawHeader}.${rawPayload}`, secret);
  if (signature !== expectedSignature) {
    return {
      valid: false,
      error: 'Invalid signature: token contents have been tampered with or key is incorrect',
      payload: null,
      expired: false,
      algBypassDetected: false,
    };
  }

  // 3. Expiration Timestamp Verification
  if (enforceExp && payload && typeof payload.exp === 'number') {
    if (currentTime - clockTolerance >= payload.exp) {
      return {
        valid: false,
        error: `Token expired at epoch ${payload.exp} (current time: ${currentTime})`,
        payload,
        expired: true,
        algBypassDetected: false,
      };
    }
  }

  return {
    valid: true,
    error: null,
    payload,
    expired: false,
    algBypassDetected: false,
  };
}

/**
 * Perform offline dictionary brute-force cracking against a JWT signature
 */
export function crackHmacSecret(tokenString, wordlist = COMMON_WEAK_SECRETS) {
  const parsed = parseJwt(tokenString);
  if (!parsed.validFormat || !parsed.signature) {
    return {
      cracked: false,
      secret: null,
      attempts: 0,
      timeMs: 0,
      error: 'Token must be validly formatted and contain a signature to crack',
    };
  }

  const startTime = Date.now();
  const data = `${parsed.rawHeader}.${parsed.rawPayload}`;
  let attempts = 0;

  for (const candidate of wordlist) {
    attempts++;
    const candidateSig = simulateHmacSha256(data, candidate);
    if (candidateSig === parsed.signature) {
      return {
        cracked: true,
        secret: candidate,
        attempts,
        timeMs: Math.max(1, Date.now() - startTime),
        error: null,
      };
    }
  }

  return {
    cracked: false,
    secret: null,
    attempts,
    timeMs: Math.max(1, Date.now() - startTime),
    error: 'Secret not found in dictionary wordlist',
  };
}

/**
 * Calculate Shannon entropy and cryptographic strength rating of a secret key
 */
export function calculateKeyEntropy(keyString) {
  if (!keyString || typeof keyString !== 'string') {
    return { entropy: 0, bits: 0, rating: 'None', labelColor: 'text-red-500' };
  }

  const len = keyString.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const ch = keyString[i];
    frequencies[ch] = (frequencies[ch] || 0) + 1;
  }

  let entropy = 0;
  for (const ch in frequencies) {
    const p = frequencies[ch] / len;
    entropy -= p * Math.log2(p);
  }

  // Approximate bit-strength (entropy * length)
  const bits = Math.round(entropy * len);

  let rating = 'Weak';
  let labelColor = 'text-red-400';

  if (bits >= 128) {
    rating = 'Cryptographic Grade';
    labelColor = 'text-emerald-400';
  } else if (bits >= 64) {
    rating = 'Strong';
    labelColor = 'text-cyan-400';
  } else if (bits >= 36) {
    rating = 'Moderate';
    labelColor = 'text-yellow-400';
  }

  return {
    entropy: Math.round(entropy * 100) / 100,
    bits,
    rating,
    labelColor,
  };
}

/**
 * Look up a hash in precomputed rainbow tables
 */
export function lookupRainbowTable(hashString) {
  if (!hashString || typeof hashString !== 'string') {
    return { cracked: false, plaintext: null, algorithm: 'Unknown' };
  }

  const normalized = hashString.trim().toLowerCase();
  if (RAINBOW_TABLE_LOOKUP[normalized]) {
    const entry = RAINBOW_TABLE_LOOKUP[normalized];
    return {
      cracked: true,
      plaintext: entry.plaintext,
      algorithm: entry.algorithm,
    };
  }

  return {
    cracked: false,
    plaintext: null,
    algorithm: normalized.length === 32 ? 'MD5' : 'Unknown',
  };
}

/**
 * Evaluate an API Security Challenge scenario
 */
export function evaluateApiChallenge(scenarioId, tokenOrInput, options = {}) {
  const { defenseActive = false, secret = 'super-secret-hmac-key' } = options;

  switch (scenarioId) {
    case 'jwt_alg_none': {
      const parsed = parseJwt(tokenOrInput);
      if (!parsed.validFormat) {
        return {
          passed: false,
          statusCode: 400,
          responseBody: { error: 'Bad Request', details: parsed.error },
          explanation: 'The provided token is malformed and could not be parsed by the API gateway.',
          attackVector: 'Malformed Token Injection',
          mitigationDetails: 'Gateways must reject malformed tokens before passing to authorization handlers.',
        };
      }

      const isAlgNone = parsed.header && parsed.header.alg && parsed.header.alg.toLowerCase() === 'none';
      const role = parsed.payload ? parsed.payload.role : null;
      const isAdmin = role === 'admin';

      if (defenseActive) {
        // Secure API Gateway
        if (isAlgNone) {
          return {
            passed: true,
            statusCode: 401,
            responseBody: {
              error: 'Unauthorized',
              code: 'INSECURE_ALGORITHM',
              message: 'Algorithm "none" is explicitly prohibited by security policy.',
            },
            explanation:
              'DEFENSE ACTIVATED: The gateway rejected the tampered token. Algorithm whitelisting successfully prevented the signature bypass.',
            attackVector: 'CVE-2015-9235 (alg: none bypass attempt)',
            mitigationDetails: 'Strict algorithm whitelist: only HS256/RS256 accepted.',
          };
        }
        return {
          passed: false,
          statusCode: 403,
          responseBody: { error: 'Forbidden', message: 'Admin role required.' },
          explanation: 'Token was processed securely, but caller does not possess administrative privileges.',
          attackVector: 'Insufficient Privileges',
          mitigationDetails: 'Role-based access control (RBAC) enforced.',
        };
      } else {
        // Vulnerable API Gateway
        if (isAlgNone && isAdmin) {
          return {
            passed: true,
            statusCode: 200,
            responseBody: {
              status: 'ACCESS_GRANTED',
              endpoint: '/api/v1/admin/financial-records',
              data: [
                { fiscal_year: 2026, q1_revenue: '$42,500,000', net_profit: '$11,800,000' },
                { secret_merger_target: 'Project Apex Holdings', escrow_balance: '$8,250,000' },
              ],
            },
            explanation:
              'EXPLOIT SUCCESSFUL: The vulnerable API gateway trusted {"alg": "none"}, bypassed signature validation, and granted admin access!',
            attackVector: 'JWT Signature Bypass via alg: none (CWE-347)',
            mitigationDetails: 'Whitelist permitted signing algorithms and discard tokens declaring "none".',
          };
        }

        return {
          passed: false,
          statusCode: 403,
          responseBody: { error: 'Forbidden', message: 'Admin role required or signature check failed.' },
          explanation:
            'The request failed. To execute the exploit, set {"alg": "none"} in the header, elevate "role" to "admin", and clear the signature.',
          attackVector: 'Failed Exploit Attempt',
          mitigationDetails: 'Review hints to complete the exploit.',
        };
      }
    }

    case 'jwt_weak_secret': {
      const parsed = parseJwt(tokenOrInput);
      if (!parsed.validFormat) {
        return {
          passed: false,
          statusCode: 400,
          responseBody: { error: 'Invalid token format' },
          explanation: 'Token format is invalid.',
        };
      }

      const role = parsed.payload ? parsed.payload.role : null;
      const isSuperUser = role === 'superuser' || role === 'admin';
      const expectedSig = simulateHmacSha256(`${parsed.rawHeader}.${parsed.rawPayload}`, 'secret123');
      const isSignatureValid = parsed.signature === expectedSig;

      if (defenseActive) {
        return {
          passed: true,
          statusCode: 401,
          responseBody: { error: 'Unauthorized', message: 'Signature validation failed against 256-bit CSPRNG cluster key.' },
          explanation:
            'DEFENSE ACTIVATED: The server switched from weak dictionary secret "secret123" to a 256-bit cryptographic key. Forged tokens signed with dictionary words are completely rejected!',
          attackVector: 'HMAC Key Brute-Force Neutralized',
          mitigationDetails: '256-bit cryptographically secure pseudorandom secret deployed.',
        };
      } else {
        if (isSuperUser && isSignatureValid) {
          return {
            passed: true,
            statusCode: 200,
            responseBody: {
              status: 'ACCESS_GRANTED',
              endpoint: '/api/v1/management/system-audit',
              audit_log: 'Superuser credentials accepted. Full server orchestration permissions granted.',
            },
            explanation:
              'EXPLOIT SUCCESSFUL: You cracked the weak HMAC key ("secret123") and forged a valid superuser token!',
            attackVector: 'CWE-326 (Inadequate Encryption Strength / Weak Secret)',
            mitigationDetails: 'Enforce secret keys with at least 256 bits of entropy generated via CSPRNG.',
          };
        }

        return {
          passed: false,
          statusCode: 401,
          responseBody: { error: 'Unauthorized', message: 'Invalid token signature or insufficient role.' },
          explanation: 'Token must have superuser role and a valid signature calculated with the cracked secret ("secret123").',
        };
      }
    }

    case 'jwt_expired_replay': {
      const parsed = parseJwt(tokenOrInput);
      if (!parsed.validFormat) {
        return {
          passed: false,
          statusCode: 400,
          responseBody: { error: 'Invalid token format' },
          explanation: 'Token format is invalid.',
        };
      }

      const isExpired = parsed.payload && parsed.payload.exp && parsed.payload.exp < Math.floor(Date.now() / 1000);

      if (defenseActive) {
        if (isExpired) {
          return {
            passed: true,
            statusCode: 401,
            responseBody: { error: 'TokenExpiredError', message: 'jwt expired', expiredAt: parsed.payload.exp },
            explanation:
              'DEFENSE ACTIVATED: The API gateway strictly validated the "exp" claim and rejected the expired token.',
            attackVector: 'Replay Attack Blocked (CWE-613)',
            mitigationDetails: 'Enforce expiration verification and token revocation lists.',
          };
        }
      } else {
        if (isExpired) {
          return {
            passed: true,
            statusCode: 200,
            responseBody: {
              status: 'WIRE_TRANSFER_EXECUTED',
              amount: '$2,500,000.00 USD',
              destination: 'Offshore Account #8942-CH',
              authorized_by: parsed.payload ? parsed.payload.email : 'Unknown',
            },
            explanation:
              'VULNERABILITY DEMONSTRATED: The API server processed the expired CFO token because it neglected to check the "exp" timestamp!',
            attackVector: 'CWE-613 (Insufficient Session Expiration / Token Replay)',
            mitigationDetails: 'Validate "exp" on every request and implement short token lifetimes with refresh rotation.',
          };
        }
      }
      return {
        passed: false,
        statusCode: 400,
        responseBody: { error: 'Token is not expired' },
        explanation: 'Scenario requires an expired token to demonstrate replay.',
      };
    }

    case 'crypto_unsalted_hashes': {
      const rainbowResult = lookupRainbowTable(tokenOrInput);
      if (defenseActive) {
        return {
          passed: true,
          statusCode: 200,
          responseBody: {
            hash_algorithm: 'bcrypt',
            work_factor: 12,
            salt: '$2b$12$e8Y6bU68n... (unique 128-bit salt)',
            rainbow_table_resistant: true,
          },
          explanation:
            'DEFENSE ACTIVATED: The database upgraded to salted bcrypt with work factor 12. Precomputed rainbow tables are completely ineffective against unique per-user salts.',
          attackVector: 'Rainbow Table Cracking Neutralized (CWE-916)',
          mitigationDetails: 'Use bcrypt, Argon2id, or PBKDF2 with unique salts and sufficient cost factors.',
        };
      } else {
        if (rainbowResult.cracked) {
          return {
            passed: true,
            statusCode: 200,
            responseBody: {
              hash: tokenOrInput,
              plaintext_password: rainbowResult.plaintext,
              algorithm: rainbowResult.algorithm,
              cracking_time: '< 1 millisecond (Instant Table Lookup)',
            },
            explanation:
              `EXPLOIT SUCCESSFUL: The unsalted MD5 hash was instantly reversed to plaintext "${rainbowResult.plaintext}" using a precomputed rainbow table!`,
            attackVector: 'CWE-916 (Use of Password Hash With Insufficient Computational Effort)',
            mitigationDetails: 'Never store unsalted hashes. Always use salted, adaptive key-derivation functions.',
          };
        }

        return {
          passed: false,
          statusCode: 404,
          responseBody: { message: 'Hash not found in common table.' },
          explanation: 'Try looking up the leaked executive hash: 5f4dcc3b5aa765d61d8327deb882cf99.',
        };
      }
    }

    default:
      return {
        passed: false,
        statusCode: 400,
        responseBody: { error: `Unknown scenario ${scenarioId}` },
        explanation: 'Scenario not recognized.',
      };
  }
}
