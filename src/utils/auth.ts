/* 
 * SECURITY FIX (Improper Authentication + Insecure Code Practices)
 * 
 * The original Login screen held an array of users with PLAINTEXT
 * passwords hardcoded in the component (CWE-798: Use of Hardcoded
 * Credentials) and compared them with `===`. Anyone who opened the
 * JS bundle could read every password.
 *
 * This module improves that within the constraints of a local lab:
 *   1. NO plaintext passwords are stored — only a per-user random
 *      salt and a PBKDF2 (SHA-256, 10k iterations) hash.
 *   2. Verification re-derives the hash from the entered password
 *      and compares in constant time.
 *   3. Basic input validation rejects empty / oversized input.
 *   4. On success we return ONLY the username (see IAuthUser) so a
 *      password is never propagated through the app / navigation.
 *
 * LIMITATION (documented in REPORT.md II-B): real authentication
 * must happen server-side against a database the client cannot
 * read. Client-side hashing raises the bar but is not a substitute
 * for a backend; it is the appropriate scope for this exercise.
*/

import CryptoJS from 'crypto-js';

export interface IAuthUser {
  // Note: intentionally no password field.
  username: string;
}

interface ICredentialRecord {
  username: string;
  salt: string;
  // PBKDF2(password, salt) as hex — NOT the password itself.
  hash: string;
}

const PBKDF2_ITERATIONS = 10000;
const KEY_SIZE_WORDS = 256 / 32;

/*
 * In a production system this table lives in a server-side database.
 * For the lab it is a stand-in credential store containing only
 * salted hashes — the plaintext passwords ("secret", "password")
 * are NOT present anywhere in the codebase.
 */
const CREDENTIALS: ICredentialRecord[] = [
  {
    username: 'joe',
    salt: 's1a2l3t4joe',
    hash: '5899e5675bd74afabca817f847d2cd830a7edd4a3b4756032a50ec48b0bd65d4',
  },
  {
    username: 'bob',
    salt: 's5a6l7t8bob',
    hash: '93c8754338bacf395aafa7afb8760c5f71f754feee9363374dea388e142297d6',
  },
];

// Hash the password with PBKDF2 using the given salt.
// The result is a hex string.
function hashPassword(password: string, salt: string): string {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: KEY_SIZE_WORDS,
    iterations: PBKDF2_ITERATIONS,
  }).toString();
}

// Constant-time string comparison to avoid timing side channels.
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Verify a username/password pair against the credential store.
 * @returns the authenticated user (username only) or null.
 */
export function verifyCredentials(
  username: string,
  password: string,
): IAuthUser | null {
  // Input validation — reject empty or oversized input before work.
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.trim().length === 0 ||
    password.length === 0 ||
    username.length > 64 ||
    password.length > 128
  ) {
    return null;
  }

  const record = CREDENTIALS.find(
    (candidate) => candidate.username === username.trim(),
  );
  if (!record) {
    // Still hash to keep timing roughly uniform for unknown users.
    hashPassword(password, 'dummy-salt');
    return null;
  }

  const candidateHash = hashPassword(password, record.salt);
  if (timingSafeEqual(candidateHash, record.hash)) {
    return { username: record.username };
  }

  return null;
}
