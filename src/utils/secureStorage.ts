/* 
 * SECURITY FIX (Insecure Data Storage)
 * 
 * The original app wrote notes to AsyncStorage as PLAINTEXT JSON,
 * and — worse — embedded the user's plaintext password in the
 * storage key ("notes-<username>-<password>"). On a rooted /
 * jailbroken device or via a device backup, both the notes AND
 * the password were readable (CWE-312: Cleartext Storage).
 *
 * This module:
 *   1. Derives the storage key from the USERNAME ONLY (the
 *      password never touches storage).
 *   2. Encrypts note contents with AES before persisting, using a
 *      key loaded from a git-ignored .env file (see @env import).
 *   3. Wraps all I/O in try/catch so corrupt/undecryptable data
 *      fails safe (returns []) instead of crashing the app.
 * See REPORT.md II-C.
*/

import AsyncStorage from '@react-native-async-storage/async-storage';
import CryptoJS from 'crypto-js';
import { NOTES_ENC_KEY } from '@env';

export interface INote {
  title: string;
  text: string;
}

// Namespaced, password-free storage key.
function storageKey(username: string): string {
  return `notes:${username}`;
}

function assertKeyConfigured(): void {
  if (!NOTES_ENC_KEY) {
    // Fail closed: never fall back to storing plaintext.
    throw new Error('NOTES_ENC_KEY is not configured in .env');
  }
}

/**
 * Encrypt and persist a user's notes.
 */
export async function saveNotes(
  username: string,
  notes: INote[],
): Promise<void> {
  try {
    assertKeyConfigured();
    const plaintext = JSON.stringify(notes);
    const ciphertext = CryptoJS.AES.encrypt(plaintext, NOTES_ENC_KEY).toString();
    await AsyncStorage.setItem(storageKey(username), ciphertext);
  } catch (error) {
    // Do not leak details to the UI; log for the developer only.
    console.error('Failed to save notes securely:', error);
    throw error;
  }
}

/**
 * Load and decrypt a user's notes. Returns [] when there is no
 * data or the data cannot be decrypted/parsed.
 */
export async function loadNotes(username: string): Promise<INote[]> {
  try {
    assertKeyConfigured();
    const ciphertext = await AsyncStorage.getItem(storageKey(username));
    if (!ciphertext) {
      return [];
    }

    const bytes = CryptoJS.AES.decrypt(ciphertext, NOTES_ENC_KEY);
    const plaintext = bytes.toString(CryptoJS.enc.Utf8);
    if (!plaintext) {
      // Wrong key or tampered data.
      return [];
    }

    const parsed = JSON.parse(plaintext);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error('Failed to load notes securely:', error);
    return [];
  }
}
