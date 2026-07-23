# A Security Assessment and Hardening of the "Totally Secure Math" Mobile Application

**Course:** ITSC320-B — Software Security

**Group:** Group 9

**Assignment:** Lab — Cross-Platform Security

**Application:** _Totally Secure Math_ (`AwesomeProject`)

**Date:** July 23, 2026

---

## I. Introduction

Mobile applications routinely handle credentials, tokens, and user data on devices that are
outside the developer's control. The OWASP Mobile Top 10 identifies insecure data storage,
insecure authentication, and code-quality issues (including injection) as recurring, high-impact
risks. _Totally Secure Math_ is an intentionally vulnerable teaching application that exhibits
all of these.

**Scope.** The assessment targets the application's own source code under `src/`:

- `src/App.tsx` — navigation container and top-level auth state.
- `src/Login.tsx` — the login screen.
- `src/Notes.tsx` — note creation and persistence.
- `src/components/Note.tsx` — rendering and evaluation of an individual note.

**Methodology.** We performed a manual static (source-code) review, tracing untrusted input
(the login form and the note fields) from entry to the sensitive sinks it reaches (`eval`,
`AsyncStorage`, and the credential comparison). Findings are classified by vulnerability type
and mapped to the corresponding Common Weakness Enumeration (CWE) identifiers.

---

## II. Identified Vulnerabilities

### A. Code Injection — `eval()` on user input (CWE-95)

**Type:** Code injection / unsafe dynamic evaluation.

**Location:** `src/components/Note.tsx`, `evaluateEquation()`:

```ts
const result = eval(props.text); // props.text is fully user-controlled
```

**Description.** The body of every note is passed directly to JavaScript's `eval()` when the
user taps _Evaluate_. `eval()` executes its argument as arbitrary code with the application's
privileges — it is not restricted to arithmetic.

**How it causes issues.** A user (or anyone who can get a crafted note onto the device) can
enter a payload such as `while(true){}` to freeze the app, or expressions that reach global
objects and platform bridges to read or exfiltrate data, corrupt stored state, or trigger
malware-like behavior. Because notes are persisted (see II-C), a malicious note becomes a
stored, re-triggerable payload. This is the single most dangerous flaw in the application.

**Severity:** Critical.

### B. Improper Authentication — hardcoded plaintext credentials (CWE-798, CWE-256)

**Type:** Improper authentication / use of hardcoded credentials.

**Location:** `src/Login.tsx`:

```ts
const users: IUser[] = [
  { username: 'joe', password: 'secret' },
  { username: 'bob', password: 'password' },
];
// ...
if (username === user.username && password === user.password) { ... }
```

**Description.** Valid usernames and passwords are hardcoded in plaintext inside a component
that ships in the JavaScript bundle. Authentication is a simple client-side string comparison,
and the authenticated `IUser` object (including the password) is then passed through navigation
into the Notes screen.

**How it causes issues.** Anyone who unpacks the app bundle — trivial for a distributed mobile
app — can read every credential directly. The plaintext password also propagates into app state
and, as shown next, into a storage key. There is no server-side check, so the "authentication"
provides no real assurance of identity.

**Severity:** High.

### C. Insecure Data Storage — unencrypted notes keyed by the password (CWE-312)

**Type:** Insecure data storage / cleartext storage of sensitive information.

**Location:** `src/Notes.tsx`, `getStoredNotes()` / `storeNotes()`:

```ts
const suffix = user.username + '-' + user.password; // password in the key!
await AsyncStorage.setItem('notes-' + suffix, JSON.stringify(notes)); // plaintext value
```

**Description.** Notes are serialized to `AsyncStorage` as plaintext JSON. `AsyncStorage` is an
unencrypted key–value store (backed by SQLite/plist files on disk) — it is the React Native
equivalent of the web browser's `localStorage`/`sessionStorage`, and it shares the same core
weakness: values are written in cleartext with no encryption at rest. (Note that `localStorage`
itself is a _browser_ API and is not available in the React Native runtime; `AsyncStorage` is
what this app uses.) Worse, the storage key embeds the user's plaintext password.

**How it causes issues.** On a rooted/jailbroken device, through a filesystem or cloud backup,
or via forensic tooling, an attacker can read the stored notes _and_ recover the password from
the key name. This leaks both user data and a credential that may be reused on other services.

**Severity:** High.

### D. Insufficient Input Validation (CWE-20)

**Type:** Improper input validation.

**Location:** `src/Notes.tsx` (`addNote`) and `src/components/Note.tsx`.

**Description.** The only validation performed was an empty-string check on the note title and
equation. The equation was never validated to be an actual arithmetic expression before being
stored and later handed to `eval()`. There were no length limits and no character whitelist.

**How it causes issues.** Unvalidated input flows straight into the `eval()` sink (II-A) and
into persistent storage (II-C). Without a whitelist, injected code and malformed data are
accepted and saved, turning a validation gap into the enabler for the code-injection flaw.

**Severity:** High (as a contributing factor to II-A).

### E. Insecure Coding Practices (CWE-798, CWE-388, CWE-209)

**Type:** General insecure coding practices.

**Location:** across `src/`.

**Description.** Several practices weaken the app independently of any single bug:

- **Hardcoded secrets** — credentials in source (II-B); had the app used an API key or token, it
  would very likely have been hardcoded too.
- **No error handling** — `JSON.parse()` on stored data and `eval()` are uncaught; malformed
  data or input crashes the app.
- **Over-sharing of sensitive data** — the password is carried through navigation params and
  app state well beyond the login screen (least-privilege violation).
- **No access control / fail-open behavior** — storage reads assume well-formed data and fail
  in undefined ways.

**How it causes issues.** These practices make the app fragile and leaky, and they amplify the
concrete vulnerabilities above. Poor error handling can also disclose internal details or crash
the process (a denial of service).

**Severity:** Medium.

---

## III. Implemented Security Measures

Every change in the codebase is marked with a `SECURITY FIX` block comment referencing the
relevant section of this report. New logic lives in three focused utility modules under
`src/utils/`.

### A. Eliminating code injection (fixes II-A, II-D)

`eval()` was removed. `src/utils/safeEvaluate.ts` implements a self-contained arithmetic
evaluator:

1. The input must match a strict whitelist — `^[0-9+\-*/().\s]+$` — and is length-bounded.
2. It is tokenized and evaluated with the shunting-yard algorithm on a numeric stack.

Because the evaluator can only ever produce a number, there is no code path that can execute
JavaScript, reach globals, or loop indefinitely. `Note.tsx` now calls `safeEvaluate()` inside a
`try/catch` and shows a friendly error for invalid input instead of executing it.

```ts
try {
  const result = safeEvaluate(props.text);
  Alert.alert('Result', 'Result: ' + result);
} catch (error) {
  Alert.alert('Invalid equation' /* safe message */);
}
```

### B. Secure authentication (fixes II-B)

Credential handling moved to `src/utils/auth.ts`. No plaintext passwords remain in the source:
the credential store holds only a per-user random **salt** and a **PBKDF2 (SHA-256, 10,000
iterations)** hash. `verifyCredentials()` re-derives the hash from the entered password and
compares it in constant time, returning an `IAuthUser` that contains **only the username**. The
password field was removed from the user type entirely, so it no longer flows through navigation
or app state. The password input is now masked (`secureTextEntry`) and cleared after use.

### C. Encrypted, password-free storage (fixes II-C)

`src/utils/secureStorage.ts` wraps `AsyncStorage`:

- Notes are **AES-encrypted** (`crypto-js`) before being written and decrypted on read.
- The storage key is derived from the **username only** (`notes:<username>`) — the password is
  never used.
- All I/O is wrapped in `try/catch`; undecryptable or corrupt data fails safe (returns `[]`)
  rather than crashing.

```ts
const ciphertext = CryptoJS.AES.encrypt(
  JSON.stringify(notes),
  NOTES_ENC_KEY,
).toString();
await AsyncStorage.setItem(`notes:${username}`, ciphertext);
```

### D. Input validation and sanitization (fixes II-D)

`addNote()` now trims both fields, enforces length limits, and validates the equation against the
same arithmetic whitelist used at evaluation time, so malformed or injected input is rejected at
the point of entry — before it can be stored.

### E. Removing insecure practices — secrets management and error handling (fixes II-E)

- **Secrets externalized.** The AES key and example API credentials were moved to a git-ignored
  `.env` file, loaded at build time through the `react-native-dotenv` babel plugin via typed
  `@env` imports. `.env` is added to `.gitignore`; a committed `.env.example` documents the
  required keys without real values.
- **Robust error handling.** `JSON.parse`, decryption, and evaluation are all wrapped in
  `try/catch` that fail safe and never surface internal details to the user.
- **Least privilege.** The password no longer propagates beyond authentication.

---

## IV. Why These Security Measures Matter

**Replacing `eval` (defense against injection).** Dynamic evaluation of untrusted input is the
canonical mobile/web code-injection vector. Restricting evaluation to a parser that can _only_
compute arithmetic removes the entire class of attack rather than trying to blacklist "bad"
inputs — a whitelist is far more robust than a blacklist because it defaults to denying anything
unexpected.

**Salted password hashing (authentication).** Storing only salted PBKDF2 hashes means that even
if the credential store is read, the original passwords are not directly recoverable; per-user
salts defeat precomputed (rainbow-table) attacks, and the iteration count slows brute forcing.
Removing the password from the user object enforces least privilege — sensitive data should
exist in as few places, for as short a time, as possible.

**Encrypting on-device data (data-at-rest protection).** Mobile devices are lost, stolen, and
backed up. Encrypting stored data ensures that filesystem access alone does not reveal user
content, and keying storage by username (not password) removes credential leakage through
metadata.

**Input validation (defense in depth).** Validating at the boundary stops bad data before it
reaches a sensitive sink. Combined with the safe evaluator, it provides two independent layers:
even if one check were bypassed, the other still holds.

**Secrets management and error handling (code quality as security).** Keeping secrets out of
source control prevents accidental credential leaks through the repository, and consistent,
fail-safe error handling prevents crashes and information disclosure. Secure code is
maintainable code: small, well-named modules with a single responsibility are easier to review
and to reason about than logic scattered through UI components.

---

## V. Reflection and Best Practices Going Forward

Working through this assessment reinforced that most of these vulnerabilities were not exotic —
they were the result of convenient defaults (`eval`, `AsyncStorage`, hardcoded test users) left
in place. The most valuable lesson was to _think about where untrusted input goes_: tracing the
note text to `eval()` and the password into a storage key made the risks obvious.

Best practices we will carry forward:

1. **Never evaluate untrusted input as code.** Use a parser or a vetted library; prefer
   whitelists over blacklists.
2. **Keep secrets out of source.** Use environment configuration and, in production, a secrets
   manager or the platform Keychain/Keystore — never commit credentials or keys.
3. **Encrypt sensitive data at rest** and never place secrets in identifiers/keys/logs.
4. **Hash passwords with a salted, iterated KDF**, and do authentication server-side; treat the
   client as untrusted.
5. **Validate and bound all input at the boundary**, and fail safe with proper error handling.
6. **Apply least privilege** — carry sensitive data no further than necessary.
7. **Isolate security-sensitive logic** into small, testable modules and cover them with tests
   (as done for the safe evaluator).

**Honest limitations.** This remains a local, client-only lab app. Client-side credential
verification and a bundled encryption key are improvements _within that scope_, not a substitute
for production security: real authentication must be server-side, and the encryption key should
be device-derived (Keychain/Keystore) rather than shipped. Secrets in a `.env` file are kept out
of source control but are still embedded in the built bundle. These trade-offs are called out so
they are not mistaken for production-grade guarantees.

---

## VI. Conclusion

_Totally Secure Math_ demonstrated five common mobile vulnerability classes: a critical
`eval()`-based code-injection flaw, hardcoded plaintext credentials, unencrypted storage keyed
by the password, insufficient input validation, and assorted insecure coding practices. Each was
mitigated with a focused, well-understood technique — a whitelist-based evaluator, salted PBKDF2
authentication, AES-encrypted storage, boundary input validation, and externalized secrets with
fail-safe error handling — and each change is marked in the source with a block comment. The
result is an application that is meaningfully more resistant to the assessed attacks and, just as
importantly, structured so that its security properties can be reviewed and tested.

---

## References

- OWASP, _OWASP Mobile Top 10_, Open Worldwide Application Security Project.
- MITRE, _CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')_.
- MITRE, _CWE-798: Use of Hard-coded Credentials_.
- MITRE, _CWE-312: Cleartext Storage of Sensitive Information_.
- MITRE, _CWE-20: Improper Input Validation_.
- MITRE, _CWE-256: Plaintext Storage of a Password_; _CWE-209: Generation of Error Message Containing Sensitive Information_.
- B. Kaliski, _PKCS #5: Password-Based Cryptography Specification Version 2.0 (PBKDF2)_, RFC 2898.
