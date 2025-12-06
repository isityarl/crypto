# Yarl Lock – Security Analysis

## 1. Threat Model

### Attacker Capabilities

We assume an attacker can:

- Copy or read:
  - All encrypted files (`*.enc`)
  - All signatures (`*.enc.sig`)
  - Potentially `public_key.pem` and `private_key.enc` (e.g. from disk/backup)
- Modify, delete, or replace encrypted files and signatures.
- Run offline password‑guessing attacks on captured data.
- Observe GUI error messages and general behavior.

We do **not** defend against:

- Malware on the user’s machine (keyloggers, remote control, etc.).
- An attacker who already knows the correct password.
- Hardware side‑channels (power analysis, RAM dumps).
- OS‑level compromise while the app is running.

Threats considered:

- Confidentiality breach of encrypted files.
- Integrity violation (encrypted files modified or replaced).
- Forged encrypted files pretending to come from the legitimate user.
- Theft or misuse of the RSA private key.

---

## 2. Security Assumptions

Yarl Lock relies on the following assumptions:

- The user chooses a **strong, non‑trivial password**.
- The environment running the app is **not compromised** by malware.
- The Python `cryptography` library correctly implements:
  - AES‑GCM
  - PBKDF2
  - RSA‑PSS
  - SHA‑256
- `os.urandom` provides cryptographically secure randomness.
- PBKDF2 parameters (salt length, iteration count) are chosen to meaningfully slow brute‑force.
- The `keys_dir` (where `public_key.pem` and `private_key.enc` live) is not trivially exposed to everyone.

If these assumptions are broken (e.g. weak password + keylogger), the guarantees degrade accordingly.

---

## 3. Potential Vulnerabilities

### Weak or Reused Passwords

- A short or common password makes offline brute‑force attacks much easier, even with PBKDF2.
- If the same password is used across many services, compromise elsewhere may reveal it.

Impact:

- Attacker with `.enc` files and `private_key.enc` can eventually guess the password and decrypt everything.

### Attacker with Password + Key Files

If an attacker obtains:

- `private_key.enc` and the **correct password**, and
- The folder of encrypted files (`*.enc`),

then they can:

- Decrypt the RSA private key.
- Decrypt all encrypted files.
- Generate new valid signatures.

Impact:

- Full loss of confidentiality and authenticity; attacker becomes indistinguishable from the legitimate user.

### Missing or Tampered Signature Files

- If `.enc.sig` files are lost:
  - The app can still decrypt (via AES‑GCM) but loses higher‑level authenticity.
- If `.enc.sig` are tampered with:
  - Verification fails, but this may cause usability issues if user does not understand what changed.

Impact:

- Reduced assurance about file origin.
- Potential denial‑of‑service (files won’t decrypt if signatures are invalid).

### Local System Compromise

- If the operating system or user account is compromised:
  - A keylogger can capture the password when typed into the GUI.
  - Malware can copy plaintext files before encryption or after decryption.

Impact:

- Complete loss of confidentiality and key secrecy.
- Out of scope for this project, but important in real use.

### No Network Key Exchange / Multi‑User Logic

- Yarl Lock is designed for **local storage only**.
- There is no key exchange protocol for sharing encrypted data with another user over a network.

Impact:

- Not a direct vulnerability, but limits scope: the app does not solve secure communication, only local file protection.

---

## 4. Mitigation Strategies

### Use of Strong Cryptographic Primitives

- **AES‑256‑GCM** for symmetric encryption:
  - Provides confidentiality and per‑file integrity (authentication tag).
- **PBKDF2** for password‑based key derivation:
  - Introduces computational cost per password guess, slowing brute‑force.
- **RSA‑2048 + RSA‑PSS (SHA‑256)** for digital signatures:
  - Signatures on ciphertext (`.enc.sig`) detect tampering and prove origin.
- **SHA‑256** for hashing in tests:
  - Confirms that decrypted files match the original plaintext.

These primitives are standard and widely recommended.

### Encrypted Private Key Storage

- The RSA private key is stored only as `private_key.enc`:
  - Encrypted with AES‑GCM under a key derived from the user’s password via PBKDF2.
  - Decrypted only in memory during signing.

Mitigation:

- Even if `private_key.enc` is copied from disk, it is not useful without the password.

### Signature Verification Before Decryption

- For each `file.enc`, the app:
  - Verifies `file.enc` against `file.enc.sig` using `public_key.pem`.
  - Only decrypts if the signature is valid.

Mitigation:

- Prevents silent decryption of modified or replaced encrypted files.
- Ensures the data originated from the user’s RSA keypair.

### Input Validation and Confirmation

- GUI checks:
  - Input folder is selected.
  - Output folder is selected.
  - Password and confirm password are filled and match.
- Errors are shown via message boxes on missing input or failures.

Mitigation:

- Reduces user mistakes (e.g. typos in password) that could cause permanent data loss.

### Recommended Operational Practices

While not enforced by code, the following are recommended:

- Use a **high‑entropy password** and do not reuse it on other services.
- Keep `keys_dir` in a location not easily exposed to others (e.g., user’s home directory, not a public share).
- Back up `private_key.enc` and `public_key.pem` securely:
  - Loss of these means loss of ability to verify or decrypt previously encrypted data.
- Run the app on a system you trust (free of obvious malware).

---

## 5. Overall Security Assessment

Under the stated assumptions, Yarl Lock provides:

- **Strong confidentiality** of files at rest (AES‑256‑GCM + PBKDF2‑derived keys).
- **Robust integrity and authenticity** for encrypted files (AES‑GCM tags + RSA‑PSS signatures).
- **Reasonable key management**:
  - Public key in clear,
  - Private key encrypted with password,
  - No plaintext private key on disk.

The main remaining risks are:

- Weak passwords chosen by users.
- A fully compromised local machine (malware).
- Loss of signature files, which reduces authenticity guarantees.
