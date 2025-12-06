## Overview

Yarl Lock is a desktop application that encrypts and decrypts folders using a user‑supplied password.  
It uses modern cryptography (AES‑GCM, PBKDF2, RSA, RSA‑PSS, SHA‑256) and provides a simple Tkinter GUI.

Core goals:

- Confidentiality of files at rest
- Integrity and authenticity of encrypted files
- Simple, usable interface

---

## Features

- Folder‑level encryption and decryption
- AES‑256‑GCM symmetric encryption (per file)
- PBKDF2 password‑based key derivation
- RSA‑2048 keypair with encrypted private key
- RSA‑PSS digital signatures for encrypted files (`.enc.sig`)
- SHA‑256 hashing for integrity testing
- GUI with:
  - Folder selection (input/output)
  - Password + confirm password
  - Status messages and error dialogs

---

## Cryptographic Design

- **Symmetric encryption:** AES‑256‑GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`)
- **Password hashing / KDF:** PBKDF2 with random salt
- **Asymmetric crypto:** RSA‑2048
- **Digital signatures:** RSA‑PSS with SHA‑256
- **Hashing:** SHA‑256 (used in separate tests for integrity)
- **Randomness:** `os.urandom` for salts, nonces, and key material

Security properties:

- AES‑GCM provides confidentiality + per‑file integrity.
- PBKDF2 slows brute‑force attacks against passwords.
- RSA‑PSS signatures over ciphertext detect tampering and prove origin (tied to the user’s keypair).
- The private key is always stored encrypted (hardened with password + PBKDF2 + AES‑GCM).

---

## Security Model (Short)

- Attacker can:
  - Read/copy all `.enc` and `.enc.sig` files.
  - Try to modify or replace encrypted files.
  - Perform offline guesses of weak passwords.

- Attacker is assumed **not** to:
  - Have a keylogger or full control of the running system.
  - Already know the user’s password.

If the attacker gains:

- `private_key.enc` + correct password → they can decrypt files.  
  This is expected and inherent to password‑based encryption.

If `.enc` files are modified or replaced:

- AES‑GCM and RSA‑PSS detection causes verification/decryption to fail.

For a more detailed threat model see `security.md`.

---

## Installation and Usage

Install dependencies:

pip install -r requirements.txt


### Running the app

python src/main.py

### First run (keys)

You should have a `keys_dir` (e.g. `tests/ax/keys`) with:

- `public_key.pem`
- `private_key.enc`

If not, generate them once using a small helper script that:

- calls `init_keys.py`,
- encrypts the private key with your chosen password,
- and writes both files to `keys_dir`.

(You can describe this briefly in your report or script comments.)

### Encrypting a folder

1. Start Yarl Lock.
2. Browse and select an **input folder** (plaintext files).
3. Browse and select an **output folder** (destination).
4. Type a **password** and **confirm password**.
5. Click **Encrypt**.
6. The app will:
   - Encrypt files into the output folder as `.enc`.
   - Create signatures `*.enc.sig` next to each `.enc`.

### Decrypting a folder

1. Select the folder containing encrypted files (`*.enc` + `*.enc.sig`).
2. Select an output folder for decrypted data.
3. Enter the **same password** used for encryption.
4. Click **Decrypt**.
5. The app will:
   - Verify signatures for all `.enc` files.
   - If all signatures are valid, decrypt files to the output folder.

---

