# Yarl Lock – Architecture

## 1. Big Picture

Yarl Lock is a **local desktop app** that encrypts and decrypts folders.  
It has three main parts:

1. A **Tkinter GUI** where the user selects folders and types the password.
2. A **file crypto module** that does AES‑GCM encryption/decryption and RSA signatures.
3. A **key management module** that stores the RSA keypair securely on disk.


---

## 2. Main Components

### 2.1 GUI / Application Layer (`src/ui/app_window.py`)

Class: `SecureFileApp(tk.Tk)`

**Responsibilities**

- Display the main window.
- Let the user:
  - Choose an **input folder** (for encryption or decryption).
  - Choose an **output folder**.
  - Enter and confirm a **password**.
- Provide buttons:
  - **Encrypt** – encrypts and signs everything in the input folder.
  - **Decrypt** – verifies signatures and decrypts everything in the input folder.
- Show status messages and error dialogs.

**How it talks to crypto code**

On button clicks:

- Encrypt:
encrypt_and_sign_path(input_folder, output_folder, password, keys_dir)
- Decrypt:
verify_and_decrypt_path(input_folder, output_folder, password, keys_dir)


So the GUI only passes four things: input path, output path, password, and location of keys.

---

### 2.2 File Crypto Layer (`src/crypto/file_crypto.py`)

This module is the **engine** of the app. It knows how to:

- Encrypt and decrypt bytes with AES‑GCM.
- Walk through folders and apply crypto to every file.
- Sign and verify encrypted files with RSA‑PSS.

**Low‑level functions**

- `_encrypt_bytes(data: bytes, password: str) -> bytes`
- Derives an AES‑256 key from the password using PBKDF2 with a random salt.
- Encrypts `data` with AES‑GCM using a random nonce.
- Returns: `salt || nonce || ciphertext_with_tag`.

- `_decrypt_bytes(blob: bytes, password: str) -> bytes`
- Splits `salt`, `nonce`, `ciphertext`.
- Re‑derives the AES key with PBKDF2(same password, same salt).
- Uses AES‑GCM to decrypt and verify authenticity.

**Folder / file operations**

- `encrypt_path(input_path, output_path, password, recursive=True)`
- If `input_path` is a file:
  - Encrypts it and writes one `.enc` file.
- If `input_path` is a folder:
  - Recursively encrypts all files inside and writes `.enc` files under `output_path`, preserving the folder structure.

- `decrypt_path(input_path, output_path, password, recursive=True)`
- Reverses `encrypt_path`:
  - Reads `salt || nonce || ciphertext`.
  - Decrypts each file.
  - Restores original filenames in `output_path`.

**Digital signatures**

- `sign_encrypted_path(enc_path, password, keys_dir) -> Path`
- Loads `public_key.pem` and `private_key.enc` from `keys_dir`.
- Decrypts `private_key.enc` using the password (via key_management).
- Reads the encrypted file bytes from `enc_path`.
- Computes a **RSA‑PSS (SHA‑256)** signature over the ciphertext.
- Saves signature as `enc_path.with_suffix(enc_path.suffix + ".sig")` (e.g. `file.txt.enc.sig`).

- `verify_encrypted_path(enc_path, keys_dir) -> bool`
- Loads `public_key.pem` from `keys_dir`.
- Reads `enc_path` and `enc_path.sig`.
- Verifies the RSA‑PSS signature and returns True/False.

**High‑level functions used by GUI**

- `encrypt_and_sign_path(input_path, output_path, password, keys_dir)`
- Calls `encrypt_path` to encrypt the whole input folder into `output_path`.
- Then finds all `.enc` files in `output_path` and calls `sign_encrypted_path` on each.

- `verify_and_decrypt_path(input_path, output_path, password, keys_dir)`
- First, for every `.enc` file in the input folder:
  - Calls `verify_encrypted_path`.
  - If any signature is missing or invalid → raises an error and stops.
- Only if all signatures pass, calls `decrypt_path` to restore the original files.

This layer hides all cryptographic details from the GUI: the GUI only cares about “encrypt+sign” and “verify+decrypt”.

---

### 2.3 Key Management Layer (`src/crypto/key_management.py`)

This module handles the **RSA keypair** and its secure storage on disk.

**Key generation**

- `rsa_keypair() -> (private_pem: bytes, public_pem: bytes)`
- Generates a 2048‑bit RSA keypair.
- Returns both keys in PEM format.

**Encrypting and decrypting the private key**

- `encrypt_private_key(private_key_pem: bytes, password: str) -> bytes`
- Uses a random salt and PBKDF2(password, salt) to derive an AES key.
- Uses AES‑GCM to encrypt the private key.
- Stores: `salt || nonce || ciphertext`.

- `decrypt_private_key(encrypted_private_key: bytes, password: str) -> bytes`
- Splits salt and nonce.
- Derives the same AES key via PBKDF2.
- Decrypts with AES‑GCM and returns the private key in PEM format.
- If the password is wrong or data is corrupted, AES‑GCM raises `InvalidTag`.

**Saving and loading keys**

- `save_keys_to_files(private_key_data, public_key_data, directory)`
- Writes:
  - `directory/private_key.enc` (encrypted private key data)
  - `directory/public_key.pem` (public key in clear)

- `load_keys_from_files(directory) -> (public_pem | None, encrypted_private | None)`
- Reads both files if they exist; otherwise returns `(None, None)`.

In the running app:

- `keys_dir` is a fixed directory (e.g. `tests/ax/keys`) that must contain:
- `public_key.pem`
- `private_key.enc`
- The **public key** is used for verifying signatures.
- The **encrypted private key** is unlocked with the GUI password when signing encrypted files.

---

## 3. Data Flow Overview


**Encryption flow (normal use)**

1. User picks input folder, output folder, and password (twice).
2. GUI calls `encrypt_and_sign_path(input_folder, output_folder, password, keys_dir)`.
3. `encrypt_and_sign_path`:
   - Encrypts all files in input folder to output folder using AES‑GCM.
   - Then, for each `.enc` file:
     - Decrypts `private_key.enc` with the same password.
     - Signs the ciphertext and writes `file.enc.sig`.
4. Files at rest: only `.enc` + `.enc.sig` are stored in the output folder.

**Decryption flow**

1. User picks encrypted input folder (with `.enc` + `.enc.sig`), output folder, and password.
2. GUI calls `verify_and_decrypt_path(input_folder, output_folder, password, keys_dir)`.
3. `verify_and_decrypt_path`:
   - For each `.enc` file:
     - Reads `public_key.pem` and verifies `file.enc` against `file.enc.sig`.
     - If any verification fails → decryption is aborted.
   - If all signatures are valid, decrypts all `.enc` files back to plaintext.

---

## 4. Why this architecture

This structure is intentional:

- The **GUI** stays simple and is easy to modify without touching cryptography.
- The **file_crypto** module groups all security‑critical operations in one place and can be tested without the GUI.
- The **key_management** module isolates RSA key handling and password‑based protection, making it easy to reason about how keys are stored and loaded.

This separation matches how real‑world systems are often organized and makes the project easier to understand, explain, and extend.
