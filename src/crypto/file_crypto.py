from pathlib import Path
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import derive_key_from_password
from src.utils.paths import ensure_dir, default_encrypted_name, default_decrypted_name
from src.crypto.signatures import sign_bytes, verify_signature
from src.crypto.key_management import load_keys_from_files, decrypt_private_key


def _encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return salt + nonce + ciphertext


def _decrypt_bytes(blob: bytes, password: str) -> bytes:
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_path(input_path: str, output_path: str, password: str, recursive: bool = True) -> None:
    src = Path(input_path)
    dest = Path(output_path)
    ensure_dir(dest if src.is_dir() else dest.parent) #create new if needed

    if src.is_file(): #for file
        output_file = dest if dest.suffix else dest / default_encrypted_name(src).name
        output_file.write_bytes(_encrypt_bytes(src.read_bytes(), password))
    elif src.is_dir(): #for dir
        for item in src.iterdir():
            target_path = dest / item.name
            if item.is_file():
                target_file = dest / default_encrypted_name(item).name
                target_file.write_bytes(_encrypt_bytes(item.read_bytes(), password))
            elif item.is_dir() and recursive:
                encrypt_path(item, target_path, password, recursive)
    else:
        print("LOL")


def decrypt_path(input_path: str, output_path: str, password: str, recursive: bool = True) -> None:
    src = Path(input_path)
    dest = Path(output_path)
    ensure_dir(dest if src.is_dir() else dest.parent)

    if src.is_file():
        output_file = dest if dest.suffix else dest / default_decrypted_name(src).name
        output_file.write_bytes(_decrypt_bytes(src.read_bytes(), password))
    elif src.is_dir():
        for item in src.iterdir():
            target_path = dest / item.name
            if item.is_file() and item.suffix == ".enc":
                target_file = dest / default_decrypted_name(item).name
                target_file.write_bytes(_decrypt_bytes(item.read_bytes(), password))
            elif item.is_dir() and recursive:
                decrypt_path(item, target_path, password, recursive)
    else:
        print("LOL")

#signatures for integrity
def sign_encrypted_path(enc_path: str | Path, password: str, keys_dir: str | Path) -> Path:
    enc_path = Path(enc_path)
    keys_dir = Path(keys_dir)

    #load keys
    public_pem, encrypted_private = load_keys_from_files(keys_dir)
    if public_pem is None or encrypted_private is None:
        raise ValueError("Keys not found in keys_dir")

    #decrypt private key
    private_pem = decrypt_private_key(encrypted_private, password)

    #sign the file
    data = enc_path.read_bytes()
    signature = sign_bytes(private_pem, data)

    #store next to encrypted file
    sig_path = enc_path.with_suffix(enc_path.suffix + ".sig")
    sig_path.write_bytes(signature)
    return sig_path


def verify_encrypted_path(enc_path: str | Path, keys_dir: str | Path) -> bool:
    enc_path = Path(enc_path)
    keys_dir = Path(keys_dir)

    public_pem, _ = load_keys_from_files(keys_dir)
    if public_pem is None:
        raise ValueError("Public key not found in keys_dir")

    sig_path = enc_path.with_suffix(enc_path.suffix + ".sig")
    if not sig_path.exists():
        return False

    data = enc_path.read_bytes()
    signature = sig_path.read_bytes()

    return verify_signature(public_pem, data, signature)

def encrypt_and_sign_path(input_path: str, output_path: str, password: str, keys_dir: str | Path) -> None:
    encrypt_path(input_path, output_path, password)
    out = Path(output_path)
    for p in out.rglob("*.enc"):
        sign_encrypted_path(p, password, keys_dir)


def verify_and_decrypt_path(input_path: str, output_path: str, password: str, keys_dir: str | Path) -> None:
    inp = Path(input_path)
    # verify all .enc files first
    for p in inp.rglob("*.enc"):
        if not verify_encrypted_path(p, keys_dir):
            raise ValueError(f"Signature verification failed for {p}")
    decrypt_path(input_path, output_path, password)
