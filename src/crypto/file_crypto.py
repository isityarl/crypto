from pathlib import Path
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kdf import derive_key_from_password
from src.utils.paths import ensure_dir, default_encrypted_name, default_decrypted_name


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
    ensure_dir(dest if src.is_dir() else dest.parent)

    if src.is_file():
        output_file = dest if dest.suffix else dest / default_encrypted_name(src).name
        output_file.write_bytes(_encrypt_bytes(src.read_bytes(), password))
    elif src.is_dir():
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
