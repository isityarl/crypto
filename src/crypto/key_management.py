from typing import Optional, Tuple

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    raise NotImplementedError

def encrypt_private_key(private_key_pem: bytes, password: str) -> bytes:
    raise NotImplementedError

def decrypt_private_key(encrypted_private_key: bytes, password: str) -> bytes:
    raise NotImplementedError

def save_keys_to_files(private_key_data: bytes, public_key_data: bytes, directory: str) -> None:
    raise NotImplementedError

def load_keys_from_files(directory: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    raise NotImplementedError
