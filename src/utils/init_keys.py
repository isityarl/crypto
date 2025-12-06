from pathlib import Path
from src.crypto.key_management import rsa_keypair, encrypt_private_key, save_keys_to_files

keys_dir = Path("tests/ax/keys")
keys_dir.mkdir(parents=True, exist_ok=True)

password = ""

private_pem, public_pem = rsa_keypair()
encrypted_private = encrypt_private_key(private_pem, password)
save_keys_to_files(encrypted_private, public_pem, keys_dir)
