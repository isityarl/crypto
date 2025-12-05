from pathlib import Path

from src.crypto.file_crypto import encrypt_path, decrypt_path, sign_encrypted_path, verify_encrypted_path
from src.crypto.key_management import generate_and_store_keys

base = Path("tests/ax")
input_dir = base / "ax1"
enc_dir = base / "ax1_enc"
dec_dir = base / "ax1_dec"
password = "axax123"
keys_dir = base / "keys"

keys_dir.mkdir(parents=True, exist_ok=True)
pub = keys_dir / "public_key.pem"
priv_enc = keys_dir / "private_key.enc"
if not pub.exists() or not priv_enc.exists():
    generate_and_store_keys(keys_dir, password)


# clean old enc/dec dirs if they exist
import shutil
if enc_dir.exists():
    shutil.rmtree(enc_dir)
if dec_dir.exists():
    shutil.rmtree(dec_dir)

encrypt_path(str(input_dir), str(enc_dir), password)

decrypt_path(str(enc_dir), str(dec_dir), password)

#check files
original_files = sorted(p.relative_to(input_dir) for p in input_dir.rglob("*") if p.is_file())
decrypted_files = sorted(p.relative_to(dec_dir) for p in dec_dir.rglob("*") if p.is_file())

assert original_files == decrypted_files

for rel in original_files:
    orig = input_dir / rel
    dec = dec_dir / rel
    assert orig.read_bytes() == dec.read_bytes()

print("Done, files")


enc_files = sorted(enc_dir.rglob("*.enc"))
assert enc_files, "No .enc files found to sign."
enc_file = enc_files[0]

#sign encrypted file -> creates .sig
sig_path = sign_encrypted_path(enc_file, password, keys_dir)
assert sig_path.exists()

#verify OK
assert verify_encrypted_path(enc_file, keys_dir)

#simulate tampering and verify fails
data = enc_file.read_bytes()
enc_file.write_bytes(data + b"x")  #modify ciphertext

assert not verify_encrypted_path(enc_file, keys_dir)

print("Done, signature")