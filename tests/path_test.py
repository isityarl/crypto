from pathlib import Path

from src.crypto.file_crypto import encrypt_path, decrypt_path

base = Path("tests/ax")
input_dir = base / "ax1"
enc_dir = base / "ax1_enc"
dec_dir = base / "ax1_dec"
password = "test-password"

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

print("Done")