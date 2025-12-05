from pathlib import Path

from src.crypto.file_crypto import decrypt_path
from src.crypto.hash_utils import file_sha256


def test_hash():
    base = Path("tests/ax")
    original_dir = base / "ax1"
    enc_dir = base / "ax1_enc"
    dec_dir = base / "ax1_dec"
    password = "axax123"

    #hash
    original_hashes = {}
    for p in original_dir.iterdir():
        if p.is_file():
            original_hashes[p.name] = file_sha256(str(p))

    #decrypt
    decrypt_path(str(enc_dir), str(dec_dir), password)

    #hash decrypted
    for name, orig_hash in original_hashes.items():
        dec_file = dec_dir / name
        assert dec_file.exists(), f"Missing decrypted file: {dec_file}"
        dec_hash = file_sha256(str(dec_file))
        assert dec_hash == orig_hash, f"Hash mismatch for {name}" #compare

    print("SHA-256 integrity test passed")


if __name__ == "__main__":
    test_hash()
