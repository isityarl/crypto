from pathlib import Path

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def default_encrypted_name(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".enc")

def default_decrypted_name(path: Path) -> Path:
    if path.suffix == ".enc":
        return path.with_suffix("")
    return path
