import os
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .kdf import derive_key_from_password
from src.utils.paths import ensure_dir

# private:public key pair
def rsa_keypair() -> Tuple[bytes, bytes]:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend
    )

    private_key = key.private_bytes(
        encoding=ser.Encoding.PEM, 
        format=ser.PrivateFormat.PKCS8,
        encryption_algorithm=ser.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key

#Encrypt the private key using AES-GCM
def encrypt_private_key(private_key_pem: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt) #derive AES key
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, None) #no extra metadata to authenticate

    return salt + nonce + ciphertext

#Decrypt an RSA private key
def decrypt_private_key(encrypted_private_key: bytes, password: str) -> bytes:
    #extract components
    salt = encrypted_private_key[:16]
    nonce = encrypted_private_key[16:28]
    ciphertext = encrypted_private_key[28:]

    key = derive_key_from_password(password, salt) #rederive AES key
    aesgcm = AESGCM(key)

    private_key_pem = aesgcm.decrypt(nonce, ciphertext, None)
    return private_key_pem

#Save keys to a directory
def save_keys_to_files(private_key_data: bytes, public_key_data: bytes, directory: str) -> None:
    dir = Path(directory)
    ensure_dir(dir)

    priv_path = dir/"private_key.enc"
    pub_path = dir/"public_key.pem"

    priv_path.write_bytes(private_key_data)
    pub_path.write_bytes(public_key_data)

#Load keys from a directory
def load_keys_from_files(directory: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    dir = Path(directory)

    priv_path = dir/"private_key.enc"
    pub_path = dir/"public_key.pem"

    if not (priv_path.exists() and pub_path.exists()): return None,None

    encrypted_priv = priv_path.read_bytes()
    public_pem = pub_path.read_bytes()
    return encrypted_priv, public_pem