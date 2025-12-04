from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from typing import Tuple, Optional
from .kdf import derive_key_from_password

#Generate RSA private:public key pair
def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=key_size,)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # encrypt manually later
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    #in PEM format
    return private_pem, public_pem

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
    os.makedirs(directory, exist_ok=True)

    with open(os.path.join(directory, "private_key.enc"), "wb") as f:
        f.write(private_key_data)

    with open(os.path.join(directory, "public_key.pem"), "wb") as f:
        f.write(public_key_data)

#Load keys from a directory
def load_keys_from_files(directory: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    priv_path = os.path.join(directory, "private_key.enc")
    pub_path = os.path.join(directory, "public_key.pem")

    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        return None, None

    with open(priv_path, "rb") as f:
        priv = f.read()
    with open(pub_path, "rb") as f:
        pub = f.read()
    return priv, pub
