import os
import tempfile

from src.crypto.key_management import (
    rsa_keypair,
    encrypt_private_key,
    decrypt_private_key,
    save_keys_to_files,
    load_keys_from_files,
)

def test_generate_and_encrypt_decrypt_private_key():
    priv_pem, pub_pem = rsa_keypair() #generate keypair
    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem
    
    #encrypt + decrypt private key with password
    password = "master123password"
    enc_priv = encrypt_private_key(priv_pem, password)
    dec_priv = decrypt_private_key(enc_priv, password)
    assert priv_pem == dec_priv

def test_save_and_load_keys_roundtrip():
    #generate + encrypt
    priv_pem, pub_pem = rsa_keypair()
    password = "master-password"
    enc_priv = encrypt_private_key(priv_pem, password)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_keys_to_files(enc_priv, pub_pem, tmpdir) #save to files

        #load back
        loaded_enc_priv, loaded_pub_pem = load_keys_from_files(tmpdir)
        assert loaded_enc_priv is not None
        assert loaded_pub_pem is not None

        #decrypt and compare
        dec_priv = decrypt_private_key(loaded_enc_priv, password)
        assert dec_priv == priv_pem
        assert loaded_pub_pem == pub_pem

    print("No problem mate")

if __name__ == "__main__":
    test_generate_and_encrypt_decrypt_private_key()
    test_save_and_load_keys_roundtrip()
