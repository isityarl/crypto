from src.crypto.key_management import (generate_rsa_keypair, encrypt_private_key, decrypt_private_key)
from cryptography.exceptions import InvalidTag

priv_pem, pub_pem = generate_rsa_keypair()

password = "master123password"
password1 = "master122password"
enc_priv = encrypt_private_key(priv_pem, password)
try:
    dec_priv = decrypt_private_key(enc_priv, password1)
except InvalidTag:
    print('wrong password')

dec_priv = decrypt_private_key(enc_priv, password)
assert priv_pem == dec_priv

print(enc_priv)
print(dec_priv)