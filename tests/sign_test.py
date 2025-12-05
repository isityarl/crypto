# tests/signatures_test.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from src.crypto.signatures import sign_bytes, verify_signature


def sign_test():
    #temp RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #signing data
    data = b"test message for signature"
    signature = sign_bytes(private_pem, data)

    #verification
    assert verify_signature(public_pem, data, signature)

    data1 = b"test message for SIGNATURE"
    assert not verify_signature(public_pem, data1, signature)

    print("sign/verify test passed")


if __name__ == "__main__":
    sign_test()
