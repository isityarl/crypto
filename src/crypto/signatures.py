from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign_bytes(private_key_pem: bytes, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
