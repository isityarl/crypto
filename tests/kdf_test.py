import os
from src.crypto.kdf import derive_key_from_password

def test_kdf():
    password = "rara"
    salt = os.urandom(16)

    key1 = derive_key_from_password(password, salt)
    key2 = derive_key_from_password(password, salt)
    assert key1 == key2, "Same password+salt should give same key"

    salt2 = os.urandom(16)
    key3 = derive_key_from_password(password, salt2)
    assert key1 != key3, "Different salt should give different key"

    print(key1)
    print(key2)
    print(key3)
    print("PBKDF2 tests passed")

if __name__ == "__main__":
    test_kdf()
