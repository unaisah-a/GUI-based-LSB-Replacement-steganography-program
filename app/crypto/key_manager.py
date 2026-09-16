import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size: int = 2048):
    "Generates an RSA private/public key pair (2048-bit standard)."
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_pem(key, filepath: str, is_private: bool = True) -> None:
    "Saves an RSA key object to a PEM file on disk."
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.SubjectPublicKeyInfo
        )
    with open(filepath, "wb") as f:
        f.write(pem)

def load_private_key_from_pem(filepath: str):
    "Loads an RSA private key from a PEM file."
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key_from_pem(filepath: str):
    "Loads an RSA public key from a PEM file."
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read())