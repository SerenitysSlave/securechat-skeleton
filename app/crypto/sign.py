"""RSA PKCS#1 v1.5 SHA-256 sign/verify helpers."""

from __future__ import annotations

from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class RSASignError(ValueError):
    pass


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    if key_size < 2048:
        raise RSASignError("Key size must be >= 2048 bits")
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign message with RSA PKCS#1 v1.5 + SHA-256."""
    if not isinstance(message, bytes):
        raise RSASignError("Message must be bytes")
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify RSA PKCS#1 v1.5 + SHA-256 signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def save_private_key(path: str, private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> None:
    """Persist private key (PKCS#8 PEM)."""
    encryption = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(path, "wb") as f:
        f.write(data)


def save_public_key(path: str, public_key: rsa.RSAPublicKey) -> None:
    """Persist public key (SubjectPublicKeyInfo PEM)."""
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(data)


def load_private_key(path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key(path: str) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


if __name__ == "__main__":
    # Simple self-test
    priv = generate_rsa_key()
    pub = priv.public_key()
    msg = b"test message"
    sig = sign(msg, priv)
    assert verify(msg, sig, pub)
    assert not verify(b"tampered", sig, pub)
    print("[RSA] Self-test passed")
