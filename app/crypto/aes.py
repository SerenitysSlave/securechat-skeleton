"""
AES-128 ECB + PKCS#7 helpers and key derivation from DH shared secret.

Key derivation:
    K = Trunc16(SHA256(big-endian(shared_secret)))
(Uses existing DH kdf_trunc16_sha256)

"""

from __future__ import annotations

from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .dh import kdf_trunc16_sha256, DEFAULT_GROUP


BLOCK_SIZE = 16  # AES block size (bytes)


class AesError(ValueError):
    pass


def derive_aes_key_from_shared(shared_secret: int) -> bytes:
    """Derive 16-byte AES-128 key from DH shared secret using the assignment KDF."""
    return kdf_trunc16_sha256(shared_secret, DEFAULT_GROUP)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not (1 <= block_size <= 255):
        raise AesError("Invalid block size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not padded or len(padded) % block_size != 0:
        raise AesError("Invalid padded length")
    pad_len = padded[-1]
    if not (1 <= pad_len <= block_size):
        raise AesError("Bad padding length")
    if padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise AesError("Bad padding bytes")
    return padded[:-pad_len]


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-128 ECB + PKCS#7 padding."""
    if len(key) != 16:
        raise AesError("Key must be 16 bytes for AES-128")
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES-128 ECB and remove PKCS#7 padding."""
    if len(key) != 16:
        raise AesError("Key must be 16 bytes for AES-128")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise AesError("Ciphertext length must be multiple of block size")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded, BLOCK_SIZE)


def dh_encrypt_message(shared_secret: int, message: bytes) -> Tuple[bytes, bytes]:
    """
    Convenience: derive key from DH shared secret and encrypt message.
    Returns (key, ciphertext).
    """
    key = derive_aes_key_from_shared(shared_secret)
    ciphertext = encrypt_ecb(key, message)
    return key, ciphertext


def dh_decrypt_message(shared_secret: int, ciphertext: bytes) -> bytes:
    """Convenience: derive key from DH shared secret and decrypt."""
    key = derive_aes_key_from_shared(shared_secret)
    return decrypt_ecb(key, ciphertext)


if __name__ == "__main__":
    # Demo with fake shared secret (use real DH in practice)
    from .dh import generate_keypair, compute_shared_secret

    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    ss_a = compute_shared_secret(a_priv, b_pub)
    ss_b = compute_shared_secret(b_priv, a_pub)
    assert ss_a == ss_b

    key = derive_aes_key_from_shared(ss_a)
    msg = b"Hello DH + AES ECB!"
    ct = encrypt_ecb(key, msg)
    pt = decrypt_ecb(key, ct)
    assert pt == msg
    print(f"[AES] Key: {key.hex()}")
    print(f"[AES] Ciphertext: {ct.hex()}")
    print(f"[AES] Decrypted: {pt}")
