"""
Crypto tests: DH, AES-128-ECB/PKCS#7, RSA sign/verify.
"""

import sys
import os
import tempfile

sys.path.insert(0, ".")

from cryptography.exceptions import InvalidSignature

from app.crypto.dh import (
    DEFAULT_GROUP,
    generate_keypair,
    compute_shared_secret,
    kdf_trunc16_sha256,
    public_bytes,
    public_from_bytes,
    DHError,
)
from app.crypto.aes import (
    derive_aes_key_from_shared,
    encrypt_ecb,
    decrypt_ecb,
    pkcs7_pad,
    pkcs7_unpad,
    AesError,
)
from app.crypto.sign import (
    generate_rsa_key,
    sign,
    verify,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)


def _i2osp(x: int, length: int) -> bytes:
    """Integer-to-octet-string primitive."""
    return x.to_bytes(length, "big")


# --------------------------------------------------------------------------- #
#   DIFFIE–HELLMAN TESTS
# --------------------------------------------------------------------------- #

def test_diffie_hellman():
    print("=== DH ===")

    # Generate key pairs
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()

    # Public encode/decode roundtrip
    a_pub_bytes = public_bytes(a_pub, DEFAULT_GROUP)
    b_pub_bytes = public_bytes(b_pub, DEFAULT_GROUP)

    a_pub2 = public_from_bytes(a_pub_bytes, DEFAULT_GROUP)
    b_pub2 = public_from_bytes(b_pub_bytes, DEFAULT_GROUP)

    assert a_pub2 == a_pub, "Public key decode mismatch for A"
    assert b_pub2 == b_pub, "Public key decode mismatch for B"

    # Shared secret equality
    ss_a = compute_shared_secret(a_priv, b_pub)
    ss_b = compute_shared_secret(b_priv, a_pub)
    assert ss_a == ss_b, "Shared secrets did not match"

    # KDF correctness check (truncate SHA-256(Ks))
    spec_key = __import__("hashlib").sha256(
        _i2osp(ss_a, DEFAULT_GROUP.byte_len)
    ).digest()[:16]

    dh_key = kdf_trunc16_sha256(ss_a, DEFAULT_GROUP)
    assert dh_key == spec_key, "KDF mismatch"
    assert dh_key == kdf_trunc16_sha256(ss_b, DEFAULT_GROUP)

    print("[PASS] DH key exchange, encode/decode, and KDF")

    # Invalid peer key rejection
    try:
        compute_shared_secret(a_priv, 1)
        assert False, "Expected DHError for invalid peer public"
    except DHError:
        print("[PASS] DH invalid public key rejected")


# --------------------------------------------------------------------------- #
#   AES-ECB + PKCS#7 TESTS
# --------------------------------------------------------------------------- #

def test_aes_ecb_pkcs7():
    print("=== AES-128-ECB + PKCS#7 ===")

    # Fresh DH-derived key
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    ss = compute_shared_secret(a_priv, b_pub)
    key = derive_aes_key_from_shared(ss)

    assert len(key) == 16, "AES key must be 16 bytes"

    vectors = [
        b"",
        b"A" * 1,
        b"B" * 15,
        b"C" * 16,
        b"D" * 17,
        b"Hello, world!",
        b"The quick brown fox jumps over the lazy dog.",
        os.urandom(1024),
    ]

    for idx, msg in enumerate(vectors, 1):
        ct = encrypt_ecb(key, msg)
        pt = decrypt_ecb(key, ct)
        assert pt == msg, f"ECB roundtrip failed for vector {idx}"

    print("[PASS] AES ECB encryption/decryption vectors")

    # Padding: empty input
    padded = pkcs7_pad(b"", 16)
    assert len(padded) == 16, "Padding for empty input should be one full block"
    assert all(b == 16 for b in padded), "Empty padding bytes incorrect"
    assert pkcs7_unpad(padded, 16) == b"", "Unpad failed for empty padding case"

    # Padding: malformed
    bad = b"\x01" * 15 + b"\x02"
    try:
        pkcs7_unpad(bad, 16)
        assert False, "Expected AesError for malformed padding"
    except AesError:
        pass

    # Key length check
    try:
        encrypt_ecb(b"\x00" * 15, b"test")
        assert False, "AES key length validation failed"
    except AesError:
        print("[PASS] AES key length & padding checks")


# --------------------------------------------------------------------------- #
#   RSA TESTS
# --------------------------------------------------------------------------- #

def test_rsa_sign_verify():
    print("=== RSA PKCS#1 v1.5 SHA-256 ===")

    priv = generate_rsa_key(2048)
    pub = priv.public_key()

    msg = b"message to sign"
    sig = sign(msg, priv)

    assert verify(msg, sig, pub), "RSA signature failed to verify"
    assert not verify(b"tampered", sig, pub), "RSA incorrectly verified tampered message"

    # Wrong key must fail
    other_pub = generate_rsa_key(2048).public_key()
    assert not verify(msg, sig, other_pub), "RSA verified using wrong key"

    # Save & load test
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = os.path.join(tmp, "priv.pem")
        pub_path = os.path.join(tmp, "pub.pem")

        save_private_key(priv_path, priv)
        save_public_key(pub_path, pub)

        priv2 = load_private_key(priv_path)
        pub2 = load_public_key(pub_path)

        sig2 = sign(msg, priv2)
        assert verify(msg, sig2, pub2), "Loaded RSA keys failed verification"

    print("[PASS] RSA sign/verify and key I/O")


# --------------------------------------------------------------------------- #
#   MAIN
# --------------------------------------------------------------------------- #

def main():
    try:
        test_diffie_hellman()
        test_aes_ecb_pkcs7()
        test_rsa_sign_verify()
        print("\nALL CRYPTO TESTS PASSED ✓")
    except AssertionError as e:
        print(f"[FAIL] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected exception: {e}")
        raise


if __name__ == "__main__":
    main()
