"""Classic Diffie-Hellman helpers using RFC3526 MODP 2048-bit group (g=2)
and key derivation: Trunc16(SHA256(Ks))

Exports:
- DEFAULT_GROUP: DHGroup (p, g, q)
- generate_keypair() -> (priv, pub)
- validate_peer_public(pub) -> None (raises on invalid)
- compute_shared_secret(priv, peer_pub) -> int
- kdf_trunc16_sha256(shared_secret) -> 16-byte key
- public_bytes(pub) / public_from_bytes(b) for wire encoding
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple


class DHError(ValueError):
    pass


@dataclass(frozen=True)
class DHGroup:
    p: int
    g: int

    @property
    def q(self) -> int:
        # For RFC3526 MODP groups, p is a safe prime: p = 2q + 1
        return (self.p - 1) // 2

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8


# RFC 3526 Group 14 (2048-bit MODP) prime and generator
# https://www.rfc-editor.org/rfc/rfc3526
_MODP_2048_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DEFAULT_GROUP = DHGroup(p=int(_MODP_2048_P_HEX, 16), g=2)


def _i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def generate_private_key(group: DHGroup = DEFAULT_GROUP) -> int:
    # Uniform in [2, p-2]
    return secrets.randbelow(group.p - 3) + 2


def public_key(priv: int, group: DHGroup = DEFAULT_GROUP) -> int:
    if not (isinstance(priv, int) and 2 <= priv <= group.p - 2):
        raise DHError("Invalid private key range")
    return pow(group.g, priv, group.p)


def validate_peer_public(pub: int, group: DHGroup = DEFAULT_GROUP) -> None:
    if not isinstance(pub, int):
        raise DHError("Peer public key must be an integer")
    if not (2 <= pub <= group.p - 2):
        raise DHError("Peer public key out of range")
    # Explicitly exclude 1, then check subgroup membership:
    if pub == 1 or pow(pub, group.q, group.p) != 1:
        raise DHError("Peer public key failed subgroup check")


def compute_shared_secret(
    priv: int, peer_pub: int, group: DHGroup = DEFAULT_GROUP
) -> int:
    validate_peer_public(peer_pub, group)
    return pow(peer_pub, priv, group.p)


def kdf_trunc16_sha256(shared_secret: int, group: DHGroup = DEFAULT_GROUP) -> bytes:
    # Use fixed-length (len(p)) big-endian representation for consistency
    ss_bytes = _i2osp(shared_secret, group.byte_len)
    digest = hashlib.sha256(ss_bytes).digest()
    return digest[:16]


def generate_keypair(group: DHGroup = DEFAULT_GROUP) -> Tuple[int, int]:
    priv = generate_private_key(group)
    pub = public_key(priv, group)
    return priv, pub


def public_bytes(pub: int, group: DHGroup = DEFAULT_GROUP) -> bytes:
    return _i2osp(pub, group.byte_len)


def public_from_bytes(b: bytes, group: DHGroup = DEFAULT_GROUP) -> int:
    if len(b) != group.byte_len:
        raise DHError("Invalid public key byte length")
    pub = _os2ip(b)
    validate_peer_public(pub, group)
    return pub


if __name__ == "__main__":
    # Simple self-test / demo
    g = DEFAULT_GROUP

    # Alice
    a_priv, a_pub = generate_keypair(g)
    # Bob
    b_priv, b_pub = generate_keypair(g)

    # Exchange a_pub <-> b_pub
    a_ss = compute_shared_secret(a_priv, b_pub, g)
    b_ss = compute_shared_secret(b_priv, a_pub, g)
    assert a_ss == b_ss

    a_key = kdf_trunc16_sha256(a_ss, g)
    b_key = kdf_trunc16_sha256(b_ss, g)
    assert a_key == b_key
    print(f"[DH] Shared key (16B): {a_key.hex()}")
