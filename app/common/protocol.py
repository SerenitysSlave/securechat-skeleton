"""
Pydantic models and helpers for the secure chat protocol.

Message types:
- hello, server_hello
- register, login
- dh_client, dh_server
- msg, receipt
- error
"""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Literal, Union

from pydantic import BaseModel, Field, validator, root_validator


HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _is_b64(s: str) -> bool:
    """Strict Base64 validator (no whitespace, no urlsafe)."""
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def _is_pem_cert(pem: str) -> bool:
    pem = pem.strip()
    return (
        pem.startswith("-----BEGIN CERTIFICATE-----")
        and pem.endswith("-----END CERTIFICATE-----")
        and "-----" in pem  # cheap sanity check
    )


# ------------------------------------------------------
# HELLO / SERVER_HELLO
# ------------------------------------------------------

class Hello(BaseModel):
    type: Literal["hello"] = "hello"
    client_cert: str  # PEM
    nonce: str        # base64

    @validator("client_cert")
    def _validate_cert(cls, v: str) -> str:
        if not _is_pem_cert(v):
            raise ValueError("client_cert must be a valid PEM certificate")
        return v

    @validator("nonce")
    def _validate_nonce(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("nonce must be valid Base64")
        return v


class ServerHello(BaseModel):
    type: Literal["server_hello"] = "server_hello"
    server_cert: str
    nonce: str

    @validator("server_cert")
    def _validate_cert(cls, v: str) -> str:
        if not _is_pem_cert(v):
            raise ValueError("server_cert must be a valid PEM certificate")
        return v

    @validator("nonce")
    def _validate_nonce(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("nonce must be valid Base64")
        return v


# ------------------------------------------------------
# REGISTER / LOGIN
# ------------------------------------------------------

class Register(BaseModel):
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str  # PBKDF2 string or legacy hex
    salt: str  # base64

    @validator("salt")
    def _validate_salt(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("salt must be valid Base64")
        return v


class Login(BaseModel):
    type: Literal["login"] = "login"
    email: str
    pwd: str
    nonce: str  # base64

    @validator("nonce")
    def _validate_nonce(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("nonce must be valid Base64")
        return v


# ------------------------------------------------------
# DIFFIE-HELLMAN
# ------------------------------------------------------

def _positive_int(v: int) -> int:
    if not isinstance(v, int) or v <= 0:
        raise ValueError("Value must be a positive integer")
    return v


class DhClient(BaseModel):
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int

    _check_all = validator("g", "p", "A", allow_reuse=True)(_positive_int)


class DhServer(BaseModel):
    type: Literal["dh_server"] = "dh_server"
    B: int

    _check_B = validator("B", allow_reuse=True)(_positive_int)


# ------------------------------------------------------
# ENCRYPTED MESSAGE
# ------------------------------------------------------

class Msg(BaseModel):
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int = Field(default_factory=lambda: int(time.time() * 1000))  # ms
    ct: str  # base64 ciphertext
    sig: str  # base64 signature
    peer_fpr: str | None = None  # hex SHA-256

    @validator("seqno")
    def _seq_valid(cls, v: int) -> int:
        if v < 0:
            raise ValueError("seqno must be non-negative")
        return v

    @validator("ts")
    def _ts_valid(cls, v: int) -> int:
        if v < 0:
            raise ValueError("timestamp must be non-negative")
        return v

    @validator("ct", "sig")
    def _b64_valid(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("ct/sig must be valid Base64")
        return v

    @validator("peer_fpr")
    def _fpr_hex(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not HEX_SHA256_RE.match(v):
            raise ValueError("peer_fpr must be 64 hex chars (SHA-256)")
        return v


# ------------------------------------------------------
# RECEIPT
# ------------------------------------------------------

class Receipt(BaseModel):
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex digest
    sig: str                # base64

    @validator("first_seq", "last_seq")
    def _seq_valid(cls, v: int) -> int:
        if v < 0:
            raise ValueError("sequence numbers must be non-negative")
        return v

    @validator("transcript_sha256")
    def _hash_valid(cls, v: str) -> str:
        if not HEX_SHA256_RE.match(v):
            raise ValueError("transcript_sha256 must be 64 hex chars")
        return v

    @validator("sig")
    def _sig_valid(cls, v: str) -> str:
        if not _is_b64(v):
            raise ValueError("sig must be valid Base64")
        return v


# ------------------------------------------------------
# ERROR
# ------------------------------------------------------

class ErrorMsg(BaseModel):
    type: Literal["error"] = "error"
    code: str
    message: str


# ------------------------------------------------------
# DISPATCH
# ------------------------------------------------------

Message = Union[
    Hello,
    ServerHello,
    Register,
    Login,
    DhClient,
    DhServer,
    Msg,
    Receipt,
    ErrorMsg,
]


def parse_message(obj: str | dict) -> Message:
    """
    Parse a JSON string or dict and return the appropriate typed message.
    Raises ValueError on unknown type or validation error.
    """
    data = json.loads(obj) if isinstance(obj, str) else obj

    mtype = data.get("type")
    cls = {
        "hello": Hello,
        "server_hello": ServerHello,
        "register": Register,
        "login": Login,
        "dh_client": DhClient,
        "dh_server": DhServer,
        "msg": Msg,
        "receipt": Receipt,
        "error": ErrorMsg,
    }.get(mtype)

    if cls is None:
        raise ValueError(f"Unknown message type: {mtype}")

    return cls(**data)


__all__ = [
    "Hello",
    "ServerHello",
    "Register",
    "Login",
    "DhClient",
    "DhServer",
    "Msg",
    "Receipt",
    "ErrorMsg",
    "Message",
    "parse_message",
]
