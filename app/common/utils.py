"""Utility helpers for the secure chat system."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import time
from typing import Optional, Union


# ---------------------------------------------------------------------------
# Time / Encoding / Hash Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    """Return current Unix timestamp in milliseconds (UTC)."""
    return int(time.time() * 1000)


def b64e(b: Union[bytes, bytearray, memoryview]) -> str:
    """Base64-encode arbitrary bytes into an ASCII string."""
    return base64.b64encode(bytes(b)).decode("ascii")


def b64d(s: str) -> bytes:
    """
    Strict Base64-decode of ASCII string into bytes.
    Raises ValueError on invalid base64.
    """
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}") from e


def sha256_hex(data: Union[bytes, bytearray, memoryview]) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(bytes(data)).hexdigest()


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------

def generate_nonce(length: int = 16) -> bytes:
    """Generate a cryptographically secure random nonce."""
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    return os.urandom(length)


# ---------------------------------------------------------------------------
# Socket Framing (4-byte length prefixed)
# ---------------------------------------------------------------------------

_MAX_FRAME = 10 * 1024 * 1024  # 10 MiB hard safety limit


def recv_exact(sock: socket.socket, n: int, timeout: Optional[float] = None) -> Optional[bytes]:
    """
    Receive exactly `n` bytes from the socket.
    Returns None on EOF, timeout, or any failure.
    """
    if n <= 0:
        return b""

    prev_timeout = None
    try:
        if timeout is not None:
            prev_timeout = sock.gettimeout()
            sock.settimeout(timeout)

        buf = bytearray(n)
        view = memoryview(buf)
        read = 0

        while read < n:
            try:
                r = sock.recv_into(view[read:], n - read)
            except socket.timeout:
                return None
            except Exception:
                return None

            if r == 0:
                return None  # EOF

            read += r

        return bytes(buf)

    finally:
        # Restore timeout if changed
        if timeout is not None and prev_timeout is not None:
            try:
                sock.settimeout(prev_timeout)
            except Exception:
                pass


def send_message(sock: socket.socket, message: Union[str, bytes]) -> None:
    """
    Send a UTF-8 string or bytes with a 4-byte big-endian length prefix.
    Raises RuntimeError on failure.
    """
    try:
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)

        if len(msg_bytes) > _MAX_FRAME:
            raise ValueError(f"Message too large: {len(msg_bytes)} bytes (max {_MAX_FRAME})")

        header = len(msg_bytes).to_bytes(4, "big")
        sock.sendall(header + msg_bytes)

    except Exception as e:
        raise RuntimeError(f"Failed to send message: {e}") from e


def receive_message(sock: socket.socket, max_len: int = _MAX_FRAME) -> Optional[str]:
    """
    Receive a length-prefixed UTF-8 message.
    Returns decoded string, or None on EOF/timeout/error.
    """
    try:
        length_bytes = recv_exact(sock, 4)
        if not length_bytes:
            return None

        msg_length = int.from_bytes(length_bytes, "big")
        if msg_length <= 0 or msg_length > max_len:
            return None  # Reject suspicious lengths

        msg_bytes = recv_exact(sock, msg_length)
        if not msg_bytes:
            return None

        return msg_bytes.decode("utf-8")

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Certificates / Display Helpers
# ---------------------------------------------------------------------------

def format_cert_fingerprint(cert) -> str:
    """Return SHA-256 fingerprint of an X.509 cert as a lowercase hex string."""
    from cryptography.hazmat.primitives import hashes
    return cert.fingerprint(hashes.SHA256()).hex()


def print_banner(title: str) -> None:
    """Pretty CLI banner."""
    width = 60
    print("\n" + "=" * width)
    print(f"{title:^{width}}")
    print("=" * width + "\n")
