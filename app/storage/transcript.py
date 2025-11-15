# filepath: /home/serenitys/securechat-skeleton/app/storage/transcript.py
"""
Transcript Module: Logging + Integrity + Non-repudiation
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import List, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from app.crypto.sign import sign as rsa_sign, verify as rsa_verify


def _is_base64(s: str) -> bool:
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def _is_hex_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


class TranscriptManager:
    def __init__(
        self,
        role: str = "client",
        peer_name: str = "unknown",
        session_id: Optional[str] = None,
    ):
        self.role = role
        self.peer_name = peer_name
        self.session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.entries: List[str] = []
        self.started_at = datetime.now(timezone.utc).isoformat()

        os.makedirs("logs", exist_ok=True)

        self.filename = f"logs/transcript_{self.role}_{self.session_id}.log"

        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(
                "# Secure Chat Transcript\n"
                f"# Role: {self.role}\n"
                f"# Peer: {self.peer_name}\n"
                f"# Session ID: {self.session_id}\n"
                f"# Started: {self.started_at}\n"
                "# Format: seqno|timestamp_ms|ciphertext_b64|signature_b64|peer_cert_fingerprint_sha256_hex\n"
                "#======================================================================\n"
            )
            f.flush()
            os.fsync(f.fileno())

        try:
            os.chmod(self.filename, 0o600)
        except Exception:
            pass

    def append_message(
        self,
        seqno: int,
        timestamp_ms: int,
        ciphertext_b64: str,
        signature_b64: str,
        peer_cert_fingerprint_hex: str,
    ) -> None:
        if not (isinstance(seqno, int) and seqno >= 0):
            raise ValueError("seqno must be a non-negative integer")
        if not (isinstance(timestamp_ms, int) and timestamp_ms >= 0):
            raise ValueError("timestamp_ms must be a non-negative integer")
        if not _is_base64(ciphertext_b64):
            raise ValueError("ciphertext_b64 must be valid base64")
        if not _is_base64(signature_b64):
            raise ValueError("signature_b64 must be valid base64")
        if not _is_hex_sha256(peer_cert_fingerprint_hex):
            raise ValueError("peer_cert_fingerprint_hex must be 64-char hex SHA-256")

        entry = f"{seqno}|{timestamp_ms}|{ciphertext_b64}|{signature_b64}|{peer_cert_fingerprint_hex}"
        self.entries.append(entry)

        with open(self.filename, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
            f.flush()
            os.fsync(f.fileno())

        print(f"[+] Transcript: Message {seqno} logged")

    def compute_transcript_hash(self) -> str:
        return hashlib.sha256("\n".join(self.entries).encode("utf-8")).hexdigest()

    def get_sequence_range(self) -> Tuple[int, int]:
        if not self.entries:
            return 0, 0
        seqnos = [int(e.split("|", 1)[0]) for e in self.entries]
        return min(seqnos), max(seqnos)

    def save_receipt(self, private_key: RSAPrivateKey, extra: Optional[dict] = None) -> str:
        receipt_path = f"logs/receipt_{self.role}_{self.session_id}.json"

        t_hash = self.compute_transcript_hash()
        sig = rsa_sign(t_hash.encode("utf-8"), private_key)

        receipt = {
            "role": self.role,
            "peer": self.peer_name,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "total_messages": len(self.entries),
            "seq_range": {
                "first": self.get_sequence_range()[0],
                "last": self.get_sequence_range()[1],
            },
            "transcript_file": self.filename,
            "transcript_sha256": t_hash,
            "sig_alg": "RSASSA-PKCS1-v1_5+SHA256",
            "sig": base64.b64encode(sig).decode("ascii"),
        }

        if extra:
            receipt["meta"] = extra

        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        print(f"[+] Receipt saved: {receipt_path}")
        return receipt_path

    def finalize(self) -> None:
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write(
                "#======================================================================\n"
                f"# Ended: {datetime.now(timezone.utc).isoformat()}\n"
                f"# Total messages: {len(self.entries)}\n"
                f"# Transcript hash: {self.compute_transcript_hash()}\n"
            )
            f.flush()
            os.fsync(f.fileno())

        print(f"[+] Transcript finalized: {self.filename}")


class TranscriptVerifier:
    def __init__(self, transcript_file: str):
        self.transcript_file = transcript_file
        self.entries: List[str] = []
        self._load_transcript()

    def _load_transcript(self) -> None:
        with open(self.transcript_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("#"):
                    line = line.strip()
                    if line:
                        self.entries.append(line)

    def compute_hash(self) -> str:
        return hashlib.sha256("\n".join(self.entries).encode("utf-8")).hexdigest()

    def verify_receipt(
        self,
        receipt_file: str,
        public_key: RSAPublicKey,
    ) -> Tuple[bool, str]:
        with open(receipt_file, "r", encoding="utf-8") as f:
            receipt = json.load(f)

        expected = receipt.get("transcript_sha256", "")
        actual = self.compute_hash()

        if expected != actual:
            return False, f"Hash mismatch: expected {expected}, got {actual}"

        sig_b64 = receipt.get("sig", "")
        try:
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:
            return False, "Invalid signature encoding"

        if rsa_verify(expected.encode("utf-8"), sig, public_key):
            return True, "Receipt verified successfully"

        try:
            digest_bytes = bytes.fromhex(expected)
        except Exception:
            return False, "Invalid expected hash format"

        if rsa_verify(digest_bytes, sig, public_key):
            return True, "Receipt verified successfully (compat mode)"

        return False, "Invalid receipt signature"

    def verify_message_signatures(
        self,
        public_key: RSAPublicKey,
    ) -> Tuple[bool, List[int]]:
        failed: List[int] = []

        for entry in self.entries:
            parts = entry.split("|")
            if len(parts) != 5:
                continue

            seqno_s, ts_s, ciphertext_b64, signature_b64, _ = parts
            canonical = f"{seqno_s}|{ts_s}|{ciphertext_b64}".encode("utf-8")

            try:
                sig = base64.b64decode(signature_b64, validate=True)
            except Exception:
                failed.append(int(seqno_s))
                continue

            ok = rsa_verify(canonical, sig, public_key)

            if not ok:
                legacy = f"{seqno_s}{ts_s}{ciphertext_b64}".encode("utf-8")
                ok = rsa_verify(legacy, sig, public_key)

            if not ok:
                try:
                    failed.append(int(seqno_s))
                except Exception:
                    failed.append(-1)

        return (len(failed) == 0), failed
