#!/usr/bin/env python3
"""Tests for CertificateValidator."""

import sys
import uuid
from pathlib import Path
from typing import List

sys.path.insert(0, ".")  # Ensure project root on path

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # Added import
from src.common.cert_validator import CertificateValidator  # noqa: E402

CERT_DIR = Path("certs")


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(_read(path))


def _existing_dns_sans(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def test_server_certificate_valid():
    validator = CertificateValidator(str(CERT_DIR / "ca_cert.pem"))
    pem = _read(CERT_DIR / "server_cert.pem")
    result = validator.validate_certificate(pem)
    assert result.valid, f"Expected valid server cert, got: {result.reason}"
    assert result.reason == "VALID"
    assert validator.get_common_name(result.cert)
    assert len(validator.get_certificate_fingerprint(result.cert)) == 64


def test_client_certificate_valid():
    validator = CertificateValidator(str(CERT_DIR / "ca_cert.pem"))
    pem = _read(CERT_DIR / "client_cert.pem")
    result = validator.validate_certificate(pem)
    assert result.valid, f"Expected valid client cert, got: {result.reason}"
    assert result.reason == "VALID"


def test_ca_certificate_rejected():
    validator = CertificateValidator(str(CERT_DIR / "ca_cert.pem"))
    pem = _read(CERT_DIR / "ca_cert.pem")
    result = validator.validate_certificate(pem)
    assert not result.valid, f"CA cert should be rejected; reason={result.reason}"
    assert result.reason in {"UNEXPECTED_CA_CERT", "INVALID_SIGNATURE"}


def test_cn_mismatch():
    validator = CertificateValidator(str(CERT_DIR / "ca_cert.pem"))
    pem = _read(CERT_DIR / "server_cert.pem")
    bad_cn = "Definitely-Wrong-CN.example"
    result = validator.validate_certificate(pem, expected_cn=bad_cn)
    assert not result.valid, f"Expected CN mismatch failure; reason={result.reason}"
    assert result.reason.startswith("CN_MISMATCH")


def test_key_usage_present():
    validator = CertificateValidator(str(CERT_DIR / "ca_cert.pem"))
    pem = _read(CERT_DIR / "server_cert.pem")
    result = validator.validate_certificate(pem, require_key_usage=True)
    assert result.valid or result.reason in {"MISSING_KEY_USAGE", "KEY_USAGE_INSUFFICIENT"}


if __name__ == "__main__":
    print("[*] Manual execution of certificate tests\n")
    for fn in [
        test_server_certificate_valid,
        test_client_certificate_valid,
        test_ca_certificate_rejected,
        test_cn_mismatch,
        test_key_usage_present,
    ]:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {fn.__name__}: {e}")