"""
PKI Module - Certificate validation and management
"""

from __future__ import annotations
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional, Iterable
import ipaddress
import os

@dataclass(frozen=True)
class CertValidationResult:
    valid: bool
    reason: str
    cert: Optional[x509.Certificate] = None

class CertificateValidator:
    """Handles certificate loading and validation."""

    def __init__(self, ca_cert_path: str = "certs/ca_cert.pem"):
        self.ca_cert = self._load_certificate(ca_cert_path)
        self.ca_public_key = self.ca_cert.public_key()

    def _load_certificate(self, cert_path: str) -> x509.Certificate:
        try:
            with open(cert_path, "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
        except FileNotFoundError:
            raise FileNotFoundError(f"CA certificate not found: {cert_path}")

    @staticmethod
    def _now_utc() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _ensure_aware(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    def validate_certificate(
        self,
        cert_pem_data: bytes | str,
        expected_cn: Optional[str] = None,
        expected_dns: Optional[Iterable[str]] = None,
        expected_ips: Optional[Iterable[str]] = None,
        require_key_usage: bool = True,
    ) -> CertValidationResult:
        """Validate a PEM certificate with optional identity expectations."""
        try:
            if isinstance(cert_pem_data, str):
                cert_pem_data = cert_pem_data.encode()

            cert = x509.load_pem_x509_certificate(cert_pem_data)

            # 1. Signature (chain length = 1; direct CA sign)
            try:
                self.ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except InvalidSignature:
                return CertValidationResult(False, "INVALID_SIGNATURE", None)

            # 2. Validity period (timezone-safe)
            now = self._now_utc()
            not_before = self._ensure_aware(cert.not_valid_before)
            not_after = self._ensure_aware(cert.not_valid_after)
            if now < not_before:
                return CertValidationResult(False, "NOT_YET_VALID", cert)
            if now > not_after:
                return CertValidationResult(False, "EXPIRED", cert)

            # 3. Basic constraints (must be end-entity)
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                if bc.ca:
                    return CertValidationResult(False, "UNEXPECTED_CA_CERT", cert)
            except x509.ExtensionNotFound:
                # End-entity certs should generally have this; warn but allow.
                pass

            # 4. Common Name match
            if expected_cn:
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                if cn != expected_cn:
                    return CertValidationResult(False, f"CN_MISMATCH(expected={expected_cn},got={cn})", cert)

            # 5. SAN verification (DNS/IP)
            if expected_dns or expected_ips:
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    dns_values = {d.value for d in san.get_values_for_type(x509.DNSName)}
                    ip_values = {str(i) for i in san.get_values_for_type(x509.IPAddress)}
                except x509.ExtensionNotFound:
                    return CertValidationResult(False, "MISSING_SAN", cert)

                if expected_dns:
                    missing_dns = set(expected_dns) - dns_values
                    if missing_dns:
                        return CertValidationResult(False, f"MISSING_DNS_SAN({','.join(missing_dns)})", cert)
                if expected_ips:
                    normalized_expected_ips = {str(ipaddress.ip_address(ip)) for ip in expected_ips}
                    missing_ips = normalized_expected_ips - ip_values
                    if missing_ips:
                        return CertValidationResult(False, f"MISSING_IP_SAN({','.join(missing_ips)})", cert)

            # 6. Key Usage sanity (optional)
            if require_key_usage:
                try:
                    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                    if not (ku.digital_signature and ku.key_encipherment):
                        return CertValidationResult(False, "KEY_USAGE_INSUFFICIENT", cert)
                except x509.ExtensionNotFound:
                    return CertValidationResult(False, "MISSING_KEY_USAGE", cert)

            return CertValidationResult(True, "VALID", cert)

        except Exception as e:
            return CertValidationResult(False, f"ERROR({e})", None)

    @staticmethod
    def get_certificate_fingerprint(cert: x509.Certificate) -> str:
        return cert.fingerprint(hashes.SHA256()).hex()

    @staticmethod
    def get_common_name(cert: x509.Certificate) -> str:
        return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

def load_private_key(key_path: str, password: Optional[bytes] = None):
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def load_certificate(cert_path: str) -> x509.Certificate:
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())