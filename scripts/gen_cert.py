#!/usr/bin/env python3
"""
Generate and sign certificates for server/client
Issues X.509 certificates signed by Root CA
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import argparse
import ipaddress
import os
import sys

def load_ca():
    """Load CA certificate and private key (supports passphrase via CA_KEY_PASSPHRASE)"""
    try:
        with open("certs/ca_private_key.pem", "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=(os.environ.get("CA_KEY_PASSPHRASE") or None),
            )
    except FileNotFoundError:
        print("[-] Missing certs/ca_private_key.pem. Generate the CA first.")
        sys.exit(1)

    try:
        with open("certs/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print("[-] Missing certs/ca_cert.pem. Generate the CA first.")
        sys.exit(1)

    return ca_key, ca_cert

def generate_entity_cert(entity_name, common_name, dns_names, ip_addrs):
    """Generate certificate for server or client"""
    print(f"[*] Generating certificate for: {entity_name}")

    ca_key, ca_cert = load_ca()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Build SANs: use provided DNS/IP, otherwise fall back to CN
    san_entries = []
    for d in dns_names:
        san_entries.append(x509.DNSName(d))
    for ip in ip_addrs:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if not san_entries:
        # Infer from CN
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(common_name)))
        except ValueError:
            san_entries.append(x509.DNSName(common_name))

    now = datetime.now(timezone.utc)

    eku_oids = (
        [ExtendedKeyUsageOID.SERVER_AUTH] if entity_name == "server"
        else [ExtendedKeyUsageOID.CLIENT_AUTH]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        # Allow small clock skew
        .not_valid_before(now - timedelta(minutes=5))
        # 397 days (within common ecosystem limits)
        .not_valid_after(now + timedelta(days=397))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(eku_oids),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    os.makedirs("certs", mode=0o700, exist_ok=True)

    key_filename = f"certs/{entity_name}_private_key.pem"
    entity_pass = os.environ.get("CERT_KEY_PASSPHRASE")
    key_encryption = (
        serialization.BestAvailableEncryption(entity_pass.encode())
        if entity_pass else serialization.NoEncryption()
    )
    with open(key_filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=key_encryption,
            )
        )
    try:
        os.chmod(key_filename, 0o600)
    except Exception:
        pass
    print(f"[+] Private key saved: {key_filename}")

    cert_filename = f"certs/{entity_name}_cert.pem"
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved: {cert_filename}")

    print(f"[✓] Certificate for {entity_name} generated successfully!")

    # Display certificate info
    print("\n[*] Certificate Details:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Issuer: {cert.issuer.rfc4514_string()}")
    print(f"    SANs: {[str(g.value) for g in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid From: {cert.not_valid_before.isoformat()}")
    print(f"    Valid Until: {cert.not_valid_after.isoformat()}")

def main():
    parser = argparse.ArgumentParser(description="Generate entity certificates")
    parser.add_argument("--entity", required=True, choices=["server", "client"],
                        help="Entity type (server or client)")
    parser.add_argument("--cn", required=True, help="Common Name for certificate")
    parser.add_argument("--dns", action="append", default=[],
                        help="DNS SAN entry (repeatable)")
    parser.add_argument("--ip", action="append", default=[],
                        help="IP SAN entry (repeatable)")
    args = parser.parse_args()

    generate_entity_cert(args.entity, args.cn, args.dns, args.ip)

if __name__ == "__main__":
    main()