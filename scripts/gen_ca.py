"""
Generate Root Certificate Authority (CA)
Creates a self-signed CA certificate and private key
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import os

def generate_ca():
    """Generate root CA certificate and private key"""
    
    print("[*] Generating Root CA...")
    
    # Generate RSA private key (4096-bit for CA)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    now = datetime.now(timezone.utc)
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)  # timezone-aware UTC
        .not_valid_after(now + timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Create certs directory with restrictive perms
    os.makedirs("certs", mode=0o700, exist_ok=True)
    
    # Save private key (optionally encrypted if CA_KEY_PASSPHRASE is set)
    key_path = "certs/ca_private_key.pem"
    passphrase = os.environ.get("CA_KEY_PASSPHRASE")
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase else serialization.NoEncryption()
    )
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        )
    os.chmod(key_path, 0o600)
    print(f"[+] CA private key saved: {key_path}")
    
    # Save certificate
    cert_path = "certs/ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved: {cert_path}")
    
    print("[✓] Root CA generated successfully!")
    
    # Display certificate info
    print("\n[*] Certificate Details:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Issuer: {cert.issuer.rfc4514_string()}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid From: {cert.not_valid_before.isoformat()}")
    print(f"    Valid Until: {cert.not_valid_after.isoformat()}")

if __name__ == "__main__":
    generate_ca()