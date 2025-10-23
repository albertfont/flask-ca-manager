import os
from datetime import datetime, timedelta
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def _write_pem(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def create_ca(certs_root: str, name: str, tld: str, years_valid: int = 10) -> Tuple[str, str]:
    """Create a CA key+cert under certs_root/ca/<tld>/
    Returns (cert_path, key_path)."""
    ca_dir = os.path.join(certs_root, 'ca', tld)
    os.makedirs(ca_dir, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{tld} Local CA"),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365 * years_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     key_encipherment=False, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, encipher_only=False,
                                     decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    ).sign(private_key=key, algorithm=hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),  # for home use; consider passphrase in prod
    )

    cert_path = os.path.join(ca_dir, f"{tld}-ca.crt")
    key_path = os.path.join(ca_dir, f"{tld}-ca.key")
    _write_pem(cert_path, cert_pem)
    _write_pem(key_path, key_pem)

    return cert_path, key_path


def issue_cert(certs_root: str, ca_cert_path: str, ca_key_path: str, tld: str,
               common_name: str, san_dns: List[str], days_valid: int = 825,
               serial_int: int | None = None) -> Tuple[str, str, datetime]:
    """Issue a leaf cert signed by the CA. Returns (cert_path, key_path, expires_at)."""
    # Load CA
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, 'rb') as f:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        ca_key = load_pem_private_key(f.read(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{tld}.local"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    expires = now + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_int if serial_int else x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, crl_sign=False,
                                     key_cert_sign=False, content_commitment=False, data_encipherment=True,
                                     key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                       critical=False)
    )

    # Subject Alternative Names
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    cert_dir = os.path.join(certs_root, 'issued', tld, common_name)
    os.makedirs(cert_dir, exist_ok=True)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    cert_path = os.path.join(cert_dir, f"{common_name}.crt")
    key_path = os.path.join(cert_dir, f"{common_name}.key")

    _write_pem(cert_path, cert_pem)
    _write_pem(key_path, key_pem)

    # Also write a bundle (fullchain)
    bundle_path = os.path.join(cert_dir, f"{common_name}-bundle.pem")
    with open(bundle_path, 'wb') as f:
        f.write(cert_pem)
        with open(ca_cert_path, 'rb') as caf:
            f.write(caf.read())

    return cert_path, key_path, expires