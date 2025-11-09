import os
import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, IPAddress, SubjectAlternativeName
from datetime import datetime, timedelta, timezone
import ipaddress

DEFAULT_CERT_DIR: str = ".container_volumes/certs"
DEFAULT_COUNTRY: str = "US"
DEFAULT_STATE: str = "State"
DEFAULT_CITY: str = "City"
DEFAULT_ORG: str = "OrgName"
DEFAULT_CA_CN: str = "InternalCA"
DEFAULT_BAO_CN: str = "openbao"
DEFAULT_APP_CN: str = "app"
DEFAULT_BAO_SANS: list[str] = [
    "DNS:openbao",
    "DNS:localhost",
    "DNS:host.docker.internal",
    "IP:127.0.0.1",
]
DEFAULT_APP_SANS: list[str] = [
    "DNS:app",
    "DNS:localhost",
    "DNS:host.docker.internal",
    "IP:127.0.0.1",
]


def parse_args() -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Generate CA, OpenBao, and App certificates."
    )

    parser.add_argument("-d", "--dir", default=DEFAULT_CERT_DIR, help="Output cert dir")
    parser.add_argument("-c", "--country", default=DEFAULT_COUNTRY)
    parser.add_argument("-s", "--state", default=DEFAULT_STATE)
    parser.add_argument("-l", "--city", default=DEFAULT_CITY)
    parser.add_argument("-o", "--org", default=DEFAULT_ORG)
    parser.add_argument("--ca-cn", default=DEFAULT_CA_CN)
    parser.add_argument("--bao-cn", default=DEFAULT_BAO_CN)
    parser.add_argument("--app-cn", default=DEFAULT_APP_CN)
    parser.add_argument("--bao-sans", default=",".join(DEFAULT_BAO_SANS))
    parser.add_argument("--app-sans", default=",".join(DEFAULT_APP_SANS))

    return parser.parse_args()


def parse_sans(sans_str: str) -> list:
    """
    Parse Subject Alternative Names (SANs) from a comma-separated string.

    Args:
        sans_str (str): Comma-separated SANs, e.g. "DNS:example.com, IP:192.168.1.1"

    Returns:
        list: List of SAN objects (DNSName or IPAddress).
    """

    sans: list = []

    for entry in sans_str.split(","):
        entry = entry.strip()

        if entry.startswith("DNS:"):
            sans.append(DNSName(entry[4:]))
        elif entry.startswith("IP:"):
            sans.append(IPAddress(ipaddress.ip_address(entry[3:])))

    return sans


def write_pem(filename: str, data: bytes, is_key: bool = False):
    """
    Write PEM data to a file.

    Args:
        filename (str): The file path to write the PEM data.
        data (bytes): The PEM data to write.
        is_key (bool): If True, the file is treated as a private key.
    """

    with open(filename, "wb") as f:
        f.write(data)


def build_subject(country: str, state: str, city: str, org: str, cn: str) -> x509.Name:
    """
    Build a X.500 distinguished name (DN) for a certificate subject.

    Args:
        country (str): Country name (2-letter code).
        state (str): State or province name.
        city (str): Locality or city name.
        org (str): Organization name.
        cn (str): Common name (CN) for the certificate.

    Returns:
        x509.Name: A X.500 distinguished name object.
    """

    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def main():
    """
    Main function to generate CA, OpenBao, and App certificates.
    """

    args: argparse.Namespace = parse_args()

    cert_dir: str = os.path.abspath(args.dir)
    ca_dir: str = os.path.join(cert_dir, "ca")
    bao_dir: str = os.path.join(cert_dir, "bao")
    app_dir: str = os.path.join(cert_dir, "app")

    os.makedirs(ca_dir, exist_ok=True)
    os.makedirs(bao_dir, exist_ok=True)
    os.makedirs(app_dir, exist_ok=True)

    # Generate CA key and cert
    ca_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )
    ca_subject: x509.Name = build_subject(
        args.country, args.state, args.city, args.org, args.ca_cn
    )
    ca_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    write_pem(
        os.path.join(ca_dir, "ca.key"),
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        is_key=True,
    )
    write_pem(
        os.path.join(ca_dir, "ca.crt"), ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    # Generate OpenBao key and cert
    bao_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bao_subject: x509.Name = build_subject(
        args.country, args.state, args.city, args.org, args.bao_cn
    )
    bao_sans: list[x509.Name] = parse_sans(args.bao_sans)
    (
        x509.CertificateSigningRequestBuilder()
        .subject_name(bao_subject)
        .add_extension(SubjectAlternativeName(bao_sans), critical=False)
        .sign(bao_key, hashes.SHA256())
    )
    bao_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(bao_subject)
        .issuer_name(ca_cert.subject)
        .public_key(bao_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(SubjectAlternativeName(bao_sans), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    write_pem(
        os.path.join(bao_dir, "bao.key"),
        bao_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        is_key=True,
    )
    write_pem(
        os.path.join(bao_dir, "bao.crt"),
        bao_cert.public_bytes(serialization.Encoding.PEM),
    )

    # Generate App key and cert
    app_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    app_subject: x509.Name = build_subject(
        args.country, args.state, args.city, args.org, args.app_cn
    )
    app_sans: list[x509.Name] = parse_sans(args.app_sans)
    (
        x509.CertificateSigningRequestBuilder()
        .subject_name(app_subject)
        .add_extension(SubjectAlternativeName(app_sans), critical=False)
        .sign(app_key, hashes.SHA256())
    )
    app_cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(app_subject)
        .issuer_name(ca_cert.subject)
        .public_key(app_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(SubjectAlternativeName(app_sans), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    write_pem(
        os.path.join(app_dir, "app.key"),
        app_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        is_key=True,
    )
    write_pem(
        os.path.join(app_dir, "app.crt"),
        app_cert.public_bytes(serialization.Encoding.PEM),
    )

    print(f"Certificate generation complete! Certificates are in: {cert_dir}")


if __name__ == "__main__":
    main()
