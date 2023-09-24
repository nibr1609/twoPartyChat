from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import datetime

# Self sign a MSG
def self_sign(private_key: Ed25519PrivateKey):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"XYZ"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"XYZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"XYZ"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"XYZ"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, None)
    return cert