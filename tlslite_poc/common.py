"""Shared constants, test PKI, and helpers for the tlslite-ng wire PoC.

Experimental code points (private-use / experimental range, following the
0xFE** convention ECH used as draft-ietf-tls-esni; final values are TBD via
IANA):

    migration_support   extension      0xFE4D
    migration_allowed    extension      0xFE4E   (carried in NewSessionTicket)
    migrate_request      handshake msg  0xFD     (post-handshake)
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Experimental code points.
EXT_MIGRATION_SUPPORT = 0xFE4D
EXT_MIGRATION_ALLOWED = 0xFE4E
HS_MIGRATE_REQUEST = 0xFD  # post-handshake HandshakeType (experimental/TBD)

SERVICE_NAME = "svc.example"

# A fixed 32-byte session-ticket key shared by all in-domain instances. This is
# what lets instance B decrypt and resume a ticket that instance A issued.
SHARED_TICKET_KEY = bytearray(b"poc-shared-ticket-key-0123456789")  # 32 bytes
# A different key for the "foreign" instance: it cannot resume in-domain
# sessions, which demonstrates the anti-redirection / fail-closed property.
FOREIGN_TICKET_KEY = bytearray(b"poc-foreign-ticket-key-ABCDEFGHI")  # 32 bytes

assert len(SHARED_TICKET_KEY) == 32 and len(FOREIGN_TICKET_KEY) == 32

CERT_PEM = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_PEM = os.path.join(os.path.dirname(__file__), "key.pem")


def ensure_cert():
    """Generate a deterministic-enough self-signed cert+key for SERVICE_NAME."""
    if os.path.exists(CERT_PEM) and os.path.exists(KEY_PEM):
        return
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVICE_NAME)])
    now = datetime.datetime(2024, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(20260101)
        .not_valid_before(now)
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVICE_NAME)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(CERT_PEM, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_PEM, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def load_cert_key():
    """Load the PEM cert+key into tlslite objects."""
    from tlslite import X509, X509CertChain
    from tlslite.utils.keyfactory import parsePEMKey

    ensure_cert()
    with open(CERT_PEM) as f:
        cert_pem = f.read()
    with open(KEY_PEM) as f:
        key_pem = f.read()
    x = X509()
    x.parse(cert_pem)
    chain = X509CertChain([x])
    private_key = parsePEMKey(key_pem, private=True)
    return chain, private_key


if __name__ == "__main__":
    ensure_cert()
    print("wrote", CERT_PEM, "and", KEY_PEM)
