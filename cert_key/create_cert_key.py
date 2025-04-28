from cryptography import x509
from cryptography.x509.oid import NameOID
#from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
import datetime
from os.path import dirname, realpath, join

# Generate Ed25519 private key
#key = ed25519.Ed25519PrivateKey.generate()
# Generate EC (P-256 / ES256) private key
key = ec.generate_private_key(ec.SECP256R1())

# Build subject and issuer (self-signed)
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fondazione Bruno Kessler"),
    x509.NameAttribute(NameOID.COMMON_NAME, "mydomain.com"),
])

# Create the self-signed certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.UTC))
    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    #.sign(private_key=key, algorithm=None)  # algorithm=None for Ed25519
    .sign(key, hashes.SHA256())
)

# Store locally
dir = dirname(realpath(__file__))

# Save certificate and key in PEM format
with open(join(dir,"certificate.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open(join(dir,"private_key.pem"), "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
