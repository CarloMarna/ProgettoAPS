from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os

def generate_cert_and_key(subject_dn: dict, cert_path: str, key_path: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_dn.get("C")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_dn.get("O")),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_dn.get("CN")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=5 * 365))
        .sign(private_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )

    print(f" Certificato generato per: {subject_dn['CN']}")
    print(f"    Chiave privata: {key_path}")
    print(f"    Certificato:    {cert_path}")

if __name__ == "__main__":
    import time

    # 🔁 Imposta a True per attivare la raccolta delle prestazioni
    ANALISI_PRESTAZIONI = True

    os.makedirs("issuer/cert", exist_ok=True)
    os.makedirs("holder/cert", exist_ok=True)
    os.makedirs("verifier/cert", exist_ok=True)
    os.makedirs("ocsp/cert", exist_ok=True)

    entities = [
        {
            "name": "Issuer",
            "subject_dn": {"CN": "University of Rennes", "O": "RENES", "C": "FR"},
            "cert_path": "issuer/cert/issuer_cert.pem",
            "key_path": "issuer/cert/issuer_private_key.pem"
        },
        {
            "name": "Holder",
            "subject_dn": {"CN": "Mario Rossi", "O": "University of Salerno", "C": "IT"},
            "cert_path": "holder/cert/holder_cert.pem",
            "key_path": "holder/cert/holder_private_key.pem"
        },
        {
            "name": "Verifier",
            "subject_dn": {"CN": "Verifier Inc", "O": "VerifierOrg", "C": "EU"},
            "cert_path": "verifier/cert/verifier_cert.pem",
            "key_path": "verifier/cert/verifier_private_key.pem"
        },
        {
            "name": "OCSP",
            "subject_dn": {"CN": "OCSP Authority", "O": "OCSPRegistry", "C": "EU"},
            "cert_path": "ocsp/cert/ocsp_cert.pem",
            "key_path": "ocsp/cert/ocsp_private_key.pem"
        }
    ]

    table = []

    for entity in entities:
        if ANALISI_PRESTAZIONI:
            start = time.time()

        generate_cert_and_key(entity["subject_dn"], entity["cert_path"], entity["key_path"])

        if ANALISI_PRESTAZIONI:
            elapsed_ms = (time.time() - start) * 1000
            cert_size_kb = os.path.getsize(entity["cert_path"]) / 1024
            key_size_kb = os.path.getsize(entity["key_path"]) / 1024

            table.append([
                entity["name"],
                f"{cert_size_kb:.2f} KB",
                f"{key_size_kb:.2f} KB",
                f"{elapsed_ms:.1f} ms"
            ])

    if ANALISI_PRESTAZIONI:
        print("\n=== Tabella Prestazioni Certificati ===")
        print(f"{'Entità':<10} {'Certificato':>15} {'Chiave':>12} {'Tempo':>10}")
        print("-" * 50)
        for row in table:
            print(f"{row[0]:<10} {row[1]:>15} {row[2]:>12} {row[3]:>10}")
