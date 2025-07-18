import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography import x509

def sha256_digest(*args: str) -> bytes:
    """Calcola SHA-256 su una concatenazione di stringhe"""
    h = hashlib.sha256()
    for value in args:
        h.update(value.encode("utf-8"))
    return h.digest()

def verify_signature(digest: bytes, signature: bytes, public_key) -> bool:
    """Verifica firma su un digest già calcolato (Prehashed)"""
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False

def verify_signature_VC(vc: dict) -> bool:
    """Verifica la firma hash-then-sign dell’università"""
    signed_data = vc["signature"]["signedData"]
    signature = bytes.fromhex(vc["signature"]["signatureValue"])

    with open("issuer/cert/issuer_cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        pk_issuer = cert.public_key()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(signed_data.encode())
    final_digest = digest.finalize()

    try:
        pk_issuer.verify(
            signature,
            final_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False