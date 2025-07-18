import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography import x509

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

    try:
        with open("issuer/cert/issuer_cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            pk_issuer = cert.public_key()

        # Calcola il digest
        digest = hashes.Hash(hashes.SHA256())
        digest.update(signed_data.encode("utf-8"))
        final_digest = digest.finalize()

        # Verifica la firma (digest pre-calcolato)
        pk_issuer.verify(
            signature,
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())  # ← IMPORTANTE
        )
        return True
    except Exception as e:
        print(f"Errore nella verifica della firma VC: {e}")
        return False
