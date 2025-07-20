import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography import x509
import json

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
    try:
        signature_block = vc["signature"]
        signature = bytes.fromhex(signature_block["signatureValue"])
        cert_path = signature_block["verificationMethod"]

        # Rimuove la firma prima di serializzare
        vc_to_verify = vc.copy()
        vc_to_verify["signature"] = vc_to_verify["signature"].copy()
        del vc_to_verify["signature"]["signatureValue"]

        # Serializza la VC nello stesso modo usato in firma
        vc_serialized = json.dumps(vc_to_verify, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Calcola digest
        digest = hashes.Hash(hashes.SHA256())
        digest.update(vc_serialized)
        final_digest = digest.finalize()

        # Carica il certificato e verifica
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            pk_issuer = cert.public_key()

        pk_issuer.verify(
            signature,
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True

    except Exception as e:
        return False

