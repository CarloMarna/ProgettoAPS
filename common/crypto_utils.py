import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

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
