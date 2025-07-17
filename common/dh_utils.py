import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Gruppo DH per l'issuer (es: RFC 3526 group 14 - 2048-bit MODP)
ISSUER_P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
ISSUER_G = 2

# Gruppo DH per il verifier (es: RFC 3526 group 15 - 3072-bit MODP)
VERIFIER_P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
VERIFIER_G = 5

DH_PARAMS = {
    "issuer": {"p": ISSUER_P, "g": ISSUER_G},
    "verifier": {"p": VERIFIER_P, "g": VERIFIER_G}
}


def generate_dh_key_pair(p, g):
    """Genera una coppia (x, y) per Diffie-Hellman: x privato, y=g^x mod p"""
    x = int.from_bytes(os.urandom(32), byteorder="big")  # Esponente privato casuale
    y = pow(g, x, p)  # Chiave pubblica DH
    return x, y


def sign_dh_public_key(y: int, private_key) -> bytes:
    """Firma il valore y usando la chiave privata (hash-then-sign)"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(y).encode())
    hash_value = digest.finalize()

    signature = private_key.sign(
        hash_value,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature


def verify_dh_signature(y: int, signature: bytes, public_key) -> bool:
    """Verifica la firma di y usando la chiave pubblica"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(y).encode())
    hash_value = digest.finalize()

    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def derive_shared_key(their_y: int, my_x: int, p) -> bytes:
    """Deriva la chiave simmetrica condivisa: K = y^x mod p"""
    shared_secret = pow(their_y, my_x, p)  # valore numerico segreto
    shared_bytes = str(shared_secret).encode()  # converti in bytes

    # Applica SHA-256 sul numero condiviso
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_bytes)
    final_key = digest.finalize()

    # Codifica per renderla compatibile con Fernet
    return base64.urlsafe_b64encode(final_key)
