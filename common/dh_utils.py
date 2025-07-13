import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Parametri comuni di Diffie-Hellman (un numero primo sicuro e un generatore)
# Questi vengono scelti in modo fisso nel nostro esempio semplificato
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16
)
DEFAULT_G = 2


def generate_dh_key_pair(p=DEFAULT_P, g=DEFAULT_G):
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


def derive_shared_key(their_y: int, my_x: int, p=DEFAULT_P) -> bytes:
    """Deriva la chiave simmetrica condivisa: K = y^x mod p"""
    shared_secret = pow(their_y, my_x, p)  # valore numerico segreto
    shared_bytes = str(shared_secret).encode()  # converti in bytes

    # Applica SHA-256 sul numero condiviso
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_bytes)
    final_key = digest.finalize()

    # Codifica per renderla compatibile con Fernet
    return base64.urlsafe_b64encode(final_key)
