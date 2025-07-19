import os
import base64

from cryptography.hazmat.primitives import hashes
# Gruppo DH per l'issuer 
ISSUER_P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
ISSUER_G = 2

# Gruppo DH per il verifier
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

BENCHMARK_DH = True  
import time

def benchmark(func):
    def wrapper(*args, **kwargs):
        if BENCHMARK_DH:
            start = time.time()
            result = func(*args, **kwargs)
            elapsed = (time.time() - start) * 1000
            print(f"[BENCH] {func.__name__} eseguita in {elapsed:.2f} ms")
            return result
        else:
            return func(*args, **kwargs)
    return wrapper

@benchmark
def generate_dh_key_pair(p, g):
    """Genera una coppia (x, y) per Diffie-Hellman: x privato, y=g^x mod p"""
    x = int.from_bytes(os.urandom(32), byteorder="big") 
    y = pow(g, x, p) 
    return x, y
    
@benchmark
def derive_shared_key(their_y: int, my_x: int, p) -> bytes:
    """Deriva la chiave simmetrica condivisa: K = y^x mod p"""
    if not (1 < their_y < p - 1):
        raise ValueError("Valore y non valido.")

    shared_secret = pow(their_y, my_x, p)  
    shared_bytes = str(shared_secret).encode() 

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_bytes)
    final_key = digest.finalize()

    return base64.urlsafe_b64encode(final_key)
