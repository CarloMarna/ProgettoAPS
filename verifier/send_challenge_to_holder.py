import os
import json
from datetime import datetime, timedelta, timezone

timestamp = datetime.now(timezone.utc).isoformat()
expiration = (datetime.now(timezone.utc) + timedelta(minutes=3)).isoformat()
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from common.dh_utils import generate_dh_key_pair, sign_dh_public_key, DEFAULT_P, DEFAULT_G

if __name__ == "__main__":
    # === Step 1: Parametri challenge ===
    nonce = os.urandom(16).hex()
    timestamp = datetime.now(timezone.utc).isoformat()
    expiration = (datetime.now(timezone.utc) + timedelta(minutes=3)).isoformat()
    aud = "CN=Mario Rossi, SerialNumber=123456"
    sp = hex(DEFAULT_P)
    gen = str(DEFAULT_G)

    # === Step 2: Chiave Diffie-Hellman del verificatore ===
    x_V, y_V = generate_dh_key_pair()
    with open("verifier_dh_private.txt", "w") as f:
        f.write(str(x_V))

    # === Step 3: Firma H(y_V) con sk_verifier ===
    with open("verifier/verifier_private_key.pem", "rb") as f:
        sk_verifier = serialization.load_pem_private_key(f.read(), password=None)

    sig_verifier = sign_dh_public_key(y_V, sk_verifier).hex()

    # === Step 4: Costruzione della challenge ===
    clear_challenge = {
        "challenge": {
            "challenge": "presenta esami X",
            "nonce": nonce,
            "timestamp": timestamp,
            "aud": aud,
            "sp": sp,
            "gen": gen,
            "y_V": str(y_V)
        },
        "signature_issuer": sig_verifier
    }

    '''# === Step 5: Carica la chiave pubblica dello studente (pk_holder) ===
    with open("holder/holder_cert.pem", "rb") as f:
        holder_cert = x509.load_pem_x509_certificate(f.read())
        pk_holder = holder_cert.public_key()

    # === Step 6: Cifra la challenge con pk_holder (RSA + OAEP) ===
    plaintext = json.dumps(clear_challenge, separators=(",", ":")).encode()

    encrypted = pk_holder.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # === Step 7: Salva output ===
    with open("data/challenge_verifier.enc", "wb") as f:
        f.write(encrypted)'''
    
    with open("data/challenge_verifier.enc", "w") as f:
        json.dump(clear_challenge, f, indent=2)

    print("✅ Challenge cifrata (RSA+OAEP) salvata in 'data/challenge_verifier.enc'")
    print("🔐 x_V salvata in 'verifier_dh_private.txt'")
