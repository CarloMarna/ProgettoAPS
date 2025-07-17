import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.dh_utils import derive_shared_key
from common.crypto_utils import sha256_digest, verify_signature

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def load_private_dh_key(path):
    with open(path, "r") as f:
        return int(f.read())

if __name__ == "__main__":
    print("Verifica challenge ricevuta.")

    # === Step 1: Carica la risposta del verificatore ===
    dh_response = load_json("data/challenge_verifier_holder/server_dh_response.json")
    response = dh_response["server_response"]
    signature = bytes.fromhex(dh_response["signature"])

    # === Step 2: Calcola il digest da verificare ===
    digest = sha256_digest(
        response["nonce"],
        response["issued_at"],
        response["expires_at"],
        response["aud"],
        response["y_b"]
    )

    # === Step 3: Carica il certificato pubblico del verificatore ===
    with open("verifier/cert/verifier_cert.pem", "rb") as f:
        verifier_cert = x509.load_pem_x509_certificate(f.read())
        pk_verifier = verifier_cert.public_key()

    # === Step 4: Verifica firma del verificatore ===
    if verify_signature(digest, signature, pk_verifier):
        print(" Firma valida.")
    else:
        print(" Firma NON valida.")
        exit(1)

    # === Step 5: Verifica validità temporale ===
    now = datetime.now(timezone.utc)
    issued_at = datetime.fromisoformat(response["issued_at"])
    expires_at = datetime.fromisoformat(response["expires_at"])

    if not (issued_at <= now <= expires_at):
        print(" Finestra temporale fuori intervallo temporale valido.")
        exit(1)
    else:
        print(" Finestra temporale valida.")

    # === Step 6: Deriva chiave di sessione DH ===
    p_hex = load_json("data/challenge_verifier_holder/challenge_response.json")["original_challenge"]["sp"]
    p = int(p_hex, 16)
    y_b = int(response["y_b"]) 
    
    # Carica chiave privata DH dello studente (x_A) da file
    x_a = load_private_dh_key("data/holder/holder_dh_private.txt")

    # Deriva chiave simmetrica condivisa
    session_key = derive_shared_key(y_b, x_a, p)

    # Salva la chiave di sessione per uso successivo (es. Fernet)
    with open("data/challenge_verifier_holder/key/session_key_holder.shared", "wb") as f:
        f.write(session_key)

    print("Chiave di sessione DH derivata e salvata in 'data/session_key_holder.shared'")
