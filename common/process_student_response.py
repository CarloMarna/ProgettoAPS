import os
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.dh_utils import generate_dh_key_pair, derive_shared_key
from common.crypto_utils import sha256_digest, verify_signature

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def save_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def process_response(role):
    base_path = f"data/challenge_{role}_holder"
    response_path = os.path.join(base_path, "challenge_response.json")
    dh_response_path = os.path.join(base_path, "server_dh_response.json")
    nonce_log = f"data/{role}/used_nonces_{role}.txt"
    private_key_path = f"{role}/cert/{role}_private_key.pem"
    cert_path = f"{role}/cert/{role}_cert.pem"

    # === Step 1: Carica risposta dello studente ===
    message = load_json(response_path)
    response = message["response"]
    signature_student = bytes.fromhex(message["signature"])
    challenge = message["original_challenge"]
    signature_challenge = bytes.fromhex(message["original_signature"])
    nonce = response["nonce"]
    y_a = int(response["y_a"])

    # === Step 2: Verifica firma sulla challenge ===
    digest_challenge = sha256_digest(
        challenge["nonce"],
        challenge["issued_at"],
        challenge["expires_at"],
        challenge["aud"],
        challenge["sp"],
        challenge["ge"]
    )

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        pk_server = cert.public_key()

    print("Verifica challenge ricevuta")
    if not verify_signature(digest_challenge, signature_challenge, pk_server):
        print(" Firma NON valida.")
        exit(1)
    print(" Firma valida.")

    # === Step 3: Verifica nonce ===
    if response["nonce"] != challenge["nonce"]:
        print(" Nonce mismatch.")
        exit(1)

    used_nonces = set()
    if os.path.exists(nonce_log):
        with open(nonce_log, "r") as f:
            used_nonces = set(line.strip() for line in f)
    if nonce in used_nonces:
        print(" Nonce già usato.")
        exit(1)
    with open(nonce_log, "a") as f:
        f.write(nonce + "\n")

    print(" Challenge attualmente valida.")

    # === Step 4: Verifica firma dello studente ===
    digest_student = sha256_digest(
        response["nonce"],
        response["issued_at"],
        response["expires_at"],
        response["aud"],
        response["y_a"]
    )

    with open("holder/cert/holder_cert.pem", "rb") as f:
        holder_cert = x509.load_pem_x509_certificate(f.read())
        pk_holder = holder_cert.public_key()

    if not verify_signature(digest_student, signature_student, pk_holder):
        print(" Firma dello studente NON valida.")
        exit(1)
    print(" Firma studente verificata.")

    # === Step 5: Verifica validità temporale ===
    now = datetime.now(timezone.utc)
    if not (datetime.fromisoformat( response["issued_at"]) <= now <= datetime.fromisoformat(response["expires_at"])):
        print(" Finestra scaduto o non ancora valido.")
        exit(1)
    print(" Finestra temporale valida.")

    # === Step 6: Genera chiave DH (x_B, y_B) ===
    p = int(challenge["sp"], 16)
    g = int(challenge["ge"])
    x_b, y_b = generate_dh_key_pair(p=p, g=g)

    with open(f"data/{role}/{role}_dh_private.txt", "w") as f:
        f.write(str(x_b))

    # === Step 7: Firma messaggio con y_B ===
    issued_at = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    aud = challenge["aud"]

    digest_response = sha256_digest(nonce, issued_at, expires_at, aud, str(y_b))

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        digest_response,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA256())
    )

    response_obj = {
        "server_response": {
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "aud": aud,
            "y_b": str(y_b)
        },
        "signature": signature.hex()
    }

    save_json(response_obj, dh_response_path)

    print("\nMessaggio DH firmato e salvato:")
    print(f"  Nonce:      {nonce}")
    print(f"  Issued_at:  {issued_at}")
    print(f"  Expires_at: {expires_at}")
    print(f"  Audience:   {aud}")
    print(f"  y_B:        {str(y_b)[:40]}...")
    print(f"  Firma:      {response_obj['signature'][:40]}...")
    print(f"Salvato in {dh_response_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["issuer", "verifier"], help="Ruolo che elabora la risposta")
    args = parser.parse_args()

    process_response(args.role)
