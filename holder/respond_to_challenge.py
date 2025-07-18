import json
import os
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.dh_utils import generate_dh_key_pair
from common.crypto_utils import  verify_signature
import hashlib

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def save_json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def respond_to_challenge(role):
    # === Percorsi dinamici ===
    challenge_path = f"data/challenge_{role}_holder/challengeHolder.json"
    cert_path = f"{role}/cert/{role}_cert.pem"
    response_path = f"data/challenge_{role}_holder/challenge_response.json"

    # === Step 1: Carica challenge ===
    challenge = load_json(challenge_path)
    signature_server = bytes.fromhex(challenge["signature"])
    # Rimuovi temporaneamente la firma per calcolare il digest corretto
    challenge_data = {k: v for k, v in challenge.items() if k != "signature"}

    nonce = challenge["nonce"]
    issued_at = challenge["issued_at"]
    expires_at = challenge["expires_at"]
    aud = challenge["aud"]
    sp = challenge["sp"]
    ge = challenge["ge"]

    print(f"Verifica challenge ricevuta")
    digest = hashlib.sha256(
        json.dumps(challenge_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        pk_server = cert.public_key()
        server_subject = cert.subject.rfc4514_string()
    
    if not verify_signature(digest, signature_server, pk_server):
        print(" Firma NON valida.")
        sys.exit(1)
    print(" Firma valida.")

    # === Step 2: Verifica tempi ===
    now = datetime.now(timezone.utc)
    if not (datetime.fromisoformat(issued_at) <= now <= datetime.fromisoformat(expires_at)):
        print(" Finestra temporale scaduta o non ancora valida.")
        sys.exit(1)
    print(" Finestra temporale valida.")

    # === Step 3: Verifica audience ===
    my_identity = "CN=Mario Rossi, SerialNumber=123456"
    if aud != my_identity:
        print(" Audience non corrisponde.")
        sys.exit(1)
    print(" Audience corretta.")

    # === Step 4: Verifica nonce ===
    nonce_file = "data/holder/used_nonces.txt"
    used_nonces = set()
    if os.path.exists(nonce_file):
        with open(nonce_file, "r") as f:
            used_nonces = set(line.strip() for line in f)
    if nonce in used_nonces:
        print(" Nonce già usato.")
        sys.exit(1)
    with open(nonce_file, "a") as f:
        f.write(nonce + "\n")

    # === Step 5: Genera chiave DH ===
    p = int(sp, 16)
    g = int(ge)
    x_A, y_A = generate_dh_key_pair(p, g)
    with open("data/holder/holder_dh_private.txt", "w") as f:
        f.write(str(x_A))

    # === Step 6: Timestamp per la risposta ===
    issued_at_p = datetime.now(timezone.utc).isoformat()
    expires_at_p = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()

    # === Step 7: Firma dello studente ===
    response_data = {
        "nonce": nonce,
        "issued_at": issued_at_p,
        "expires_at": expires_at_p,
        "aud": server_subject,
        "y_a": str(y_A),
    }

    digest_student = hashlib.sha256(
        json.dumps(response_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()

    with open("holder/cert/holder_private_key.pem", "rb") as f:
        sk_holder = serialization.load_pem_private_key(f.read(), password=None)

    signature_student = sk_holder.sign(
        digest_student,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA256())
    )

    # === Step 8: Costruzione risposta ===
    response = {
        "response": response_data,
        "signature": signature_student.hex(),
        "original_challenge": challenge_data,
        "original_signature": challenge["signature"]
    }


    save_json(response, response_path)
    print(f"\nChallenge inviata:")
    print(f"  Nonce:        {nonce}")
    print(f"  Issued_at:    {issued_at_p}")
    print(f"  Expires_at:   {expires_at_p}")
    print(f"  Audience:     {server_subject}")
    print(f"  y_A : {str(y_A)[:40]}...")
    print(f"  Signature:    {signature_student.hex()[:40]}...")
    print(f"  Original Challenge...")
    print(f"  Original Signature...")

  
    print(f"Risposta salvata in {response_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["issuer", "verifier"], help="Chi ha mandato la challenge")
    args = parser.parse_args()
    respond_to_challenge(args.role)
