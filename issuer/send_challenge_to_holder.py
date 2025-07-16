import os
import json
from datetime import timedelta, datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from common.dh_utils import generate_dh_key_pair, DEFAULT_P, DEFAULT_G

from cryptography.hazmat.primitives.asymmetric import utils
import hashlib

def sign_challenge_dict(challenge_dict, private_key):
    """Firma il digest SHA-256 della concatenazione dei campi della challenge."""
    
    # Estrai i campi nell'ordine specificato
    fields = [
        challenge_dict["nonce"],
        challenge_dict["issued_at"],
        challenge_dict["expires_at"],
        challenge_dict["aud"],
        challenge_dict["sp"],
        challenge_dict["ge"]
    ]
    
    # Concatenazione dei valori come stringa
    concatenated = "".join(fields).encode("utf-8")

    # Calcolo SHA-256 del messaggio
    digest = hashlib.sha256(concatenated).digest()

    # Firma del digest pre-hashato (Prehashed)
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256())
    )
    
    return signature

if __name__ == "__main__":
    # === Step 1: Parametri challenge ===
    nonce = os.urandom(32).hex()
    issued_at = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    aud = "CN=Mario Rossi, SerialNumber=123456"
    sp = hex(DEFAULT_P)
    ge = str(DEFAULT_G)


    # === Step 3: Carica chiave privata issuer ===
    with open("issuer/issuer_private_key.pem", "rb") as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # === Step 4: Crea oggetto challenge da firmare ===
    challenge_dict = {
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "aud": aud,
        "sp": sp,
        "ge": ge,
    }

    # === Step 5: Firma della challenge ===
    signature = sign_challenge_dict(challenge_dict, issuer_private_key)
    signature_hex = signature.hex()

    # === Step 6: Costruzione finale e salvataggio ===
    full_challenge = {
        "challenge": challenge_dict,
        "signature": signature_hex
    }

    with open("data/challengeHolder.json", "w") as f:
        json.dump(full_challenge, f, indent=2)
    
    print("Challenge creata:")
    print(f" Nonce:        {nonce}")
    print(f" Issued at:    {issued_at}")
    print(f" Expires at:   {expires_at}")
    print(f" Audience:     {aud}")
    print(f" DH Param P:   {sp[:20]}...")  
    print(f" DH Param G:   {ge}")
    print(f" Signature:    {signature_hex[:40]}...")  
    print("Challenge firmata salvata in 'challenge.json'")
    print("Chiave segreta DH salvata in 'issuer_dh_private.txt'")