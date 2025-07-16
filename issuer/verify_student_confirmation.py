import json
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.crypto_utils import sha256_digest, verify_signature
from common.dh_utils import derive_shared_key

# === Step 1: Carica conferma dello studente ===
with open("data/student_session_confirm.json", "r") as f:
    message = json.load(f)

confirmation = message["student_confirmation"]
signature = bytes.fromhex(message["signature"])

nonce = confirmation["nonce"]
issued_at = confirmation["issued_at"]
expires_at = confirmation["expires_at"]
aud = confirmation["aud"]
confirmation_type = confirmation["confirmation_type"]

print("Conferma ricevuta dallo studente:")
print(f"  Nonce:       {nonce}")
print(f"  Issued_at:   {issued_at}")
print(f"  Expires_at:  {expires_at}")
print(f"  Audience:    {aud}")
print(f"  Tipo:        {confirmation_type}")
print(f"  Firma ricevuta: {signature.hex()[:40]}...")

# === Step 2: Verifica firma dello studente ===
digest = sha256_digest(nonce, issued_at, expires_at, aud, confirmation_type)

with open("holder/holder_cert.pem", "rb") as f:
    holder_cert = x509.load_pem_x509_certificate(f.read())
    pk_holder = holder_cert.public_key()

if verify_signature(digest, signature, pk_holder):
    print("Firma dello studente verificata.")
else:
    print("Firma dello studente NON valida.")
    exit(1)

# === Step 3: Verifica validità temporale ===
now = datetime.now(timezone.utc)
if not (datetime.fromisoformat(issued_at) <= now <= datetime.fromisoformat(expires_at)):
    print("Messaggio scaduto o non ancora valido.")
    exit(1)
print("Finestra temporale valida.")

# === Step 4: Verifica che il nonce sia coerente e non riutilizzato ===
nonce_file = "data/confirmed_nonces.txt"
used_nonces = set()
if os.path.exists(nonce_file):
    with open(nonce_file, "r") as f:
        used_nonces = set(line.strip() for line in f)

if nonce in used_nonces:
    print("Nonce già registrato. Potenziale replay.")
    exit(1)

# === Step 5: Registra il nonce come usato definitivamente ===
with open(nonce_file, "a") as f:
    f.write(nonce + "\n")
print("Nonce registrato come usato.")

# === Step 6: Calcola chiave di sessione: K_session = y_A^x_B mod p ===
with open("data/challenge_response.json", "r") as f:
    response = json.load(f)

y_A = int(response["response"]["y_a"])

with open("issuer/issuer_dh_private.txt", "r") as f:
    x_B = int(f.read())

with open("data/challengeHolder.json", "r") as f:
    challenge = json.load(f)["challenge"]

p = int(challenge["sp"], 16)
shared_key = derive_shared_key(y_A, x_B, p)

with open("data/session_key_issuer.shared", "wb") as f:
    f.write(shared_key)

print("Chiave di sessione calcolata dal server e salvata.")
print("Scambio DH completato in modo sicuro.")
