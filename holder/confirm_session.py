import json
from datetime import datetime, timedelta, timezone
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.dh_utils import derive_shared_key
from common.crypto_utils import verify_signature
import hashlib

# === Step 0: Carica la risposta del server (y_B) ===
with open("data/challenge_issuer_holder/server_dh_response.json", "r") as f:
    server_msg = json.load(f)

server_response = server_msg["server_response"]
signature_server = bytes.fromhex(server_msg["signature"])

nonce = server_response["nonce"]
issued_at = server_response["issued_at"]
expires_at = server_response["expires_at"]
aud = server_response["aud"]
y_b = int(server_response["y_b"])


# === Step 1: Verifica validità temporale ===
print("Verifica challenge ricevuta")
now = datetime.now(timezone.utc)
if not (datetime.fromisoformat( server_response["issued_at"]) <= now <= datetime.fromisoformat(server_response["expires_at"])):
    print(" Messaggio scaduto o non ancora valido.")
    exit(1)
print(" Finestra temporale valida.")

# === Step 2: Verifica firma del server ===
digest = hashlib.sha256(
    json.dumps(server_response, sort_keys=True, separators=(",", ":")).encode("utf-8")
).digest()

with open("issuer/cert/issuer_cert.pem", "rb") as f:
    issuer_cert = x509.load_pem_x509_certificate(f.read())
    pk_issuer = issuer_cert.public_key()
    issuer_subject = issuer_cert.subject.rfc4514_string()
newAud = issuer_subject

if verify_signature(digest, signature_server, pk_issuer):
    print(" Firma valida.")
else:
    print(" Firma  NON valida.")
    exit(1)

# === Step Added: Verifica nonce ===
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
print(" Nonce2 Verificato con Successo.")

# === Step 3: Calcola chiave di sessione K_session = y_B ^ x_A mod p ===
with open("data/holder/holder_dh_private.txt", "r") as f:
    x_a = int(f.read())

with open("data/challenge_issuer_holder/challengeHolder.json", "r") as f:
    challenge = json.load(f)

p = int(challenge["sp"], 16)
shared_key = derive_shared_key(y_b, x_a, p)

with open("data/challenge_issuer_holder/key/session_key.shared", "wb") as f:
    f.write(shared_key)

print("\nChiave di sessione condivisa calcolata e salvata.")

# === Step 4: Costruisci conferma firmata ===
issued_at_c = datetime.now(timezone.utc).isoformat()
expires_at_c = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
confirmation_aud = newAud  # CN=Mario Rossi, SerialNumber=...

confirmation_dict = {
    "nonce": nonce,
    "issued_at": issued_at_c,
    "expires_at": expires_at_c,
    "aud": confirmation_aud,
    "confirmation_type": "session_established"
}

digest_confirmation = hashlib.sha256(
    json.dumps(confirmation_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
).digest()

with open("holder/cert/holder_private_key.pem", "rb") as f:
    sk_holder = serialization.load_pem_private_key(f.read(), password=None)

signature_confirmation = sk_holder.sign(
    digest_confirmation,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(hashes.SHA256())
)

# === Step 5: Salva messaggio di conferma ===
final_confirmation = {
    "student_confirmation": confirmation_dict,
    "signature": signature_confirmation.hex()
}

with open("data/challenge_issuer_holder/student_session_confirm.json", "w") as f:
    json.dump(final_confirmation, f, indent=2)

print("\nConferma inviata all’università:")
print(f"  Nonce:       {nonce}")
print(f"  Issued_at:   {issued_at_c}")
print(f"  Expires_at:  {expires_at_c}")
print(f"  Audience:    {confirmation_aud}")
print(f"  Firma:       {final_confirmation['signature'][:40]}...")
print("Messaggio salvato in 'data/challenge_issuer_holder/student_session_confirm.json'")
