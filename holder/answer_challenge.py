import json
import os
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

from common.dh_utils import generate_dh_key_pair, derive_shared_key
from common.crypto_utils import sha256_digest, verify_signature 

# === Step 1: Carica la challenge ricevuta ===
with open("data/challengeHolder.json", "r") as f:
    challenge_obj = json.load(f)

challenge = challenge_obj["challenge"]
signature_server = bytes.fromhex(challenge_obj["signature"])

# === Step 2: Estrai parametri challenge ===
nonce = challenge["nonce"]
issued_at = challenge["issued_at"]
expires_at = challenge["expires_at"]
aud = challenge["aud"]
sp = challenge["sp"]
ge = challenge["ge"]

print("Challenge ricevuta dallo studente:")
print(f"  Nonce:       {nonce}")
print(f"  Issued at:   {issued_at}")
print(f"  Expires at:  {expires_at}")
print(f"  Audience:    {aud}")
print(f"  DH Param P:  {sp[:40]}...")
print(f"  DH Param G:  {ge}")
print(f"  Firma ricevuta: {signature_server.hex()[-40:]}...")

# === Step 3: Verifica firma su H(nonce ∥ issued_at ∥ expires_at ∥ aud ∥ sp ∥ ge) ===
digest = sha256_digest(nonce, issued_at, expires_at, aud, sp, ge)

with open("issuer/issuer_cert.pem", "rb") as f:
    issuer_cert = x509.load_pem_x509_certificate(f.read())
    pk_issuer = issuer_cert.public_key()
    issuer_subject = issuer_cert.subject.rfc4514_string()
newAud = issuer_subject

print("\nVerifica della firma digitale dell'università:")
if verify_signature(digest, signature_server, pk_issuer):
    print("  Firma digitale VERIFICATA con successo.")
else:
    print(" Firma NON valida. Interruzione.")
    
# === Step 4: Verifica periodo di validità ===
now = datetime.now(timezone.utc)
print("\nVerifica validità temporale della challenge:")
print(f"  Tempo corrente: {now.isoformat()}")

if not (datetime.fromisoformat(issued_at) <= now <= datetime.fromisoformat(expires_at)):
    print("Challenge scaduta o non ancora valida.")
    exit(1)
print("  Risultato:  Challenge attualmente valida.")

# === Step 5: Verifica audience ===
my_identity = "CN=Mario Rossi, SerialNumber=123456"
print("\nVerifica identità destinatario (audience):")
print(f"  Attesa:   {my_identity}")
print(f"  Ricevuta: {aud}")

if aud != my_identity:
    print("Audience non corrisponde.")
    exit(1)
print("  Risultato:  Audience corretta.")

# === Step 6: Verifica nonce non riutilizzato ===
nonce_file = "data/used_nonces.txt"
used_nonces = set()
print("\nVerifica univocità del nonce:")
print(f"  Nonce ricevuto: {nonce}")

if os.path.exists(nonce_file):
    with open(nonce_file, "r") as f:
        used_nonces = set(line.strip() for line in f)

if nonce in used_nonces:
    print("Nonce già usato. Potenziale replay attack.")
    exit(1)
print("  Risultato:  Nonce non utilizzato in precedenza.")

# === Step 7: Salva il nonce ===
with open(nonce_file, "a") as f:
    f.write(nonce + "\n")

# === Step 8: Genera chiave DH dello studente ===
print("\nGenerazione chiave Diffie-Hellman dello studente:")
p = int(sp, 16)
g = int(ge)
x_A, y_A = generate_dh_key_pair(p=p, g=g)
with open("holder/holder_dh_private.txt", "w") as f:
    f.write(str(x_A))
print(f"  x_A (privata): salvata su file")
print(f"  y_A (pubblica): {str(y_A)[:40]}...")

# === Step 9: Prepara issued_at' e expires_at' ===
issued_at_p = datetime.now(timezone.utc).isoformat()
expires_at_p = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()

# === Step 10: Firma dello studente su nuovo digest ===
digest_student = sha256_digest(nonce, issued_at_p, expires_at_p, newAud, str(y_A))

with open("holder/holder_private_key.pem", "rb") as f:
    sk_holder = serialization.load_pem_private_key(f.read(), password=None)

signature_student = sk_holder.sign(
    digest_student,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    utils.Prehashed(hashes.SHA256())
)

# === Step 11: Costruisci risposta ===
response = {
    "response": {
        "nonce": nonce,
        "issued_at": issued_at_p,
        "expires_at": expires_at_p,
        "aud": newAud,
        "y_a": str(y_A),
    },
    "signature": signature_student.hex(),
    "original_challenge": challenge,
    "original_signature": challenge_obj["signature"]
}

resp = response["response"]
signature_preview = response["signature"][:40] + "..."
y_a_preview = resp["y_a"][:40] + "..."

print("\nRisposta finale generata:")
print(f"  Nonce:        {resp['nonce']}")
print(f"  Issued_at:    {resp['issued_at']}")
print(f"  Expires_at:   {resp['expires_at']}")
print(f"  Audience:      {resp['aud']}")
print(f"  y_A (pubblica): {y_a_preview}")
print(f"  Firma holder:  {signature_preview}")

# === Step 12: Salva risposta ===
with open("data/challenge_response.json", "w") as f:
    json.dump(response, f, indent=2)

print("Challenge verificata e risposta generata.")
