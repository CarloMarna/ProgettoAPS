import json
import os
from datetime import datetime, timedelta, timezone
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.dh_utils import generate_dh_key_pair, DEFAULT_G, derive_shared_key
from common.crypto_utils import sha256_digest, verify_signature

# === Step 1: Carica risposta ricevuta dallo studente ===
with open("data/challenge_response.json", "r") as f:
    message = json.load(f)

response = message["response"]
signature_student = bytes.fromhex(message["signature"])
challenge_body = message["original_challenge"]
signature_server = bytes.fromhex(message["original_signature"])

nonce = response["nonce"]
y_a = response["y_a"]

# === Step 2: Verifica firma server sulla challenge originale ===
digest_challenge = sha256_digest(
    challenge_body["nonce"],
    challenge_body["issued_at"],
    challenge_body["expires_at"],
    challenge_body["aud"],
    challenge_body["sp"],
    challenge_body["ge"]
)

with open("issuer/issuer_cert.pem", "rb") as f:
    issuer_cert = x509.load_pem_x509_certificate(f.read())
    pk_issuer = issuer_cert.public_key()

print("Verifica firma digitale sulla challenge originale:")
if not verify_signature(digest_challenge, signature_server, pk_issuer):
    print(" Firma su challenge non valida.")
    exit(1)
print(" Firma sulla challenge verificata.")

# === Step 3: Verifica che il nonce sia coerente ===
if response["nonce"] != challenge_body["nonce"]:
    print(" Il nonce della risposta non corrisponde a quello originale.")
    exit(1)
print(" Il nonce corrisponde.")

# === Step 4: Verifica che il nonce non sia già stato usato ===
nonce_file = "data/used_nonces_issuer.txt"
used_nonces = set()
if os.path.exists(nonce_file):
    with open(nonce_file, "r") as f:
        used_nonces = set(line.strip() for line in f)

if nonce in used_nonces:
    print(" Nonce già usato. Possibile replay.")
    exit(1)

'''with open(nonce_file, "a") as f:
    f.write(nonce + "\n")
print(" Nonce nuovo, accettato.")'''

# === Step 5: Verifica firma dello studente ===
digest_response = sha256_digest(
    response["nonce"],
    response["issued_at"],
    response["expires_at"],
    response["aud"],
    response["y_a"]
)

with open("holder/holder_cert.pem", "rb") as f:
    holder_cert = x509.load_pem_x509_certificate(f.read())
    pk_holder = holder_cert.public_key()

print("\nVerifica firma dello studente sulla risposta:")
if not verify_signature(digest_response, signature_student, pk_holder):
    print(" Firma dello studente NON valida.")
    exit(1)
print(" Firma dello studente verificata.")

# === Step 6: Genera chiave DH dell’università ===
print("\nGenerazione chiave DH del server:")
sp = int(challenge_body["sp"], 16)
g = int(challenge_body["ge"])

x_b, y_b = generate_dh_key_pair(p=sp, g=g)

with open("issuer/issuer_dh_private.txt", "w") as f:
    f.write(str(x_b))
print(f"  x_B salvata")
print(f"  y_B: {str(y_b)[:40]}...")

# === Step 7: Costruzione messaggio di risposta firmato ===
issued_at_r = datetime.now(timezone.utc).isoformat()
expires_at_r = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
aud = challenge_body["aud"]  # CN=Mario Rossi...

digest_response_server = sha256_digest(
    nonce,
    issued_at_r,
    expires_at_r,
    aud,
    str(y_b)
)

with open("issuer/issuer_private_key.pem", "rb") as f:
    sk_issuer = serialization.load_pem_private_key(f.read(), password=None)

signature_response = sk_issuer.sign(
    digest_response_server,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(hashes.SHA256())
)

# === Step 8: Costruisci e salva messaggio ===
server_response = {
    "server_response": {
        "nonce": nonce,
        "issued_at": issued_at_r,
        "expires_at": expires_at_r,
        "aud": aud,
        "y_b": str(y_b)
    },
    "signature": signature_response.hex()
}

with open("data/server_dh_response.json", "w") as f:
    json.dump(server_response, f, indent=2)

print("\nServer Response generata e salvata:")
print(f"  Nonce:        {nonce}")
print(f"  Issued_at:    {issued_at_r}")
print(f"  Expires_at:   {expires_at_r}")
print(f"  Audience:     {aud}")
print(f"  y_B (pubblica): {str(y_b)[:40]}...")
print(f"  Firma server:   {server_response['signature'][:40]}...")
print("Messaggio salvato in 'data/server_dh_response.json'")
