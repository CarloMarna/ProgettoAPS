import json
import base64
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

# === Funzione di utilità ===
def load_student_exams(aud: str) -> list:
    with open("data/verifier/student_exam_map.json", "r") as f:
        db = json.load(f)
    return db.get(aud, [])

# === Carica chiave simmetrica condivisa ===
with open("data/challenge_verifier_holder/key/session_key_verifier.shared", "rb") as f:
    session_key = f.read()

fernet = Fernet(session_key)

# === Parametri della challenge ===
nonce = os.urandom(16).hex()
issued_at = datetime.now(timezone.utc)
expires_at = issued_at + timedelta(minutes=2)

# === AUDIENCE (studente) ===
aud = "CN=Mario Rossi, SerialNumber=123456"

# === Carica tutti gli esami disponibili dello studente
tutti_esami = load_student_exams(aud)

if not tutti_esami:
    print(f" Nessun esame associato allo studente '{aud}'. Challenge non generata.")
    exit(1)

# === Mostra all'utente gli esami disponibili
print("\nEsami disponibili per lo studente:")
for i, nome_esame in enumerate(tutti_esami):
    print(f" [{i}] {nome_esame}")

# === Selezione degli esami da inserire nella challenge
while True:
    scelti = input("\nInserisci gli indici separati da virgola degli esami da includere nella challenge: ")
    try:
        indici = [int(x.strip()) for x in scelti.split(",")]
        if any(i < 0 or i >= len(tutti_esami) for i in indici):
            print(" Indici non validi. Riprova.")
            continue
        esami = [tutti_esami[i] for i in indici]
        break
    except ValueError:
        print(" Input non valido. Usa numeri separati da virgole.")

# === Costruisce il messaggio della challenge ===
challenge_text = f"Presenta esami {', '.join(esami)}"

# === Calcola digest firmato ===
challenge_obj_to_sign = {
    "challenge": challenge_text,
    "nonce": nonce,
    "issued_at": issued_at.isoformat(),
    "expires_at": expires_at.isoformat(),
    "aud": aud
}

digest = hashes.Hash(hashes.SHA256())
digest.update(json.dumps(challenge_obj_to_sign, sort_keys=True, separators=(",", ":")).encode())
final_digest = digest.finalize()

# === Firma con chiave privata del verificatore ===
with open("verifier/cert/verifier_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

signature = private_key.sign(
    final_digest,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    utils.Prehashed(hashes.SHA256())
)

# === Costruisce challenge finale ===
challenge_obj = {
    "challenge": challenge_text,
    "nonce": nonce,
    "issued_at": issued_at.isoformat(),
    "expires_at": expires_at.isoformat(),
    "aud": aud,
    "signature_verifier": signature.hex()
}

# === Cifra e salva ===
ciphered = fernet.encrypt(json.dumps(challenge_obj, separators=(",", ":"), sort_keys=True).encode())

with open("data/challenge_verifier_holder/encrypted_challenge.json", "wb") as f:
    f.write(ciphered)

print("Challenge selettiva firmata e cifrata.")
print(f"  Nonce: {nonce}")
print(f"  Issued_at: {issued_at.isoformat()}")
print(f"  Expires_at: {expires_at.isoformat()}")
print(f"  Aud: {aud}")
print(f"  Esami richiesti: {', '.join(esami)}")
print(f"  Firma: {signature.hex()[:40]}...")
print("Salvata in 'data/challenge_verifier_holder/encrypted_challenge.json'")
