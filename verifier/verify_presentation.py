import json
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.fernet import Fernet
from common.crypto_utils import sha256_digest, verify_signature_VC, verify_signature
from common.exercise_3 import verify_merkle_proof, sha256
from ocsp.registry import OCSPRegistry


# === CONFIG ===
P_PROT_PATH = "data/challenge_verifier_holder/P_prot_ciphered.enc"
SESSION_KEY_PATH = "data/challenge_verifier_holder/key/session_key_verifier.shared"
USED_NONCES_PATH = "data/verifier/used_nonces_verifier.txt"

# === Step 1: Decifra la presentazione ===
with open(SESSION_KEY_PATH, "rb") as f:
    session_key = f.read()
fernet = Fernet(session_key)

with open(P_PROT_PATH, "rb") as f:
    encrypted = f.read()

decrypted = fernet.decrypt(encrypted)
P_prot = json.loads(decrypted)

# === Step 2: Estrai dati ===
VC = P_prot["Credenziale"]
m_i_list = P_prot["m_i"]
pi_list = P_prot["π_i"]
nonce = P_prot["nonce"]
issued_at = P_prot["issued_at"]
expires_at = P_prot["expires_at"]
aud = P_prot["aud"]
signature_holder = bytes.fromhex(P_prot["signature_holder"])

# === Step 3: Verifica firma issuer sulla VC ===
print("\nVerifica della Verifiable Credential (VC)")
merkle_root = VC["merkle"]["root"]


signed_data = VC["signature"]["signedData"]
issuer_cert_path = "issuer/cert/issuer_cert.pem"

with open(issuer_cert_path, "rb") as f:
    issuer_cert = x509.load_pem_x509_certificate(f.read())

if not verify_signature_VC(VC):
    print(" Firma dell’università NON valida.")
    exit(1)
print(" Firma dell’università valida.")

# === Step 4: Verifica OCSP (simulata) ===
print("\nVerifica OCSP")
revocation = VC["revocation"]
revocation_id = revocation["revocationId"]
ocsp_response = registry.check_status(revocation_id)
if ocsp_response["status"] != "valid":
    print("Credenziale revocata secondo OCSP.")
    exit(1)
print(" Stato OCSP: good")

# === Step 5: Verifica firma dello studente ===
print("\nVerifica firma dello studente")
holder_cert_path = "holder/cert/holder_cert.pem"
holder_cert = x509.load_pem_x509_certificate(open(holder_cert_path, "rb").read())
pk_holder = holder_cert.public_key()

unsigned = {k: P_prot[k] for k in P_prot if k not in ("signature_holder", "Credenziale")}
serialized = json.dumps(unsigned, separators=(",", ":"), sort_keys=True)
digest_holder = sha256_digest(serialized)

if not verify_signature(digest_holder, signature_holder, pk_holder):
    print("Firma dello studente NON valida.")
    exit(1)
print("Firma dello studente valida.")

# === Step 6: Verifica Merkle Proofs ===
print("\nVerifica Merkle Proofs")
print("--------------------------------------------------")
for i, (attr_serialized, proof_entry) in enumerate(zip(m_i_list, pi_list)):
    h_i = sha256(attr_serialized)
    index = proof_entry["index"]
    proof = proof_entry["proof"]

    print(f"Attributo {i}")
    print(f"  - m_i       : {attr_serialized}")
    print(f"  - h_i       : {h_i}")
    print(f"  - index     : {index}")
    print("  - π_i       :")
    for j, p in enumerate(proof):
        print(f"      [{j}] {p}")
    print(f"  - Merkle Root attesa: {merkle_root}")

    result = verify_merkle_proof(h_i, proof, merkle_root, index)
    if result:
        print("  - Verifica Merkle Proof: VALIDA\n")
    else:
        print("  - Verifica Merkle Proof: NON valida\n")
        exit(1)

# === Step 7: Timestamp e nonce ===
now = datetime.now(timezone.utc)
if not (datetime.fromisoformat(issued_at) <= now <= datetime.fromisoformat(expires_at)):
    print("Timestamp non valido.")
    exit(1)

used_nonces = set()
if os.path.exists(USED_NONCES_PATH):
    with open(USED_NONCES_PATH, "r") as f:
        used_nonces = set(line.strip() for line in f)

if nonce in used_nonces:
    print("Nonce già usato.")
    exit(1)

with open(USED_NONCES_PATH, "a") as f:
    f.write(nonce + "\n")

print("Timestamp e nonce validi.")
print("\nPresentazione accettata e verificata con successo.")
