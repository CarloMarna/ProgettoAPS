import json
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.fernet import Fernet
from common.crypto_utils import  verify_signature_VC, verify_signature
from common.exercise_3 import verify_merkle_proof, sha256
from ocsp.registry import OCSPRegistry
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
from cryptography.x509.oid import NameOID
import time
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

# === Step 4: Verifica OCSP  ===
ocsp = OCSPRegistry(VC["revocation"]["registry"])

revocation_id = VC["revocation"]["revocationId"]
ocsp_response = ocsp.check_status(revocation_id)

rev_id = ocsp_response["revocationId"]
status = ocsp_response["status"]
timestamp = ocsp_response["timestamp"]
path_cert = ocsp_response["path_cert"]
signature = bytes.fromhex(ocsp_response["signature"])

message = (rev_id + status + timestamp + path_cert).encode()

with open(path_cert, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()

digest = hashes.Hash(hashes.SHA256())
digest.update(message)
final_digest = digest.finalize()

try:
    start = time.perf_counter()
    public_key.verify(
        signature,
        final_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(" Firma OCSP verificata correttamente.")
    t_ocsp = (time.perf_counter() - start) * 1000
    print(f"[Tempo] Verifica firma OCSP: {t_ocsp:.2f} ms")
except Exception as e:
    print(" Errore verifica firma OCSP:", e)
    exit(1)


if ocsp_response["status"] == "revoked":
    print(" Credenziale revocata secondo OCSP.")
    exit(1)
elif ocsp_response["status"] == "unknown":
    print(" Credenziale sconosciuta secondo OCSP.")
    exit(1)
print(" Stato OCSP: good")

# === Step 5: Verifica firma dello studente ===
holder_cert_path = "holder/cert/holder_cert.pem"
holder_cert = x509.load_pem_x509_certificate(open(holder_cert_path, "rb").read())
pk_holder = holder_cert.public_key()

# === Step 5.1: Verifica corrispondenza holder in vc con holder che sta presentando
vc_holder = VC["holder"]
vc_cn = next((x.split("=")[1] for x in vc_holder.split(",") if x.startswith("CN=")), None)
cert_cn = holder_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

if vc_cn != cert_cn:
    print("Mismatch sul CN tra VC e certificato.")
    exit(1)
print("CN del holder corrispondente.")

unsigned = {k: P_prot[k] for k in P_prot if k not in ("signature_holder", "Credenziale")}
serialized = json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode()
digest_holder = hashlib.sha256(serialized).digest()

if not verify_signature(digest_holder, signature_holder, pk_holder):
    print(" Firma dello studente NON valida.")
    exit(1)
print(" Firma dello studente valida.")

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

if(VC["expirationDate"] < now.isoformat()):
    print("Credenziale scaduta.")
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

print("Credenziale valida, Timestamp e nonce validi.")
print("Presentazione accettata e verificata con successo.")
