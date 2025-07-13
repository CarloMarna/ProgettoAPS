import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

from common.exercise_3 import sha256
from common.dh_utils import derive_shared_key

NONCE_DB = set()  # simulazione di un database dei nonce visti

def verify_merkle_proof(h_i, proof, root, index):
    current = h_i
    for sibling in proof:
        if index % 2 == 0:
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)
        index //= 2
    return current == root


if __name__ == "__main__":
    # === Step 1: Carica challenge originale per y_H, sp ===
    with open("../holder/challenge_response_verifier.json", "r") as f:
        challenge = json.load(f)
    y_H = int(challenge["y_H"])
    sp = int(challenge["original_challenge"]["challenge"]["sp"], 16)

    # === Step 2: Carica chiave x_V del verificatore ===
    with open("verifier_dh_private.txt", "r") as f:
        x_V = int(f.read())

    R = derive_shared_key(y_H, x_V, p=sp)
    fernet = Fernet(R)

    # === Step 3: Decifra la presentazione ===
    with open("../data/P_prot_ciphered.enc", "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    P_prot = json.loads(decrypted)

    # === Step 4: Verifica firma dell’università sulla MerkleRoot ===
    with open("verifier_cert.pem", "rb") as f:
        cert_verifier = x509.load_pem_x509_certificate(f.read())

    with open("../issuer/issuer_cert.pem", "rb") as f:
        cert_issuer = x509.load_pem_x509_certificate(f.read())
        pk_issuer = cert_issuer.public_key()

    to_sign = (
        P_prot["MerkleRoot"] + "∥" +
        P_prot["ID_C"] + "∥" +
        P_prot["issuer"] + "∥" +
        P_prot["holder"] + "∥" +
        P_prot["schema"] + "∥" +
        P_prot["expirationDate"] + "∥" +
        P_prot["revocation"]["revocationId"] + "∥" +
        P_prot["revocation"]["registry"]
    ).encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(to_sign)
    h_root = digest.finalize()

    try:
        pk_issuer.verify(
            bytes.fromhex(P_prot["signature"]["signatureValue"]),
            h_root,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✅ Firma università sulla MerkleRoot valida.")
    except:
        print("❌ Firma università NON valida.")
        exit(1)

    # === Step 5: Verifica firma dello studente ===
    signature_holder = bytes.fromhex(P_prot["signature_holder"])
    del P_prot["signature_holder"]
    message_bytes = json.dumps(P_prot, separators=(",", ":"), sort_keys=True).encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    h_prot = digest.finalize()

    cert_holder = x509.load_pem_x509_certificate(P_prot["cert_holder"].encode())
    pk_holder = cert_holder.public_key()

    try:
        pk_holder.verify(
            signature_holder,
            h_prot,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✅ Firma dello studente su P_prot valida.")
    except:
        print("❌ Firma dello studente NON valida.")
        exit(1)

    # === Step 6: Verifica Merkle proof ===
    m_i = json.dumps(P_prot["m_i"], separators=(",", ":"), sort_keys=True)
    h_i = sha256(m_i)
    if verify_merkle_proof(h_i, P_prot["π_i"], P_prot["MerkleRoot"], 0):
        print("✅ Merkle proof valida.")
    else:
        print("❌ Merkle proof NON valida.")
        exit(1)

    # === Step 7: Verifica freshness ===
    now = datetime.utcnow()
    ts = datetime.fromisoformat(P_prot["timestamp"].replace("Z", "+00:00"))
    exp = datetime.fromisoformat(P_prot["expiration"].replace("Z", "+00:00"))

    if not (ts <= now <= exp):
        print("❌ Timestamp non valido.")
        exit(1)

    if P_prot["nonce"] in NONCE_DB:
        print("❌ Nonce già visto: replay.")
        exit(1)

    NONCE_DB.add(P_prot["nonce"])
    print("🕓 Freshness OK.")

    # === Step 8: Mock verifica OCSP ===
    print("🕵️‍♂️ Verifica OCSP simulata (OK)")

    print("\n✅ Presentazione verificata correttamente.")
