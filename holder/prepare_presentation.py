import json
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from common.exercise_3 import sha256
from common.dh_utils import derive_shared_key

if __name__ == "__main__":
    # === Step 1: Carica dati base ===
    with open("../data/session_key.shared", "rb") as f:
        session_key = f.read()
    fernet = Fernet(session_key)

    decrypted = fernet.decrypt(open("../data/vc_payload.enc", "rb").read())
    vc_package = json.loads(decrypted)
    VC = vc_package["VC"]
    attributes = vc_package["attributes"]
    proofs = vc_package["proofs"]

    # === Step 2: Seleziona attributo da presentare ===
    index_to_present = 0  # esempio: presentiamo il primo esame
    m_i = json.loads(attributes[index_to_present])
    π_i = proofs[index_to_present]
    h_i = sha256(attributes[index_to_present])

    # === Step 3: Carica chiave privata dello studente ===
    with open("cert/holder_private_key.pem", "rb") as f:
        sk_holder = serialization.load_pem_private_key(f.read(), password=None)

    with open("cert/holder_cert.pem", "rb") as f:
        cert_holder = f.read()
        cert_obj = x509.load_pem_x509_certificate(cert_holder)
        holder_dn = cert_obj.subject.rfc4514_string()

    # === Step 4: Crea struttura P_prot senza firma_holder ===
    nonce = os.urandom(16).hex()
    timestamp = datetime.utcnow().isoformat() + "Z"
    expiration = (datetime.utcnow() + timedelta(minutes=3)).isoformat() + "Z"

    P_prot_base = {
        "ID_C": VC["ID_C"],
        "issuer": VC["issuer"],
        "holder": holder_dn,
        "expirationDate": VC["expirationDate"],
        "schema": VC["schema"],
        "m_i": m_i,
        "π_i": π_i,
        "MerkleRoot": VC["merkle"]["root"],
        "signature": VC["signature"],
        "revocation": VC["revocation"],
        "nonce": nonce,
        "timestamp": timestamp,
        "expiration": expiration,
        "cert_holder": cert_holder.decode()
    }

    # === Step 5: Firma P_prot_base ===
    to_sign = json.dumps(P_prot_base, separators=(",", ":"), sort_keys=True).encode()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(to_sign)
    digest_final = digest.finalize()

    sig_holder = sk_holder.sign(
        digest_final,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # === Step 6: Aggiungi firma_holder e completa P_prot ===
    P_prot_base["signature_holder"] = sig_holder.hex()

    # === Step 7: Deriva R = y_V^x_H mod p ===
    with open("holder/holder_dh_private_v2.txt", "r") as f:
        x_H = int(f.read())

    y_V = int(VC["signature"]["signedData"].split("∥")[0], 16)  # NON disponibile: usare challenge originale
    with open("challenge_response_verifier.json", "r") as f:
        challenge_obj = json.load(f)
        y_V = int(challenge_obj["original_challenge"]["challenge"]["y_V"])
        sp = int(challenge_obj["original_challenge"]["challenge"]["sp"], 16)

    R = derive_shared_key(y_V, x_H, p=sp)
    fernet_session = Fernet(R)

    # === Step 8: Cifra P_prot ===
    P_prot_bytes = json.dumps(P_prot_base, separators=(",", ":"), sort_keys=True).encode()
    encrypted_presentation = fernet_session.encrypt(P_prot_bytes)

    with open("../data/P_prot_ciphered.enc", "wb") as f:
        f.write(encrypted_presentation)

    print("📦 Presentazione cifrata salvata in 'data/P_prot_ciphered.enc'")
    print("🔐 R derivata e usata da DH y_V^x_H")
