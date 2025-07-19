import json
import sys
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
from common.crypto_utils import  verify_signature
from holder.credential_holder import CredentialHolder
import hashlib
def list_certifications(base_path="data/holder/wallet"):
    return [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]

def load_vc_package(cert_path):
    with open(os.path.join(cert_path, "valid_vc.json")) as f:
        vc = json.load(f)
    with open(os.path.join(cert_path, "attributes.json")) as f:
        attributes = json.load(f)
    with open(os.path.join(cert_path, "proofs.json")) as f:
        proofs = json.load(f)
    with open(os.path.join(cert_path, "vc_hmac.bin"), "rb") as f:
        vc_hmac = f.read()
    return vc, attributes, proofs, vc_hmac


def stampa_presentazione(P_prot):
    VC = P_prot["Credenziale"]
    print("Contenuto parziale certificato inviato:")
    print(f" - ID_C: {VC['ID_C']}")
    print(f" - Issuer: {VC['issuer']}")
    print(f" - Holder: {VC['holder']}")
    print(f" - Expiration: {VC['expirationDate']}")
    print(f" - Merkle Root: {VC['merkle']['root'][:8]}...")

    print("\nAttributi presentati:")
    for i, (m_serialized, proof_entry) in enumerate(zip(P_prot["m_i"], P_prot["π_i"])):
        attr = json.loads(m_serialized)
        print(f"\n [{i}] {attr['nome_esame']}")
        print(f"     • Codice: {attr['cod_corso']}")
        print(f"     • Voto: {attr['voto']}")
        print(f"     • Data: {attr['data']}")
        print(f"     • Docente: {attr['docente']}")
        print(f"     • Tipo: {attr['tipo_esame']}")
        print(f"     • CFU: {attr['CFU']}")

        print(f"     • Index Merkle originale: {proof_entry['index']}")
        print(f"     • Proof π_{i}:")
        for j, h in enumerate(proof_entry["proof"]):
            print(f"         ├─ {j+1}. {h}")


if __name__ == "__main__":
    # === Step 1: Carica e decifra la challenge ===
    with open("data/challenge_verifier_holder/key/session_key_holder.shared", "rb") as f:
        session_key_holder = f.read()
    fernet = Fernet(session_key_holder)

    with open("data/challenge_verifier_holder/encrypted_challenge.json", "rb") as f:
        encrypted_challenge = f.read()

    decrypted = fernet.decrypt(encrypted_challenge)
    challenge_obj = json.loads(decrypted)
    challenge = challenge_obj["challenge"]
    signature_verifier = bytes.fromhex(challenge_obj["signature_verifier"])

    # === Step 2: Verifica firma del verificatore ===
    challenge_obj_to_verify = {
        "challenge": challenge,
        "nonce": challenge_obj["nonce"],
        "issued_at": challenge_obj["issued_at"],
        "expires_at": challenge_obj["expires_at"],
        "aud": challenge_obj["aud"]
    }

    digest = hashlib.sha256(
        json.dumps(challenge_obj_to_verify, sort_keys=True, separators=(",", ":")).encode()
    ).digest()

    with open("verifier/cert/verifier_cert.pem", "rb") as f:
        verifier_cert = x509.load_pem_x509_certificate(f.read())
        pk_verifier = verifier_cert.public_key()
        audNew = verifier_cert.subject.rfc4514_string()

    print("Verifca challenge ricevuta")
    if not verify_signature(digest, signature_verifier, pk_verifier):
        print(" Firma del verificatore NON valida.")
        exit(1)

    # === Step 3: Verifica validità temporale ===
    now = datetime.now(timezone.utc)
    issued_at = datetime.fromisoformat(challenge_obj["issued_at"])
    expires_at = datetime.fromisoformat(challenge_obj["expires_at"])

    if not (issued_at <= now <= expires_at):
        print(" Challenge scaduta o non ancora valida.")
        exit(1)
    print(" Challenge valida e firmata correttamente.")

    #Step 3.1 Verifica nonce
    nonce = challenge_obj["nonce"]
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
    print(" Nonce verificato con successo")

    # === Step 3.2: Verifica audience ===
    my_identity = "CN=Mario Rossi, SerialNumber=123456"
    if challenge_obj["aud"]!= my_identity:
        print(" Audience non corrisponde.")
        sys.exit(1)
    print(" Audience corretta.")
    
    # === Step 4: Carica VC, attributi e proof ===
    certs = list_certifications()

    if not certs:
        print("Nessuna certificazione trovata.")
        exit(1)

    print("\nSeleziona la certificazione da presentare:")
    for i, cert in enumerate(certs):
        print(f" {i + 1}. {cert}")

    while True:
        try:
            choice = int(input("Inserisci il numero: ")) - 1
            if 0 <= choice < len(certs):
                selected_cert = certs[choice]
                break
            else:
                print(f"Inserisci un numero tra 1 e {len(certs)}.")
        except ValueError:
            print("Inserisci un numero valido.")
    cert_path = os.path.join("data/holder/wallet", selected_cert)

    VC, attributes, proofs, vc_hmac = load_vc_package(cert_path)

    # === Step 5: Prepara P_prot ===
    holder = CredentialHolder("holder/cert/holder_private_key.pem", "holder/cert/holder_cert.pem")
    nonce = challenge_obj["nonce"]
    issued_at = challenge_obj["issued_at"]
    expires_at = challenge_obj["expires_at"]
    start = time.time()
    P_prot = holder.prepare_presentation(
        vc=VC,
        vc_hmac=vc_hmac,
        attributes=attributes,
        proofs=proofs,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        aud=audNew
    )
    if P_prot is None:
        print("Preparazione della presentazione fallita.")
        exit(1)
    t_presentation = (time.time() - start) * 1000
    print(f"[TEMPO] Preparazione presentazione: {t_presentation:.2f} ms")    
    # === Step 6: Cifra P_prot con R ===
    R = session_key_holder
    fernet_session = Fernet(R)

    P_prot_bytes = json.dumps(P_prot, separators=(",", ":"), sort_keys=True).encode()
    start = time.time()
    encrypted_presentation = fernet_session.encrypt(P_prot_bytes)
    t_encryption = (time.time() - start) * 1000
    size_kb = len(encrypted_presentation) / 1024
    print(f"[TEMPO] Cifratura presentazione: {t_encryption:.2f} ms")
    print(f"[DIMENSIONE] Dimensione presentazione cifrata: {size_kb:.2f} KB")
    with open("data/challenge_verifier_holder/P_prot_ciphered.enc", "wb") as f:
        f.write(encrypted_presentation)

    print("=== Contenuto della presentazione inviata ===")
    stampa_presentazione(P_prot)

    print("\nPresentazione cifrata salvata in 'data/challenge_verifier_holder/P_prot_ciphered.enc'")
  
