import json
import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from common.crypto_utils import sha256_digest, verify_signature
from holder.credential_holder import CredentialHolder
##RICORDA DI AGGIUNGERE AUD DELL'Universita


def list_certifications(base_path="data/wallet"):
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
    digest = sha256_digest(
        challenge,                        
        challenge_obj["nonce"],
        challenge_obj["issued_at"],
        challenge_obj["expires_at"],
        challenge_obj["aud"]
    )


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
    cert_path = os.path.join("data/wallet", selected_cert)

    VC, attributes, proofs, vc_hmac = load_vc_package(cert_path)

    # === Step 5: Prepara P_prot ===
    holder = CredentialHolder("holder/cert/holder_private_key.pem", "holder/cert/holder_cert.pem")
    nonce = challenge_obj["nonce"]
    issued_at = challenge_obj["issued_at"]
    expires_at = challenge_obj["expires_at"]

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
        
    # === Step 6: Cifra P_prot con R ===
    R = session_key_holder
    fernet_session = Fernet(R)

    P_prot_bytes = json.dumps(P_prot, separators=(",", ":"), sort_keys=True).encode()
    encrypted_presentation = fernet_session.encrypt(P_prot_bytes)

    with open("data/challenge_verifier_holder/P_prot_ciphered.enc", "wb") as f:
        f.write(encrypted_presentation)

    print("Presentazione cifrata salvata in 'data/challenge_verifier_holder/P_prot_ciphered.enc'")
  
