import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from common.dh_utils import (
    generate_dh_key_pair,
    verify_dh_signature,
    sign_dh_public_key
)

if __name__ == "__main__":
    # === Step 1: Carica la challenge ricevuta ===
    with open("data/challengeHolder.json", "r") as f:
        challenge_obj = json.load(f)

    challenge = challenge_obj["challenge"]
    signature_server = bytes.fromhex(challenge_obj["signature"])

    y_B = int(challenge["y_B"])
    sp = int(challenge["sp"], 16)  # converti da hex a int
    ge = int(challenge["ge"])

    # === Step 2: Verifica firma su y_B con certificato issuer ===
    with open("issuer/issuer_cert.pem", "rb") as f:
        issuer_cert = x509.load_pem_x509_certificate(f.read())
        pk_issuer = issuer_cert.public_key()

    if verify_dh_signature(y_B, signature_server, pk_issuer):
        print("✅ Firma dell'università su y_B valida.")
    else:
        print("❌ Firma non valida. STOP.")
        exit(1)

    # === Step 3: Genera chiavi DH dello studente ===
    x_A, y_A = generate_dh_key_pair(p=sp, g=ge)

    # Salva x_A per derivare R più tardi
    with open("holder/holder_dh_private.txt", "w") as f:
        f.write(str(x_A))

    # === Step 4: Firma y_A con la chiave privata dello studente ===
    with open("holder/holder_private_key.pem", "rb") as f:
        sk_holder = serialization.load_pem_private_key(f.read(), password=None)

    sig_holder = sign_dh_public_key(y_A, sk_holder)

    # === Step 5: Prepara risposta alla challenge ===
    response = {
        "student_signature": sig_holder.hex(),  # Sign(sk_holder, H(y_A))
        "y_A": str(y_A),
        "original_challenge": challenge_obj
    }

    # === Step 6: Salva risposta su file ===
    with open("data/challenge_response.json", "w") as f:
        json.dump(response, f, indent=2)

    print("📤 Risposta alla challenge salvata in 'challenge_response.json'")
    print("🔐 Chiave segreta DH dello studente salvata in 'holder_dh_private.txt'")
