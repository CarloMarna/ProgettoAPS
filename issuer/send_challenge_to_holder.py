import os
import json
from datetime import timedelta
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from common.dh_utils import generate_dh_key_pair, sign_dh_public_key, DEFAULT_P, DEFAULT_G


if __name__ == "__main__":
    # === Step 1: Generazione parametri della challenge ===

    # Genera un nonce crittograficamente sicuro (256 bit)
    nonce = os.urandom(32).hex()

    # Timestamp corrente e scadenza della challenge
    issued_at = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.utcnow() + timedelta(minutes=2)).isoformat() + "Z"

    # Identità prevista del destinatario (DN dello studente)
    aud = "CN=Mario Rossi, SerialNumber=123456"

    # Parametri Diffie-Hellman condivisi (primo sicuro e generatore)
    sp = hex(DEFAULT_P)  # per leggibilità usiamo hex string
    ge = str(DEFAULT_G)

    # === Step 2: Generazione chiave DH dell’università ===

    # x_B: segreto privato, y_B = g^x_B mod p
    x_B, y_B = generate_dh_key_pair()

    # Salviamo x_B per derivare R in seguito (formato decimale stringa)
    with open("issuer_dh_private.txt", "w") as f:
        f.write(str(x_B))

    # === Step 3: Firma della chiave pubblica DH (y_B) ===

    # Carica chiave privata dell’università per firmare y_B
    with open("issuer/issuer_private_key.pem", "rb") as f:
        issuer_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Firma y_B con sk_issuer: Sign(sk_issuer, H(y_B))
    signature = sign_dh_public_key(y_B, issuer_private_key)
    signature_hex = signature.hex()

    # Salva la firma (opzionale/debug)
    with open("issuer/issuer_dh_signature.txt", "w") as f:
        f.write(signature_hex)

    # === Step 4: Costruzione della challenge firmata ===

    challenge = {
        "challenge": {
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "aud": aud,
            "sp": sp,
            "ge": ge,
            "y_B": str(y_B)  # chiave pubblica DH dell’università
        },
        "signature": signature_hex
    }

    # === Step 5: Salvataggio in challenge.json da inviare allo studente ===
    with open("data/challengeHolder.json", "w") as f:
        json.dump(challenge, f, indent=2)

    print("✅ Challenge firmata salvata in 'challenge.json'")
    print("🔐 Chiave segreta DH salvata in 'issuer_dh_private.txt'")
