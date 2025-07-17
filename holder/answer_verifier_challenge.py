import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from common.dh_utils import generate_dh_key_pair, sign_dh_public_key, verify_dh_signature

if __name__ == "__main__":
    # === Step 1: Carica challenge cifrata ===
    with open("../data/challenge_issuer_holder/challenge_verifier.enc", "rb") as f:
        encrypted = f.read()

    with open("cert/holder_private_key.pem", "rb") as f:
        sk_holder = serialization.load_pem_private_key(f.read(), password=None)

    # Decifra usando la chiave privata holder (RSA-OAEP)
    clear_challenge = sk_holder.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    challenge_obj = json.loads(clear_challenge)
    challenge = challenge_obj["challenge"]
    signature_issuer = bytes.fromhex(challenge_obj["signature_issuer"])

    # === Step 2: Verifica firma del verificatore ===
    data_to_hash = (
        challenge["challenge"] +
        challenge["nonce"] +
        challenge["timestamp"] +
        challenge["aud"] +
        challenge["sp"] +
        challenge["gen"]
    ).encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_to_hash)
    h_challenge = digest.finalize()

    # Carica certificato verificatore
    with open("../verifier/cert/verifier_cert.pem", "rb") as f:
        verifier_cert = x509.load_pem_x509_certificate(f.read())
        pk_verifier = verifier_cert.public_key()

    try:
        pk_verifier.verify(
            signature_issuer,
            h_challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(" Firma del verificatore sulla challenge è valida.")
    except:
        print(" Firma non valida. STOP.")
        exit(1)

    # === Step 3: Verifica timestamp e freshness ===
    now = datetime.utcnow()
    issued = datetime.fromisoformat(challenge["timestamp"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(challenge["expiration"].replace("Z", "+00:00"))

    if not (issued <= now <= expires):
        print(" Challenge scaduta.")
        exit(1)

    # === Step 4: Genera DH holder: x_H, y_H ===
    sp = int(challenge["sp"], 16)
    gen = int(challenge["gen"])
    x_H, y_H = generate_dh_key_pair(p=sp, g=gen)

    with open("holder/holder_dh_private_v2.txt", "w") as f:
        f.write(str(x_H))

    sig_y_H = sign_dh_public_key(y_H, sk_holder)

    # === Step 5: Costruisci risposta ===
    response = {
        "y_H": str(y_H),
        "signature_holder": sig_y_H.hex(),
        "original_challenge": challenge_obj
    }

    with open("challenge_issuer_holder/challenge_response_verifier.json", "w") as f:
        json.dump(response, f, indent=2)

    print(" Risposta alla challenge salvata in 'challenge_response_verifier.json'")
    print(" Chiave x_H salvata in 'holder_dh_private_v2.txt'")
