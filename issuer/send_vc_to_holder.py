import json
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.fernet import Fernet

from issuer.credential_issuer import CredentialIssuer
from common.dh_utils import derive_shared_key, verify_dh_signature
from common.exercise_3 import build_merkle_tree, sha256


def compute_merkle_proofs(leaves, tree):
    """Costruisce la lista completa di Merkle proof π_i per ogni attributo"""
    proofs = []
    for i in range(len(leaves)):
        proof = []
        index = i
        for level in tree[:-1]:
            if index % 2 == 0:
                sibling = index + 1 if index + 1 < len(level) else index
            else:
                sibling = index - 1
            proof.append(level[sibling])
            index //= 2
        proofs.append(proof)
    return proofs


if __name__ == "__main__":
    # === Step 1: Carica risposta challenge dello studente ===
    with open("data/challenge_response.json", "r") as f:
        response = json.load(f)

    y_A = int(response["y_A"])
    sig_holder = bytes.fromhex(response["student_signature"])
    challenge = response["original_challenge"]["challenge"]
    sp = int(challenge["sp"], 16)
    ge = int(challenge["ge"])

    # === Step 2: Verifica firma su y_A con certificato dello studente ===
    with open("holder/holder_cert.pem", "rb") as f:
        holder_cert = x509.load_pem_x509_certificate(f.read())
        pk_holder = holder_cert.public_key()

    if verify_dh_signature(y_A, sig_holder, pk_holder):
        print("✅ Firma dello studente su y_A valida.")
    else:
        print("❌ Firma su y_A non valida. STOP.")
        exit(1)

    # === Step 3: Deriva la chiave di sessione R = y_A^x_B mod p ===
    with open("issuer_dh_private.txt", "r") as f:
        x_B = int(f.read())

    session_key = derive_shared_key(y_A, x_B, p=sp)
    fernet = Fernet(session_key)

    # === Step 4: Costruisci la VC ===
    holder_dn = challenge["aud"]

    # Attributi accademici
    attributes = [
        {
            "nome_esame": "Basi di Dati",
            "cod_corso": "INF123",
            "CFU": 9,
            "voto": "29",
            "data": "2024-07-10",
            "anno_accademico": "2023/2024",
            "tipo_esame": "scritto",
            "docente": "Prof. Bianchi",
            "lingua": "IT"
        },
        {
            "nome_esame": "Sistemi Operativi",
            "cod_corso": "INF201",
            "CFU": 6,
            "voto": "30",
            "data": "2024-06-15",
            "anno_accademico": "2023/2024",
            "tipo_esame": "orale",
            "docente": "Prof. Neri",
            "lingua": "IT"
        },
        {
            "nome_esame": "Reti di Calcolatori",
            "cod_corso": "INF305",
            "CFU": 6,
            "voto": "28",
            "data": "2024-05-22",
            "anno_accademico": "2023/2024",
            "tipo_esame": "misto",
            "docente": "Prof. Verdi",
            "lingua": "IT"
        },
        {
            "nome_esame": "Inglese B2",
            "cod_corso": "LAN402",
            "CFU": 3,
            "voto": "30L",
            "data": "2024-04-30",
            "anno_accademico": "2023/2024",
            "tipo_esame": "scritto",
            "docente": "Dr. Smith",
            "lingua": "EN"
        }
    ]


    issuer = CredentialIssuer(
        issuer_dn="CN=University of Rennes, O=RENES, C=FR",
        cert_path="issuer/issuer_cert.pem",
        private_key_path="issuer/issuer_private_key.pem",
        schema_url="https://schemas.rennes.edu/credential/v1",
        revocation_registry="https://ocsp.edu-europe.eu/rennes"
    )

    vc, serialized_attrs, tree = issuer.issue(holder_dn, attributes)

    # === Step 5: Costruzione delle Merkle proof π_i ===
    proofs = compute_merkle_proofs(tree[0], tree)

    # === Step 6: Pacchetto finale da cifrare e inviare ===
    payload = {
        "VC": vc,
        "attributes": serialized_attrs,
        "proofs": proofs
    }

    encrypted_payload = fernet.encrypt(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())

    # === Step 7: Salvataggio in /data ===
    with open("data/vc_payload.enc", "wb") as f:
        f.write(encrypted_payload)

    with open("data/session_key.shared", "wb") as f:
        f.write(session_key)

    print("📦 VC, attributi e π_i cifrati salvati in 'data/vc_payload.enc'")
    print("🔐 Chiave simmetrica condivisa salvata in 'data/session_key.shared'")
