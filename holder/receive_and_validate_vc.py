import json
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes, hmac

from common.exercise_3 import sha256
from holder.credential_holder import CredentialHolder

# === Funzione per verificare Merkle proof ===
def verify_merkle_proof(h_i, proof, root, index):
    current_hash = h_i
    for sibling in proof:
        if index % 2 == 0:
            current_hash = sha256(current_hash + sibling)
        else:
            current_hash = sha256(sibling + current_hash)
        index //= 2
    return current_hash == root


# === Funzione per caricare schema ufficiale ===
def load_schema():
    return {
        "type": "object",
        "required": ["nome_esame", "cod_corso", "CFU", "voto", "data", "anno_accademico", "tipo_esame", "docente", "lingua"],
        "properties": {
            "nome_esame": {"type": "string"},
            "cod_corso": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{2,10}$"},
            "CFU": {"type": "integer", "minimum": 1, "maximum": 30},
            "voto": {"type": "string", "pattern": "^(18|19|2[0-9]|30|30L)$"},
            "data": {"type": "string", "format": "date"},
            "anno_accademico": {"type": "string", "pattern": "^[0-9]{4}/[0-9]{4}$"},
            "docente": {"type": "string"},
            "lingua": {"type": "string", "enum": ["IT", "EN", "FR", "DE", "ES"]},
            "tipo_esame": {"type": "string", "enum": ["scritto", "orale", "progetto", "misto"]}
        },
        "additionalProperties": False
    }


if __name__ == "__main__":
    # === Step 1: Carica la chiave di sessione R e il payload cifrato ===
    with open("data/session_key.shared", "rb") as f:
        session_key = f.read()
    fernet = Fernet(session_key)
    with open("data/vc_payload.enc", "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    payload = json.loads(decrypted)

    VC = payload["VC"]
    attributes = payload["attributes"]
    proofs = payload["proofs"]

    # === Step 2: Inizializza holder per verifica firma + HMAC ===
    holder = CredentialHolder(
        private_key_path="holder/holder_private_key.pem",
        cert_path="holder/holder_cert.pem"
    )

    # === Step 3: Verifica firma dell’università su Merkle Root ===
    if holder.verify_signature(VC):
        print("✅ Firma dell’università sulla VC è valida.")
    else:
        print("❌ Firma sulla VC non valida. STOP.")
        exit(1)

    # === Step 4: Validazione schema JSON per ogni attributo ===
    from jsonschema import validate
    schema = load_schema()

    for i, attr_json in enumerate(attributes):
        attr_dict = json.loads(attr_json)
        try:
            validate(attr_dict, schema)
            print(f"✔ Attributo [{i}] conforme allo schema.")
        except Exception as e:
            print(f"❌ Attributo [{i}] NON conforme allo schema:", e)
            exit(1)

    # === Step 5: Verifica Merkle proof per ogni attributo ===
    merkle_root = VC["merkle"]["root"]
    all_pass = True

    for i, (attr_json, proof) in enumerate(zip(attributes, proofs)):
        h_i = sha256(attr_json)
        if verify_merkle_proof(h_i, proof, merkle_root, i):
            print(f"✔ π_{i} valida per attributo [{i}].")
        else:
            print(f"❌ π_{i} NON valida. STOP.")
            all_pass = False

    if not all_pass:
        exit(1)

    # === Step 6: Calcolo e salvataggio HMAC locale ===
    hmac_value = holder.compute_local_hmac(VC)
    with open("vc_hmac.bin", "wb") as f:
        f.write(hmac_value)
    print("🔐 HMAC locale salvato in 'vc_hmac.bin'")

    print("\n✅ Tutti i controlli completati. VC valida e archiviata.")
