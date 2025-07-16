import json
from cryptography.fernet import Fernet

from issuer.credential_issuer import CredentialIssuer
from common.exercise_3 import build_merkle_tree, sha256

def compute_merkle_proofs(leaves, tree):
    """Costruisce la lista completa di Merkle proof π_i per ogni attributo"""
    proofs = []
    for i in range(len(leaves)):
        proof = []
        index = i
        for level in tree[:-1]:
            sibling = index + 1 if index % 2 == 0 else index - 1
            if 0 <= sibling < len(level):
                proof.append(level[sibling])
            index //= 2
        proofs.append(proof)
    return proofs

if __name__ == "__main__":
    print("Preparazione Verifiable Credential per lo studente...")

    # === Step 1: Carica risposta challenge dello studente ===
    with open("data/challenge_response.json", "r") as f:
        response = json.load(f)

    challenge = response["original_challenge"]
    holder_dn = challenge["aud"]

    print(f" Holder DN: {holder_dn}")

    # === Step 2: Carica la chiave di sessione derivata ===
    with open("data/session_key_issuer.shared", "rb") as f:
        session_key = f.read()

    fernet = Fernet(session_key)
    print(" Chiave di sessione (issuer) caricata con successo.")

    # === Step 3: Attributi accademici ===
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
    print(f" Numero attributi nella VC: {len(attributes)}")

    # === Step 4: Emissione della VC ===
    issuer = CredentialIssuer(
        issuer_dn="CN=University of Rennes, O=RENES, C=FR",
        cert_path="issuer/issuer_cert.pem",
        private_key_path="issuer/issuer_private_key.pem",
        schema_url="https://schemas.rennes.edu/credential/v1",
        revocation_registry="https://ocsp.edu-europe.eu/rennes"
    )

    vc, serialized_attrs, tree = issuer.issue(holder_dn, attributes)

    print("Verifiable Credential firmata correttamente.")
    print(f" ID credenziale: {vc['ID_C']}")
    print(f" Merkle Root: {vc['merkle']['root'][:40]}...")
    print(f" Firma VC (σ): {vc['signature']['signatureValue'][:40]}...")
    print(f" Revocation ID: {vc['revocation']['revocationId'][:40]}...")

    # === Step 5: Calcolo delle Merkle proof π_i ===
    proofs = compute_merkle_proofs(tree[0], tree)
    print(f" Merkle tree costruito e {len(proofs)} prove generate.")

    # === Step 6: Costruzione del payload cifrato ===
    payload = {
        "VC": vc,
        "attributes": serialized_attrs,
        "proofs": proofs
    }

    encrypted_payload = fernet.encrypt(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )

    # === Step 7: Salvataggio del pacchetto cifrato ===
    with open("data/vc_payload.enc", "wb") as f:
        f.write(encrypted_payload)

    print("Pacchetto VC cifrato salvato in 'data/vc_payload.enc'")
    print("Procedura completata con successo.\n")
