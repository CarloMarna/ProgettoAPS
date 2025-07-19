import json
from cryptography.fernet import Fernet

from issuer.credential_issuer import CredentialIssuer
from common.exercise_3 import compute_merkle_proofs

with open("data/issuer/esami_holder.json", "r", encoding="utf-8") as f:
    esami_per_holder = json.load(f)

if __name__ == "__main__":
    print("Preparazione Verifiable Credential per lo studente...")

    # === Step 1: Carica risposta challenge dello studente ===
    with open("data/challenge_issuer_holder/challenge_response.json", "r") as f:
        response = json.load(f)

    challenge = response["original_challenge"]
    holder_dn = challenge["aud"]

    print(f" Holder DN: {holder_dn}")

    # === Step 2: Carica la chiave di sessione derivata ===
    with open("data/challenge_issuer_holder/key/session_key_issuer.shared", "rb") as f:
        session_key = f.read()

    fernet = Fernet(session_key)

    # === Step 3: Attributi accademici ===
    print("\nCaricamento degli attributi accademici dello studente...")
    attributes = esami_per_holder.get(holder_dn)

    if not attributes:
        raise ValueError(f"Nessun attributo trovato per lo studente con DN: {holder_dn}")

    print(f" Numero attributi nella VC: {len(attributes)}")


    # === Step 4: Emissione della VC ===
    issuer = CredentialIssuer(
        issuer_dn="CN=University of Rennes, O=RENES, C=FR",
        cert_path="issuer/cert/issuer_cert.pem",
        private_key_path="issuer/cert/issuer_private_key.pem",
        schema_url="data/issuer/schemes/scheme.json",
        revocation_registry="data/ocsp/ocsp_registry.json"
    )

    vc, serialized_attrs, tree = issuer.issue(holder_dn, attributes)

    print("\nVerifiable Credential firmata correttamente.")
    print(f" ID credenziale: {vc['ID_C']}")
    print(f" Merkle Root: {vc['merkle']['root'][:40]}...")
    print(f" Firma VC (σ): {vc['signature']['signatureValue'][:40]}...")
    print(f" Revocation ID: {vc['revocation']['revocationId'][:40]}...")

    # === Step 5: Calcolo delle Merkle proof π_i ===
    proofs_with_index = compute_merkle_proofs(tree[0], tree)
    print(f" Merkle tree costruito e {len(proofs_with_index)} prove generate.")

    # === Step 6: Costruzione del payload cifrato ===
    payload = {
        "VC": vc,
        "attributes": serialized_attrs,
        "proofs": proofs_with_index
    }

    encrypted_payload = fernet.encrypt(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )

    # === Step 7: Salvataggio del pacchetto cifrato ===
    with open("data/challenge_issuer_holder/vc_payload.enc", "wb") as f:
        f.write(encrypted_payload)

    print("\nPacchetto VC cifrato salvato in 'data/vc_payload.enc'")
    print("Procedura completata con successo.")
