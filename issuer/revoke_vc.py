import json
import os
from ocsp.registry import OCSPRegistry
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

REVOCATION_REGISTRY_PATH = "data/ocsp/ocsp_registry.json"
VC_DIRECTORY = "data/issuer/VC"
PRIVATE_KEY_PATH = "issuer/cert/issuer_private_key.pem"
CERT_PATH = "issuer/cert/issuer_cert.pem"

def carica_vc_disponibili():
    vcs = []
    if not os.path.exists(VC_DIRECTORY):
        print(f"Nessuna VC trovata in {VC_DIRECTORY}")
        return vcs

    for file in os.listdir(VC_DIRECTORY):
        if file.endswith(".json"):
            with open(os.path.join(VC_DIRECTORY, file), "r") as f:
                data = json.load(f)
                vc = data.get("VC", data)
                try:
                    vcs.append((
                        file,
                        vc["ID_C"],
                        vc["revocation"]["revocationId"],
                        vc.get("holder", "N/A")
                    ))
                except KeyError:
                    print(f"  File {file} non contiene VC valida (ID_C o revocationId mancante)")
    return vcs

def seleziona_vc(vcs):
    print("\nCredenziali disponibili per la revoca:")
    for idx, (_, vc_id, _, holder) in enumerate(vcs):
        print(f"{idx + 1}. {vc_id} - {holder}")
    scelta = input("Seleziona il numero della VC da revocare: ")
    try:
        index = int(scelta) - 1
        if index < 0 or index >= len(vcs):
            raise ValueError
        return vcs[index]
    except ValueError:
        print("Scelta non valida.")
        return None

def firma_revoca(revocation_id, reason, cert_path, private_key_path):
    message_dict = {
        "revocation_id": revocation_id,
        "cert_path": cert_path,
        "reason": reason
    }
    message = json.dumps(message_dict, separators=(",", ":"), sort_keys=True).encode()

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

if __name__ == "__main__":
    vcs = carica_vc_disponibili()
    if not vcs:
        print(" Nessuna Verifiable Credential disponibile per la revoca.")
        exit(1)

    selected_vc = seleziona_vc(vcs)
    if not selected_vc:
        exit(1)

    _, vc_id, revocation_id, holder = selected_vc
    motivo = input("Motivo della revoca (invio per 'unspecified'): ") or "unspecified"

    # Firma i dati
    signature = firma_revoca(revocation_id, motivo, CERT_PATH, PRIVATE_KEY_PATH)

    # Chiama OCSP con firma e certificato
    revocation_request = {
        "revocation_id": revocation_id,
        "reason": motivo,
        "cert_path": CERT_PATH,
        "signature": signature
    }

    registry = OCSPRegistry(REVOCATION_REGISTRY_PATH)
    registry.revoke(revocation_request)


