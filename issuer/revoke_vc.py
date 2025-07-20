import json
import os
from ocsp.registry import OCSPRegistry
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

REVOCATION_REGISTRY_PATH = "data/ocsp/ocsp_registry.json"
VC_DIRECTORY = "data/issuer/VC"
PRIVATE_KEY_PATH = "issuer/cert/issuer_private_key.pem"
CERT_PATH = "issuer/cert/issuer_cert.pem"

def carica_ultima_vc():
    vc_files = [
        os.path.join(VC_DIRECTORY, file)
        for file in os.listdir(VC_DIRECTORY)
        if file.endswith(".json")
    ]

    if not vc_files:
        return None

    vc_files.sort(key=os.path.getmtime, reverse=True)
    latest_file = vc_files[0]

    with open(latest_file, "r") as f:
        data = json.load(f)
        vc = data.get("VC", data)
        try:
            return (
                os.path.basename(latest_file),
                vc["ID_C"],
                vc["revocation"]["revocationId"],
                vc.get("holder", "N/A")
            )
        except KeyError:
            print(f"File {latest_file} non contiene VC valida.")
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
    selected_vc = carica_ultima_vc()

    _, vc_id, revocation_id, holder = selected_vc
    motivo = input("Motivo della revoca: ") or "unspecified"

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


