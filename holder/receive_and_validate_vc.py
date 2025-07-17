import json
import copy
from cryptography.fernet import Fernet
from holder.credential_holder import CredentialHolder
import traceback

def load_encrypted_payload(path_enc: str, path_key: str) -> dict:
    """Decifra il payload cifrato usando la session key"""
    with open(path_key, "rb") as f:
        session_key = f.read()
    fernet = Fernet(session_key)

    with open(path_enc, "rb") as f:
        ciphertext = f.read()

    decrypted = fernet.decrypt(ciphertext)
    print("Payload decifrato correttamente.")
    return json.loads(decrypted)

if __name__ == "__main__":
    try:
        # === Step 1: Caricamento e decifratura ===
        payload = load_encrypted_payload(
            path_enc="data/vc_payload.enc",
            path_key="data/challenge_issuer_holder/key/session_key.shared"
        )

        # === Step 2: Ispezione del payload ===
        VC = payload["VC"]
        attributes = payload["attributes"]
        proofs = payload["proofs"]

        # Stampa 
        vc_pretty = copy.deepcopy(payload["VC"])
        vc_pretty["signature"]["signatureValue"] = vc_pretty["signature"]["signatureValue"][:64] + "..."  # primi 64 caratteri
        vc_pretty["signature"]["signedData"] = vc_pretty["signature"]["signedData"][:64] + "..."
        print("\n Verifiable Credential (VC):")
        print(json.dumps(vc_pretty, indent=2))


        print("\n Attributi ricevuti:")
        for i, attr_json in enumerate(attributes):
            print(f"  • Attributo [{i}]:")
            print(json.dumps(json.loads(attr_json), indent=2))

        print("\n Merkle Proofs:")
        for i, proof in enumerate(proofs):
            print(f"  • π_{i}: {proof}")

        # === Step 3: Inizializzazione del CredentialHolder ===
        holder = CredentialHolder(
            private_key_path="holder/cert/holder_private_key.pem",
            cert_path="holder/cert/holder_cert.pem"
        )

        # === Step 4: Carica lo schema e verifica la VC ===
        print("\nAvvio della verifica completa della credenziale...")
        schema = holder.load_default_schema()
        if holder.verify_credential(payload):
            print("La credenziale è valida e archiviata nel wallet.")
        else:
            print("La credenziale NON è valida. Operazione interrotta.")

    except Exception as e:
        print("\n Errore durante l'esecuzione:")
        traceback.print_exc()
