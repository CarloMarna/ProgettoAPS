import json
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from common.exercise_3 import sha256, verify_merkle_proof
from common.crypto_utils import verify_signature_VC
from typing import List
from cryptography.hazmat.primitives.asymmetric import utils
import copy


class CredentialHolder:
    def __init__(self, private_key_path: str, cert_path: str):
        # Carica chiave privata holder
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Carica certificato holder (per eventuali presentazioni selettive)
        with open(cert_path, "rb") as f:
            self.cert_holder = x509.load_pem_x509_certificate(f.read())

        # Chiave HMAC generata localmente per il wallet
        k_wallet_path = "data/wallet/k_wallet.bin"
        if os.path.exists(k_wallet_path):
            with open(k_wallet_path, "rb") as f:
                self.k_wallet = f.read()
        else:
            self.k_wallet = os.urandom(32)
            os.makedirs(os.path.dirname(k_wallet_path), exist_ok=True)
            with open(k_wallet_path, "wb") as f:
                f.write(self.k_wallet)
    def verify_credential(self, payload: dict) -> bool:
        """Esegue tutti i controlli sulla VC ricevuta"""
        VC = payload["VC"]
        attributes = payload["attributes"]
        proofs = payload["proofs"]

        issuer_dn = VC["issuer"]
        issuer_id = issuer_dn.lower().replace("cn=", "").replace(",", "").replace(" ", "-")
        wallet_path = os.path.join("data/wallet", issuer_id)
        os.makedirs(wallet_path, exist_ok=True)

        # Step 1: verifica firma dell’università
        if not verify_signature_VC(VC):
            print(" Firma dell’università non valida.")
            return False
        print(" Firma dell’università valida.")

        # Step 2: validazione schema JSON
        try:
            schema = self.load_default_schema()
            self.validate_schema(attributes, schema)
        except Exception as e:
            print(f" Errore nella validazione schema: {e}")
            return False
        print(" Tutti gli attributi sono conformi allo schema.")

        # Step 3: verifica Merkle proof per ogni attributo
        merkle_root = VC["merkle"]["root"]
        for i, (attr_json, proof_entry) in enumerate(zip(attributes, proofs)):
            h_i = sha256(attr_json)
            index = proof_entry["index"]
            proof = proof_entry["proof"]
            if not verify_merkle_proof(h_i, proof, merkle_root, index):
                print(f" π_{i} NON valida per attributo {i} (indice Merkle: {index})")
                return False
            print(f" π_{i} valida per attributo {i} (indice Merkle: {index})")

        # Step 4: salva HMAC locale nel wallet
        hmac_value = self.compute_local_hmac(VC)
    
        with open(os.path.join(wallet_path, "valid_vc.json"), "w") as f:
            json.dump(VC, f, indent=2)

        with open(os.path.join(wallet_path, "attributes.json"), "w") as f:
            json.dump(attributes, f, indent=2)

        with open(os.path.join(wallet_path, "proofs.json"), "w") as f:
            json.dump(proofs, f, indent=2)

        with open(os.path.join(wallet_path, "vc_hmac.bin"), "wb") as f:
            f.write(hmac_value)

    
        print("\nTutte le informazioni sono state salvate nel wallet.")
        return True

    def compute_local_hmac(self, vc: dict) -> bytes:
        """Calcola e salva HMAC della VC per protezione locale"""
        vc_bytes = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode()
        h = hmac.HMAC(self.k_wallet, hashes.SHA256())
        h.update(vc_bytes)
        return h.finalize()

    def verify_local_integrity(self, vc: dict, stored_hmac: bytes) -> bool:
        """Verifica HMAC locale con confronto a tempo costante"""
        vc_bytes = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode()
        h = hmac.HMAC(self.k_wallet, hashes.SHA256())
        h.update(vc_bytes)
        try:
            h.verify(stored_hmac)
            return True
        except Exception:
            return False
    def prepare_presentation(self, vc: dict, vc_hmac: bytes, attributes: List[str], proofs: List[List[str]], nonce: str, issued_at: str, expires_at: str, aud: str) -> dict:
        while True:
            print("\nEsami disponibili:")
            for i, attr in enumerate(attributes):
                esame = json.loads(attr)["nome_esame"]
                print(f" [{i}] {esame}")

            scelti = input("Inserisci gli indici separati da virgola degli esami da presentare: ")
            try:
                indici = [int(x.strip()) for x in scelti.split(",")]
                if any(i < 0 or i >= len(attributes) for i in indici):
                    print(" Alcuni indici sono fuori dal range. Riprova.\n")
                    continue
            except ValueError:
                print(" Input non valido. Usa solo numeri separati da virgole.\n")
                continue

            #m_i = [json.loads(attributes[i]) for i in indici]
            m_i = [attributes[i] for i in indici]
            π_i = [proofs[i] for i in indici]

            print("\nHai selezionato i seguenti esami:")
            for m in m_i:
                m_dict = json.loads(m)
                print(f" - {m_dict['nome_esame']} ({m_dict['cod_corso']}, voto: {m_dict['voto']})")

            conferma = input("Vuoi procedere con la creazione del certificato? (s/n): ").lower()
            if conferma == "s":
                break
            else:
                print("Ripeti la selezione degli esami.\n")

        if self.verify_local_integrity(vc, vc_hmac):
            print("\nIntegrità della VC verificata con successo. \n")
        else:
            print("\nIntegrità della VC compromessa. Non è possibile procedere.")
            return None
        
        # Costruzione presentazione
        P_prot = {
            "Credenziale": vc,
            "m_i": m_i,
            "π_i": π_i,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "aud": aud,
        }

        P_prot_to_sign = copy.deepcopy(P_prot) 
        del P_prot_to_sign["Credenziale"]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(json.dumps(P_prot_to_sign, separators=(",", ":"), sort_keys=True).encode())
        final_digest = digest.finalize()

        signature = self.private_key.sign(
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )

        P_prot["signature_holder"] = signature.hex()
        return P_prot

#QUESTI NON DEVONO STARE QUI
    @staticmethod
    def load_default_schema() -> dict:
        """Restituisce lo schema JSON ufficiale degli attributi accademici"""
        return {
            "type": "object",
            "required": [
                "nome_esame", "cod_corso", "CFU", "voto", "data",
                "anno_accademico", "tipo_esame", "docente", "lingua"
            ],
            "properties": {
                "nome_esame": {"type": "string"},
                "cod_corso": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9_\\-]{2,10}$"
                },
                "CFU": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30
                },
                "voto": {
                    "type": "string",
                    "pattern": "^(18|19|2[0-9]|30|30L)$"
                },
                "data": {
                    "type": "string",
                    "format": "date"
                },
                "anno_accademico": {
                    "type": "string",
                    "pattern": "^[0-9]{4}/[0-9]{4}$"
                },
                "docente": {"type": "string"},
                "lingua": {
                    "type": "string",
                    "enum": ["IT", "EN", "FR", "DE", "ES"]
                },
                "tipo_esame": {
                    "type": "string",
                    "enum": ["scritto", "orale", "progetto", "misto"]
                }
            },
            "additionalProperties": False
        }

    @staticmethod
    def validate_schema(attributes: List[str], json_schema: dict) -> None:
        """Verifica conformità di ciascun attributo allo schema JSON"""
        import jsonschema
        for i, attr_json in enumerate(attributes):
            data = json.loads(attr_json)
            jsonschema.validate(instance=data, schema=json_schema)