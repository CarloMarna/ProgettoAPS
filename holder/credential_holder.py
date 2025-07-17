import json
import os
from typing import List, Tuple
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from common.exercise_3 import sha256


class CredentialHolder:
    def __init__(self, private_key_path: str, cert_path: str):
        # Carica chiave privata holder
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Carica certificato holder (per eventuali presentazioni selettive)
        with open(cert_path, "rb") as f:
            self.cert_holder = x509.load_pem_x509_certificate(f.read())

        # Chiave HMAC generata localmente per il wallet
        self.k_wallet = os.urandom(32)

    def verify_credential(self, payload: dict) -> bool:
        """Esegue tutti i controlli sulla VC ricevuta"""
        VC = payload["VC"]
        attributes = payload["attributes"]
        proofs = payload["proofs"]

        # Step 1: verifica firma dell’università
        if not self.verify_signature(VC):
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
        for i, (attr_json, proof) in enumerate(zip(attributes, proofs)):
            h_i = sha256(attr_json)
            if not self.verify_merkle_proof(h_i, proof, merkle_root, i):
                print(f" π_{i} NON valida per attributo {i}")
                return False
            print(f" π_{i} valida per attributo {i}")

        # Step 4: salva HMAC locale nel wallet
        hmac_value = self.compute_local_hmac(VC)
        with open("data/wallet/vc_hmac.bin", "wb") as f:
            f.write(hmac_value)
        print("\nHMAC locale salvato in 'data/wallet/vc_hmac.bin'")

        with open("data/wallet/valid_vc.json", "w") as f:
            json.dump(VC, f, indent=2)
        print("VC salvata nel wallet: data/wallet/valid_vc.json")


        return True

    def verify_signature(self, vc: dict) -> bool:
        """Verifica la firma hash-then-sign dell’università"""
        signed_data = vc["signature"]["signedData"]
        signature = bytes.fromhex(vc["signature"]["signatureValue"])

        with open("issuer/cert/issuer_cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            pk_issuer = cert.public_key()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(signed_data.encode())
        final_digest = digest.finalize()

        try:
            pk_issuer.verify(
                signature,
                final_digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

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

    def prepare_presentation(self, vc: dict, attr_json: str, merkle_tree: List[List[str]], leaf_index: int, nonce: str, timestamp: str, expiration: str) -> dict:
        """Prepara presentazione selettiva protetta P_prot"""
        attr_dict = json.loads(attr_json)
        h_i = sha256(attr_json)

        # Ricava π_i = lista degli hash fratelli
        proof = []
        index = leaf_index
        for level in merkle_tree[:-1]:
            if index % 2 == 0:
                sibling_index = index + 1 if index + 1 < len(level) else index
            else:
                sibling_index = index - 1
            proof.append(level[sibling_index])
            index //= 2

        # Firma del pacchetto P_prot senza la firma_holder
        P_prot_unsigned = {
            "ID_C": vc["ID_C"],
            "issuer": vc["issuer"],
            "holder": vc["holder"],
            "expirationDate": vc["expirationDate"],
            "schema": vc["schema"],
            "m_i": attr_dict,
            "π_i": proof,
            "MerkleRoot": vc["merkle"]["root"],
            "signature": vc["signature"],
            "revocation": vc["revocation"],
            "nonce": nonce,
            "timestamp": timestamp,
            "expiration": expiration,
            "cert_holder": self.cert_holder.public_bytes(serialization.Encoding.PEM).decode()
        }

        digest = hashes.Hash(hashes.SHA256())
        digest.update(json.dumps(P_prot_unsigned, separators=(",", ":"), sort_keys=True).encode())
        digest_final = digest.finalize()

        signature_holder = self.private_key.sign(
            digest_final,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        P_prot_unsigned["signature_holder"] = signature_holder.hex()
        return P_prot_unsigned

    def encrypt_presentation(self, P_prot: dict, session_key: bytes) -> bytes:
        """Cifra simmetricamente P_prot con chiave di sessione R"""
        f = Fernet(session_key)
        serialized = json.dumps(P_prot, separators=(",", ":"), sort_keys=True)
        return f.encrypt(serialized.encode())

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
    def verify_merkle_proof(h_i: bytes, proof: List[str], root: str, index: int) -> bool:
        """Verifica che h_i + π_i risalga alla Merkle Root"""
        current_hash = h_i
        for sibling in proof:
            if index % 2 == 0:
                current_hash = sha256(current_hash + sibling)
            else:
                current_hash = sha256(sibling + current_hash)
            index //= 2
        return current_hash == root

    @staticmethod
    def validate_schema(attributes: List[str], json_schema: dict) -> None:
        """Verifica conformità di ciascun attributo allo schema JSON"""
        import jsonschema
        for i, attr_json in enumerate(attributes):
            data = json.loads(attr_json)
            jsonschema.validate(instance=data, schema=json_schema)