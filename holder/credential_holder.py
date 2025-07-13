import json
import base64
import os
import hmac as hmac_builtin
from typing import List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from common.exercise_3 import sha256, verify_data


class CredentialHolder:
    def __init__(self, private_key_path: str, cert_path: str):
        # Carica chiave privata holder (sk_holder)
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Carica certificato holder (usato per presentazione)
        with open(cert_path, "rb") as f:
            self.cert_holder = x509.load_pem_x509_certificate(f.read())

        # HMAC key memorizzata localmente e protetta (es. Secure Enclave)
        self.k_wallet = os.urandom(32)

    def decrypt_payload(self, encrypted_payload: bytes, session_key: bytes) -> Tuple[dict, List[str], List[List[str]]]:
        """Decifra VC + attributi + proof con chiave R"""
        f = Fernet(session_key)
        decrypted = f.decrypt(encrypted_payload).decode()
        obj = json.loads(decrypted)
        return obj["VC"], obj["attributes"], obj["merkle_tree"]

    def validate_schema(self, attributes: List[str], json_schema: dict) -> bool:
        """Controlla che gli attributi siano conformi allo schema JSON"""
        import jsonschema
        for attr_json in attributes:
            data = json.loads(attr_json)
            jsonschema.validate(instance=data, schema=json_schema)
        return True

    def verify_signature(self, vc: dict) -> bool:
        """Verifica la firma hash-then-sign dell'università"""
        verification_method = vc["signature"]["verificationMethod"]
        signed_data = vc["signature"]["signedData"]
        signature = bytes.fromhex(vc["signature"]["signatureValue"])

        # Scarica o carica localmente il certificato issuer
        with open("issuer/issuer_cert.pem", "rb") as f:
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
