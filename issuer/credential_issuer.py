import uuid
import os
import json
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from common.exercise_3 import build_merkle_tree
from ocsp.registry import OCSPRegistry


class CredentialIssuer:
    def __init__(self,
                 issuer_dn: str,
                 cert_path: str,
                 private_key_path: str,
                 schema_url: str,
                 revocation_registry: str):

        self.issuer_dn = issuer_dn
        self.schema_url = schema_url
        self.revocation_registry = revocation_registry
        self.expiration_date = "2028-03-15T10:30:00Z"
        self.ocsp_registry = OCSPRegistry(revocation_registry)
        self.verification_method = cert_path  

        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    def serialize_attribute(self, attr_dict: dict) -> str:
        return json.dumps(attr_dict, separators=(",", ":"), sort_keys=True)

    def generate_revocation_id(self, id_c: str, salt: bytes) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(id_c.encode())
        digest.update(self.issuer_dn.encode())
        digest.update(salt)
        return digest.finalize().hex()

    def issue(self, holder_dn: str, attributes: List[dict]) -> Tuple[dict, List[str], List[List[str]]]:
        # === Step 1: Serializza gli attributi m_i
        serialized = [self.serialize_attribute(attr) for attr in attributes]

        # === Step 2: Costruisce il Merkle Tree
        merkle_root, tree = build_merkle_tree(serialized)

        # === Step 3: Genera ID e salt per revoca
        id_c = str(uuid.uuid4())
        salt = os.urandom(16)
        revocation_id = self.generate_revocation_id(id_c, salt)

        # === Step 4: Firma revocation_id + fingerprint del certificato
        with open(self.verification_method, "rb") as f:
            cert_bytes = f.read()
            cert = x509.load_pem_x509_certificate(cert_bytes)
            cert_fingerprint = cert.fingerprint(hashes.SHA256())

        digest = hashes.Hash(hashes.SHA256())
        digest.update(revocation_id.encode())
        digest.update(cert_fingerprint)
        final_digest = digest.finalize()

        revocation_id_signature = self.private_key.sign(
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        message = {
            "revocation_id": revocation_id,
            "signature": revocation_id_signature.hex(),
            "cert_path": self.verification_method
        }

        # === Step 5: Registra la revoca su OCSP
        self.ocsp_registry.register(message)

        # === Step 6: Crea VC senza firma
        VC = {
            "ID_C": id_c,
            "issuer": self.issuer_dn,
            "holder": holder_dn,
            "expirationDate": self.expiration_date,
            "schema": self.schema_url,
            "merkle": {
                "root": merkle_root,
                "hashAlgorithm": "SHA-256"
            },
            "revocation": {
                "revocationId": revocation_id,
                "registry": self.revocation_registry
            },

            "signature": {
                "verificationMethod": self.verification_method
            }
        }

        # === Step 7: Firma VC 
        vc_serialized = json.dumps(VC, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(vc_serialized)
        final_digest = digest.finalize()

        signature = self.private_key.sign(
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )

        # === Step 8: Aggiunge la firma + signedData alla VC
        VC["signature"]["signatureValue"] = signature.hex()

        # === Step 9: Salva la VC su file
        vc_path = os.path.join("data/issuer/VC", f"{id_c}.json")
        os.makedirs(os.path.dirname(vc_path), exist_ok=True)
        with open(vc_path, "w") as f:
            json.dump(VC, f, indent=2)

        return VC, serialized, tree
