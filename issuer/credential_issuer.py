import uuid  # per generare un ID_C univoco
import os    # per generare salt casuale
import json  # per serializzare attributi
from typing import List, Tuple  # per annotazioni di tipo

from cryptography import x509  # per gestire certificati
from cryptography.hazmat.primitives import hashes, serialization  # per hash e chiavi
from cryptography.hazmat.primitives.asymmetric import padding  # per padding RSA PSS

from common.exercise_3 import build_merkle_tree, sha256  # Merkle Tree dal codice del professore
from ocsp.registry import OCSPRegistry  # per la gestione della revoca

class CredentialIssuer:
    def __init__(self,
                 issuer_dn: str,
                 cert_path: str,
                 private_key_path: str,
                 schema_url: str,
                 revocation_registry: str):

        self.issuer_dn = issuer_dn                          # Distinguished Name dell'università
        self.schema_url = schema_url                        # URL dello schema JSON ufficiale
        self.revocation_registry = revocation_registry      # Endpoint OCSP per verifica revoca
        self.expiration_date = "2028-03-15T10:30:00Z"       # Scadenza della credenziale
        self.ocsp_registry = OCSPRegistry()            # Registry per OCSP

        # Carica il certificato dell’università per estrarre l'URL di verifica
        with open(cert_path, "rb") as f:
            self.verification_method = cert_path

        # Carica la chiave privata dell’università da file PEM per firmare i dati
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    def serialize_attribute(self, attr_dict: dict) -> str:
        # Serializza in JSON compatto e ordinato l'attributo m_i
        return json.dumps(attr_dict, separators=(",", ":"), sort_keys=True)

    def generate_revocation_id(self, id_c: str, salt: bytes) -> str:
        # Calcola revocationId = H(ID_C ∥ issuer_DN ∥ salt) per unicità e non correlabilità
        digest = hashes.Hash(hashes.SHA256())
        digest.update(id_c.encode())
        digest.update(self.issuer_dn.encode())
        digest.update(salt)
        return digest.finalize().hex()

    def sign_metadata_digest(self, data: str) -> str:
        # Applica hash SHA-256 ai dati concatenati
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode())
        final_digest = digest.finalize()

        # Firma il digest con la chiave privata dell’università (RSA-PSS)
        signature = self.private_key.sign(
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # MGF1 con SHA256
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()  # ritorna la firma in formato esadecimale

    def issue(self, holder_dn: str, attributes: List[dict]) -> Tuple[dict, List[str], List[List[str]]]:
        # Serializza gli attributi accademici in JSON (m_i → stringa)
        serialized = [self.serialize_attribute(attr) for attr in attributes]

        # Costruisce il Merkle Tree e ottiene la radice
        merkle_root, tree = build_merkle_tree(serialized)

        # Genera un identificatore univoco per la credenziale
        id_c = str(uuid.uuid4())

        # Genera un salt sicuro per la creazione del revocationId
        salt = os.urandom(16)

        # Calcola l’identificatore di revoca crittograficamente sicuro
        revocation_id = self.generate_revocation_id(id_c, salt)
        revocation_id_signature = self.private_key.sign(
            revocation_id.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
       
        self.ocsp_registry.register( revocation_id, revocation_id_signature.hex(), self.verification_method)

        print("\nCredenziale aggiunta al registro di revoca OCSP")
        # Costruisce la stringa da firmare con hash-then-sign
        signed_data = f"{merkle_root}∥{id_c}∥{self.issuer_dn}∥{holder_dn}∥{self.schema_url}∥{self.expiration_date}∥{revocation_id}∥{self.revocation_registry}"

        # Calcola la firma digitale dell’università
        signature = self.sign_metadata_digest(signed_data)

        # Costruisce l'intera Verifiable Credential (VC)
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
            "signature": {
                "signatureValue": signature,
                "signedData": signed_data,
                "verificationMethod": self.verification_method
            },
            "revocation": {
                "revocationId": revocation_id,
                "registry": self.revocation_registry
            }
        }

        return VC, serialized, tree
