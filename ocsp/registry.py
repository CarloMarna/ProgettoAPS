from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import os
import json

class OCSPRegistry:
    def __init__(self, filepath="data/ocsp/ocsp_registry.json"):
        self.filepath = filepath
        self.db = self._load()

    def _load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {}
        return {}

    def _save(self):
        with open(self.filepath, "w") as f:
            json.dump(self.db, f, indent=2)

    def register(self, revocation_id: str, signature_hex: str, cert_path: str):
        """Verifica la firma sul revocationId usando il certificato locale"""
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                public_key = cert.public_key()

            # Verifica la firma con hash-then-sign (più sicuro)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(revocation_id.encode())
            final_digest = digest.finalize()

            public_key.verify(
                bytes.fromhex(signature_hex),
                final_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Se la verifica riesce, salva
            self.db[revocation_id] = {
                "status": "valid",
                "timestamp": datetime.utcnow().isoformat(),
                "verified_from": cert_path
            }
            self._save()
            print(f"[OCSP]  Revocation ID registrato correttamente.")
        except Exception as e:
            print(f"[OCSP]  Errore verifica firma Revocation ID: {e}")

    def revoke(self, revocation_id: str, reason: str = "unspecified"):
        """Revoca una VC marcandola come 'revoked'"""
        self.db[revocation_id] = {
            "status": "revoked",
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        self._save()

    def check_status(self, revocation_id: str):
        """Restituisce lo stato della credenziale"""
        return self.db.get(revocation_id, {"status": "unknown"})
