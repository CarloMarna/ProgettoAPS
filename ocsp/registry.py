from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import os
import json

class OCSPRegistry:
    def __init__(self, filepath: str = "data/ocsp/ocsp_registry.json"):
        self.filepath = filepath
        self.private_key_path = "ocsp/cert/ocsp_private_key.pem"
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

    def register(self, revocation_id: str, signature_hex: str, cert_path: str ):
        """Verifica la firma sul revocationId usando il certificato locale"""
        try:
            with open(cert_path, "rb") as f:
                cert_bytes = f.read()
                cert = x509.load_pem_x509_certificate(cert_bytes)
                public_key = cert.public_key()
                cert_fingerprint = cert.fingerprint(hashes.SHA256())

            # Costruisci lo stesso digest
            digest = hashes.Hash(hashes.SHA256())
            digest.update(revocation_id.encode())
            digest.update(cert_fingerprint)
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
                "issuer": cert.subject.rfc4514_string(),
                "timestamp": datetime.utcnow().isoformat(),
                "signature": signature_hex,
                "verified_from": cert_path
            }
            self._save()
            print(f"\n[OCSP]  Revocation ID registrato correttamente.")
        except Exception as e:
            print(f"\n[OCSP]  Errore verifica firma Revocation ID: {e}")

    def revoke(self, revocation_id: str, reason: str = "unspecified"):
        """Revoca una VC marcandola come 'revoked'"""
        self.db[revocation_id] = {
            "status": "revoked",
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        self._save()

    def check_status(self, revocation_id: str) -> dict:
        """
        Costruisce una risposta OCSP firmata digitalmente.
        """
        status_entry = self.db.get(revocation_id)
        if not status_entry:
            status = "unknown"
        else:
            status = status_entry.get("status", "unknown")

        timestamp = datetime.utcnow().isoformat()

        # Firma con la chiave privata del registry
        with open(self.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        message = (revocation_id + status + timestamp).encode()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        final_digest = digest.finalize()

        signature = private_key.sign(
            final_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        response = {
            "revocationId": revocation_id,
            "status": status,
            "timestamp": timestamp,
            "signature": signature.hex()
        }
        return response

