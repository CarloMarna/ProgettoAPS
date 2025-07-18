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
    def register(self, request: dict):
        """
        Registra un nuovo revocation ID solo se la firma è valida.
        Il digest firmato è: SHA256(revocation_id || fingerprint del certificato)
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from datetime import datetime

        revocation_id = request["revocation_id"]
        signature_hex = request["signature"]
        cert_path = request["cert_path"]

        try:
            with open(cert_path, "rb") as f:
                cert_bytes = f.read()
                cert = x509.load_pem_x509_certificate(cert_bytes)
                public_key = cert.public_key()
                cert_fingerprint = cert.fingerprint(hashes.SHA256())

            # Calcola digest da verificare
            digest = hashes.Hash(hashes.SHA256())
            digest.update(revocation_id.encode())
            digest.update(cert_fingerprint)
            final_digest = digest.finalize()

            # Verifica firma
            public_key.verify(
                bytes.fromhex(signature_hex),
                final_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

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

    def revoke(self, request: dict):
        """Revoca una VC autenticata da una firma sul messaggio completo"""

        revocation_id = request["revocation_id"]
        reason = request["reason"]
        cert_path = request["cert_path"]
        signature = request["signature"]

        message_dict = {
            "revocation_id": revocation_id,
            "cert_path": cert_path,
            "reason": reason
        }
        message = json.dumps(message_dict, separators=(",", ":"), sort_keys=True).encode()

        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            public_key = cert.public_key()
        except Exception as e:
            print(f" Errore nel caricamento del certificato: {e}")
            return

        try:
            public_key.verify(
                bytes.fromhex(signature),
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print(" Firma non valida. Revoca rifiutata.")
            return

        # Verifica che l'issuer della richiesta coincida con quello registrato
        issuer_dn = cert.subject.rfc4514_string()
        registered_entry = self.db.get(revocation_id)
        if registered_entry:
            registered_issuer = registered_entry.get("issuer")
            if registered_issuer != issuer_dn:
                print(f" Issuer non autorizzato.")
                return

        # Se esiste già, aggiorna solo i campi necessari
        entry = self.db.get(revocation_id, {})
        entry["status"] = "revoked"
        entry["reason"] = reason
        entry["timestamp"] = datetime.utcnow().isoformat()

        self.db[revocation_id] = entry
        self._save()
        print(f" Revoca accettata per {revocation_id}.")


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
        path_cert = "ocsp/cert/ocsp_cert.pem"

        # Firma con la chiave privata del registry
        with open(self.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        message = (revocation_id + status + timestamp + path_cert).encode()

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
            "path_cert": path_cert,
            "signature": signature.hex()
        }
        return response

