from datetime import datetime

class OCSPRegistry:
    def __init__(self):
        self.db = {}

    def register(self, revocation_id: str):
        """Registra un nuovo revocationId come valido"""
        self.db[revocation_id] = {
            "status": "valid",
            "timestamp": datetime.utcnow().isoformat()
        }

    def revoke(self, revocation_id: str, reason: str = "unspecified"):
        """Revoca una VC marcandola come 'revoked'"""
        self.db[revocation_id] = {
            "status": "revoked",
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }

    def check_status(self, revocation_id: str):
        """Restituisce lo stato della credenziale"""
        return self.db.get(revocation_id, {"status": "unknown"})
