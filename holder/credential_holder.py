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
import time

class CredentialHolder:
    def __init__(self, private_key_path: str, cert_path: str):
        # Carica chiave privata holder
        with open(private_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Carica certificato holder (per eventuali presentazioni selettive)
        with open(cert_path, "rb") as f:
            self.cert_holder = x509.load_pem_x509_certificate(f.read())

        # Chiave HMAC generata localmente per il wallet
        k_wallet_path = "data/holder/wallet/k_wallet.bin"
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

        # Step 1: verifica firma dell’università
        if not verify_signature_VC(VC):
            print(" Firma dell’università non valida.")
            return False
        print(" Firma dell’università valida.")

        # Step 2: validazione schema JSON
        try:
            schema_path = VC["schema"] 
            with open(schema_path, "r") as f:
                schema = json.load(f)
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
        hmac_value = self.compute_local_hmac(VC, attributes, proofs)
        print(" HMAC locale calcolato e pronto per la verifica futura.")
    
        wallet_path = os.path.join("data/holder/wallet", issuer_id + "_id_"+VC["ID_C"][:5])
        os.makedirs(wallet_path, exist_ok=True)

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
                start_time = time.perf_counter()
                break
            else:
                print("Ripeti la selezione degli esami.\n")

        if self.verify_local_integrity(vc, attributes, proofs, vc_hmac):
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
        t_elapsed = (time.perf_counter() - start_time) * 1000
        print(f"[TEMPO] Costruzione presentazione: {t_elapsed:.2f} ms")
        return P_prot


    def validate_schema(self, attributes: List[str], json_schema: dict) -> None:
        """Verifica conformità di ciascun attributo allo schema JSON"""
        import jsonschema
        for i, attr_json in enumerate(attributes):
            data = json.loads(attr_json)
            jsonschema.validate(instance=data, schema=json_schema)
            
    def compute_local_hmac(self, vc: dict, attributes: List[str], proofs: List[dict]) -> bytes:
        """Calcola HMAC sull'intero payload locale (VC, attributi, prove)"""
        data = {
            "VC": vc,
            "attributes": attributes,
            "proofs": proofs
        }
        serialized = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        h = hmac.HMAC(self.k_wallet, hashes.SHA256())
        h.update(serialized)
        return h.finalize()

    def verify_local_integrity(self, vc: dict, attributes: List[str], proofs: List[dict], stored_hmac: bytes) -> bool:
        """Verifica HMAC locale su VC, attributi e proof"""
        data = {
            "VC": vc,
            "attributes": attributes,
            "proofs": proofs
        }
        serialized = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        h = hmac.HMAC(self.k_wallet, hashes.SHA256())
        h.update(serialized)
        try:
            h.verify(stored_hmac)
            return True
        except Exception:
            return False

        