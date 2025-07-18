import os
import json
import argparse
from datetime import timedelta, datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
import hashlib

from common.dh_utils import DH_PARAMS

def create_challenge(role):
    nonce = os.urandom(32).hex()
    issued_at = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    aud = "CN=Mario Rossi, SerialNumber=123456"

    sp = hex(DH_PARAMS[role]["p"])
    ge = str(DH_PARAMS[role]["g"])

    base_dir = os.path.dirname(os.path.dirname(__file__))
    key_path = os.path.join(base_dir, role, "cert", f"{role}_private_key.pem")
    output_path = os.path.join(base_dir, "data", f"challenge_{role}_holder", "challengeHolder.json")

    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Step 1: challenge senza firma
    challenge_dict = {
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "aud": aud,
        "sp": sp,
        "ge": ge,
    }

    # Step 2: serializzazione deterministica per la firma
    json_data = json.dumps(challenge_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(json_data).digest()

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256())
    )

    # Step 3: aggiunta della firma dentro la challenge
    challenge_dict["signature"] = signature.hex()

    # Step 4: scrittura su file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(challenge_dict, f, indent=2)

    print(f"Challenge creata per '{role}' e salvata in '{output_path}'")
    print(f" Nonce:        {nonce}")
    print(f" Issued at:    {issued_at}")
    print(f" Expires at:   {expires_at}")
    print(f" Audience:     {aud}")
    print(f" SP:           {sp[:40]}...")
    print(f" GE:           {ge}")
    print(f" Signature:    {challenge_dict['signature'][:40]}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crea una challenge firmata per issuer o verifier")
    parser.add_argument("role", choices=["issuer", "verifier"], help="Ruolo che firma la challenge")
    args = parser.parse_args()

    create_challenge(args.role)
