import os
import hashlib
import base64
import json
import sys

def crea_password_hash(password):
    salt = os.urandom(16) 
    hash_pwd = hashlib.sha256(salt + password.encode()).hexdigest()
    return {
        "salt": base64.b64encode(salt).decode(),  
        "hash": hash_pwd
    }

password_file_path = "data/holder/wallet/password_data.json"

if os.path.exists(password_file_path):
    print(f"  Una password esiste già in '{password_file_path}'. Operazione annullata.")
    print("   Se vuoi cambiarla, elimina prima il file manualmente.")
    sys.exit(0)  

password_in_chiaro = input("Imposta la password per il wallet: ")

password_data = crea_password_hash(password_in_chiaro)
os.makedirs("data/holder/wallet", exist_ok=True)

with open(password_file_path, "w") as f:
    json.dump(password_data, f)

print(" Password hashata e salvata in 'data/holder/wallet/password_data.json'")
