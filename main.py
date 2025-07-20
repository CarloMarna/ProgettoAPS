import subprocess
import sys
import os

sys.path.insert(0, os.path.abspath(".")) 

def run(title, command):
    print(f"\n🟢 {title}")
    print("─" * (len(title) + 3))
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError:
        print(f"❌ Errore in: {command}")
        exit(1)
    input("\nPremi INVIO per continuare...\n")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    
    # === 1. Setup: Generazione certificati e password wallet
    run("1. Generazione certificati", "python -m common.generate_certs")
    run("1.1 Generazione password wallet", "python -m holder.genera_password_wallet")

    # === 2. ISSUER → HOLDER
    run("2.1 Issuer invia challenge", "python -m common.create_challenge issuer")
    run("2.2 Holder risponde alla challenge", "python -m holder.respond_to_challenge issuer")
    run("2.3 Issuer verifica risposta e genera chiave DH", "python -m common.process_student_response issuer")
    run("2.4 Holder verifica risposta DH e conferma sessione", "python -m holder.confirm_session")
    run("2.5 Issuer verifica conferma finale e calcola chiave", "python -m issuer.verify_student_confirmation")
    run("2.6 Issuer genera VC e la cifra con la chiave condivisa", "python -m issuer.send_vc_to_holder")
    run("2.7 Holder riceve e valida VC", "python -m holder.receive_and_validate_vc")

    # === 3. VERIFIER → HOLDER
    run("3.1 Verifier invia challenge", "python -m common.create_challenge verifier")
    run("3.2 Holder risponde alla challenge", "python -m holder.respond_to_challenge verifier")
    run("3.3 Verifier verifica risposta e calcola chiave DH", "python -m common.process_student_response verifier")
    run("3.4 Holder verifica risposta ", "python -m holder.process_dh_response")
    run("3.5 Verifier invia challenge selettiva", "python -m verifier.generate_selective_challenge")
    run("3.6 Holder prepara presentazione selettiva", "python -m holder.prepare_presentation")

    # === 4. VERIFIER
    run("4. Verifier verifica presentazione", "python -m verifier.verify_presentation")

    # === 5. Simula Revoca
    run("5.1 Issuer revoca VC", "python -m issuer.revoke_vc")
    run("4. Verifier verifica presentazione", "python -m verifier.verify_presentation")
    print("\nTutto il flusso è stato eseguito con successo.")
