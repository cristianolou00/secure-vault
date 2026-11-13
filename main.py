"""
Aplicação Principal - Fase 1: Motor Criptográfico e Armazenamento Binário

Este script permite testar diretamente no terminal todos os conceitos da Fase 1:
1. Criação e inicialização de um cofre com derivação de chave Argon2id.
2. Inspecção do ficheiro binário gerado (Magic Bytes, Salt, Nonce, Ciphertext).
3. Desbloqueio e leitura com a palavra-passe mestre correta.
4. Teste de segurança contra senhas erradas (rejeição com DecryptionError).
5. Teste de adulteração (Bit-Flipping test): alteração de 1 único byte no disco
   para demonstrar como a Authentication Tag do AES-256-GCM impede ataques.
"""

import os
import sys
import time
import getpass
from datetime import datetime, timezone
from vault.storage import VaultStorage, MAGIC_BYTES, VAULT_VERSION
from vault.crypto import DecryptionError, SecurityError

DEFAULT_VAULT_PATH = "meu_cofre.vault"


def print_banner():
    print("=" * 65)
    print("       COFRE CRIPTOGRÁFICO LOCAL (FASE 1: MOTOR DE SEGURANÇA)    ")
    print("=" * 65)
    print(" * Criptografia : AES-256-GCM (Autenticada com AAD)")
    print(" * Derivação KDF: Argon2id (64 MiB RAM, 2 iterações, 4 lanes)")
    print(" * Formato Disco: Binário Estruturado (.vault)")
    print(" * Higiene RAM  : Limpeza com ctypes.memset(0)")
    print("=" * 65)


def format_hex_dump(data: bytes, max_bytes: int = 48) -> str:
    """Formata bytes para exibição legível em hexadecimal no terminal."""
    preview = data[:max_bytes]
    hex_str = " ".join(f"{b:02X}" for b in preview)
    if len(data) > max_bytes:
        hex_str += f" ... (+{len(data) - max_bytes} bytes)"
    return hex_str


def action_inspect_vault(filepath: str = DEFAULT_VAULT_PATH):
    """Lê o cabeçalho binário em baixo nível e mostra a estrutura do ficheiro."""
    if not os.path.exists(filepath):
        print(f"\n[!] O ficheiro '{filepath}' ainda não existe.")
        return

    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        content = f.read()

    print(f"\n--- INSPEÇÃO DO FICHEIRO BINÁRIO: {filepath} ({file_size} bytes) ---")
    print(f" * Magic Bytes (4B) : {content[0:4]} -> {format_hex_dump(content[0:4])}")
    print(f" * Versão (2B)      : {int.from_bytes(content[4:6], 'big')} -> {format_hex_dump(content[4:6])}")
    print(f" * Salt Argon2 (16B): {format_hex_dump(content[6:22])}")
    print(f" * Nonce GCM (12B)  : {format_hex_dump(content[22:34])}")
    print(f" * Ciphertext + Tag : {format_hex_dump(content[34:])}")
    print("------------------------------------------------------------------\n")


def action_create_vault():
    """Inicializa um novo cofre no disco com senha mestre."""
    filepath = DEFAULT_VAULT_PATH
    if os.path.exists(filepath):
        confirm = input(f"[?] O ficheiro '{filepath}' já existe. Desejas substituí-lo? (s/n): ").strip().lower()
        if confirm != "s":
            print("Operação cancelada.")
            return
        os.remove(filepath)

    print("\n--- CRIAÇÃO DE NOVO COFRE ---")
    pwd1 = getpass.getpass("Define a tua Palavra-passe Mestre: ")
    if not pwd1:
        print("[!] A senha não pode estar vazia.")
        return

    pwd2 = getpass.getpass("Confirma a Palavra-passe Mestre: ")
    if pwd1 != pwd2:
        print("[!] As palavras-passe não coincidem!")
        return

    print("\n[+] A derivar chave com Argon2id (alocação de 64MB de RAM)...")
    start_time = time.perf_counter()

    initial_payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "vault_name": "Cofre Pessoal Seguro",
        "description": "Fase 1 operacional com sucesso.",
        "entries": {
            "exemplo_github": {
                "title": "GitHub Pessoal",
                "username": "estudante_multimedia",
                "password": "SenhaSuperSecreta123!#",
                "url": "https://github.com",
                "notes": "Criado durante o teste da Fase 1"
            }
        }
    }

    VaultStorage.create_new_vault(filepath, pwd1, initial_payload)
    elapsed = time.perf_counter() - start_time

    print(f"[✓] Cofre criado com sucesso em '{filepath}'!")
    print(f"[i] Tempo de derivação Argon2id: {elapsed:.3f} segundos.")
    print("    (Este custo de tempo e memória é intencional para inviabilizar ataques de força bruta)")
    action_inspect_vault(filepath)


def action_unlock_vault():
    """Desbloqueia e lê o conteúdo de um cofre existente."""
    filepath = DEFAULT_VAULT_PATH
    if not os.path.exists(filepath):
        print(f"\n[!] Ficheiro '{filepath}' não encontrado. Cria um primeiro.")
        return

    print(f"\n--- DESBLOQUEAR COFRE: {filepath} ---")
    pwd = getpass.getpass("Introduz a Palavra-passe Mestre: ")

    start_time = time.perf_counter()
    try:
        data = VaultStorage.load_vault(filepath, pwd)
        elapsed = time.perf_counter() - start_time
        print(f"\n[✓] Cofre Desbloqueado com Sucesso! ({elapsed:.3f}s)")
        print(f"Nome do Cofre : {data.get('vault_name')}")
        print(f"Data Criação  : {data.get('created_at')}")
        print(f"Total Entradas: {len(data.get('entries', {}))}")
        print("\nConteúdo desencriptado:")
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except DecryptionError as exc:
        print(f"\n[X] ACESSO NEGADO: {exc}")
    except SecurityError as exc:
        print(f"\n[X] ERRO DE SEGURANÇA: {exc}")


def action_test_tampering():
    """
    Demonstra a segurança do AES-256-GCM.
    Altera 1 único bit no meio do ficheiro encriptado e tenta abrir com a senha correta.
    """
    filepath = DEFAULT_VAULT_PATH
    if not os.path.exists(filepath):
        print(f"[!] Cria um cofre primeiro para realizar o teste.")
        return

    pwd = getpass.getpass("Introduz a tua senha correta para testar a resistência a adulteração: ")

    # Testa se a senha abre o ficheiro original primeiro
    try:
        VaultStorage.load_vault(filepath, pwd)
    except DecryptionError:
        print("[!] Senha incorreta. Teste abortado.")
        return

    print("\n[i] A clonar o cofre para 'teste_adulterado.vault' e alterar exatamente 1 BYTE...")
    with open(filepath, "rb") as f:
        raw_bytes = bytearray(f.read())

    # Modifica o último byte do ciphertext/tag
    raw_bytes[-1] ^= 0xFF

    tampered_path = "teste_adulterado.vault"
    with open(tampered_path, "wb") as f:
        f.write(raw_bytes)

    print(f"[i] Ficheiro corrompido criado. A tentar desencriptar com a senha mestre CORRETA...")
    try:
        VaultStorage.load_vault(tampered_path, pwd)
        print("[X] FALHA CRÍTICA: O ficheiro adulterado foi aceite!")
    except DecryptionError as exc:
        print(f"[✓] SUCESSO DO TESTE: A Authentication Tag do AES-GCM detetou a adulteração!")
        print(f"    Mensagem: {exc}")
    finally:
        if os.path.exists(tampered_path):
            os.remove(tampered_path)


def main():
    # Se passar argumento --cli, executa no terminal
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("--cli", "-c", "cli"):
        print_banner()
        while True:
            print("\nMENU PRINCIPAL (MODO CLI / TERMINAL):")
            print("1. Criar novo cofre (.vault)")
            print("2. Desbloquear e ler cofre existente")
            print("3. Inspecionar estrutura binária do ficheiro")
            print("4. Teste de Adulteração (Bit-Flipping / AES-GCM Tag Check)")
            print("0. Sair")

            choice = input("\nEscolhe uma opção (0-4): ").strip()
            if choice == "1":
                action_create_vault()
            elif choice == "2":
                action_unlock_vault()
            elif choice == "3":
                action_inspect_vault()
            elif choice == "4":
                action_test_tampering()
            elif choice == "0":
                print("\nA encerrar. Até já!")
                break
            else:
                print("[!] Opção inválida.")
    else:
        # Por padrão, abre a aplicação gráfica nativa para Desktop!
        try:
            from app import SecureVaultApp
            print("[+] A iniciar a aplicação gráfica SecureVault no Desktop...")
            app = SecureVaultApp()
            app.mainloop()
        except ImportError as e:
            print(f"[!] Não foi possível carregar a interface gráfica ({e}). A arrancar em modo CLI...")
            main_cli()


if __name__ == "__main__":
    main()
