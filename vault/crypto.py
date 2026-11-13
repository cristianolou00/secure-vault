"""
Módulo Criptográfico Principal (crypto.py)

CONCEITOS DE SEGURANÇA IMPLEMENTADOS:

1. ARGON2id (Key Derivation Function - KDF):
   - Por que NÃO usar MD5 ou SHA-256 diretamente?
     Funções de hash normais são desenhadas para serem ultra-rápidas (milhões por segundo em GPUs).
     Um atacante conseguiria testar biliões de senhas por segundo num ataque de força bruta.
   - Argon2id é a função vencedora da 'Password Hashing Competition'.
   - É 'Memory-Hard': exige uma quantidade significativa de memória RAM (64 MB por tentativa)
     e múltiplos núcleos de CPU, tornando ataques com placas gráficas (GPUs) ou chips dedicados (ASICs)
     economicamente inviáveis.
   - O 'Salt' aleatório de 16 bytes garante que duas pessoas com a mesma senha tenham
     chaves criptográficas completamente diferentes, anulando ataques de Rainbow Tables.

2. AES-256-GCM (Authenticated Encryption with Associated Data - AEAD):
   - AES com chave de 256 bits é o padrão militar de cifra simétrica.
   - Modo GCM (Galois/Counter Mode):
     Combina encriptação (confidencialidade) com uma 'Authentication Tag' de 16 bytes (integridade).
   - Se um atacante alterar um único bit do ficheiro em disco, o algoritmo deteta a adulteração
     e recusa-se a devolver os dados, evitando ataques de 'Bit-Flipping'.
   - Cada operação de escrita gera um 'Nonce' (Number Used Once) único de 12 bytes (96 bits).
     NUNCA reutilizamos o mesmo Nonce com a mesma chave.
"""

import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault.secure_mem import SecureBuffer


class SecurityError(Exception):
    """Exceção base para falhas de segurança."""
    pass


class DecryptionError(SecurityError):
    """
    Lançada quando a chave está incorreta OU os dados foram adulterados.
    
    IMPORTANTE: Nunca devemos dizer ao utilizador se o erro foi 'senha errada' ou
    'ficheiro corrompido'. Manter a mesma mensagem e tempo de resposta impede
    ataques de oráculo (Oracle Padding / Timing Attacks).
    """
    pass


# Constantes Criptográficas Recomendadas (alinhadas com normas OWASP)
SALT_SIZE_BYTES = 16       # 128 bits de entropia para o Salt
NONCE_SIZE_BYTES = 12      # 96 bits recomendado pelo NIST para AES-GCM
KEY_SIZE_BYTES = 32        # 256 bits para chave AES-256
ARGON2_TIME_COST = 2       # Número de iterações sobre a memória
ARGON2_MEMORY_COST = 65536 # 64 MiB (em KiB) de RAM alocados por cálculo
ARGON2_PARALLELISM = 4     # Número de threads/lanes simultâneas


def generate_salt() -> bytes:
    """Gera 16 bytes criptograficamente seguros a partir do gerador de entropia do SO."""
    return os.urandom(SALT_SIZE_BYTES)


def generate_nonce() -> bytes:
    """Gera 12 bytes únicos para o Nonce do AES-GCM."""
    return os.urandom(NONCE_SIZE_BYTES)


def derive_key(master_password: str, salt: bytes) -> SecureBuffer:
    """
    Deriva uma chave AES de 256 bits a partir da senha mestre usando Argon2id.
    
    Retorna a chave envolvida num 'SecureBuffer' para garantir destruição na RAM.
    """
    if not isinstance(master_password, str) or len(master_password) == 0:
        raise ValueError("A palavra-passe mestre não pode estar vazia.")

    if len(salt) != SALT_SIZE_BYTES:
        raise ValueError(f"O Salt deve ter exatamente {SALT_SIZE_BYTES} bytes.")

    # Converte a senha para bytes
    pwd_bytes = master_password.encode("utf-8")

    # Configuração do Argon2id
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE_BYTES,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )

    # Deriva os 32 bytes da chave
    raw_key = kdf.derive(pwd_bytes)

    # Devolve dentro do container seguro de memória
    return SecureBuffer(raw_key)


def encrypt_bytes(key_buffer: SecureBuffer, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encripta bytes de texto limpo usando AES-256-GCM.
    
    Parâmetros:
      - key_buffer: Chave simétrica protegida de 256 bits.
      - plaintext: Os dados em claro que queremos proteger.
      - associated_data (AAD): Dados de cabeçalho que NÃO são encriptados, mas cuja
        autenticidade é validada matematicamente pela tag de autenticação.
        
    Retorna:
      - (nonce, ciphertext_com_tag)
    """
    nonce = generate_nonce()
    raw_key = key_buffer.get_bytes()

    try:
        aesgcm = AESGCM(raw_key)
        # O AESGCM da biblioteca cryptography anexa automaticamente a tag de 16 bytes ao fim do ciphertext
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    finally:
        # Garante que a cópia temporária da chave é removida da referência local
        del raw_key


def decrypt_bytes(key_buffer: SecureBuffer, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Desencripta e autentica os dados usando AES-256-GCM.
    
    Se a chave estiver errada, ou se o cabeçalho/conteúdo tiver sido modificado em 1 bit,
    a função lança 'DecryptionError'.
    """
    if len(nonce) != NONCE_SIZE_BYTES:
        raise DecryptionError("Tamanho inválido de Nonce.")

    raw_key = key_buffer.get_bytes()
    try:
        aesgcm = AESGCM(raw_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except Exception as exc:
        # Qualquer falha criptográfica (tag inválida, padding, etc.) é mascarada como DecryptionError
        raise DecryptionError("Falha na desencriptação: Senha incorreta ou ficheiro corrompido/adulterado.") from exc
    finally:
        del raw_key
