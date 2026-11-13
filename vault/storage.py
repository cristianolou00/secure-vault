"""
Módulo de Armazenamento e Serialização Binária (storage.py)

ESTRUTURA DO FICHEIRO BINÁRIO (.vault):
Para não expor dados nem depender de formatos frágeis, desenhamos uma especificação
binária rigorosa com cabeçalho fixo:

Offsets:
0..3   (4 bytes)  : Magic Bytes -> b"VAUL" (Identificador único de formato)
4..5   (2 bytes)  : Formato / Versão -> uint16 em Big-Endian (ex: 0x0001 = versão 1)
6..21  (16 bytes) : Salt criptográfico (usado pelo Argon2id para derivar a chave)
22..33 (12 bytes) : Nonce único do AES-256-GCM
34..N  (Restante) : Payload cifrado + Tag de Autenticação de 16 bytes

SEGURANÇA ADICIONAL (AAD - Associated Authenticated Data):
Os primeiros 6 bytes (Magic + Versão) são passados como 'Associated Data' ao AES-GCM.
Isto significa que, se alguém alterar a versão do ficheiro no disco para tentar
explorar bugs de compatibilidade retroativa, a verificação da Tag falha de imediato.

ESCRITA ATÓMICA (ACID):
Nunca sobrescrevemos o ficheiro diretamente. Escrevemos primeiro num ficheiro temporário
(.tmp), forçamos a gravação física no disco com 'os.fsync()', e só depois usamos
'os.replace()'. Desta forma, se a energia falhar durante a gravação, o ficheiro
antigo nunca fica corrompido pela metade.
"""

import json
import os
import struct
from typing import Any, Dict
from vault.crypto import (
    SALT_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    generate_salt,
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
    DecryptionError,
    SecurityError,
)

# Constantes do Formato Binário
MAGIC_BYTES = b"VAUL"
VAULT_VERSION = 1
HEADER_STRUCT = ">4sH"  # 4 bytes string, 2 bytes unsigned short (Big-Endian)
HEADER_SIZE = struct.calcsize(HEADER_STRUCT) + SALT_SIZE_BYTES + NONCE_SIZE_BYTES
# 4 + 2 + 16 + 12 = 34 bytes fixos de cabeçalho


class InvalidVaultFormatError(SecurityError):
    """Lançada quando o ficheiro não é um cofre legítimo ou o cabeçalho está corrompido."""
    pass


class VaultStorage:
    """
    Controlador de leitura, escrita e serialização do cofre no disco.
    """

    @staticmethod
    def _create_aad(version: int) -> bytes:
        """Gera os bytes autenticados adicionais (AAD) correspondentes ao cabeçalho."""
        return struct.pack(HEADER_STRUCT, MAGIC_BYTES, version)

    @classmethod
    def create_new_vault(cls, filepath: str, master_password: str, initial_data: Dict[str, Any] = None) -> None:
        """
        Inicializa e grava um novo cofre encriptado no disco com um Salt novo.
        """
        if os.path.exists(filepath):
            raise FileExistsError(f"O ficheiro '{filepath}' já existe.")

        if initial_data is None:
            initial_data = {
                "created_at": None,
                "version": VAULT_VERSION,
                "entries": {},
                "notes": {},
            }

        salt = generate_salt()
        cls.save_vault(filepath, master_password, initial_data, salt=salt)

    @classmethod
    def save_vault(
        cls,
        filepath: str,
        master_password: str,
        data: Dict[str, Any],
        salt: bytes = None
    ) -> None:
        """
        Encripta e grava os dados no disco de forma atómica.
        
        Se 'salt' não for fornecido, reutiliza o salt existente lendo o cabeçalho,
        ou gera um novo se o ficheiro for novo.
        """
        # Se for um ficheiro existente e não indicámos salt, lemos o salt existente
        if salt is None:
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    header = f.read(HEADER_SIZE)
                    if len(header) >= HEADER_SIZE and header.startswith(MAGIC_BYTES):
                        salt = header[6:22]
            if salt is None:
                salt = generate_salt()

        # 1. Serializar os dados em memória para JSON codificado em UTF-8
        plaintext_json = json.dumps(data, ensure_ascii=False, indent=None).encode("utf-8")

        # 2. Derivar a chave de 256 bits com Argon2id
        with derive_key(master_password, salt) as key_buffer:
            # 3. Preparar o AAD com os Magic Bytes e Versão
            aad = cls._create_aad(VAULT_VERSION)

            # 4. Encriptar o payload com AES-256-GCM (gera um novo nonce único)
            nonce, ciphertext = encrypt_bytes(key_buffer, plaintext_json, associated_data=aad)

        # 5. Montar o cabeçalho binário exato
        # [0..5]: MAGIC (4B) + VERSÃO (2B)
        # [6..21]: SALT (16B)
        # [22..33]: NONCE (12B)
        binary_header = aad + salt + nonce

        # 6. Gravação Atómica: Escreve num ficheiro temporário (.tmp)
        tmp_filepath = f"{filepath}.tmp"
        try:
            with open(tmp_filepath, "wb") as f:
                f.write(binary_header)
                f.write(ciphertext)
                f.flush()
                # Força o sistema operativo a gravar os setores no hardware (disco físico)
                os.fsync(f.fileno())

            # Substitui atomicamente o ficheiro antigo pelo novo
            os.replace(tmp_filepath, filepath)
        except Exception:
            if os.path.exists(tmp_filepath):
                try:
                    os.remove(tmp_filepath)
                except OSError:
                    pass
            raise

    @classmethod
    def load_vault(cls, filepath: str, master_password: str) -> Dict[str, Any]:
        """
        Lê e desencripta o ficheiro do cofre, validando a integridade do cabeçalho
        e do conteúdo.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"O cofre '{filepath}' não foi encontrado.")

        # Ler o ficheiro binário
        with open(filepath, "rb") as f:
            file_bytes = f.read()

        if len(file_bytes) < HEADER_SIZE + 16:  # Cabeçalho + pelo menos 16B de tag AES
            raise InvalidVaultFormatError("O ficheiro é demasiado pequeno ou está truncado.")

        # Extração e validação do cabeçalho
        magic, version = struct.unpack_from(HEADER_STRUCT, file_bytes, 0)
        if magic != MAGIC_BYTES:
            raise InvalidVaultFormatError("Assinatura binária inválida. Não é um ficheiro de cofre válido.")

        if version != VAULT_VERSION:
            raise InvalidVaultFormatError(f"Versão de formato '{version}' não suportada (versão esperada: {VAULT_VERSION}).")

        # Extrair Salt (16 bytes) e Nonce (12 bytes)
        salt = file_bytes[6:22]
        nonce = file_bytes[22:34]
        ciphertext_with_tag = file_bytes[34:]

        aad = cls._create_aad(version)

        # Derivar a chave e tentar desencriptar
        with derive_key(master_password, salt) as key_buffer:
            plaintext_bytes = decrypt_bytes(
                key_buffer=key_buffer,
                nonce=nonce,
                ciphertext_with_tag=ciphertext_with_tag,
                associated_data=aad
            )

        # Converter JSON de volta para dicionário Python
        try:
            data = json.loads(plaintext_bytes.decode("utf-8"))
            return data
        except Exception as exc:
            raise DecryptionError("Erro ao interpretar os dados desencriptados.") from exc
