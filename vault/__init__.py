"""
Pacote do Cofre Seguro (vault)

Exporta as interfaces principais para o motor criptográfico e de armazenamento.
"""

from vault.crypto import (
    SecurityError,
    DecryptionError,
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
)
from vault.storage import (
    VaultStorage,
    InvalidVaultFormatError,
    MAGIC_BYTES,
    VAULT_VERSION,
)
from vault.secure_mem import SecureBuffer, zero_memory
from vault.pwned import check_password_leak

__all__ = [
    "VaultStorage",
    "SecurityError",
    "DecryptionError",
    "InvalidVaultFormatError",
    "derive_key",
    "encrypt_bytes",
    "decrypt_bytes",
    "SecureBuffer",
    "zero_memory",
    "check_password_leak",
    "MAGIC_BYTES",
    "VAULT_VERSION",
]
