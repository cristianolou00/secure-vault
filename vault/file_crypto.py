"""
Módulo de Encriptação e Armazenamento de Ficheiros (file_crypto.py)

Permite armazenar ficheiros confidenciais (PDFs, imagens, documentos, chaves SSH)
diretamente dentro do cofre encriptado, ou encriptar ficheiros soltos no disco.
"""

import base64
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from vault.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    derive_key,
    generate_salt,
    DecryptionError,
)
from vault.secure_mem import SecureBuffer


class VaultFileAttachment:
    """Representa um ficheiro seguro armazenado no cofre."""

    def __init__(
        self,
        filename: str,
        data_bytes: bytes,
        file_id: Optional[str] = None,
        created_at: Optional[str] = None,
        file_size: Optional[int] = None,
    ):
        self.id = file_id or str(uuid.uuid4())
        self.filename = filename
        self.data_bytes = data_bytes
        self.file_size = file_size if file_size is not None else len(data_bytes)
        now_iso = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_iso

    def to_dict(self) -> Dict[str, Any]:
        """Serializa o ficheiro codificando o payload binário em Base64."""
        return {
            "id": self.id,
            "filename": self.filename,
            "file_size": self.file_size,
            "created_at": self.created_at,
            "data_b64": base64.b64encode(self.data_bytes).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultFileAttachment":
        """Reconstrói o anexo a partir do dicionário decodificando o Base64."""
        data_bytes = base64.b64decode(data.get("data_b64", "").encode("ascii"))
        return cls(
            file_id=data.get("id"),
            filename=data.get("filename", "ficheiro"),
            data_bytes=data_bytes,
            created_at=data.get("created_at"),
            file_size=data.get("file_size"),
        )


def format_file_size(size_bytes: int) -> str:
    """Converte bytes para formato legível (KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
