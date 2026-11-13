"""
Módulo de Modelos e Gestão de Entradas (models.py)

Define a estrutura de dados para credenciais, notas seguras e validação.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class VaultEntry:
    """Representa uma entrada individual de credencial no cofre."""

    def __init__(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        category: str = "Geral",
        entry_id: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.id = entry_id or str(uuid.uuid4())
        self.title = title.strip()
        self.username = username.strip()
        self.password = password
        self.url = url.strip()
        self.notes = notes.strip()
        self.category = category.strip() or "Geral"
        now_iso = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_iso
        self.updated_at = updated_at or now_iso

    def to_dict(self) -> Dict[str, Any]:
        """Converte a entrada num dicionário serializável em JSON."""
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "category": self.category,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultEntry":
        """Instancia um VaultEntry a partir de um dicionário."""
        return cls(
            entry_id=data.get("id"),
            title=data.get("title", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            category=data.get("category", "Geral"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )
