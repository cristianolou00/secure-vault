"""
Módulo de Backup, Exportação, Importação e Mudança de Palavra-passe Mestre (backup.py)

Permite:
1. Exportar e importar credenciais em formato CSV padronizado (compatível com Chrome e Bitwarden).
2. Criar cópias de segurança integrais cifradas (.vaultbackup).
3. Alteração segura da Palavra-passe Mestre com re-cifragem atómica de todo o cofre.
"""

import csv
import io
import os
from typing import List, Dict, Any, Tuple
from vault.models import VaultEntry
from vault.storage import VaultStorage


def export_entries_to_csv(entries: List[VaultEntry]) -> str:
    """Exporta a lista de credenciais para uma string em formato CSV padronizado."""
    output = io.StringIO()
    writer = csv.writer(output)
    # Cabeçalho padrão de gestores de senhas
    writer.writerow(["Title", "Username", "Password", "URL", "Category", "Notes", "Created_At"])

    for e in entries:
        writer.writerow([
            e.title,
            e.username,
            e.password,
            e.url,
            e.category,
            e.notes.replace("\n", " "),
            e.created_at,
        ])

    return output.getvalue()


def import_entries_from_csv(csv_content: str) -> Tuple[List[VaultEntry], int]:
    """
    Importa credenciais a partir de uma string CSV (compatível com Bitwarden, Chrome, KeePass).
    Retorna: (novas_entradas, total_importadas)
    """
    reader = csv.reader(io.StringIO(csv_content))
    rows = list(reader)
    if not rows:
        return [], 0

    header = [h.strip().lower() for h in rows[0]]

    # Mapeamento dinâmico de colunas
    def find_idx(*names):
        for name in names:
            if name in header:
                return header.index(name)
        return -1

    title_idx = find_idx("title", "name", "título", "serviço")
    user_idx = find_idx("username", "user", "email", "login", "utilizador")
    pwd_idx = find_idx("password", "pass", "senha", "palavra-passe")
    url_idx = find_idx("url", "website", "uri", "link")
    cat_idx = find_idx("category", "folder", "categoria", "grupo")
    notes_idx = find_idx("notes", "note", "notas", "observações", "comentários")

    imported = []
    for row in rows[1:]:
        if not row or all(not col.strip() for col in row):
            continue

        title = row[title_idx].strip() if title_idx != -1 and len(row) > title_idx else "Importado"
        user = row[user_idx].strip() if user_idx != -1 and len(row) > user_idx else ""
        pwd = row[pwd_idx] if pwd_idx != -1 and len(row) > pwd_idx else ""
        url = row[url_idx].strip() if url_idx != -1 and len(row) > url_idx else ""
        cat = row[cat_idx].strip() if cat_idx != -1 and len(row) > cat_idx else "Importado"
        notes = row[notes_idx].strip() if notes_idx != -1 and len(row) > notes_idx else ""

        if not title and not user and not pwd:
            continue

        imported.append(VaultEntry(
            title=title or "Sem Título",
            username=user,
            password=pwd,
            url=url,
            notes=notes,
            category=cat or "Geral",
        ))

    return imported, len(imported)


def change_master_password(filepath: str, old_password: str, new_password: str) -> None:
    """
    Altera de forma segura a senha mestre de um cofre existente:
    1. Desencripta e valida os dados com a senha antiga.
    2. Gera um NOVO Salt aleatório de 16 bytes.
    3. Re-deriva a nova chave de 256 bits com Argon2id.
    4. Gera um NOVO Nonce de 12 bytes e re-encripta com AES-256-GCM.
    5. Grava atomicamente no disco.
    """
    if len(new_password) < 6:
        raise ValueError("A nova palavra-passe mestre deve ter pelo menos 6 caracteres.")

    # 1. Carregar dados atuais
    data = VaultStorage.load_vault(filepath, old_password)

    # 2. Gravar com a nova senha gerando um novo Salt
    from vault.crypto import generate_salt
    new_salt = generate_salt()
    VaultStorage.save_vault(filepath, new_password, data, salt=new_salt)
