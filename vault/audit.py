"""
Módulo de Auditoria de Segurança (audit.py)

Analisa as credenciais armazenadas no cofre para detetar:
1. Senhas reutilizadas em múltiplos serviços (risco crítico de invasão em cadeia).
2. Senhas fracas (baixa entropia ou comprimento insuficiente).
3. Pontuação Global de Saúde do Cofre (Health Score de 0 a 100%).
"""

from typing import List, Dict, Any
from vault.models import VaultEntry
from vault.generator import calculate_entropy


class AuditReport:
    """Relatório estruturado de saúde de segurança do cofre."""

    def __init__(
        self,
        total_entries: int,
        weak_entries: List[VaultEntry],
        reused_groups: Dict[str, List[VaultEntry]],
        health_score: int,
    ):
        self.total_entries = total_entries
        self.weak_entries = weak_entries
        self.reused_groups = reused_groups  # {password: [entry1, entry2]}
        self.health_score = health_score

    @property
    def total_reused(self) -> int:
        """Número de credenciais que partilham senhas repetidas."""
        return sum(len(entries) for entries in self.reused_groups.values())

    @property
    def total_weak(self) -> int:
        return len(self.weak_entries)


def audit_vault(entries: List[VaultEntry]) -> AuditReport:
    """
    Executa uma análise de segurança aprofundada sobre todas as entradas do cofre.
    """
    if not entries:
        return AuditReport(total_entries=0, weak_entries=[], reused_groups={}, health_score=100)

    total = len(entries)
    weak_list: List[VaultEntry] = []
    pwd_map: Dict[str, List[VaultEntry]] = {}

    for entry in entries:
        pwd = entry.password or ""

        # Agrupar por senha para detetar repetições
        if pwd:
            pwd_map.setdefault(pwd, []).append(entry)

        # Avaliar entropia e comprimento
        entropy, rating, _ = calculate_entropy(pwd)
        if entropy < 50.0 or len(pwd) < 10:
            weak_list.append(entry)

    # Filtrar apenas as senhas que aparecem mais de uma vez
    reused_groups = {pwd: elist for pwd, elist in pwd_map.items() if len(elist) > 1}

    # Cálculo da Pontuação de Saúde (0 a 100)
    # Deduções:
    # - Cada senha fraca subtrai pontos proporcionais
    # - Cada senha reutilizada subtrai pontos com maior penalização
    score = 100

    if total > 0:
        weak_ratio = len(weak_list) / total
        reused_count = sum(len(elist) for elist in reused_groups.values())
        reused_ratio = reused_count / total

        # Penalidades
        score -= int(weak_ratio * 45)      # Até -45 pontos por senhas fracas
        score -= int(reused_ratio * 55)    # Até -55 pontos por senhas reutilizadas

    score = max(0, min(100, score))

    return AuditReport(
        total_entries=total,
        weak_entries=weak_list,
        reused_groups=reused_groups,
        health_score=score,
    )
