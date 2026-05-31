"""
Clasificador de Eventos — ISO/IEC 27001:2022 Anexo A (4 Dominios Oficiales)
=============================================================================
Clasifica cada evento de log en uno de los 4 dominios del Anexo A:
  A.5 Organizacional | A.6 Personas | A.7 Físico | A.8 Tecnológico

También realiza sub-clasificación interna de A.8 en 4 sub-áreas
para el radar de detalle (sin alterar el scoring oficial).
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict

from rules.iso27001_controls import (
    ISO27001_DOMAINS, A8_SUBDOMAINS,
    ControlDomain, A8SubDomain,
    MIN_EVENTS_FOR_LOGGING,
)


@dataclass
class DomainStats:
    """Estadísticas de clasificación para un dominio del Anexo A."""
    domain_key:    str
    domain_id:     str          # A.5 / A.6 / A.7 / A.8
    domain_name:   str
    annex_ref:     str
    total_events:  int = 0
    risk_events:   int = 0
    unique_ips:    Set[str] = field(default_factory=set)
    unique_users:  Set[str] = field(default_factory=set)
    raw_messages:  List[str] = field(default_factory=list)

    @property
    def safe_events(self) -> int:
        return max(0, self.total_events - self.risk_events)

    @property
    def risk_rate(self) -> float:
        return self.risk_events / self.total_events if self.total_events > 0 else 0.0

    @property
    def has_data(self) -> bool:
        return self.total_events >= MIN_EVENTS_FOR_LOGGING


@dataclass
class A8SubStats:
    """Estadísticas para un sub-dominio de A.8 Tecnológico."""
    sub_key:       str
    sub_id:        str          # A.8.1 / A.8.2 / A.8.3 / A.8.4
    sub_name:      str
    controls_ref:  str
    total_events:  int = 0
    risk_events:   int = 0

    @property
    def risk_rate(self) -> float:
        return self.risk_events / self.total_events if self.total_events > 0 else 0.0


@dataclass
class ClassificationResult:
    """Resultado completo de la clasificación."""
    domain_stats:    Dict[str, DomainStats]   # 4 dominios oficiales
    a8_sub_stats:    Dict[str, A8SubStats]    # 4 sub-áreas de A.8
    total_classified: int = 0
    total_unclassified: int = 0


class EventClassifier:
    """
    Clasifica eventos de log según los 4 dominios oficiales del Anexo A
    de ISO/IEC 27001:2022, con sub-clasificación de A.8 para el radar de detalle.

    NOTA METODOLÓGICA:
        Los dominios se denominan A.5, A.6, A.7, A.8 (Anexo A),
        NO "Cláusula 5/6/7/8" (que corresponde al SGSI, Cl.4-10).
    """

    def __init__(self):
        # Compilar patrones para los 4 dominios principales
        self._domain_patterns: Dict[str, Tuple] = {}
        for key, domain in ISO27001_DOMAINS.items():
            ind_re = [re.compile(p, re.IGNORECASE) for p in domain.indicators]
            risk_re = [re.compile(p, re.IGNORECASE) for p in domain.risk_patterns]
            self._domain_patterns[key] = (ind_re, risk_re)

        # Compilar patrones para sub-dominios de A.8
        self._a8_patterns: Dict[str, Tuple] = {}
        for key, sub in A8_SUBDOMAINS.items():
            ind_re = [re.compile(p, re.IGNORECASE) for p in sub.indicators]
            risk_re = [re.compile(p, re.IGNORECASE) for p in sub.risk_patterns]
            self._a8_patterns[key] = (ind_re, risk_re)

    def _match(self, patterns: List, text: str) -> bool:
        return any(p.search(text) for p in patterns)

    def classify(self, log_entries) -> ClassificationResult:
        """
        Clasifica todos los eventos y retorna estadísticas por dominio.
        """
        # Inicializar estadísticas para los 4 dominios
        domain_stats: Dict[str, DomainStats] = {}
        for key, domain in ISO27001_DOMAINS.items():
            domain_stats[key] = DomainStats(
                domain_key=key,
                domain_id=domain.id,
                domain_name=domain.name,
                annex_ref=domain.annex_ref,
            )

        # Inicializar estadísticas para sub-dominios de A.8
        a8_sub_stats: Dict[str, A8SubStats] = {}
        for key, sub in A8_SUBDOMAINS.items():
            a8_sub_stats[key] = A8SubStats(
                sub_key=key,
                sub_id=sub.id,
                sub_name=sub.name,
                controls_ref=sub.controls_ref,
            )

        total_classified = 0
        total_unclassified = 0

        for entry in log_entries:
            msg = entry.message or ""
            raw = entry.raw or msg
            ip = getattr(entry, 'source_ip', None) or ""
            user = getattr(entry, 'user', None) or ""

            classified_any = False

            # ── Clasificar en los 4 dominios principales ───────────
            for key, (ind_re, risk_re) in self._domain_patterns.items():
                if self._match(ind_re, raw):
                    ds = domain_stats[key]
                    ds.total_events += 1
                    if ip:   ds.unique_ips.add(ip)
                    if user: ds.unique_users.add(user)
                    if self._match(risk_re, raw):
                        ds.risk_events += 1
                    if len(ds.raw_messages) < 500:
                        ds.raw_messages.append(raw[:200])
                    classified_any = True

            # ── Sub-clasificar dentro de A.8 ───────────────────────
            if domain_stats["A8_technological"].total_events > 0:
                for key, (ind_re, risk_re) in self._a8_patterns.items():
                    if self._match(ind_re, raw):
                        ss = a8_sub_stats[key]
                        ss.total_events += 1
                        if self._match(risk_re, raw):
                            ss.risk_events += 1

            if classified_any:
                total_classified += 1
            else:
                total_unclassified += 1

        return ClassificationResult(
            domain_stats=domain_stats,
            a8_sub_stats=a8_sub_stats,
            total_classified=total_classified,
            total_unclassified=total_unclassified,
        )

    # ── Backward compatibility: .classify() returns dict-like result ──
    def classify_compat(self, log_entries) -> Dict[str, DomainStats]:
        """Retorna solo domain_stats (compatibilidad con código anterior)."""
        result = self.classify(log_entries)
        return result.domain_stats
