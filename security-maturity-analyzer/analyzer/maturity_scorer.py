"""
Motor de Scoring de Madurez — ISO/IEC 27001:2022 (4 Dominios Oficiales)
========================================================================
Calcula el nivel de madurez COBIT para cada dominio oficial del Anexo A
y para los 4 sub-dominios de A.8 Tecnológico.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from rules.iso27001_controls import (
    ISO27001_DOMAINS, A8_SUBDOMAINS,
    MATURITY_LEVELS, THRESHOLDS, get_maturity_level,
)
from analyzer.event_classifier import DomainStats, A8SubStats, ClassificationResult


@dataclass
class DomainScore:
    """Score calculado para un dominio del Anexo A."""
    domain_key:   str
    domain_id:    str           # A.5 / A.6 / A.7 / A.8
    domain_name:  str
    annex_ref:    str
    num_controls: int
    weight:       float
    raw_score:    float         # 0–100
    level:        int           # 0–5 COBIT
    level_name:   str
    breakdown:    Dict[str, float] = field(default_factory=dict)
    gap_to_next:  float = 0.0   # Puntos al siguiente nivel


@dataclass
class A8SubScore:
    """Score para un sub-dominio de A.8 (radar de detalle)."""
    sub_key:      str
    sub_id:       str
    sub_name:     str
    controls_ref: str
    raw_score:    float
    level:        int
    level_name:   str


@dataclass
class MaturityResult:
    """Resultado completo de la evaluación de madurez."""
    overall_score:      float
    overall_level:      int
    overall_level_name: str
    total_events:       int
    total_risk_events:  int
    total_domains_active: int   # Dominios con datos >= MIN_EVENTS

    domain_scores:      Dict[str, DomainScore]   # 4 dominios oficiales
    a8_sub_scores:      Dict[str, A8SubScore]    # Detalle de A.8
    recommendations:    List[str]
    critical_findings:  List[str]


class MaturityScorer:
    """
    Calcula el score de madurez ISO/IEC 27001:2022 sobre los
    4 dominios oficiales del Anexo A, con detalle de A.8.
    """

    # ── Componentes del score (suman 100) ────────────────────────
    W_PRESENCE    = 30.0   # Presencia de logs (escala log₁₀)
    W_EFFECTIV    = 40.0   # Efectividad de controles (inversa de tasa riesgo)
    W_SEVERITY    = 15.0   # Ajuste por severidad de eventos
    W_COVERAGE    = 15.0   # Cobertura IPs / usuarios únicos

    def _score_domain(self, ds: DomainStats) -> DomainScore:
        domain = ISO27001_DOMAINS[ds.domain_key]

        if ds.total_events == 0:
            raw = 0.0
            breakdown = {k: 0.0 for k in ["presence","effectiveness","severity","coverage"]}
        else:
            # 1. Presencia de logs
            presence = min(self.W_PRESENCE,
                           math.log10(ds.total_events + 1) / math.log10(1001) * self.W_PRESENCE)

            # 2. Efectividad (inversa de tasa de riesgo)
            rr = ds.risk_rate
            if   rr >= THRESHOLDS["critical_failure_rate"]:  eff = self.W_EFFECTIV * 0.10
            elif rr >= THRESHOLDS["high_failure_rate"]:       eff = self.W_EFFECTIV * 0.35
            elif rr >= THRESHOLDS["medium_failure_rate"]:     eff = self.W_EFFECTIV * 0.65
            else:                                              eff = self.W_EFFECTIV * 0.95

            # 3. Ajuste por severidad
            critical_msg_patterns = [
                "CRITICAL","EMERGENCY","ALERT","ransomware","exploit",
                "breach","intrusion","exfiltrat","zero.day"
            ]
            has_critical = any(
                any(p.lower() in m.lower() for p in critical_msg_patterns)
                for m in ds.raw_messages[:100]
            )
            sev = self.W_SEVERITY * (0.2 if has_critical else 1.0)

            # 4. Cobertura
            ip_pts   = min(7.5, len(ds.unique_ips)   * 0.5)
            user_pts = min(7.5, len(ds.unique_users) * 0.75)
            cov = ip_pts + user_pts

            raw = min(100.0, presence + eff + sev + cov)
            breakdown = {
                "presence":      round(presence, 2),
                "effectiveness": round(eff, 2),
                "severity":      round(sev, 2),
                "coverage":      round(cov, 2),
            }

        level = get_maturity_level(raw)
        level_name = MATURITY_LEVELS[level]["name"]
        next_thresh = {0:1,1:21,2:41,3:61,4:81,5:81}.get(level, 81)
        gap = max(0.0, float(next_thresh) - raw)

        return DomainScore(
            domain_key=ds.domain_key,
            domain_id=domain.id,
            domain_name=domain.name,
            annex_ref=domain.annex_ref,
            num_controls=domain.num_controls,
            weight=domain.weight,
            raw_score=round(raw, 1),
            level=level,
            level_name=level_name,
            breakdown=breakdown,
            gap_to_next=round(gap, 1),
        )

    def _score_a8_sub(self, ss: A8SubStats) -> A8SubScore:
        sub = A8_SUBDOMAINS[ss.sub_key]
        if ss.total_events == 0:
            raw = 0.0
        else:
            presence = min(30.0, math.log10(ss.total_events+1)/math.log10(1001)*30)
            rr = ss.risk_rate
            if   rr >= 0.30: eff = 40*0.10
            elif rr >= 0.15: eff = 40*0.35
            elif rr >= 0.05: eff = 40*0.65
            else:            eff = 40*0.95
            raw = min(100.0, presence + eff + 15.0*0.7)
        level = get_maturity_level(raw)
        return A8SubScore(
            sub_key=ss.sub_key, sub_id=sub.id, sub_name=sub.name,
            controls_ref=sub.controls_ref,
            raw_score=round(raw, 1), level=level,
            level_name=MATURITY_LEVELS[level]["name"],
        )

    def score(self, classification: ClassificationResult) -> MaturityResult:
        """
        Calcula el resultado completo de madurez a partir de la clasificación.
        Acepta también dict[str, DomainStats] para compatibilidad.
        """
        # Compatibilidad con dict plano (clasificadores anteriores)
        if isinstance(classification, dict):
            domain_stats = classification
            a8_sub_stats = {}
        else:
            domain_stats = classification.domain_stats
            a8_sub_stats = classification.a8_sub_stats

        # ── Score por dominio ─────────────────────────────────────
        domain_scores: Dict[str, DomainScore] = {}
        for key, ds in domain_stats.items():
            if key in ISO27001_DOMAINS:
                domain_scores[key] = self._score_domain(ds)

        # ── Score global ponderado ────────────────────────────────
        overall = sum(
            ds.raw_score * ds.weight
            for ds in domain_scores.values()
        )
        overall = round(overall, 1)
        overall_level = get_maturity_level(overall)
        active = sum(1 for ds in domain_stats.values() if ds.has_data)
        total_ev   = sum(ds.total_events for ds in domain_stats.values())
        total_risk = sum(ds.risk_events  for ds in domain_stats.values())

        # ── Score sub-dominios A.8 ────────────────────────────────
        a8_sub_scores: Dict[str, A8SubScore] = {}
        for key, ss in a8_sub_stats.items():
            a8_sub_scores[key] = self._score_a8_sub(ss)

        # ── Recomendaciones y hallazgos ───────────────────────────
        recommendations: List[str] = []
        critical_findings: List[str] = []

        sorted_domains = sorted(domain_scores.values(), key=lambda d: d.raw_score)
        for ds in sorted_domains[:2]:
            level_data = MATURITY_LEVELS[ds.level]
            recommendations.extend(level_data["recommendations"][:2])
            if ds.level <= 1:
                critical_findings.append(
                    f"CRÍTICO: {ds.domain_id} {ds.domain_name} en Nivel {ds.level} "
                    f"({ds.raw_score:.1f}/100) — {ds.num_controls} controles sin cobertura"
                )

        return MaturityResult(
            overall_score=overall,
            overall_level=overall_level,
            overall_level_name=MATURITY_LEVELS[overall_level]["name"],
            total_events=total_ev,
            total_risk_events=total_risk,
            total_domains_active=active,
            domain_scores=domain_scores,
            a8_sub_scores=a8_sub_scores,
            recommendations=recommendations,
            critical_findings=critical_findings,
        )


# ══════════════════════════════════════════════════════════════════
# ANÁLISIS DE BRECHAS Y NIVEL EFECTIVO
# ══════════════════════════════════════════════════════════════════
@dataclass
class GapAnalysis:
    """
    Análisis de coherencia entre el score global y los dominios individuales.

    PRINCIPIO METODOLÓGICO (CMMI / ISO 27001 auditoría):
      El nivel de madurez global no puede ser creíble si un dominio crítico
      presenta una brecha de 2+ niveles respecto al nivel global.
      El "nivel efectivo para auditoría" es el global limitado por la regla:
        nivel_efectivo = min(nivel_global, nivel_dominio_más_débil + 1)
    """
    overall_score:       float
    overall_level:       int
    overall_level_name:  str
    effective_level:     int          # Nivel corregido para presentación formal
    effective_level_name: str
    effective_score:     float        # Score ajustado conservador
    level_gap:           int          # Diferencia global vs más débil
    has_critical_gap:    bool         # True si brecha >= 2 niveles
    weakest_domain_id:   str
    weakest_domain_name: str
    weakest_score:       float
    weakest_level:       int
    weakest_level_name:  str
    strongest_domain_id: str
    strongest_domain_name: str
    strongest_score:     float
    audit_note:          str          # Nota lista para presentar
    action_priority:     str          # Texto de acción prioritaria
    domain_deltas:       Dict[str, int]  # Diferencia nivel por dominio vs global


def compute_gap_analysis(result: "MaturityResult") -> GapAnalysis:
    """
    Calcula el análisis de brechas y el nivel efectivo para auditoría.
    Usar siempre antes de presentar el resultado a auditores o alta dirección.
    """
    scores = result.domain_scores

    weakest  = min(scores.values(), key=lambda d: d.raw_score)
    strongest = max(scores.values(), key=lambda d: d.raw_score)

    # Nivel efectivo: global no puede superar al más débil en más de 1 nivel
    effective_level = min(result.overall_level, weakest.level + 1)
    # Score efectivo: media simple conservadora (sin ponderar fortalezas)
    simple_avg = sum(d.raw_score for d in scores.values()) / len(scores)
    effective_score = round(min(result.overall_score, simple_avg + 5), 1)

    level_gap = result.overall_level - weakest.level
    has_critical = level_gap >= 2

    # Delta por dominio (nivel individual vs nivel global)
    domain_deltas = {
        k: ds.level - result.overall_level
        for k, ds in scores.items()
    }

    # Generar nota de auditoría automática
    if has_critical:
        audit_note = (
            f"⚠ BRECHA DE MADUREZ DETECTADA: El score global "
            f"({result.overall_score:.1f}/100 · Nivel {result.overall_level} "
            f"— {result.overall_level_name}) convive con el dominio "
            f"'{weakest.domain_id} {weakest.domain_name}' en "
            f"{weakest.raw_score:.1f}/100 · Nivel {weakest.level} "
            f"— {weakest.level_name}. Brecha de {level_gap} niveles. "
            f"Para una presentación ante auditores de certificación ISO/IEC 27001:2022, "
            f"el nivel efectivo recomendado es Nivel {effective_level} "
            f"— {MATURITY_LEVELS[effective_level]['name']} "
            f"(score efectivo: {effective_score}/100)."
        )
        action_priority = (
            f"ACCIÓN PRIORITARIA: A pesar de que el score global posiciona a la "
            f"organización en Nivel {result.overall_level} ({result.overall_level_name}) "
            f"gracias al sólido desempeño en '{strongest.domain_id} {strongest.domain_name}' "
            f"({strongest.raw_score:.1f}/100), el dominio '{weakest.domain_id} "
            f"{weakest.domain_name}' ({weakest.raw_score:.1f}/100 · Nivel {weakest.level}) "
            f"representa la principal oportunidad de mejora y debe ser el foco de acción "
            f"a corto plazo para alcanzar una madurez homogénea y certificable."
        )
    else:
        audit_note = (
            f"✅ COHERENCIA DE MADUREZ ACEPTABLE: El score global "
            f"({result.overall_score:.1f}/100 · Nivel {result.overall_level} "
            f"— {result.overall_level_name}) es consistente con todos los dominios "
            f"(brecha máxima: {level_gap} nivel/es). "
            f"Presentable ante auditores de certificación ISO/IEC 27001:2022."
        )
        action_priority = (
            f"El dominio con mayor potencial de mejora es '{weakest.domain_id} "
            f"{weakest.domain_name}' con {weakest.raw_score:.1f}/100 "
            f"(Nivel {weakest.level} — {weakest.level_name}). "
            f"Fortaleciéndolo se consolida la madurez global."
        )

    return GapAnalysis(
        overall_score=result.overall_score,
        overall_level=result.overall_level,
        overall_level_name=result.overall_level_name,
        effective_level=effective_level,
        effective_level_name=MATURITY_LEVELS[effective_level]["name"],
        effective_score=effective_score,
        level_gap=level_gap,
        has_critical_gap=has_critical,
        weakest_domain_id=weakest.domain_id,
        weakest_domain_name=weakest.domain_name,
        weakest_score=weakest.raw_score,
        weakest_level=weakest.level,
        weakest_level_name=MATURITY_LEVELS[weakest.level]["name"],
        strongest_domain_id=strongest.domain_id,
        strongest_domain_name=strongest.domain_name,
        strongest_score=strongest.raw_score,
        audit_note=audit_note,
        action_priority=action_priority,
        domain_deltas=domain_deltas,
    )
