"""
Plan de Acción Automático — ISO/IEC 27001:2022
Genera un plan de acción priorizado por dominio más débil con acciones específicas,
nivel de esfuerzo y tiempo estimado de implementación, alineado a los controles 2022.
"""

from typing import Dict, List
from analyzer.event_classifier import DomainStats
from analyzer.maturity_scorer  import MaturityResult
from rules.iso27001_controls   import ISO27001_DOMAINS, MATURITY_LEVELS


# Acciones específicas por dominio 2022 y nivel actual
DOMAIN_ACTIONS = {
    "organizational_controls": {
        "clause": "Cláusula 5 — Controles Organizacionales",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "2–4 meses",
                "actions": [
                    "Crear y aprobar la Política de Seguridad de la Información (Control 5.1).",
                    "Definir roles y responsabilidades de seguridad, incluyendo CISO (Control 5.2).",
                    "Elaborar inventario de activos de información clasificados (Control 5.9, 5.12).",
                    "Establecer proceso de gestión de riesgos conforme a ISO 27001:2022 Cláusula 6.",
                    "Iniciar programa de inteligencia de amenazas básico con feeds públicos (Control 5.7).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "1–2 meses",
                "actions": [
                    "Formalizar revisiones periódicas de políticas de seguridad (Control 5.1).",
                    "Implementar gestión de seguridad en la cadena de suministro (Control 5.19–5.21).",
                    "Documentar y probar el Plan de Continuidad de TIC (Control 5.30).",
                    "Establecer proceso formal de clasificación de información (Control 5.12).",
                    "Integrar feeds de inteligencia de amenazas al SIEM (Control 5.7).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "3–6 semanas",
                "actions": [
                    "Automatizar auditorías de cumplimiento de políticas (Control 5.36).",
                    "Implementar gestión de seguridad para servicios cloud (Control 5.23).",
                    "Revisar y actualizar acuerdos de confidencialidad con proveedores (Control 5.20).",
                    "Desarrollar métricas de desempeño del SGSI (Cláusula 9 ISO 27001:2022).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Mantener revisiones anuales del SGSI y actualizar el análisis de riesgos.",
                    "Ampliar el programa de inteligencia de amenazas con fuentes sectoriales.",
                    "Preparar documentación para auditoría de certificación ISO 27001:2022.",
                ]
            },
        }
    },
    "people_controls": {
        "clause": "Cláusula 6 — Controles de Personas",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "1–3 meses",
                "actions": [
                    "Implementar verificación de antecedentes para nuevo personal (Control 6.1).",
                    "Desarrollar programa de concienciación en seguridad (Control 6.3).",
                    "Crear e implementar acuerdos de confidencialidad (Control 6.6).",
                    "Establecer política de teletrabajo seguro con requisitos de VPN (Control 6.7).",
                    "Definir proceso de reporte de eventos de seguridad por empleados (Control 6.8).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "3–6 semanas",
                "actions": [
                    "Formalizar el proceso de baja y revocación de accesos (Control 6.5).",
                    "Implementar formación obligatoria anual en seguridad con evaluación (Control 6.3).",
                    "Establecer proceso disciplinario documentado por infracciones de seguridad (Control 6.4).",
                    "Crear programa de simulacros de phishing (Control 6.3).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "2–4 semanas",
                "actions": [
                    "Automatizar la revocación de accesos al finalizar contratos (Control 6.5).",
                    "Integrar formación de seguridad en el onboarding (Control 6.3).",
                    "Implementar canal confidencial de reporte de incidentes (Control 6.8).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Medir eficacia del programa de concienciación con métricas (Control 6.3).",
                    "Actualizar formación según nuevas amenazas y controles 2022.",
                ]
            },
        }
    },
    "physical_controls": {
        "clause": "Cláusula 7 — Controles Físicos",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "1–2 meses",
                "actions": [
                    "Establecer perímetros de seguridad física con control de acceso (Control 7.1–7.2).",
                    "Instalar sistema CCTV y monitoreo físico (Control 7.4 — NUEVO 2022).",
                    "Implementar política de escritorio y pantalla limpios (Control 7.7).",
                    "Proteger equipos contra fallas de suministro eléctrico con UPS (Control 7.11).",
                    "Establecer procedimiento de eliminación segura de equipos (Control 7.14).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "3–4 semanas",
                "actions": [
                    "Implementar registro de accesos físicos con logs auditables (Control 7.2).",
                    "Revisar y actualizar la política de uso de medios de almacenamiento (Control 7.10).",
                    "Establecer procedimiento de mantenimiento preventivo de equipos (Control 7.13).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "2–3 semanas",
                "actions": [
                    "Automatizar alertas del sistema CCTV y monitoreo físico (Control 7.4).",
                    "Implementar inventario automatizado de activos físicos (Control 7.8–7.9).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Revisar anualmente la efectividad de controles físicos (Control 7.x).",
                    "Integrar monitoreo físico con el SIEM (Control 7.4 + 8.16).",
                ]
            },
        }
    },
    "access_identity": {
        "clause": "Cláusula 8 — Acceso e Identidad (8.1–8.6)",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "1–3 meses",
                "actions": [
                    "Implementar autenticación multifactor (MFA) para todos los accesos (Control 8.5).",
                    "Establecer política de gestión de acceso privilegiado (Control 8.2).",
                    "Instalar MDM para gestión de endpoints y dispositivos (Control 8.1).",
                    "Auditar y eliminar cuentas inactivas o con privilegios excesivos (Control 8.3).",
                    "Implementar logging centralizado de todos los accesos (Control 8.15).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "2–4 semanas",
                "actions": [
                    "Configurar alertas automáticas para intentos de fuerza bruta (Control 8.5).",
                    "Implementar revisión trimestral de derechos de acceso (Control 8.3).",
                    "Centralizar logs de autenticación en SIEM (Control 8.15 + 8.16).",
                    "Desplegar PAM (Privileged Access Management) para cuentas admin (Control 8.2).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "2–4 semanas",
                "actions": [
                    "Automatizar revisión de accesos privilegiados con reportes mensuales (Control 8.2).",
                    "Implementar gestión de sesiones con timeout (Control 8.5).",
                    "Configurar alertas de acceso en horarios fuera de oficina (Control 8.16).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Evaluar implementación de Zero Trust alineada a Control 8.2–8.5.",
                    "Integrar threat intelligence para detección de credenciales comprometidas (Control 5.7).",
                ]
            },
        }
    },
    "crypto_network": {
        "clause": "Cláusula 8 — Criptografía y Seguridad de Red (8.20–8.26)",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "1–2 meses",
                "actions": [
                    "Implementar TLS 1.3 en todos los servicios web y comunicaciones (Control 8.24).",
                    "Configurar firewall con política de denegación por defecto (Control 8.20).",
                    "Implementar segmentación de red con VLANs y DMZ (Control 8.22).",
                    "Activar filtrado web con categorización de URLs (Control 8.23 — NUEVO 2022).",
                    "Deshabilitar protocolos criptográficos débiles (SSLv2/3, RC4, MD5).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "3–6 semanas",
                "actions": [
                    "Implementar IDS/IPS en el perímetro de red (Control 8.20).",
                    "Establecer proceso de gestión de certificados digitales (Control 8.24).",
                    "Configurar VPN corporativa con MFA para acceso remoto (Control 8.20 + 8.5).",
                    "Revisar y actualizar requisitos de seguridad en aplicaciones (Control 8.26).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "2–4 semanas",
                "actions": [
                    "Implementar ciclo de vida de desarrollo seguro (DevSecOps) (Control 8.25).",
                    "Automatizar monitoreo de anomalías de red con SIEM (Control 8.16).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Realizar pruebas de penetración anuales de red y aplicaciones.",
                    "Evaluar Zero Trust Network Access (ZTNA) para acceso remoto.",
                ]
            },
        }
    },
    "threat_detection": {
        "clause": "Cláusula 8 — Detección de Amenazas (8.7–8.17) + Incidentes (5.24–5.28)",
        "levels": {
            (0, 20): {
                "effort": "Alto",
                "tiempo": "1–2 meses",
                "actions": [
                    "Instalar EDR/Antimalware en todos los endpoints (Control 8.7).",
                    "Implementar proceso de gestión de vulnerabilidades con escaneo semanal (Control 8.8).",
                    "Establecer proceso formal de gestión de incidentes documentado (Control 5.24–5.26).",
                    "Configurar logging centralizado de eventos de seguridad (Control 8.15).",
                    "Implementar DLP básico para protección de datos sensibles (Control 8.12 — NUEVO 2022).",
                ]
            },
            (21, 40): {
                "effort": "Medio",
                "tiempo": "3–6 semanas",
                "actions": [
                    "Implementar SIEM con correlación de eventos y alertas (Control 8.16 — NUEVO 2022).",
                    "Establecer gestión de configuración con baselines documentadas (Control 8.9 — NUEVO 2022).",
                    "Formalizar proceso de respuesta a incidentes con roles definidos (Control 5.26).",
                    "Implementar procedimiento de eliminación segura de información (Control 8.10 — NUEVO 2022).",
                ]
            },
            (41, 60): {
                "effort": "Medio",
                "tiempo": "2–4 semanas",
                "actions": [
                    "Automatizar el ciclo de gestión de vulnerabilidades con integración SIEM (Control 8.8).",
                    "Implementar enmascaramiento de datos en entornos no productivos (Control 8.11 — NUEVO 2022).",
                    "Establecer programa de lecciones aprendidas post-incidente (Control 5.27).",
                ]
            },
            (61, 100): {
                "effort": "Bajo",
                "tiempo": "Mejora continua",
                "actions": [
                    "Implementar codificación segura y SAST/DAST en pipelines CI/CD (Control 8.28 — NUEVO 2022).",
                    "Integrar threat hunting proactivo con inteligencia de amenazas (Control 5.7 + 8.16).",
                ]
            },
        }
    },
}


def generate_action_plan(
    result: MaturityResult,
    domain_stats: Dict[str, DomainStats] = None,
) -> List[Dict]:
    """
    Genera lista de planes de acción ordenados por prioridad (dominios más débiles primero).
    Cada plan incluye: dominio, cláusula 2022, score, nivel, esfuerzo, tiempo y acciones.
    """
    plans = []

    # Ordenar dominios de peor a mejor score
    sorted_domains = sorted(
        result.domain_scores.values(),
        key=lambda d: d.raw_score
    )
    if domain_stats is None:
        domain_stats = {}

    for ds in sorted_domains:
        key = ds.domain_key
        if key not in DOMAIN_ACTIONS:
            continue

        domain_info = DOMAIN_ACTIONS[key]
        score = ds.raw_score

        # Encontrar el rango de nivel que aplica
        action_block = None
        for (lo, hi), block in domain_info["levels"].items():
            if lo <= score <= hi:
                action_block = block
                break
        if action_block is None:
            # Usar el último bloque para scores muy altos
            action_block = list(domain_info["levels"].values())[-1]

        next_lvl = ds.level + 1 if ds.level < 5 else 5
        next_thresh = {0:1, 1:21, 2:41, 3:61, 4:81, 5:81}[ds.level]
        gap = max(0, next_thresh - score)
        plans.append({
            "domain_key":  key,
            "domain_name": ds.domain_name,
            "clause":      domain_info["clause"],
            "domain":      domain_info["clause"],        # compat key for streamlit
            "score":       score,
            "level":       ds.level,
            "level_name":  ds.level_name,
            "effort":      action_block["effort"],
            "tiempo":      action_block["tiempo"],
            "actions":     action_block["actions"],
            "priority":    1 if score < 40 else (2 if score < 60 else 3),
            "gap_to_next": round(gap, 1),                # compat key for streamlit
        })

    return plans


def format_action_plan_text(plans: List[Dict]) -> str:
    """Formatea el plan de acción como texto para exportación."""
    lines = [
        "═" * 70,
        "  PLAN DE ACCIÓN — ISO/IEC 27001:2022",
        "  Acciones priorizadas por nivel de madurez más bajo",
        "═" * 70,
    ]

    priority_labels = {1: "🔴 ALTA PRIORIDAD", 2: "🟡 PRIORIDAD MEDIA", 3: "🟢 MANTENIMIENTO"}

    for i, plan in enumerate(plans, 1):
        lines.append(f"\n{'─'*70}")
        lines.append(
            f"  [{i}] {plan['domain_name']}  —  Score: {plan['score']:.1f}/100  "
            f"(Nivel {plan['level']}: {plan['level_name']})"
        )
        lines.append(f"  {plan['clause']}")
        lines.append(f"  {priority_labels.get(plan['priority'], '')}  |  "
                     f"Esfuerzo: {plan['effort']}  |  Tiempo estimado: {plan['tiempo']}")
        lines.append(f"  Acciones recomendadas:")
        for j, action in enumerate(plan["actions"], 1):
            lines.append(f"    {j}. {action}")

    lines.append(f"\n{'═'*70}")
    return "\n".join(lines)
