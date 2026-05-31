"""
ISO/IEC 27001:2022 — Estructura Oficial del Anexo A
=====================================================
El Anexo A de la norma define EXACTAMENTE 4 dominios de control:

  A.5  Controles Organizacionales  — 37 controles (5.1–5.37)
  A.6  Controles de Personas       —  8 controles (6.1–6.8)
  A.7  Controles Físicos           — 14 controles (7.1–7.14)
  A.8  Controles Tecnológicos      — 34 controles (8.1–8.34)
  TOTAL: 93 controles

NOTA METODOLÓGICA IMPORTANTE:
  Las "Cláusulas" (Cl. 4 a 10) corresponden al SGSI (gobernanza,
  planificación, apoyo, operación, evaluación, mejora).
  Los CONTROLES están en el Anexo A y se denominan "A.5", "A.6",
  "A.7", "A.8" — NO "Cláusula 5", "Cláusula 6", etc.
  Mezclar ambas nomenclaturas es un error técnico ante un auditor.

Para mayor granularidad analítica interna, A.8 se desglosa en
4 sub-áreas (usado solo en el radar secundario de detalle):
  A.8.1 — Acceso e Identidad        (8.1–8.6)
  A.8.2 — Protección de Datos       (8.7–8.13)
  A.8.3 — Red y Criptografía        (8.20–8.26)
  A.8.4 — Monitoreo y Continuidad   (8.14–8.17, 8.28–8.34)

Niveles de Madurez (COBIT/CMMI):
  0 — Inexistente      (0%)
  1 — Inicial/Ad Hoc   (1–20%)
  2 — Repetible        (21–40%)
  3 — Proceso Definido (41–60%)
  4 — Administrado     (61–80%)
  5 — Optimizado       (81–100%)
"""

from dataclasses import dataclass, field
from typing import List, Dict


# ═══════════════════════════════════════════════════════════════════
# NIVELES DE MADUREZ COBIT
# ═══════════════════════════════════════════════════════════════════
MATURITY_LEVELS = {
    0: {
        "name": "Inexistente",
        "range": (0, 0),
        "color": "\033[91m",
        "description": (
            "No existe reconocimiento de la necesidad del control. "
            "La organización no aplica ningún control del Anexo A. "
            "Riesgo crítico de incumplimiento con ISO/IEC 27001:2022."
        ),
        "recommendations": [
            "Establecer política de seguridad de la información (A.5.1).",
            "Designar responsable de seguridad / CISO (A.5.2).",
            "Iniciar evaluación de riesgos (Cláusula 6.1.2 del SGSI).",
            "Implementar registro básico de eventos (A.8.15).",
        ],
    },
    1: {
        "name": "Inicial / Ad Hoc",
        "range": (1, 20),
        "color": "\033[91m",
        "description": (
            "Controles básicos ad hoc sin documentación formal. "
            "Dependencia de individuos, no de procesos. "
            "Los dominios del Anexo A no están sistemáticamente cubiertos."
        ),
        "recommendations": [
            "Documentar procedimientos de seguridad (A.5.37).",
            "Implementar control de acceso básico (A.8.3, A.8.5).",
            "Establecer gestión de incidentes (A.5.24–A.5.26).",
            "Iniciar programa de concienciación (A.6.3).",
        ],
    },
    2: {
        "name": "Repetible pero Intuitivo",
        "range": (21, 40),
        "color": "\033[93m",
        "description": (
            "Controles operativos pero sin formalización completa. "
            "Eficacia dependiente de personas, no de procesos documentados. "
            "Falta gestión sistemática de activos y vulnerabilidades."
        ),
        "recommendations": [
            "Formalizar inventario y clasificación de activos (A.5.9–A.5.12).",
            "Implementar gestión de vulnerabilidades (A.8.8).",
            "Desarrollar programa de formación en SI (A.6.3).",
            "Establecer métricas alineadas a Cláusula 9 del SGSI.",
        ],
    },
    3: {
        "name": "Proceso Definido",
        "range": (41, 60),
        "color": "\033[93m",
        "description": (
            "Controles documentados y operación predecible. "
            "Evaluaciones periódicas en marcha. "
            "Persisten brechas en A.8 Tecnológico (DLP, monitoreo, config)."
        ),
        "recommendations": [
            "Activar monitoreo continuo (A.8.16 — nuevo en 2022).",
            "Implementar DLP (A.8.12 — nuevo en 2022).",
            "Establecer gestión de configuración (A.8.9 — nuevo en 2022).",
            "Probar plan de continuidad de TIC (A.5.30).",
        ],
    },
    4: {
        "name": "Administrado y Medible",
        "range": (61, 80),
        "color": "\033[92m",
        "description": (
            "Controles maduros con medición sistemática del desempeño. "
            "Gestión de riesgos integrada. Controles del Anexo A cubiertos "
            "en los 4 dominios con métricas formales."
        ),
        "recommendations": [
            "Integrar threat intelligence (A.5.7) al ciclo de mejora.",
            "Implementar análisis predictivo en el SIEM (A.8.16).",
            "Reforzar seguridad cloud (A.5.23) con revisiones periódicas.",
            "Ejecutar penetration testing según A.8.8.",
        ],
    },
    5: {
        "name": "Optimizado",
        "range": (81, 100),
        "color": "\033[92m",
        "description": (
            "Mejora continua integrada. Controles proactivos y predictivos. "
            "La organización puede aspirar o mantener certificación ISO 27001:2022."
        ),
        "recommendations": [
            "Mantener ciclo PDCA del SGSI (Cláusula 10).",
            "Compartir threat intelligence sectorial (A.5.7).",
            "Preparar documentación para auditoría de certificación.",
            "Implementar arquitectura Zero Trust alineada a A.8.",
        ],
    },
}


def get_maturity_level(score: float) -> int:
    """Retorna nivel de madurez (0-5) según score (0-100)."""
    if score <= 0:   return 0
    if score <= 20:  return 1
    if score <= 40:  return 2
    if score <= 60:  return 3
    if score <= 80:  return 4
    return 5


# ═══════════════════════════════════════════════════════════════════
# DOMINIOS OFICIALES ISO/IEC 27001:2022 ANEXO A
# ═══════════════════════════════════════════════════════════════════
@dataclass
class ControlDomain:
    id: str                     # Identificador oficial: A.5, A.6, A.7, A.8
    name: str                   # Nombre oficial del dominio
    annex_ref: str              # Referencia al Anexo A
    num_controls: int           # Número de controles en la norma
    weight: float               # Peso en el score global (suma = 1.0)
    indicators: List[str]       # Patrones de log que indican control activo
    risk_patterns: List[str]    # Patrones que indican problema de seguridad
    description: str = ""
    controls_new: List[str] = field(default_factory=list)  # Controles nuevos vs 2013


# ── A.5 — CONTROLES ORGANIZACIONALES ─────────────────────────────
# 37 controles: políticas, roles, threat intelligence, activos,
# clasificación, cadena de suministro, cloud, incidentes, continuidad, cumplimiento.
A5_ORGANIZATIONAL = ControlDomain(
    id="A.5",
    name="Controles Organizacionales",
    annex_ref="Anexo A, Sección 5 (A.5.1–A.5.37)",
    num_controls=37,
    weight=0.25,
    controls_new=["A.5.7 Inteligencia de amenazas", "A.5.23 Seg. cloud",
                  "A.5.30 Continuidad TIC"],
    indicators=[
        r"(?i)(policy.*enforce|compliance.*check|asset.*register|asset.*inventory|"
        r"classification.*applied|supplier.*audit|vendor.*security|cloud.*policy|"
        r"information.*classification|data.*owner|risk.*assessment|isms.*review|"
        r"security.*governance|business.*continuity|bcp.*test|dr.*test|"
        r"threat.*intelligence|ioc.*received|feed.*updated|audit.*log|"
        r"privileged.*review|access.*review|compliance.*scan|policy.*review|"
        r"incident.*open|incident.*resolv|incident.*escalat|"
        r"forensic.*collect|evidence.*preserv|security.*policy|gdpr|"
        r"data.*classification|asset.*classif|information.*owner)",
    ],
    risk_patterns=[
        r"(?i)(policy.*violation|unauthorized.*data.*transfer|unclassified.*sensitive|"
        r"supplier.*breach|vendor.*incident|cloud.*misconfiguration|"
        r"bcp.*fail|dr.*fail|compliance.*fail|audit.*finding|"
        r"gdpr.*violation|privacy.*breach|data.*leak.*detected|"
        r"threat.*intel.*miss|unknown.*ioc|critical.*asset.*unmanaged|"
        r"breach.*detect|intrusion.*detect)",
    ],
    description=(
        "37 controles: políticas (A.5.1), roles y responsabilidades (A.5.2), "
        "threat intelligence (A.5.7 NUEVO), inventario activos (A.5.9), "
        "clasificación información (A.5.12), seguridad cloud (A.5.23 NUEVO), "
        "gestión de incidentes (A.5.24–A.5.28), continuidad TIC (A.5.30 NUEVO), "
        "cumplimiento (A.5.31–A.5.36)."
    ),
)

# ── A.6 — CONTROLES DE PERSONAS ──────────────────────────────────
# 8 controles: verificación, términos empleo, concienciación, disciplina,
# responsabilidades cese, confidencialidad, teletrabajo, reporte.
A6_PEOPLE = ControlDomain(
    id="A.6",
    name="Controles de Personas",
    annex_ref="Anexo A, Sección 6 (A.6.1–A.6.8)",
    num_controls=8,
    weight=0.10,
    controls_new=["A.6.7 Teletrabajo", "A.6.8 Reporte de eventos"],
    indicators=[
        r"(?i)(training.*complet|awareness.*session|security.*training|"
        r"nda.*sign|confidentiality.*agree|user.*acknowledged|"
        r"remote.*access.*vpn|vpn.*connect|telework.*session|"
        r"security.*report.*user|incident.*report.*employee|"
        r"password.*reset.*user|mfa.*enroll|account.*provisioned|"
        r"onboarding.*complete|offboard.*complete|account.*deprovisioned|"
        r"badge.*access|employee.*screen|background.*check)",
    ],
    risk_patterns=[
        r"(?i)(insider.*threat|employee.*violat|policy.*breach.*user|"
        r"nda.*violat|data.*theft.*employee|account.*misuse|"
        r"terminated.*user.*active|offboard.*fail|ex-employee.*access|"
        r"phishing.*click.*user|social.*engineering|"
        r"byod.*policy.*violat|personal.*device.*breach|"
        r"training.*overdue|awareness.*fail|nda.*violat)",
    ],
    description=(
        "8 controles: verificación de antecedentes (A.6.1), términos de empleo (A.6.2), "
        "concienciación y formación (A.6.3), proceso disciplinario (A.6.4), "
        "responsabilidades tras el cese (A.6.5), acuerdos de confidencialidad (A.6.6), "
        "teletrabajo seguro (A.6.7 NUEVO), reporte de eventos (A.6.8 NUEVO)."
    ),
)

# ── A.7 — CONTROLES FÍSICOS ──────────────────────────────────────
# 14 controles: perímetros, entrada física, monitoreo físico (NUEVO),
# trabajo en áreas seguras, escritorio limpio, equipos, medios.
A7_PHYSICAL = ControlDomain(
    id="A.7",
    name="Controles Físicos",
    annex_ref="Anexo A, Sección 7 (A.7.1–A.7.14)",
    num_controls=14,
    weight=0.15,
    controls_new=["A.7.4 Monitoreo de seguridad física"],
    indicators=[
        r"(?i)(badge.*access|card.*reader|cctv.*record|camera.*detect|"
        r"physical.*access.*log|door.*open.*authorized|safe.*area.*entry|"
        r"clean.*desk.*audit|screen.*lock|usb.*authorized|media.*register|"
        r"ups.*ok|power.*stable|hvac.*normal|equipment.*check|"
        r"hardware.*asset|device.*tracked|physical.*security|"
        r"equipment.*maintenance|cable.*secure|media.*destroy)",
    ],
    risk_patterns=[
        r"(?i)(unauthorized.*physical|tailgating|badge.*fail|access.*denied.*physical|"
        r"cctv.*tamper|camera.*offline|physical.*breach|"
        r"clean.*desk.*fail|usb.*unauthorized|removable.*block|"
        r"equipment.*missing|device.*stolen|"
        r"power.*failure|ups.*critical|hvac.*alarm|"
        r"media.*unaccounted|disposal.*fail|data.*sanitiz.*fail)",
    ],
    description=(
        "14 controles: perímetros de seguridad física (A.7.1), controles de entrada (A.7.2), "
        "protección de oficinas (A.7.3), monitoreo físico/CCTV (A.7.4 NUEVO), "
        "trabajo en áreas seguras (A.7.6), escritorio y pantalla limpios (A.7.7), "
        "ubicación y protección de equipos (A.7.8), seguridad de activos externos (A.7.9), "
        "medios de almacenamiento (A.7.10), servicios de suministro (A.7.11), "
        "cableado (A.7.12), mantenimiento (A.7.13), eliminación segura (A.7.14)."
    ),
)

# ── A.8 — CONTROLES TECNOLÓGICOS ─────────────────────────────────
# 34 controles: endpoints, acceso, autenticación, criptografía,
# malware, vulnerabilidades, configuración (NUEVO), DLP (NUEVO),
# logging, monitoreo (NUEVO), red, filtrado web (NUEVO), desarrollo seguro.
A8_TECHNOLOGICAL = ControlDomain(
    id="A.8",
    name="Controles Tecnológicos",
    annex_ref="Anexo A, Sección 8 (A.8.1–A.8.34)",
    num_controls=34,
    weight=0.50,
    controls_new=[
        "A.8.9 Gestión de la configuración",
        "A.8.10 Eliminación de información",
        "A.8.11 Enmascaramiento de datos",
        "A.8.12 Prevención de fuga de datos (DLP)",
        "A.8.16 Actividades de monitoreo",
        "A.8.23 Filtrado web",
        "A.8.28 Codificación segura",
    ],
    indicators=[
        # A.8.1-8.6: Acceso e Identidad
        r"(?i)(login|logon|logged.on|authentication.*success|session.start|"
        r"accepted.*password|accepted.*publickey|session.*opened|"
        r"mfa.*success|2fa.*verified|otp.*accepted|"
        r"privilege.*assign|sudo.*granted|admin.*session|"
        r"account.*created|user.*provisioned|role.*assigned|"
        r"endpoint.*registered|device.*compliant|mdm.*enrolled|"
        # A.8.7-8.13: Protección de datos
        r"antivirus.*ok|malware.*quarantine|edr.*detect|"
        r"vulnerability.*scan.*complet|patch.*applied|cve.*mitigated|"
        r"config.*baseline|config.*compliant|hardening.*applied|"
        r"dlp.*monitor|data.*loss.*prevent|sensitive.*data.*detect|"
        r"backup.*ok|"
        # A.8.14-8.17: Logging y Monitoreo
        r"log.*collected|event.*forward|syslog.*ok|"
        r"siem.*alert|ids.*alert|ips.*block|"
        # A.8.20-8.26: Red y Criptografía
        r"ssl.*ok|tls.*established|https.*200|vpn.*connect|"
        r"firewall.*allow|certificate.*valid|cipher.*strong|"
        r"network.*segment|vlan.*tagged|dmz.*traffic|"
        r"web.*filter.*block|url.*categorized|proxy.*allow|"
        r"encrypt.*success|key.*exchange|aes.*256|tls.*1\.3|"
        # A.8.25-8.34: Desarrollo Seguro
        r"sast.*pass|dast.*pass|code.*review.*approv|"
        r"secure.*coding|pentest.*pass|vuln.*fix.*deploy)",
    ],
    risk_patterns=[
        # Acceso
        r"(?i)(failed.*password|authentication.*failure|invalid.*user|"
        r"access.*denied|login.*failed|logon.*failure|bad.*password|"
        r"brute.?force|too.*many.*authentication|account.*locked|"
        r"mfa.*bypass|mfa.*fail|otp.*invalid|"
        r"privilege.*escalation|sudo.*unauthorized|"
        r"account.*compromised|credential.*stolen|"
        r"endpoint.*non.*compliant|device.*unmanaged|"
        # Malware y Vulnerabilidades
        r"malware.*detect|virus.*found|ransomware|trojan|"
        r"exploit.*attempt|cve.*exploit|zero.*day|"
        r"vulnerability.*critical.*unpatched|patch.*overdue|"
        r"config.*drift|baseline.*violat|unauthorized.*change|"
        r"dlp.*block|data.*exfiltrat|sensitive.*leak|"
        r"log.*gap|logging.*fail|audit.*trail.*broken|"
        r"backup.*fail|backup.*error|restore.*fail|"
        # Red
        r"ssl.*error|tls.*error|certificate.*expired|certificate.*invalid|"
        r"weak.*cipher|sslv2|sslv3|rc4|md5.*signature|self.*signed.*prod|"
        r"port.*scan|syn.*flood|ddos|dos.*attack|"
        r"lateral.*movement|web.*filter.*bypass|malicious.*url.*access|"
        r"plain.*text.*password|unencrypted.*credential|"
        # Monitoreo
        r"critical.*error|service.*down|system.*failure)",
    ],
    description=(
        "34 controles tecnológicos: dispositivos de usuario final (A.8.1), "
        "derechos de acceso privilegiado (A.8.2), autenticación segura/MFA (A.8.5), "
        "protección contra malware (A.8.7), gestión de vulnerabilidades (A.8.8), "
        "gestión de la configuración (A.8.9 NUEVO), eliminación de información (A.8.10 NUEVO), "
        "enmascaramiento de datos (A.8.11 NUEVO), DLP (A.8.12 NUEVO), "
        "registro de eventos (A.8.15), monitoreo continuo (A.8.16 NUEVO), "
        "seguridad de redes (A.8.20), criptografía (A.8.24), "
        "filtrado web (A.8.23 NUEVO), codificación segura (A.8.28 NUEVO)."
    ),
)

# ── Mapa principal: 4 dominios oficiales del Anexo A ─────────────
ISO27001_DOMAINS: Dict[str, ControlDomain] = {
    "A5_organizational": A5_ORGANIZATIONAL,
    "A6_people":         A6_PEOPLE,
    "A7_physical":       A7_PHYSICAL,
    "A8_technological":  A8_TECHNOLOGICAL,
}

# ══════════════════════════════════════════════════════════════════
# SUB-DOMINIOS DE A.8 — Para el radar de detalle
# Fuente: ISO/IEC 27002:2022 (guía de implementación de controles)
# ══════════════════════════════════════════════════════════════════
@dataclass
class A8SubDomain:
    id: str
    name: str
    controls_ref: str
    sub_weight: float           # Peso dentro de A.8 (suma = 1.0)
    indicators: List[str]
    risk_patterns: List[str]


A8_SUBDOMAINS: Dict[str, A8SubDomain] = {

    "A8_1_access": A8SubDomain(
        id="A.8.1",
        name="Acceso e Identidad",
        controls_ref="A.8.1–A.8.6 (Endpoints, Acceso, MFA)",
        sub_weight=0.30,
        indicators=[r"(?i)(login|logon|authentication.*success|mfa.*success|"
                    r"2fa.*verified|otp.*accepted|privilege.*assign|sudo.*granted|"
                    r"account.*created|user.*provisioned|endpoint.*registered|"
                    r"device.*compliant|mdm.*enrolled|role.*assigned)"],
        risk_patterns=[r"(?i)(failed.*password|authentication.*failure|brute.?force|"
                       r"account.*locked|mfa.*bypass|privilege.*escalation|"
                       r"account.*compromised|credential.*stolen|"
                       r"endpoint.*non.*compliant|device.*unmanaged)"],
    ),

    "A8_2_protection": A8SubDomain(
        id="A.8.2",
        name="Protección de Activos y Datos",
        controls_ref="A.8.7–A.8.13 (Malware, Vuln., Config., DLP — 4 nuevos en 2022)",
        sub_weight=0.25,
        indicators=[r"(?i)(antivirus.*ok|malware.*quarantine|edr.*detect|"
                    r"vulnerability.*scan.*complet|patch.*applied|cve.*mitigated|"
                    r"config.*baseline|config.*compliant|hardening.*applied|"
                    r"dlp.*monitor|data.*loss.*prevent|sensitive.*data.*detect|"
                    r"backup.*ok|information.*deletion|data.*mask)"],
        risk_patterns=[r"(?i)(malware.*detect|virus.*found|ransomware|trojan|"
                       r"exploit.*attempt|cve.*exploit|zero.*day|"
                       r"vulnerability.*critical.*unpatched|patch.*overdue|"
                       r"config.*drift|baseline.*violat|unauthorized.*change|"
                       r"dlp.*block|data.*exfiltrat|sensitive.*leak|"
                       r"backup.*fail|backup.*error)"],
    ),

    "A8_3_network": A8SubDomain(
        id="A.8.3",
        name="Red y Criptografía",
        controls_ref="A.8.20–A.8.26 (Red, Cripto, Filtrado Web — 1 nuevo en 2022)",
        sub_weight=0.25,
        indicators=[r"(?i)(ssl.*ok|tls.*established|https.*200|vpn.*connect|"
                    r"firewall.*allow|certificate.*valid|cipher.*strong|"
                    r"network.*segment|vlan.*tagged|dmz.*traffic|"
                    r"web.*filter.*block|url.*categorized|proxy.*allow|"
                    r"encrypt.*success|key.*exchange|aes.*256|tls.*1\.3)"],
        risk_patterns=[r"(?i)(ssl.*error|tls.*error|certificate.*expired|"
                       r"weak.*cipher|sslv2|sslv3|rc4|self.*signed.*prod|"
                       r"port.*scan|syn.*flood|ddos|lateral.*movement|"
                       r"web.*filter.*bypass|malicious.*url.*access|"
                       r"plain.*text.*password|unencrypted.*credential)"],
    ),

    "A8_4_monitoring": A8SubDomain(
        id="A.8.4",
        name="Monitoreo y Continuidad",
        controls_ref="A.8.14–A.8.17, A.8.28–A.8.34 (Logging, Monitoreo — 2 nuevos en 2022)",
        sub_weight=0.20,
        indicators=[r"(?i)(log.*collected|event.*forward|syslog.*ok|"
                    r"siem.*alert|ids.*alert|ips.*block|"
                    r"backup.*ok|restore.*ok|dr.*test.*pass|"
                    r"secure.*coding|sast.*pass|dast.*pass|"
                    r"audit.*trail.*ok|clock.*sync|ntp.*ok)"],
        risk_patterns=[r"(?i)(log.*gap|logging.*fail|audit.*trail.*broken|"
                       r"backup.*fail|backup.*error|restore.*fail|"
                       r"critical.*error|service.*down|system.*failure|"
                       r"clock.*skew|time.*drift)"],
    ),
}

# ══════════════════════════════════════════════════════════════════
# UMBRALES Y CONFIGURACIÓN
# ══════════════════════════════════════════════════════════════════
MIN_EVENTS_FOR_LOGGING = 10

THRESHOLDS = {
    "critical_failure_rate": 0.30,
    "high_failure_rate":     0.15,
    "medium_failure_rate":   0.05,
    "good_log_volume":       100,
    "excellent_log_volume":  500,
}

# ── Verificación de integridad ────────────────────────────────────
assert abs(sum(d.weight for d in ISO27001_DOMAINS.values()) - 1.0) < 0.001, \
    "Los pesos de los 4 dominios deben sumar 1.0"
assert abs(sum(s.sub_weight for s in A8_SUBDOMAINS.values()) - 1.0) < 0.001, \
    "Los pesos de los sub-dominios A.8 deben sumar 1.0"

# ── Referencia cruzada 2013 → 2022 ───────────────────────────────
CONTROL_MAPPING_2013_TO_2022 = {
    "A.5  (2013) Políticas SI":          "A.5.1–A.5.2 (2022)",
    "A.6  (2013) Organización SI":       "A.5.2–A.5.3 (2022)",
    "A.7  (2013) Seguridad RRHH":        "A.6.1–A.6.8 (2022)",
    "A.8  (2013) Gestión Activos":       "A.5.9–A.5.13 (2022)",
    "A.9  (2013) Control Acceso":        "A.8.2–A.8.6 (2022)",
    "A.10 (2013) Criptografía":          "A.8.24–A.8.25 (2022)",
    "A.11 (2013) Seguridad Física":      "A.7.1–A.7.14 (2022)",
    "A.12 (2013) Seguridad Operaciones": "A.8.7–A.8.17 (2022)",
    "A.13 (2013) Comunicaciones":        "A.8.20–A.8.23 (2022)",
    "A.14 (2013) Desarrollo Seguro":     "A.8.25–A.8.26 (2022)",
    "A.15 (2013) Proveedores":           "A.5.19–A.5.22 (2022)",
    "A.16 (2013) Gestión Incidentes":    "A.5.24–A.5.28 (2022)",
    "A.17 (2013) Continuidad Negocio":   "A.5.29–A.5.30 (2022)",
    "A.18 (2013) Cumplimiento":          "A.5.31–A.5.36 (2022)",
}
