"""
generate_samples.py — Generador de Logs Simulados para ISO/IEC 27001:2022
Genera eventos realistas que cubren las 4 cláusulas de controles 2022:
  - Cláusula 5: Organizacionales (políticas, activos, cloud, threat intel)
  - Cláusula 6: Personas (formación, teletrabajo, incidentes reportados)
  - Cláusula 7: Físicos (CCTV, badges, escritorio limpio)
  - Cláusula 8: Tecnológicos (endpoints, MFA, DLP, monitoreo, config)
"""

import random
import datetime
import os

random.seed(2022)

USERS = ["admin", "jgarcia", "mlopez", "aruiz", "sysadmin", "backup_svc",
         "dbadmin", "devops", "readonly_user", "api_svc", "scanner", "root"]
IPS_INTERNAL = ["10.0.1.10", "10.0.1.20", "10.0.2.5", "192.168.1.50",
                "192.168.1.100", "172.16.0.25"]
IPS_EXTERNAL = ["185.220.101.5", "91.108.4.12", "77.88.8.8", "1.1.1.1",
                "203.0.113.50", "198.51.100.20", "45.33.32.156", "104.21.8.9"]
SERVERS = ["web-srv-01", "db-srv-02", "auth-srv-03", "proxy-srv-04",
           "cloud-gw-05", "siem-srv-06", "backup-srv-07", "dlp-agent-08"]

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def rand_ts(start="2024-01-01", days=90):
    base = datetime.datetime(2024, 1, 1, 8, 0, 0)
    offset = random.randint(0, days * 86400)
    # Bias toward business hours
    hour = random.choices(
        range(24),
        weights=[1]*6 + [4]*2 + [8]*10 + [4]*2 + [2]*4,
        k=1
    )[0]
    base = base.replace(hour=hour, minute=random.randint(0, 59),
                        second=random.randint(0, 59))
    base += datetime.timedelta(seconds=offset)
    return base.strftime("%b %d %H:%M:%S")


def rand_ip(external_prob=0.2):
    if random.random() < external_prob:
        return random.choice(IPS_EXTERNAL)
    return random.choice(IPS_INTERNAL)


def rand_user():
    return random.choice(USERS)


def rand_srv():
    return random.choice(SERVERS)


# ─────────────────────────────────────────────────────────────────
# AUTH LOG — Cláusula 8.5 (MFA), 8.2 (privilegios), 6.7 (telework)
# ─────────────────────────────────────────────────────────────────
def gen_auth_log(n=800):
    lines = []
    events = [
        # MFA events (8.5 - nuevo énfasis 2022)
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: mfa_success: MFA verified for user {rand_user()} from {rand_ip(0.3)} port {random.randint(1024,65535)} ssh2",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: mfa_fail: MFA invalid OTP for user {rand_user()} from {rand_ip(0.6)} port {random.randint(1024,65535)}",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: Accepted publickey for {rand_user()} from {rand_ip(0.2)} port {random.randint(1024,65535)} ssh2",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: Failed password for {rand_user()} from {rand_ip(0.7)} port {random.randint(1024,65535)} ssh2",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: Failed password for invalid user {random.choice(['oracle','postgres','admin123','test'])} from {rand_ip(0.9)} port {random.randint(1024,65535)} ssh2",
        # Privileged access (8.2)
        lambda: f"{rand_ts()} {rand_srv()} sudo[{random.randint(1000,9999)}]: privilege_assign: {rand_user()} : TTY=pts/{random.randint(0,5)} ; PWD=/root ; USER=root ; COMMAND=/bin/systemctl restart nginx",
        lambda: f"{rand_ts()} {rand_srv()} sudo[{random.randint(1000,9999)}]: privilege_assign: {rand_user()} granted admin role by IAM",
        lambda: f"{rand_ts()} {rand_srv()} sudo[{random.randint(1000,9999)}]: sudo_unauthorized: {rand_user()} : command not allowed ; COMMAND=/bin/passwd root",
        # Account management (8.3)
        lambda: f"{rand_ts()} {rand_srv()} useradd[{random.randint(1000,9999)}]: account_created: new user account {rand_user()} provisioned by admin",
        lambda: f"{rand_ts()} {rand_srv()} usermod[{random.randint(1000,9999)}]: role_assigned: user {rand_user()} added to group security-admins",
        # Remote/telework (6.7)
        lambda: f"{rand_ts()} {rand_srv()} vpnd[{random.randint(1000,9999)}]: remote_access_vpn: User {rand_user()} connected via VPN from {rand_ip(0.8)} (telework session)",
        # Brute force patterns
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={rand_ip(0.9)} user={rand_user()}",
        lambda: f"{rand_ts()} {rand_srv()} pam_unix[{random.randint(1000,9999)}]: authentication failure: brute_force detected from {rand_ip(0.9)}",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: Disconnecting invalid user {rand_user()} {rand_ip(0.9)} port {random.randint(1024,65535)}: Too many authentication failures",
        # Session
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: session opened for user {rand_user()} by (uid=0)",
        lambda: f"{rand_ts()} {rand_srv()} sshd[{random.randint(1000,9999)}]: account locked: too many failed attempts for user {rand_user()}",
    ]
    weights = [3, 2, 8, 5, 3, 4, 3, 1, 2, 2, 4, 3, 2, 2, 6, 1]
    for _ in range(n):
        fn = random.choices(events, weights=weights, k=1)[0]
        lines.append(fn())
    return lines


# ─────────────────────────────────────────────────────────────────
# APACHE/WEB LOG — Cláusula 8.26 (app security), 8.23 (web filter)
# ─────────────────────────────────────────────────────────────────
def gen_apache_log(n=900):
    lines = []
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    paths_ok  = ["/api/v2/assets", "/api/v2/users", "/health", "/login",
                 "/dashboard", "/reports", "/static/app.js", "/api/v2/cloud-status"]
    paths_bad = ["/admin/../etc/passwd", "/.env", "/wp-admin/", "/phpmyadmin/",
                 "/.git/config", "/api/v2/../../../../etc/shadow",
                 "/xmlrpc.php", "/cgi-bin/test.sh", "/../../../etc/passwd",
                 "/api/internal/secrets", "/debug/console"]
    user_agents_ok  = ["Mozilla/5.0 (Windows NT 10.0; Win64)", "curl/7.88", "PostmanRuntime/7.36"]
    user_agents_bad = ["sqlmap/1.7", "nikto/2.1.6", "masscan/1.3", "zgrab/0.x", "python-requests/2.31"]
    referers = ["-", "https://portal.empresa.com", "https://erp.local"]

    events = [
        # Normal web traffic (8.26)
        lambda: (
            f'{rand_ip(0.3)} - {rand_user()} [{rand_ts()}] '
            f'"{random.choice(methods)} {random.choice(paths_ok)} HTTP/2.0" '
            f'200 {random.randint(200,8000)} "{random.choice(referers)}" "{random.choice(user_agents_ok)}"'
        ),
        # Web filter blocks (8.23 - NEW 2022)
        lambda: (
            f'{rand_ip(0.8)} - - [{rand_ts()}] '
            f'"GET /api/phishing-redirect?url=http://malicious-url.tk HTTP/1.1" '
            f'403 512 "-" "curl/7.88" web_filter_block=malicious_url'
        ),
        lambda: (
            f'web_filter_block [{rand_ts()}] URL categorized=phishing blocked user={rand_user()} '
            f'dst={rand_ip(0.9)} url=http://phishing-site.net proxy=proxy-srv-04'
        ),
        # Attack patterns
        lambda: (
            f'{rand_ip(0.9)} - - [{rand_ts()}] '
            f'"GET {random.choice(paths_bad)} HTTP/1.1" '
            f'{random.choice([400,403,404,500])} 512 "-" "{random.choice(user_agents_bad)}"'
        ),
        lambda: (
            f'{rand_ip(0.9)} - - [{rand_ts()}] '
            f'"POST /api/login HTTP/1.1" 401 350 "-" "{random.choice(user_agents_bad)}" '
            f'X-Scan: port_scan'
        ),
        # DLP detection (8.12 - NEW 2022)
        lambda: (
            f'dlp_detect [{rand_ts()}] sensitive_data_detect: user={rand_user()} '
            f'file=confidential_report.pdf action=blocked classification=C3-Confidential '
            f'endpoint={random.choice(SERVERS)}'
        ),
        lambda: (
            f'dlp_monitor [{rand_ts()}] DLP monitor: data_loss_prevent triggered '
            f'user={rand_user()} dst={rand_ip(0.7)} bytes=45230 policy=DLP-Email-Outbound'
        ),
        # Encryption events (8.24)
        lambda: (
            f'{rand_ip(0.2)} - {rand_user()} [{rand_ts()}] '
            f'"GET {random.choice(paths_ok)} HTTP/2.0" '
            f'200 {random.randint(500,5000)} "https://portal.empresa.com" '
            f'"{random.choice(user_agents_ok)}" ssl=TLS1.3 cipher=AES256-GCM'
        ),
        # SSL errors (8.24)
        lambda: (
            f'[{rand_ts()}] [ssl:error] [pid {random.randint(1000,9999)}] '
            f'AH02042: ssl_error certificate_expired for {rand_ip(0.5)} '
            f'(check certificate renewal)'
        ),
    ]
    weights = [15, 3, 3, 6, 4, 3, 3, 8, 2]
    for _ in range(n):
        fn = random.choices(events, weights=weights, k=1)[0]
        lines.append(fn())
    return lines


# ─────────────────────────────────────────────────────────────────
# SYSLOG — Cláusula 8.7 (malware), 8.8 (vuln), 8.9 (config), 8.16 (monitoring)
# ─────────────────────────────────────────────────────────────────
def gen_syslog(n=700):
    lines = []
    events = [
        # Normal operations
        lambda: f"{rand_ts()} {rand_srv()} systemd[1]: service_start: Started {random.choice(['nginx','sshd','postgresql','clamav','backup-agent'])} service.",
        lambda: f"{rand_ts()} {rand_srv()} cron[{random.randint(1000,9999)}]: (root) CMD (backup --incremental --dest /backup/daily/)",
        # Malware detection (8.7)
        lambda: f"{rand_ts()} {rand_srv()} clamav[{random.randint(1000,9999)}]: malware_quarantine: {rand_ip(0.6)}:{random.randint(1024,65535)}: Eicar-Test-Signature FOUND quarantined",
        lambda: f"{rand_ts()} {rand_srv()} edr-agent[{random.randint(1000,9999)}]: edr_detect: Suspicious process injection detected pid={random.randint(100,9999)} user={rand_user()} severity=HIGH",
        lambda: f"{rand_ts()} {rand_srv()} edr-agent[{random.randint(1000,9999)}]: ransomware: Ransomware behavior detected process=svchost.exe blocking=true",
        # Vulnerability management (8.8)
        lambda: f"{rand_ts()} {rand_srv()} vuln-scanner[{random.randint(1000,9999)}]: vulnerability_scan_complet: Scan finished host={rand_ip()} findings=critical:{random.randint(0,3)},high:{random.randint(0,8)},medium:{random.randint(2,15)}",
        lambda: f"{rand_ts()} {rand_srv()} patch-mgr[{random.randint(1000,9999)}]: patch_applied: CVE-{random.randint(2022,2024)}-{random.randint(1000,50000)} patch_applied successfully on {rand_srv()}",
        lambda: f"{rand_ts()} {rand_srv()} vuln-scanner[{random.randint(1000,9999)}]: vulnerability_critical_unpatched: CVE-{random.randint(2022,2024)}-{random.randint(1000,50000)} CRITICAL unpatched on {rand_srv()} patch_overdue={random.randint(30,90)}days",
        # Configuration management (8.9 - NEW 2022)
        lambda: f"{rand_ts()} {rand_srv()} config-mgr[{random.randint(1000,9999)}]: config_baseline: Configuration compliance check passed on {rand_srv()} hardening_applied=CIS-L2",
        lambda: f"{rand_ts()} {rand_srv()} config-mgr[{random.randint(1000,9999)}]: config_drift: Unauthorized configuration change detected on {rand_srv()} param=firewall_ruleset baseline_violat=true",
        # Monitoring events (8.16 - NEW 2022)
        lambda: f"{rand_ts()} {rand_srv()} siem-agent[{random.randint(1000,9999)}]: siem_alert: SIEM correlation rule triggered: Multiple failed logins from {rand_ip(0.8)} count={random.randint(10,50)}",
        lambda: f"{rand_ts()} {rand_srv()} ids-agent[{random.randint(1000,9999)}]: ids_alert: IDS signature triggered: port_scan detected from {rand_ip(0.9)} ports_scanned={random.randint(100,1000)}",
        lambda: f"{rand_ts()} {rand_srv()} mon-agent[{random.randint(1000,9999)}]: log_collected: Event log forwarded to SIEM events={random.randint(100,5000)} syslog_ok=true",
        # Backup events
        lambda: f"{rand_ts()} {rand_srv()} backup[{random.randint(1000,9999)}]: backup_ok: Daily backup completed size={random.randint(10,500)}GB duration={random.randint(30,180)}min",
        lambda: f"{rand_ts()} {rand_srv()} backup[{random.randint(1000,9999)}]: backup_fail: Backup error: connection timeout to backup-srv-07",
        # Incident detection
        lambda: f"{rand_ts()} {rand_srv()} incident-mgr[{random.randint(1000,9999)}]: incident_open: Security incident ticket TKT-{random.randint(1000,9999)} created severity={random.choice(['LOW','MEDIUM','HIGH','CRITICAL'])}",
        lambda: f"{rand_ts()} {rand_srv()} incident-mgr[{random.randint(1000,9999)}]: breach_detect: Potential data breach detected user={rand_user()} exfiltration_attempt=true",
        # System errors
        lambda: f"{rand_ts()} {rand_srv()} kernel: [  {random.randint(100000,999999)}.{random.randint(0,999999)}] Out of memory: oom_killer invoked process={random.choice(['java','python','mysqld'])}",
        lambda: f"{rand_ts()} {rand_srv()} systemd[1]: service_down: Failed to start nginx.service - A high performance web server. Status=failed",
    ]
    weights = [10, 5, 3, 3, 1, 5, 6, 2, 5, 2, 4, 3, 5, 8, 2, 4, 1, 2, 2]
    for _ in range(n):
        fn = random.choices(events, weights=weights, k=1)[0]
        lines.append(fn())
    return lines


# ─────────────────────────────────────────────────────────────────
# WINDOWS EVENTS CSV — Cláusula 8.15 (logging), 8.16 (monitoring)
# ─────────────────────────────────────────────────────────────────
def gen_windows_events(n=600):
    rows = ["TimeGenerated,EventID,EventType,Source,Message,User,ComputerName,SourceIP"]
    event_templates = [
        # Logon/Logoff (8.5)
        lambda: (f"{rand_ts()}", "4624", "Information", "Security",
                 f"An account was successfully logged on. Subject: {rand_user()}", rand_user(), rand_srv(), rand_ip(0.2)),
        lambda: (f"{rand_ts()}", "4625", "FailureAudit", "Security",
                 f"An account failed to log on. Account Name: {rand_user()} Failure Reason: bad password", rand_user(), rand_srv(), rand_ip(0.7)),
        lambda: (f"{rand_ts()}", "4648", "Information", "Security",
                 f"A logon was attempted using explicit credentials: {rand_user()}", rand_user(), rand_srv(), rand_ip(0.3)),
        # Privilege (8.2)
        lambda: (f"{rand_ts()}", "4672", "Information", "Security",
                 f"Special privileges assigned to new logon: {rand_user()}", rand_user(), rand_srv(), rand_ip(0.1)),
        lambda: (f"{rand_ts()}", "4673", "SuccessAudit", "Security",
                 f"A privileged service was called by {rand_user()}", rand_user(), rand_srv(), rand_ip(0.1)),
        # Account changes (8.3)
        lambda: (f"{rand_ts()}", "4720", "Information", "Security",
                 f"A user account was created: {rand_user()} account_provisioned=true", "admin", rand_srv(), rand_ip(0.0)),
        lambda: (f"{rand_ts()}", "4740", "Information", "Security",
                 f"A user account was locked out after failed attempts: {rand_user()} account_locked=true", rand_user(), rand_srv(), rand_ip(0.5)),
        # Policy (5.1, 5.36)
        lambda: (f"{rand_ts()}", "4739", "Information", "Security",
                 f"Domain policy compliance_check was changed. compliance_scan=passed", "System", rand_srv(), "-"),
        # Monitoring (8.16)
        lambda: (f"{rand_ts()}", "4688", "Information", "Security",
                 f"A new process has been created: siem_alert triggered process=cmd.exe parent=explorer.exe User={rand_user()}", rand_user(), rand_srv(), rand_ip(0.2)),
        # Audit log (8.15)
        lambda: (f"{rand_ts()}", "1102", "Information", "Security",
                 f"The audit log was cleared by {rand_user()} - audit_trail_broken=true", rand_user(), rand_srv(), rand_ip(0.3)),
        # DLP Windows agent (8.12)
        lambda: (f"{rand_ts()}", "8001", "Warning", "DLP-Agent",
                 f"dlp_block: sensitive_leak attempt blocked user={rand_user()} file=financial_data.xlsx classification=C3", rand_user(), rand_srv(), rand_ip(0.2)),
        # Endpoint compliance (8.1)
        lambda: (f"{rand_ts()}", "7036", "Information", "Service Control Manager",
                 f"endpoint_registered: Device compliance check passed mdm_enrolled=true", "SYSTEM", rand_srv(), "-"),
        # Config management (8.9)
        lambda: (f"{rand_ts()}", "4826", "Information", "Security",
                 f"config_compliant: Boot configuration changed authorized_change=true baseline_check=passed", "SYSTEM", rand_srv(), "-"),
    ]
    weights = [10, 6, 4, 4, 3, 3, 2, 3, 4, 1, 3, 4, 3]
    for _ in range(n):
        fn = random.choices(event_templates, weights=weights, k=1)[0]
        ts, eid, etype, src, msg, user, comp, ip = fn()
        msg_clean = msg.replace(",", ";")
        rows.append(f"{ts},{eid},{etype},{src},{msg_clean},{user},{comp},{ip}")
    return rows


# ─────────────────────────────────────────────────────────────────
# PHYSICAL & PEOPLE LOG — Cláusula 7 (físicos), 6 (personas)
# ─────────────────────────────────────────────────────────────────
def gen_physical_people_log(n=300):
    lines = []
    events = [
        # Physical security (7.2, 7.4 NEW 2022)
        lambda: f"{rand_ts()} access-ctrl[{random.randint(100,999)}]: badge_access: User {rand_user()} badge_access granted door=ServerRoom zone=SecureArea",
        lambda: f"{rand_ts()} access-ctrl[{random.randint(100,999)}]: badge_fail: User {rand_user()} badge_fail access_denied door=DataCenter",
        lambda: f"{rand_ts()} cctv-mgr[{random.randint(100,999)}]: cctv_record: Camera CAM-{random.randint(1,20)} recording in progress physical_access_log=active",
        lambda: f"{rand_ts()} cctv-mgr[{random.randint(100,999)}]: cctv_tamper: Camera CAM-{random.randint(1,20)} tampered or offline physical_breach=suspected",
        lambda: f"{rand_ts()} phys-mon[{random.randint(100,999)}]: unauthorized_physical: Tailgating detected door=MainEntrance camera=CAM-{random.randint(1,5)}",
        # Clean desk (7.7)
        lambda: f"{rand_ts()} compliance[{random.randint(100,999)}]: clean_desk_audit: Workstation {rand_user()} clean_desk_audit passed screen_lock=active",
        lambda: f"{rand_ts()} compliance[{random.randint(100,999)}]: clean_desk_fail: Sensitive documents found unattended at workstation {rand_user()}",
        # Equipment (7.14)
        lambda: f"{rand_ts()} asset-mgr[{random.randint(100,999)}]: hardware_asset: Equipment {rand_srv()} hardware_asset tracked location=DataCenter",
        lambda: f"{rand_ts()} asset-mgr[{random.randint(100,999)}]: device_stolen: Laptop reported missing user={rand_user()} asset_id=LTPT-{random.randint(1000,9999)}",
        lambda: f"{rand_ts()} asset-mgr[{random.randint(100,999)}]: disposal_fail: Equipment disposal without data_sanitiz_fail verification",
        # UPS/Power (7.11)
        lambda: f"{rand_ts()} ups-mon[{random.randint(100,999)}]: ups_ok: UPS battery level 98% power_stable all systems nominal",
        lambda: f"{rand_ts()} ups-mon[{random.randint(100,999)}]: ups_critical: UPS power_failure detected switching to battery backup",
        # People controls (6.3 - training)
        lambda: f"{rand_ts()} hr-sys[{random.randint(100,999)}]: training_complet: User {rand_user()} security training_complet ISO27001:2022 awareness module score=95%",
        lambda: f"{rand_ts()} hr-sys[{random.randint(100,999)}]: awareness_session: Security awareness_session completed participants={random.randint(10,50)}",
        lambda: f"{rand_ts()} hr-sys[{random.randint(100,999)}]: training_overdue: User {rand_user()} security training_overdue {random.randint(30,90)} days outstanding",
        # Incident report by employee (6.8)
        lambda: f"{rand_ts()} helpdesk[{random.randint(100,999)}]: security_report_user: Employee {rand_user()} reported security incident via channel INC-{random.randint(1000,9999)}",
        # NDA / Confidentiality (6.6)
        lambda: f"{rand_ts()} hr-sys[{random.randint(100,999)}]: nda_sign: User {rand_user()} nda_sign confidentiality agreement signed onboarding_complete",
        lambda: f"{rand_ts()} hr-sys[{random.randint(100,999)}]: nda_violat: Potential NDA violation detected user={rand_user()} data shared externally",
        # Terminated user access (6.5)
        lambda: f"{rand_ts()} iam-sys[{random.randint(100,999)}]: terminated_user_active: WARNING ex-employee {rand_user()} account still active offboard_fail",
        lambda: f"{rand_ts()} iam-sys[{random.randint(100,999)}]: account_deprovisioned: User {rand_user()} account revoked on termination offboard_complete",
    ]
    weights = [5, 3, 4, 2, 2, 4, 2, 4, 1, 1, 5, 2, 6, 4, 2, 4, 4, 1, 1, 4]
    for _ in range(n):
        fn = random.choices(events, weights=weights, k=1)[0]
        lines.append(fn())
    return lines


def main():
    print("Generando logs de muestra — ISO/IEC 27001:2022 (93 controles, 4 cláusulas)...")

    # Auth log (Cláusula 8: acceso, identidad, MFA)
    auth_path = os.path.join(OUT_DIR, "sample_auth.log")
    auth_lines = gen_auth_log(800)
    with open(auth_path, "w") as f:
        f.write("\n".join(auth_lines))
    print(f"  ✅ {auth_path} ({len(auth_lines)} líneas) — Cláusula 8.2-8.6 (Acceso/Identidad/MFA)")

    # Apache log (Cláusula 8: aplicaciones, filtrado web, DLP)
    apache_path = os.path.join(OUT_DIR, "sample_apache.log")
    apache_lines = gen_apache_log(900)
    with open(apache_path, "w") as f:
        f.write("\n".join(apache_lines))
    print(f"  ✅ {apache_path} ({len(apache_lines)} líneas) — Cláusula 8.23-8.26 (Red/Cripto/Web)")

    # Syslog (Cláusula 8: malware, vuln, config, monitoreo)
    syslog_path = os.path.join(OUT_DIR, "sample_syslog.log")
    syslog_lines = gen_syslog(700)
    with open(syslog_path, "w") as f:
        f.write("\n".join(syslog_lines))
    print(f"  ✅ {syslog_path} ({len(syslog_lines)} líneas) — Cláusula 8.7-8.17 (Detección/Amenazas)")

    # Windows events (Cláusula 8.15-8.16 logging/monitoring)
    win_path = os.path.join(OUT_DIR, "sample_windows_events.csv")
    win_rows = gen_windows_events(600)
    with open(win_path, "w") as f:
        f.write("\n".join(win_rows))
    print(f"  ✅ {win_path} ({len(win_rows)} filas) — Cláusula 8.15-8.16 (Logging/Monitoring)")

    # Physical + People log (Cláusulas 7 y 6)
    phys_path = os.path.join(OUT_DIR, "sample_physical_people.log")
    phys_lines = gen_physical_people_log(300)
    with open(phys_path, "w") as f:
        f.write("\n".join(phys_lines))
    print(f"  ✅ {phys_path} ({len(phys_lines)} líneas) — Cláusulas 6 y 7 (Personas/Físicos)")

    total = len(auth_lines) + len(apache_lines) + len(syslog_lines) + len(win_rows) + len(phys_lines)
    print(f"\n  📊 Total: {total:,} eventos de muestra generados")
    print("  🛡  Cobertura: 4 cláusulas ISO/IEC 27001:2022 (6 dominios de evaluación)")


if __name__ == "__main__":
    main()
