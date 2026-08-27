"""
CyberDefense Monitoring System — Flask Backend (MySQL Edition)
Run:  pip install flask flask-cors mysql-connector-python
      python app.py
"""

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
import datetime, random, re

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# ─────────────────────────────────────────
# MYSQL CONFIG  — edit these to match yours
# ─────────────────────────────────────────

DB_CONFIG = {
    "host":     "127.0.0.1",
    "port":     3306,
    "user":     "root",
    "password": "@Wasimraja@77",          # ← your MySQL root password
    "database": "cyber_db",
}

# Connection pool (avoids opening/closing a connection on every request)
pool = pooling.MySQLConnectionPool(
    pool_name="cyberdefense_pool",
    pool_size=5,
    **DB_CONFIG
)

def get_db():
    """Get a connection from the pool."""
    return pool.get_connection()


# ─────────────────────────────────────────
# DATABASE SETUP  (run once on startup)
# ─────────────────────────────────────────

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts_log (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME    NOT NULL,
            level     VARCHAR(10) NOT NULL,
            message   TEXT        NOT NULL,
            source    VARCHAR(50) DEFAULT 'system'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS phishing_emails (
            id                  INT AUTO_INCREMENT PRIMARY KEY,
            timestamp           DATETIME     NOT NULL,
            sender              VARCHAR(200),
            subject             VARCHAR(300),
            body                TEXT,
            score               INT          DEFAULT 0,
            verdict             VARCHAR(20)  DEFAULT 'CLEAN',
            spf_pass            TINYINT(1)   DEFAULT 0,
            dkim_pass           TINYINT(1)   DEFAULT 0,
            dmarc_pass          TINYINT(1)   DEFAULT 0,
            has_urgency         TINYINT(1)   DEFAULT 0,
            has_suspicious_link TINYINT(1)   DEFAULT 0,
            has_spoofed_domain  TINYINT(1)   DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS port_scan_results (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            scan_id   VARCHAR(50)  NOT NULL,
            timestamp DATETIME     NOT NULL,
            host      VARCHAR(50),
            port      INT,
            service   VARCHAR(50),
            state     VARCHAR(20),
            risk      VARCHAR(20),
            notes     TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS ransomware_incidents (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            timestamp      DATETIME    NOT NULL,
            host           VARCHAR(100),
            files_affected INT         DEFAULT 0,
            extension      VARCHAR(20),
            status         VARCHAR(20) DEFAULT 'ACTIVE',
            playbook_step  INT         DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS file_change_events (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            timestamp  DATETIME    NOT NULL,
            directory  VARCHAR(300),
            event_type VARCHAR(50),
            details    TEXT,
            flagged    TINYINT(1)  DEFAULT 0
        )
    """)

    # Seed sample data only if alerts_log is empty
    c.execute("SELECT COUNT(*) FROM alerts_log")
    if c.fetchone()[0] == 0:
        _seed_sample_data(c)

    conn.commit()
    c.close()
    conn.close()
    print("✅  Database tables ready")


def _seed_sample_data(c):
    logs = [
        ("2024-01-15 10:00:00", "OK",   "System startup complete · All monitoring modules active",                      "system"),
        ("2024-01-15 11:34:55", "CRIT", "Fake invoice phishing blocked — sender: billing@pay-secure.net · Score: 87",  "phishing"),
        ("2024-01-15 12:11:02", "OK",   "Phishing simulation completed — report generated · 4 users trained",          "phishing"),
        ("2024-01-15 12:44:19", "WARN", "MySQL port 3306 accessible externally — immediate action required",           "network"),
        ("2024-01-15 13:00:00", "INFO", "Scheduled port scan started — target: 192.168.1.0/24",                        "network"),
        ("2024-01-15 13:04:12", "INFO", "Port scan completed — 23 open ports · 5 critical findings",                   "network"),
        ("2024-01-15 13:28:34", "WARN", "Suspicious email flagged — sender: ceo@company-secure.net · Score: 71/100",   "phishing"),
        ("2024-01-15 13:51:08", "WARN", "Port 3389 exposed to internet · Firewall rule missing on 192.168.1.12",       "network"),
        ("2024-01-15 14:02:01", "CRIT", "Phishing page submitted — credentials harvested from 192.168.1.44 · Blocked", "phishing"),
        ("2024-01-15 14:02:11", "CRIT", "Ransomware detected on DESKTOP-7F2A — 847 files affected · Host isolated",    "ransomware"),
    ]
    c.executemany(
        "INSERT INTO alerts_log (timestamp, level, message, source) VALUES (%s, %s, %s, %s)",
        logs
    )

    scan_id = "scan-001"
    ports = [
        (scan_id, "2024-01-15 13:04:12", "192.168.1.12", 3389, "RDP",    "OPEN", "CRITICAL", "Brute force risk · Restrict to VPN"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.12", 23,   "Telnet", "OPEN", "CRITICAL", "Plaintext auth · Disable immediately"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.8",  21,   "FTP",    "OPEN", "HIGH",     "Anonymous login enabled"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.5",  22,   "SSH",    "OPEN", "MEDIUM",   "Key auth required · Version outdated"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.5",  80,   "HTTP",   "OPEN", "MEDIUM",   "No HTTPS · Redirect recommended"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.1",  443,  "HTTPS",  "OPEN", "LOW",      "TLS 1.3 · Cert valid 180d"),
        (scan_id, "2024-01-15 13:04:12", "192.168.1.20", 3306, "MySQL",  "OPEN", "CRITICAL", "Exposed externally · Firewall now"),
    ]
    c.executemany(
        "INSERT INTO port_scan_results (scan_id,timestamp,host,port,service,state,risk,notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        ports
    )

    c.execute("""
        INSERT INTO ransomware_incidents (timestamp, host, files_affected, extension, status, playbook_step)
        VALUES ('2024-01-15 14:02:11', 'DESKTOP-7F2A', 847, '.enc', 'ACTIVE', 3)
    """)


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def rows_to_dicts(cursor):
    """Convert MySQL cursor rows → list of dicts using column names."""
    cols = [col[0] for col in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def log_event(level, message, source="system"):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts_log (timestamp, level, message, source) VALUES (%s, %s, %s, %s)",
        (ts(), level, message, source)
    )
    conn.commit()
    c.close()
    conn.close()


# ─────────────────────────────────────────
# SERVE FRONTEND
# ─────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'cyber_defense.html')


# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": ts(), "version": "2.0-mysql"})


# ─────────────────────────────────────────
# OVERVIEW  /api/overview
# ─────────────────────────────────────────

@app.route("/api/overview", methods=["GET"])
def overview():
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT level, COUNT(*) FROM alerts_log GROUP BY level")
    counts = {row[0]: row[1] for row in c.fetchall()}

    c.execute("""
        SELECT risk, COUNT(*) FROM port_scan_results
        WHERE scan_id = (SELECT scan_id FROM port_scan_results ORDER BY timestamp DESC LIMIT 1)
        GROUP BY risk
    """)
    port_counts = {row[0]: row[1] for row in c.fetchall()}

    c.execute("SELECT COUNT(*) FROM ransomware_incidents WHERE status = 'ACTIVE'")
    active_ransomware = c.fetchone()[0]

    today = datetime.date.today().isoformat()
    c.execute("SELECT COUNT(*) FROM phishing_emails WHERE DATE(timestamp) = %s", (today,))
    phish_today = c.fetchone()[0]

    c.close()
    conn.close()
    return jsonify({
        "alerts": {
            "critical": counts.get("CRIT", 0),
            "warning":  counts.get("WARN", 0),
            "info":     counts.get("INFO", 0),
            "ok":       counts.get("OK",   0),
        },
        "ports": {
            "critical": port_counts.get("CRITICAL", 0),
            "high":     port_counts.get("HIGH",     0),
            "medium":   port_counts.get("MEDIUM",   0),
            "low":      port_counts.get("LOW",      0),
        },
        "active_ransomware_incidents": active_ransomware,
        "phishing_emails_today":       phish_today,
        "system_status": "ACTIVE"
    })


# ─────────────────────────────────────────
# PHISHING  /api/phishing
# ─────────────────────────────────────────

URGENCY_WORDS = ["urgent", "immediately", "action required", "verify now",
                 "account suspended", "limited time", "expires", "click now"]
SUSPICIOUS_DOMAINS = ["paypal-secure", "amazon-verify", "apple-support",
                      "google-signin", "microsoft-login", "company-secure",
                      "pay-secure", "secure-login", "verify-account"]


def analyse_email(sender: str, subject: str, body: str) -> dict:
    score = 0

    spf   = random.choice([True, True, False])
    dkim  = random.choice([True, True, False])
    dmarc = spf and dkim
    if not spf:   score += 20
    if not dkim:  score += 15
    if not dmarc: score += 10

    combined    = (subject + " " + body).lower()
    has_urgency = any(w in combined for w in URGENCY_WORDS)
    if has_urgency: score += 20

    links          = re.findall(r'https?://\S+', body)
    suspicious_link = any(any(d in l.lower() for d in SUSPICIOUS_DOMAINS) for l in links) \
                      or bool(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', body))
    if suspicious_link: score += 25

    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    spoofed       = any(d in sender_domain for d in SUSPICIOUS_DOMAINS)
    if spoofed: score += 20

    if re.search(r'(paypal|amazon|apple|google|microsoft)', combined) and \
       not re.search(r'(paypal\.com|amazon\.com|apple\.com|google\.com|microsoft\.com)', sender):
        score += 10

    score   = min(score, 100)
    verdict = "PHISHING" if score >= 70 else "SUSPICIOUS" if score >= 40 else "CLEAN"

    return {
        "score": score, "verdict": verdict,
        "spf_pass": spf, "dkim_pass": dkim, "dmarc_pass": dmarc,
        "has_urgency": has_urgency,
        "has_suspicious_link": suspicious_link,
        "has_spoofed_domain":  spoofed,
    }


@app.route("/api/phishing/analyse", methods=["POST"])
def phishing_analyse():
    data    = request.get_json(force=True)
    sender  = data.get("sender",  "")
    subject = data.get("subject", "")
    body    = data.get("body",    "")

    if not sender and not subject and not body:
        return jsonify({"error": "Provide at least one of sender, subject, or body"}), 400

    result = analyse_email(sender, subject, body)

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO phishing_emails
            (timestamp, sender, subject, body, score, verdict,
             spf_pass, dkim_pass, dmarc_pass,
             has_urgency, has_suspicious_link, has_spoofed_domain)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        ts(), sender, subject, body,
        result["score"], result["verdict"],
        int(result["spf_pass"]),  int(result["dkim_pass"]),  int(result["dmarc_pass"]),
        int(result["has_urgency"]), int(result["has_suspicious_link"]), int(result["has_spoofed_domain"])
    ))
    conn.commit()
    c.close()
    conn.close()

    level = "CRIT" if result["verdict"] == "PHISHING" else \
            "WARN" if result["verdict"] == "SUSPICIOUS" else "INFO"
    log_event(level, f"{result['verdict']} email — sender: {sender} · Score: {result['score']}", "phishing")
    return jsonify(result)


@app.route("/api/phishing/history", methods=["GET"])
def phishing_history():
    limit = int(request.args.get("limit", 20))
    conn  = get_db()
    c     = conn.cursor()
    c.execute("SELECT * FROM phishing_emails ORDER BY timestamp DESC LIMIT %s", (limit,))
    result = rows_to_dicts(c)
    c.close(); conn.close()
    return jsonify(result)


@app.route("/api/phishing/simulate", methods=["POST"])
def phishing_simulate():
    templates = [
        {"sender": "security@paypal-secure.net",
         "subject": "Urgent: Your PayPal account has been limited",
         "body": "Your account has been limited. Click here: http://paypal-secure.net/verify"},
        {"sender": "noreply@amazon-verify.com",
         "subject": "Action Required: Confirm your payment method",
         "body": "Unusual activity detected. Verify now at http://amazon-verify.com/secure"},
        {"sender": "hr@company-updates.net",
         "subject": "Salary review document — please review immediately",
         "body": "Login to view your document: http://198.51.100.5/doc"},
    ]
    tpl    = random.choice(templates)
    result = analyse_email(tpl["sender"], tpl["subject"], tpl["body"])
    log_event("INFO", f"Phishing simulation triggered — {tpl['subject']}", "phishing")
    return jsonify({**tpl, **result, "simulation": True})


# ─────────────────────────────────────────
# NETWORK  /api/network
# ─────────────────────────────────────────

COMMON_PORTS = {
    21:   ("FTP",       "HIGH",     "Anonymous login may be enabled"),
    22:   ("SSH",       "MEDIUM",   "Ensure key-based auth only"),
    23:   ("Telnet",    "CRITICAL", "Plaintext auth · Disable immediately"),
    25:   ("SMTP",      "MEDIUM",   "Check relay settings"),
    53:   ("DNS",       "LOW",      "Restrict recursion"),
    80:   ("HTTP",      "MEDIUM",   "No HTTPS · Redirect recommended"),
    443:  ("HTTPS",     "LOW",      "TLS 1.3 recommended"),
    3306: ("MySQL",     "CRITICAL", "Should not be externally exposed"),
    3389: ("RDP",       "CRITICAL", "Brute force risk · Restrict to VPN"),
    5432: ("PgSQL",     "HIGH",     "Restrict network access"),
    8080: ("HTTP-ALT",  "MEDIUM",   "Dev server? Verify intentional"),
    8443: ("HTTPS-ALT", "LOW",      "Verify certificate"),
}


def simulate_port_scan(target: str):
    results = []
    hosts   = [f"192.168.1.{i}" for i in [1, 5, 8, 12, 20, 44]]
    scan_id = "scan-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    for host in hosts:
        open_ports = random.sample(list(COMMON_PORTS.keys()), k=random.randint(1, 4))
        for port in open_ports:
            service, risk, note = COMMON_PORTS[port]
            results.append({
                "scan_id": scan_id, "timestamp": ts(),
                "host": host, "port": port, "service": service,
                "state": "OPEN", "risk": risk, "notes": note,
            })

    conn = get_db()
    c = conn.cursor()
    c.executemany("""
        INSERT INTO port_scan_results
            (scan_id, timestamp, host, port, service, state, risk, notes)
        VALUES (%(scan_id)s, %(timestamp)s, %(host)s, %(port)s,
                %(service)s, %(state)s, %(risk)s, %(notes)s)
    """, results)
    conn.commit()
    c.close(); conn.close()

    crit = sum(1 for r in results if r["risk"] == "CRITICAL")
    log_event("INFO", f"Port scan on {target} — {len(results)} open ports · {crit} critical", "network")
    return results, scan_id


@app.route("/api/network/scan", methods=["POST"])
def start_scan():
    data   = request.get_json(force=True)
    target = data.get("target", "192.168.1.0/24")
    log_event("INFO", f"Port scan started — target: {target}", "network")
    results, scan_id = simulate_port_scan(target)
    return jsonify({"scan_id": scan_id, "target": target,
                    "total": len(results), "results": results})


@app.route("/api/network/results", methods=["GET"])
def scan_results():
    scan_id = request.args.get("scan_id")
    conn = get_db()
    c    = conn.cursor()
    if scan_id:
        c.execute("SELECT * FROM port_scan_results WHERE scan_id=%s ORDER BY risk DESC", (scan_id,))
    else:
        c.execute("SELECT scan_id FROM port_scan_results ORDER BY timestamp DESC LIMIT 1")
        row = c.fetchone()
        if not row:
            c.close(); conn.close(); return jsonify([])
        c.execute("SELECT * FROM port_scan_results WHERE scan_id=%s ORDER BY risk DESC", (row[0],))
    result = rows_to_dicts(c)
    c.close(); conn.close()
    return jsonify(result)


@app.route("/api/network/summary", methods=["GET"])
def network_summary():
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT scan_id FROM port_scan_results ORDER BY timestamp DESC LIMIT 1")
    row = c.fetchone()
    if not row:
        c.close(); conn.close()
        return jsonify({"critical":0,"high":0,"medium":0,"low":0,"open_ports":0,"safe_ports":0})
    c.execute("SELECT risk, COUNT(*) FROM port_scan_results WHERE scan_id=%s GROUP BY risk", (row[0],))
    counts = {r[0]: r[1] for r in c.fetchall()}
    total  = sum(counts.values())
    c.close(); conn.close()
    return jsonify({
        "critical":   counts.get("CRITICAL", 0),
        "high":       counts.get("HIGH",     0),
        "medium":     counts.get("MEDIUM",   0),
        "low":        counts.get("LOW",      0),
        "open_ports": total,
        "safe_ports": counts.get("LOW", 0),
    })


# ─────────────────────────────────────────
# RANSOMWARE  /api/ransomware
# ─────────────────────────────────────────

@app.route("/api/ransomware/monitor/start", methods=["POST"])
def ransomware_start():
    data        = request.get_json(force=True)
    directory   = data.get("directory",   r"C:\Users\Desktop\Documents")
    sensitivity = data.get("sensitivity", "High")
    log_event("INFO", f"Ransomware monitor started — dir: {directory} · sensitivity: {sensitivity}", "ransomware")
    return jsonify({"status": "monitoring", "directory": directory, "sensitivity": sensitivity})


@app.route("/api/ransomware/monitor/stop", methods=["POST"])
def ransomware_stop():
    log_event("INFO", "Ransomware monitor stopped", "ransomware")
    return jsonify({"status": "stopped"})


@app.route("/api/ransomware/test", methods=["POST"])
def ransomware_test():
    host  = request.get_json(force=True).get("host", "DESKTOP-TEST")
    count = random.randint(200, 1000)
    ext   = random.choice([".enc", ".locked", ".crypted", ".ransom"])

    conn = get_db()
    c    = conn.cursor()
    c.execute("""
        INSERT INTO ransomware_incidents
            (timestamp, host, files_affected, extension, status, playbook_step)
        VALUES (%s, %s, %s, %s, 'ACTIVE', 1)
    """, (ts(), host, count, ext))
    conn.commit()
    c.close(); conn.close()

    log_event("CRIT", f"Ransomware detected on {host} — {count} files with {ext} · Host isolated", "ransomware")
    return jsonify({"detected": True, "host": host, "files_affected": count, "extension": ext})


@app.route("/api/ransomware/incidents", methods=["GET"])
def ransomware_incidents():
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM ransomware_incidents ORDER BY timestamp DESC")
    result = rows_to_dicts(c)
    c.close(); conn.close()
    return jsonify(result)


@app.route("/api/ransomware/playbook/<int:incident_id>/advance", methods=["POST"])
def advance_playbook(incident_id):
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT playbook_step FROM ransomware_incidents WHERE id = %s", (incident_id,))
    row = c.fetchone()
    if not row:
        c.close(); conn.close()
        return jsonify({"error": "Incident not found"}), 404

    next_step = row[0] + 1
    status    = "RESOLVED" if next_step > 6 else "ACTIVE"
    c.execute(
        "UPDATE ransomware_incidents SET playbook_step=%s, status=%s WHERE id=%s",
        (min(next_step, 6), status, incident_id)
    )
    conn.commit()
    c.close(); conn.close()

    log_event("INFO", f"Playbook advanced to step {next_step} for incident #{incident_id}", "ransomware")
    return jsonify({"incident_id": incident_id, "playbook_step": min(next_step, 6), "status": status})


# ─────────────────────────────────────────
# LOGS  /api/logs
# ─────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    level  = request.args.get("level",  "")
    source = request.args.get("source", "")
    search = request.args.get("search", "")
    limit  = int(request.args.get("limit", 50))

    query  = "SELECT * FROM alerts_log WHERE 1=1"
    params = []

    if level and level != "All":
        query += " AND level = %s"
        params.append(level.upper())
    if source:
        query += " AND source = %s"
        params.append(source)
    if search:
        query += " AND message LIKE %s"
        params.append(f"%{search}%")

    query += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)

    conn = get_db()
    c    = conn.cursor()
    c.execute(query, params)
    result = rows_to_dicts(c)
    c.close(); conn.close()
    return jsonify(result)


@app.route("/api/logs/export", methods=["GET"])
def export_logs():
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM alerts_log ORDER BY timestamp DESC")
    rows = rows_to_dicts(c)
    c.close(); conn.close()

    lines = ["id,timestamp,level,source,message"]
    for r in rows:
        msg = str(r["message"]).replace('"', '""')
        lines.append(f'{r["id"]},"{r["timestamp"]}",{r["level"]},{r["source"]},"{msg}"')

    return Response(
        "\n".join(lines),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyberdefense_logs.csv"}
    )


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("✅  CyberDefense backend (MySQL) running → http://localhost:5000")
    app.run(debug=True, port=5000)
