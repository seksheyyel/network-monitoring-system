from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from datetime import datetime
import json
import threading
import time
import hashlib
from threading import Lock
from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP


# ═══════════════════════════════════════════════════════════
#  DATABASE CLASS
# ═══════════════════════════════════════════════════════════
class Database:
    CONFIG = {
        'host':     'localhost',
        'user':     'root',
        'password': '',
        'database': 'network_monitor'
    }

    @staticmethod
    def get_connection():
        return mysql.connector.connect(**Database.CONFIG)


# ═══════════════════════════════════════════════════════════
#  AUDIT LOGGER CLASS
# ═══════════════════════════════════════════════════════════
class AuditLogger:

    @staticmethod
    def get_client_ip():
        for header in ('X-Forwarded-For', 'X-Real-IP'):
            value = request.headers.get(header)
            if value:
                return value.split(',')[0].strip()
        return request.remote_addr or '0.0.0.0'

    @staticmethod
    def save(action, status='success', username='', user_id=None):
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO activity_logs
                   (user_id, username, action, ip_address, status, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (user_id, username, action,
                 AuditLogger.get_client_ip(), status, datetime.now())
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as exc:
            print(f"[LOG ERROR] {exc}")


# ═══════════════════════════════════════════════════════════
#  SETTINGS MANAGER CLASS
# ═══════════════════════════════════════════════════════════
class SettingsManager:

    DEFAULTS = {
        'ddos_threshold':     1000,
        'ddos_window':        3,
        'ddos_cooldown':      15,
        'portscan_threshold': 20,
        'portscan_window':    10,
        'portscan_cooldown':  30,
        'arp_threshold':      3,
        'arp_window':         30,
        'arp_cooldown':       15,
    }

    @staticmethod
    def load_all():
        """Return all settings as a dict {key_name: value}. Falls back to defaults."""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT key_name, value FROM settings")
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            result = dict(SettingsManager.DEFAULTS)
            for row in rows:
                result[row['key_name']] = row['value']
            return result
        except Exception as exc:
            print(f"[SETTINGS LOAD ERROR] {exc}")
            return dict(SettingsManager.DEFAULTS)

    @staticmethod
    def save(key_name, value):
        """Upsert a single setting into the database."""
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO settings (key_name, value) VALUES (%s, %s)
               ON DUPLICATE KEY UPDATE value = %s""",
            (key_name, value, value)
        )
        conn.commit()
        cursor.close()
        conn.close()

    @staticmethod
    def apply_to_capture(capture):
        """Load settings from DB and apply them to the live capture instance."""
        s = SettingsManager.load_all()
        capture.ddos_detector.THRESHOLD = s['ddos_threshold']
        capture.ddos_detector.WINDOW = s['ddos_window']
        capture.ddos_detector.COOLDOWN = s['ddos_cooldown']
        capture.port_scan_detector.THRESHOLD = s['portscan_threshold']
        capture.port_scan_detector.WINDOW = s['portscan_window']
        capture.port_scan_detector.COOLDOWN = s['portscan_cooldown']
        capture.arp_detector.THRESHOLD = s['arp_threshold']
        capture.arp_detector.WINDOW = s['arp_window']
        capture.arp_detector.COOLDOWN = s['arp_cooldown']


# ═══════════════════════════════════════════════════════════
#  ALERT MANAGER CLASS
# ═══════════════════════════════════════════════════════════
class AlertManager:

    @staticmethod
    def save(alert_type, source_ip, details):
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO network_alerts (alert_type, source_ip, details, timestamp) VALUES (%s, %s, %s, %s)",
            (alert_type, source_ip, json.dumps(details), datetime.now())
        )
        conn.commit()
        cursor.close()
        conn.close()

    @staticmethod
    def get_all():
        conn = Database.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM network_alerts ORDER BY timestamp DESC")
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        for a in alerts:
            a['details'] = json.loads(a['details'])
            a['timestamp'] = str(a['timestamp'])
        return alerts

    @staticmethod
    def delete_one(alert_id):
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM network_alerts WHERE id = %s", (alert_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        cursor.close()
        conn.close()
        return deleted

    @staticmethod
    def delete_all():
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM network_alerts")
        conn.commit()
        cursor.close()
        conn.close()


# ═══════════════════════════════════════════════════════════
#  ARP SPOOF DETECTOR CLASS
# ═══════════════════════════════════════════════════════════
class ArpSpoofDetector:
    WINDOW = 30
    THRESHOLD = 3
    COOLDOWN = 15

    def __init__(self):
        self.ip_mac_table = {}
        self.arp_history = defaultdict(list)
        self.arp_cooldown = {}
        self.lock = Lock()

    def detect(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc.lower()
        now = time.time()

        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        with self.lock:
            if src_ip not in self.ip_mac_table:
                self.ip_mac_table[src_ip] = src_mac
                self.arp_history[src_ip].append((src_mac, now))
                return

            self.arp_history[src_ip] = [
                (mac, t) for mac, t in self.arp_history[src_ip]
                if now - t <= self.WINDOW
            ]
            self.arp_history[src_ip].append((src_mac, now))
            unique_macs = {mac for mac, _ in self.arp_history[src_ip]}

            if len(unique_macs) < self.THRESHOLD:
                if src_mac != self.ip_mac_table[src_ip]:
                    self.ip_mac_table[src_ip] = src_mac
                return

            if now - self.arp_cooldown.get(src_ip, 0) < self.COOLDOWN:
                return

            AlertManager.save("ARP Spoofing", src_ip, {
                "trusted_mac":   self.ip_mac_table[src_ip],
                "attacker_macs": list(unique_macs - {self.ip_mac_table[src_ip]}),
                "description":   f"IP {src_ip} claimed {len(unique_macs)} different MACs within {self.WINDOW}s.",
                "action":        "Verify devices on the network. Enable Dynamic ARP Inspection if possible."
            })

            self.arp_cooldown[src_ip] = now
            self.arp_history[src_ip] = [(src_mac, now)]
            self.ip_mac_table[src_ip] = src_mac


# ═══════════════════════════════════════════════════════════
#  DDOS DETECTOR CLASS
# ═══════════════════════════════════════════════════════════
class DDoSDetector:
    WINDOW = 3
    COOLDOWN = 15
    THRESHOLD = 1000
    WHITELIST = set()

    def __init__(self):
        self.stats = defaultdict(
            lambda: {"pkts": 0, "start": time.time(), "last_alert": 0})
        self.lock = Lock()

    def detect(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now = time.time()

        if src_ip in self.WHITELIST:
            return

        with self.lock:
            s = self.stats[src_ip]
            if now - s["start"] > self.WINDOW:
                s["pkts"] = 0
                s["start"] = now

            s["pkts"] += 1

            if s["pkts"] < self.THRESHOLD:
                return
            if now - s["last_alert"] < self.COOLDOWN:
                return

            AlertManager.save("DDoS Attack", src_ip, {
                "packets_in_window": s["pkts"],
                "rate_per_second":   round(s["pkts"] / self.WINDOW),
                "description":       f"{src_ip} sent {s['pkts']} packets in {self.WINDOW}s.",
                "action":            "Block IP at the firewall or investigate the source device."
            })
            s["last_alert"] = now


# ═══════════════════════════════════════════════════════════
#  PORT SCAN DETECTOR CLASS
# ═══════════════════════════════════════════════════════════
class PortScanDetector:
    THRESHOLD = 20
    WINDOW = 10
    COOLDOWN = 30

    def __init__(self):
        self.tracker = defaultdict(list)
        self.cooldown = {}
        self.lock = Lock()

    def detect(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now = time.time()

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport
        else:
            return

        with self.lock:
            self.tracker[src_ip] = [
                (p, t) for p, t in self.tracker[src_ip]
                if now - t <= self.WINDOW
            ]
            self.tracker[src_ip].append((dst_port, now))
            unique_ports = {p for p, _ in self.tracker[src_ip]}

            if len(unique_ports) < self.THRESHOLD:
                return
            if now - self.cooldown.get(src_ip, 0) < self.COOLDOWN:
                return

            AlertManager.save("Port Scan", src_ip, {
                "unique_ports": len(unique_ports),
                "ports":        sorted(unique_ports),
                "description":  f"{src_ip} probed {len(unique_ports)} unique ports in {self.WINDOW}s.",
                "action":       "Monitor or block the source IP if activity is unexpected."
            })
            self.cooldown[src_ip] = now
            self.tracker[src_ip] = []


# ═══════════════════════════════════════════════════════════
#  PACKET CAPTURE CLASS
# ═══════════════════════════════════════════════════════════
class PacketCapture:

    def __init__(self):
        self.arp_detector = ArpSpoofDetector()
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()

    def handle(self, pkt):
        self.arp_detector.detect(pkt)
        self.ddos_detector.detect(pkt)
        self.port_scan_detector.detect(pkt)

    def start(self):
        sniff(iface='Wi-Fi', prn=self.handle, store=False)


# ═══════════════════════════════════════════════════════════
#  FLASK APP
# ═══════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# ── Module-level capture instance ──
# Load persisted settings from DB and apply them before the sniffer starts
capture = PacketCapture()
SettingsManager.apply_to_capture(capture)


# ── Auth ──────────────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = Database.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM admin WHERE username=%s AND password=%s",
            (username, hashlib.sha256(password.encode()).hexdigest())
        )
        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin:
            session['admin'] = username
            session['admin_id'] = admin.get('id')
            AuditLogger.save(action='Login', status='success',
                             username=username, user_id=admin.get('id'))
            return redirect(url_for('dashboard'))

        AuditLogger.save(action='Login', status='failed',
                         username=username or '(unknown)')
        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


@app.route('/logout')
def logout():
    AuditLogger.save(action='Logout', status='success', username=session.get(
        'admin', ''), user_id=session.get('admin_id'))
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('login'))


# ── Pages ─────────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['admin'])


@app.route('/alert')
def alert():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('alerts.html', user=session['admin'])


@app.route('/logs')
def logs():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('logs.html', user=session['admin'])


@app.route('/settings')
def settings():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html', user=session['admin'])


# ── Alert API ─────────────────────────────────────────────
@app.route('/api/alerts')
def api_alerts():
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    return jsonify({'alerts': AlertManager.get_all()})


@app.route('/api/alerts/delete/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    try:
        deleted = AlertManager.delete_one(alert_id)
        if deleted:
            AuditLogger.save(action='Delete Alert', status='warning', username=session.get(
                'admin', ''), user_id=session.get('admin_id'))
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Alert not found"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/alerts/delete-all', methods=['DELETE'])
def delete_all_alerts():
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    try:
        AlertManager.delete_all()
        AuditLogger.save(action='Delete All Alerts', status='warning', username=session.get(
            'admin', ''), user_id=session.get('admin_id'))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# ── Logs API ──────────────────────────────────────────────
@app.route('/api/logs')
def api_logs():
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    per_page = min(1000, int(request.args.get('per_page', 1000)))

    conn = Database.get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, user_id, username, action, ip_address, status, created_at FROM activity_logs ORDER BY created_at DESC LIMIT %s",
        (per_page,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    for row in rows:
        row['created_at'] = str(row['created_at'])

    return jsonify({'logs': rows})


# ── Settings API ──────────────────────────────────────────
@app.route('/api/settings/thresholds')
def get_thresholds():
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    return jsonify({
        'ddos': {
            'threshold': capture.ddos_detector.THRESHOLD,
            'window':    capture.ddos_detector.WINDOW,
            'cooldown':  capture.ddos_detector.COOLDOWN,
        },
        'portscan': {
            'threshold': capture.port_scan_detector.THRESHOLD,
            'window':    capture.port_scan_detector.WINDOW,
            'cooldown':  capture.port_scan_detector.COOLDOWN,
        },
        'arp': {
            'threshold': capture.arp_detector.THRESHOLD,
            'window':    capture.arp_detector.WINDOW,
            'cooldown':  capture.arp_detector.COOLDOWN,
        },
    })


@app.route('/api/settings/thresholds/<target>', methods=['POST'])
def set_thresholds(target):
    if 'admin' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    data = request.get_json(silent=True) or {}

    try:
        threshold = int(data['threshold'])
        window = int(data['window'])
        cooldown = int(data['cooldown'])
    except (KeyError, ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid payload.'}), 400

    if any(v < 1 for v in (threshold, window, cooldown)):
        return jsonify({'success': False, 'message': 'All values must be positive.'}), 400

    if target == 'ddos':
        detector = capture.ddos_detector
    elif target == 'portscan':
        detector = capture.port_scan_detector
    elif target == 'arp':
        detector = capture.arp_detector
    else:
        return jsonify({'success': False, 'message': 'Unknown target.'}), 404

    # Apply to live detector immediately
    detector.THRESHOLD = threshold
    detector.WINDOW = window
    detector.COOLDOWN = cooldown

    # Persist to database so settings survive restarts
    try:
        SettingsManager.save(f'{target}_threshold', threshold)
        SettingsManager.save(f'{target}_window',    window)
        SettingsManager.save(f'{target}_cooldown',  cooldown)
    except Exception as e:
        return jsonify({'success': False, 'message': f'DB error: {e}'}), 500

    AuditLogger.save(
        action=f'Update {target.upper()} Thresholds',
        status='success',
        username=session.get('admin', ''),
        user_id=session.get('admin_id'),
    )

    return jsonify({'success': True})


# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    threading.Thread(target=capture.start, daemon=True).start()
    app.run(debug=True)
