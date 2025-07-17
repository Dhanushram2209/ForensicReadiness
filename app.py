from flask import Flask, request, render_template, redirect, url_for, session
import hashlib, time, os, json, urllib.request, socket, uuid
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

LOG_DIR = 'logs'
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')
BAN_LIST = set()
FAILED_LOGINS = {}

EMAIL_ALERTS = True
EMAIL_TO = os.environ.get('EMAIL_TO', 'saran2209kumar@gmail.com')

os.makedirs(LOG_DIR, exist_ok=True)

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if ',' in forwarded:
        ip = forwarded.split(',')[0]
    else:
        ip = forwarded or request.headers.get('X-Real-IP') or request.remote_addr
    return ip.strip()

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        # Try fallback API
        try:
            url = f"https://api.ip.sb/geoip/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode())
                return data.get("organization", "Unknown")
        except:
            return "Unknown"

def get_geo_info(ip):
    try:
        url = f"https://ipapi.co/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())
            lat = data.get("latitude", 0)
            lon = data.get("longitude", 0)
            city = data.get("city", "Unknown")
            country = data.get("country_name", "Unknown")
            return f"{lat},{lon}", city, country
    except Exception as e:
        print(f"[GeoError] for {ip} → {e}")
        return "0,0", "Unknown", "Unknown"

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    event_id = generate_event_id()
    hostname = get_hostname(ip)
    loc, city, country = get_geo_info(ip)
    timestamp = datetime.now().isoformat()
    data_hash = hash_data(json.dumps(params or {}))
    integrity_hash = hash_data(f"{event_id}{timestamp}{ip}{msg}")

    log_entry = (
        f"EventID: {event_id}\n"
        f"Timestamp: {timestamp}\n"
        f"IP: {ip}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Method: {method}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Event: {msg}\n"
        f"DataHash: {data_hash}\n"
        f"IntegrityHash: {integrity_hash}\n"
        f"{'-'*60}\n"
    )
    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)

    if EMAIL_ALERTS and "Suspicious" in msg:
        send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id)

def send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id):
    body = (
        f"Suspicious Activity Detected!\n\n"
        f"Event ID: {event_id}\n"
        f"IP: {ip}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Event: {msg}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Time: {datetime.now().isoformat()}"
    )
    msg_obj = MIMEText(body)
    msg_obj['Subject'] = "Alert: Suspicious Activity Detected"
    msg_obj['From'] = 'alert@yourdomain.com'
    msg_obj['To'] = EMAIL_TO
    try:
        s = smtplib.SMTP('localhost')
        s.send_message(msg_obj)
        s.quit()
    except Exception as e:
        print("Email failed:", e)

def detect_attack(data):
    patterns = ["<script>", "onerror=", "' OR 1=1", "--", "DROP TABLE", "javascript:"]
    for val in data.values():
        for pat in patterns:
            if pat.lower() in val.lower():
                return True
    return False

@app.before_request
def block_banned_ips():
    ip = get_client_ip()
    if ip in BAN_LIST:
        return "403 Forbidden - You are banned", 403

@app.route('/healthz')
def health():
    return "OK", 200

@app.route('/')
def index():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Visited Home Page", request.path, request.method)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        data = {'username': username, 'password': password}

        if detect_attack(data):
            log_event(ip, ua, "Suspicious: Injection Attempt", request.path, request.method, data)
            return "Attack Detected", 403

        if username == 'admin' and password == 'password':
            session['user'] = username
            log_event(ip, ua, "Successful Login", request.path, request.method, data)
            return redirect(url_for('admin'))
        else:
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            if FAILED_LOGINS[ip] >= 5:
                BAN_LIST.add(ip)
                log_event(ip, ua, "IP Banned due to Brute Force", request.path, request.method)
            else:
                log_event(ip, ua, "Failed Login Attempt", request.path, request.method)
            return "Invalid credentials", 401
    else:
        log_event(ip, ua, "Visited Login Page", request.path, request.method)
        return render_template('login.html')

@app.route('/admin')
def admin():
    if 'user' not in session:
        return redirect(url_for('login'))
    ip = get_client_ip()
    ua = request.headers.get('User-Agent')
    log_event(ip, ua, "Accessed Admin Panel", request.path, request.method)
    with open(LOG_PATH, 'r') as f:
        logs = f.readlines()
    return render_template('admin.html', logs=logs)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple("0.0.0.0", int(os.environ.get("PORT", 5000)), app)