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
IPQS_API_KEY = "oAidb6T6KPlYfWwBTrNqbyK7ahpK8IlY"  # Provided by user

os.makedirs(LOG_DIR, exist_ok=True)

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    return forwarded.split(',')[0].strip() if forwarded else request.remote_addr

def is_internal_ip(ip):
    return ip.startswith(("127.", "10.", "192.168.", "172.", "169.254.", "0."))

def get_hostname(ip):
    if is_internal_ip(ip):
        return "Internal IP"
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_geo_info(ip):
    if is_internal_ip(ip):
        return "0,0", "Internal Network", "N/A", "Private IP", False, False, False, {}

    try:
        url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())

            lat = data.get("latitude", 0)
            lon = data.get("longitude", 0)
            city = data.get("city", "Unknown")
            region = data.get("region", "")
            country = data.get("country_code", "Unknown")
            org = data.get("ISP", data.get("organization", "Unknown"))

            vpn = data.get("vpn", False)
            proxy = data.get("proxy", False)
            hosting = data.get("hosting", False)
            tor = data.get("tor", False)

            metadata = {
                "vpn": vpn,
                "proxy": proxy,
                "hosting": hosting,
                "tor": tor,
                "connection_type": data.get("connection_type", "Unknown"),
                "abuse_score": data.get("fraud_score", "Unknown"),
                "region": region,
                "vpn_provider": data.get("provider", "Unknown"),
                "asn": data.get("ASN", "Unknown"),
                "mobile": data.get("mobile", False),
                "bot_status": data.get("is_bot", False),
            }

            return f"{lat},{lon}", f"{city}, {region}", country, org, vpn, proxy, hosting, metadata
    except Exception as e:
        print(f"[GeoError] {ip} → {e}")
        return "0,0", "Unknown", "Unknown", "Unknown", False, False, False, {}

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    event_id = generate_event_id()
    hostname = get_hostname(ip)
    loc, city, country, org, vpn, proxy, hosting, metadata = get_geo_info(ip)

    try:
        server_hostname = socket.gethostname()
        server_ip = socket.gethostbyname(server_hostname)
    except:
        server_hostname = server_ip = "Unknown"

    timestamp = datetime.now().isoformat()
    data_hash = hash_data(json.dumps(params or {}))
    integrity_hash = hash_data(f"{event_id}{timestamp}{ip}{msg}")

    vpn_details = (
        f"VPN: {vpn} | Proxy: {proxy} | Hosting: {hosting} | Tor: {metadata.get('tor')} | "
        f"Provider: {metadata.get('vpn_provider')} | ASN: {metadata.get('asn')} | "
        f"ConnType: {metadata.get('connection_type')} | Abuse: {metadata.get('abuse_score')}"
    )

    log_entry = (
        f"EventID: {event_id}\n"
        f"Timestamp: {timestamp}\n"
        f"IP Address: {ip}\n"
        f"Resolved Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"ISP/Org: {org}\n"
        f"VPN/Proxy/Hosting Details: {vpn_details}\n"
        f"Method: {method}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Event: {msg}\n"
        f"Server Hostname: {server_hostname}\n"
        f"Server Internal IP: {server_ip}\n"
        f"DataHash: {data_hash}\n"
        f"IntegrityHash: {integrity_hash}\n"
        f"{'-'*60}\n"
    )

    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)

    if EMAIL_ALERTS and ("Suspicious" in msg or vpn or proxy or hosting):
        send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, vpn_details)

def send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, vpn_details):
    body = (
        f"Suspicious Activity Detected!\n\n"
        f"Event ID: {event_id}\n"
        f"IP: {ip}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"{vpn_details}\n"
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
    _, _, _, _, vpn, proxy, hosting, metadata = get_geo_info(ip)
    if vpn or proxy or hosting or metadata.get("tor"):
        return "Access Denied – VPN/Proxy/Tor not allowed", 403

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
