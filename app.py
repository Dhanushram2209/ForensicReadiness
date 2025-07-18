from flask import Flask, request, render_template, redirect, url_for, session
import hashlib, time, os, json, urllib.request, socket, uuid
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import requests  # Added for better API requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

LOG_DIR = 'logs'
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')
BAN_LIST = set()
FAILED_LOGINS = {}

EMAIL_ALERTS = True
EMAIL_TO = os.environ.get('EMAIL_TO', 'saran2209kumar@gmail.com')

# IP quality score API for VPN/proxy detection
IP_QUALITY_KEY = os.environ.get('IP_QUALITY_KEY', '')
IP_API_KEY = os.environ.get('IP_API_KEY', '')

os.makedirs(LOG_DIR, exist_ok=True)

def get_client_ip():
    # Trust proxy headers for public IP (important on Render)
    forwarded = request.headers.get('X-Forwarded-For', '')
    ip = forwarded.split(',')[0].strip() if forwarded else request.remote_addr
    return ip

def is_internal_ip(ip):
    private_prefixes = (
        '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.2', '169.254.', '0.'
    )
    return any(ip.startswith(prefix) for prefix in private_prefixes)

def get_hostname(ip):
    if is_internal_ip(ip):
        return "Internal IP"
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        # Use external service
        try:
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode())
                return data.get("org", "Unknown")
        except:
            return "Unknown"

def get_geo_info(ip):
    if is_internal_ip(ip):
        return {
            "coordinates": "0,0",
            "city": "Internal Network",
            "country": "N/A",
            "org": "Private IP",
            "is_vpn": False,
            "is_proxy": False,
            "is_tor": False,
            "risk_score": 0
        }

    try:
        # First try ipapi.co
        url = f"https://ipapi.co/{ip}/json/"
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        if IP_API_KEY:
            url += f"?key={IP_API_KEY}"
            
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        
        lat = data.get("latitude", 0)
        lon = data.get("longitude", 0)
        city = data.get("city", "Unknown")
        region = data.get("region", "")
        country = data.get("country_name", "Unknown")
        org = data.get("org", "Unknown")
        
        # Now check for VPN/proxy using IPQualityScore
        vpn_info = check_vpn_proxy(ip)
        
        return {
            "coordinates": f"{lat},{lon}",
            "city": f"{city}, {region}",
            "country": country,
            "org": org,
            "is_vpn": vpn_info.get("vpn", False),
            "is_proxy": vpn_info.get("proxy", False),
            "is_tor": vpn_info.get("tor", False),
            "risk_score": vpn_info.get("risk_score", 0)
        }
    except Exception as e:
        print(f"[GeoError] for {ip} → {e}")
        return {
            "coordinates": "0,0",
            "city": "Unknown",
            "country": "Unknown",
            "org": "Unknown",
            "is_vpn": False,
            "is_proxy": False,
            "is_tor": False,
            "risk_score": 0
        }

def check_vpn_proxy(ip):
    """Check if IP is VPN/Proxy/Tor using IPQualityScore"""
    if not IP_QUALITY_KEY or is_internal_ip(ip):
        return {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "risk_score": 0
        }
    
    try:
        url = f"https://www.ipqualityscore.com/api/json/ip/{IP_QUALITY_KEY}/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        return {
            "vpn": data.get("vpn", False),
            "proxy": data.get("proxy", False),
            "tor": data.get("tor", False),
            "risk_score": data.get("fraud_score", 0)
        }
    except Exception as e:
        print(f"[VPNCheckError] for {ip} → {e}")
        return {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "risk_score": 0
        }

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    event_id = generate_event_id()
    hostname = get_hostname(ip)

    try:
        client_hostname = socket.gethostbyaddr(ip)[0] if not is_internal_ip(ip) else "Internal"
    except:
        client_hostname = request.headers.get("REMOTE_HOST", "Unknown")

    geo_info = get_geo_info(ip)
    loc = geo_info["coordinates"]
    city = geo_info["city"]
    country = geo_info["country"]
    org = geo_info["org"]
    is_vpn = geo_info["is_vpn"]
    is_proxy = geo_info["is_proxy"]
    is_tor = geo_info["is_tor"]
    risk_score = geo_info["risk_score"]

    try:
        server_hostname = socket.gethostname()
        server_ip = socket.gethostbyname(server_hostname)
    except:
        server_hostname = "Unknown"
        server_ip = "Unknown"

    timestamp = datetime.now().isoformat()
    data_hash = hash_data(json.dumps(params or {}))
    integrity_hash = hash_data(f"{event_id}{timestamp}{ip}{msg}")

    # Add VPN/Proxy warning to message if detected
    network_type = []
    if is_vpn:
        network_type.append("VPN")
    if is_proxy:
        network_type.append("Proxy")
    if is_tor:
        network_type.append("Tor")
    
    network_status = " | ".join(network_type) if network_type else "Direct Connection"
    risk_warning = f" (High Risk: {risk_score})" if risk_score > 75 else ""

    log_entry = (
        f"EventID: {event_id}\n"
        f"Timestamp: {timestamp}\n"
        f"IP Address: {ip}\n"
        f"Resolved Hostname: {hostname}\n"
        f"Client Hostname: {client_hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"ISP/Org: {org}\n"
        f"Network Type: {network_status}{risk_warning}\n"
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

    if EMAIL_ALERTS and ("Suspicious" in msg or risk_score > 75 or is_vpn or is_proxy or is_tor):
        send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, network_status, risk_score)

def send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id, network_status, risk_score):
    body = (
        f"Suspicious Activity Detected!\n\n"
        f"Event ID: {event_id}\n"
        f"IP: {ip}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Network Type: {network_status}\n"
        f"Risk Score: {risk_score}\n"
        f"Event: {msg}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Time: {datetime.now().isoformat()}"
    )
    msg_obj = MIMEText(body)
    msg_obj['Subject'] = f"Alert: Suspicious Activity ({risk_score} risk)" if risk_score > 0 else "Alert: Suspicious Activity"
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
        if isinstance(val, str):
            for pat in patterns:
                if pat.lower() in val.lower():
                    return True
    return False

@app.before_request
def block_banned_ips():
    ip = get_client_ip()
    if ip in BAN_LIST:
        geo_info = get_geo_info(ip)
        risk_warning = f" (Risk Score: {geo_info['risk_score']})" if geo_info['risk_score'] > 0 else ""
        return f"403 Forbidden - You are banned{risk_warning}", 403

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
    geo_info = get_geo_info(ip)
    
    # Check if high risk connection
    if geo_info['risk_score'] > 85:
        log_event(ip, ua, "Suspicious: High Risk Connection Detected", request.path, request.method)
        return "Access denied due to high risk connection", 403
        
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