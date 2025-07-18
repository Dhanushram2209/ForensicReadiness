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
VPN_BLOCK = True  # Enable VPN blocking
VPN_API_KEY = 'bf2545c0ee254df9ac88c7dee3c49346'  # Your VPNAPI.io key

EMAIL_ALERTS = True
EMAIL_TO = os.environ.get('EMAIL_TO', 'saran2209kumar@gmail.com')

os.makedirs(LOG_DIR, exist_ok=True)

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    ip = forwarded.split(',')[0].strip() if forwarded else request.remote_addr
    return ip

def is_internal_ip(ip):
    private_prefixes = (
        '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.2', '169.254.', '0.'
    )
    return any(ip.startswith(prefix) for prefix in private_prefixes)

def is_vpn_or_proxy(ip):
    """Check if IP belongs to a known VPN/proxy service using VPNAPI.io"""
    if is_internal_ip(ip):
        return False
        
    try:
        # Primary check with VPNAPI.io
        url = f"https://vpnapi.io/api/{ip}?key={VPN_API_KEY}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())
            
            # Check all security flags
            security = data.get('security', {})
            if security.get('vpn', False) or \
               security.get('proxy', False) or \
               security.get('tor', False) or \
               security.get('relay', False):
                return True
            
            # Additional check for hosting services
            if any(tag in data.get('network', {}).get('autonomous_system_organization', '').lower()
               for tag in ['hosting', 'leaseweb', 'cloud', 'server', 'datacenter']):
                return True
                
            return False
            
    except Exception as e:
        print(f"VPN detection error for {ip}: {e}")
        return False

def get_hostname(ip):
    if is_internal_ip(ip):
        return "Internal IP"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if any(tag in hostname.lower() for tag in ['.vpn.', '.proxy.', '.hosting.']):
            return f"{hostname} (VPN/Hosting)"
        return hostname
    except:
        return "Unknown"

def get_geo_info(ip):
    if is_internal_ip(ip):
        return "0,0", "Internal Network", "N/A", "Private IP"

    try:
        url = f"https://ipapi.co/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())
            lat = data.get("latitude", 0)
            lon = data.get("longitude", 0)
            city = data.get("city", "Unknown")
            region = data.get("region", "")
            country = data.get("country_name", "Unknown")
            org = data.get("org", "Unknown")
            return f"{lat},{lon}", f"{city}, {region}", country, org
    except Exception as e:
        print(f"[GeoError] for {ip} → {e}")
        return "0,0", "Unknown", "Unknown", "Unknown"

def generate_event_id():
    return str(uuid.uuid4())

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(ip, ua, msg, path, method, params=None):
    event_id = generate_event_id()
    hostname = get_hostname(ip)
    loc, city, country, org = get_geo_info(ip)
    timestamp = datetime.now().isoformat()
    
    log_entry = (
        f"EventID: {event_id}\n"
        f"Timestamp: {timestamp}\n"
        f"IP Address: {ip}\n"
        f"Resolved Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"ISP/Org: {org}\n"
        f"Method: {method}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Event: {msg}\n"
        f"{'-'*60}\n"
    )

    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)

    if EMAIL_ALERTS and any(x in msg.lower() for x in ['suspicious', 'blocked', 'vpn']):
        send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id)

def send_email_alert(ip, hostname, msg, path, loc, city, country, ua, event_id):
    body = (
        f"Security Alert!\n\n"
        f"Event ID: {event_id}\n"
        f"IP: {ip}\n"
        f"Hostname: {hostname}\n"
        f"Location: {loc} ({city}, {country})\n"
        f"Event: {msg}\n"
        f"Path: {path}\n"
        f"User-Agent: {ua}\n"
        f"Time: {datetime.now().isoformat()}\n\n"
        f"Action Recommended: Review logs for potential security issues."
    )
    msg_obj = MIMEText(body)
    msg_obj['Subject'] = f"Security Alert: {msg[:50]}..."
    msg_obj['From'] = 'security@yourdomain.com'
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
def security_checks():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    
    # Block banned IPs
    if ip in BAN_LIST:
        log_event(ip, ua, "Blocked: Banned IP Attempt", request.path, request.method)
        return render_template('blocked.html', 
                            reason="Your IP has been banned due to suspicious activity"), 403
    
    # Block VPNs/Proxies
    if VPN_BLOCK and not is_internal_ip(ip):
        if is_vpn_or_proxy(ip):
            log_event(ip, ua, "Blocked: VPN/Proxy/Hosting Detected", request.path, request.method)
            return render_template('blocked.html', 
                                reason="VPN, proxy, or hosting services are not allowed. Please disable your VPN to access this site."), 403

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
            return render_template('blocked.html', reason="Security violation detected"), 403

        if username == 'admin' and password == 'password':
            session['user'] = username
            log_event(ip, ua, "Successful Login", request.path, request.method, data)
            return redirect(url_for('admin'))
        else:
            FAILED_LOGINS[ip] = FAILED_LOGINS.get(ip, 0) + 1
            if FAILED_LOGINS[ip] >= 3:  # Reduced threshold for testing
                BAN_LIST.add(ip)
                log_event(ip, ua, "IP Banned: Too Many Failed Logins", request.path, request.method)
                return render_template('blocked.html', 
                                    reason="Too many failed login attempts. Your IP has been temporarily banned."), 403
            else:
                log_event(ip, ua, f"Failed Login Attempt ({FAILED_LOGINS[ip]}/3)", request.path, request.method)
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
    
    try:
        with open(LOG_PATH, 'r') as f:
            logs = f.readlines()
        return render_template('admin.html', logs=logs[-100:])  # Show last 100 lines
    except Exception as e:
        return f"Error reading logs: {str(e)}", 500

@app.route('/logs')
def view_logs():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        with open(LOG_PATH, 'r') as f:
            logs = f.read()
        return f"<pre>{logs}</pre>"
    except Exception as e:
        return f"Error reading logs: {str(e)}", 500

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple("0.0.0.0", int(os.environ.get("PORT", 5000)), app)