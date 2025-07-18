from flask import Flask, request, render_template
import hashlib, time, os, json, urllib.request, socket, uuid
from datetime import datetime

app = Flask(__name__)

# Create logs directory if not exists
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
LOG_PATH = os.path.join(LOG_DIR, 'activity.log')

IPQS_API_KEY = "oAidb6T6KPIYfWwBTrNqbyK7ahpK8llY"

def get_ip_details(ip):
    try:
        # Use IPQualityScore API
        url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
        return {
            "ISP/Org": data.get("organization", "Unknown"),
            "VPN": data.get("vpn", False),
            "Proxy": data.get("proxy", False),
            "Tor": data.get("tor", False),
            "Hosting": data.get("hosting", False),
            "Provider": data.get("ISP", "Unknown"),
            "ASN": data.get("ASN", "Unknown"),
            "ConnType": data.get("connection_type", "Unknown"),
            "Abuse": data.get("abuse", "Unknown"),
            "Location": f"{data.get('latitude', 0)},{data.get('longitude', 0)} ({data.get('city','Unknown')}, {data.get('region','')}, {data.get('country_code','Unknown')})"
        }
    except Exception as e:
        print("Error getting IP details:", e)
        return {
            "ISP/Org": "Unknown",
            "VPN": False,
            "Proxy": False,
            "Tor": False,
            "Hosting": False,
            "Provider": "Unknown",
            "ASN": "Unknown",
            "ConnType": "Unknown",
            "Abuse": "Unknown",
            "Location": "0,0 (Unknown, , Unknown)"
        }

def log_event(ip, path, user_agent, event):
    hostname = socket.gethostname()
    internal_ip = socket.gethostbyname(hostname)
    resolved_hostname = ""
    try:
        resolved_hostname = socket.gethostbyaddr(ip)[0]
    except:
        resolved_hostname = "Unknown"

    ip_details = get_ip_details(ip)

    # Hash for data integrity
    timestamp = datetime.utcnow().isoformat()
    raw_data = f"{ip}{path}{timestamp}{user_agent}"
    data_hash = hashlib.sha256(raw_data.encode()).hexdigest()
    integrity_hash = hashlib.sha256(data_hash.encode()).hexdigest()

    event_id = str(uuid.uuid4())

    log_entry = {
        "EventID": event_id,
        "Timestamp": timestamp,
        "IP Address": ip,
        "Resolved Hostname": resolved_hostname,
        "Location": ip_details["Location"],
        "ISP/Org": ip_details["ISP/Org"],
        "VPN/Proxy/Hosting Details": f"VPN: {ip_details['VPN']} | Proxy: {ip_details['Proxy']} | Hosting: {ip_details['Hosting']} | Tor: {ip_details['Tor']} | Provider: {ip_details['Provider']} | ASN: {ip_details['ASN']} | ConnType: {ip_details['ConnType']} | Abuse: {ip_details['Abuse']}",
        "Method": request.method,
        "Path": path,
        "User-Agent": user_agent,
        "Event": event,
        "Server Hostname": hostname,
        "Server Internal IP": internal_ip,
        "DataHash": data_hash,
        "IntegrityHash": integrity_hash
    }

    # Write to log file
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry, indent=4) + "\n\n")

@app.route("/admin")
def admin_panel():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_event(user_ip, "/admin", user_agent, "Accessed Admin Panel")
    return "<h1>Admin Panel Access Logged</h1>"

@app.route("/")
def home():
    return "<h1>Welcome to the Forensic Ready Web App</h1>"

if __name__ == "__main__":
    app.run(debug=False)
