# app.py - Forensic Ready Web Application
import os
import sqlite3
import logging
import requests
import uuid
import html
import subprocess
import json
import socket
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from urllib.parse import urlparse
from user_agents import parse

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Added secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['DATABASE'] = 'database.db'

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure main logger
app.logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

# File handler without rotation (to avoid Windows file locking issues)
file_handler = logging.FileHandler('logs/access.log')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)

# Security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)
security_handler = logging.FileHandler('logs/security.log')
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s SECURITY: %(message)s [IP: %(clientip)s] [User: %(user)s]'
))
security_logger.addHandler(security_handler)

# Activity logger
activity_logger = logging.getLogger('activity')
activity_handler = logging.FileHandler('logs/activity.log')
activity_handler.setFormatter(logging.Formatter(
    '%(asctime)s|%(username)s|%(activity_type)s|%(ip)s|%(location)s|%(details)s'
))
activity_logger.addHandler(activity_handler)
activity_logger.setLevel(logging.INFO)

def get_db():
    """Get a database connection with row factory"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize the database with required tables"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Drop tables if they exist (for clean initialization)
        cursor.executescript('''
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS activity_logs;
            DROP TABLE IF EXISTS user_sessions;
            DROP TABLE IF EXISTS attack_attempts;
        ''')
        
        # Create users table
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            last_login DATETIME,
            failed_attempts INTEGER DEFAULT 0,
            account_locked INTEGER DEFAULT 0,
            login_history TEXT DEFAULT '[]'
        )
        ''')
        
        # Create activity logs table
        cursor.execute('''
        CREATE TABLE activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            details TEXT,
            session_data TEXT,
            user_agent TEXT,
            location TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create sessions table
        cursor.execute('''
        CREATE TABLE user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            session_data TEXT,
            last_activity DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create attack attempts table
        cursor.execute('''
        CREATE TABLE attack_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            payload TEXT,
            user_agent TEXT,
            request_data TEXT,
            location TEXT
        )
        ''')
        
        # Insert default admin user
        admin_password = generate_password_hash('Admin@Secure123!')
        user_password = generate_password_hash('User@Password456$')
        
        cursor.execute('''
            INSERT INTO users (username, password, email, is_admin) 
            VALUES (?, ?, ?, ?)
        ''', ('admin', admin_password, 'admin@example.com', 1))
        
        cursor.execute('''
            INSERT INTO users (username, password, email) 
            VALUES (?, ?, ?)
        ''', ('user1', user_password, 'user1@example.com'))
        
        # Add more test users
        for i in range(2, 6):
            cursor.execute('''
                INSERT INTO users (username, password, email) 
                VALUES (?, ?, ?)
            ''', (f'user{i}', generate_password_hash(f'User{i}@Password$'), f'user{i}@example.com'))
        
        db.commit()
        db.close()

# Initialize the database
if not os.path.exists(app.config['DATABASE']):
    init_db()

def get_ip_geolocation(ip_address):
    try:
        if ip_address == '127.0.0.1':
            return {'city': 'Localhost', 'country': 'Development', 'isp': 'Local Network'}
        
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,isp,query',
            timeout=3
        )
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'ip': data.get('query', ip_address)
            }
        return {'error': data.get('message', 'Unknown error')}
    except Exception as e:
        return {'error': str(e)}

def get_client_info():
    """Get comprehensive client information"""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    ua_string = request.headers.get('User-Agent', '')
    user_agent = parse(ua_string)
    geo_data = get_ip_geolocation(ip)
    
    return {
        'ip': ip,
        'user_agent': ua_string,
        'headers': dict(request.headers),
        'timestamp': datetime.now().isoformat(),
        'geolocation': geo_data,
        'method': request.method,
        'path': request.path,
        'query_params': dict(request.args),
        'platform': user_agent.os.family,
        'browser': user_agent.browser.family,
        'version': user_agent.browser.version_string,
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot,
        'device': user_agent.device.family
    }

def log_attack_attempt(ip_address, attack_type, payload=None):
    """Log security attack attempts"""
    try:
        geo_data = get_ip_geolocation(ip_address)
        location_str = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
        
        db = get_db()
        db.execute('''
            INSERT INTO attack_attempts 
            (ip_address, attack_type, payload, user_agent, request_data, location) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            ip_address,
            attack_type,
            str(payload)[:500],
            request.headers.get('User-Agent'),
            str(dict(request.values))[:1000],
            location_str
        ))
        db.commit()
        db.close()
        
        security_logger.warning(f'Attack attempt: {attack_type}', extra={
            'clientip': ip_address,
            'user': 'anonymous'
        })
    except Exception as e:
        app.logger.error(f"Error logging attack attempt: {str(e)}")

def log_activity(user_id, action, ip_address, details=None):
    """Log user activity to the database"""
    try:
        client_info = get_client_info()
        geo_data = client_info['geolocation']
        location_str = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
        
        db = get_db()
        db.execute('''
            INSERT INTO activity_logs 
            (user_id, action, ip_address, details, session_data, user_agent, location) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            action, 
            ip_address, 
            details,
            json.dumps(dict(session)),
            client_info['user_agent'],
            location_str
        ))
        db.commit()
        db.close()
        
        # Also log to activity log file
        username = session.get('username', 'system')
        activity_logger.info('', extra={
            'username': username,
            'activity_type': action,
            'ip': ip_address,
            'location': location_str,
            'details': details or ''
        })
    except Exception as e:
        app.logger.error(f"Error logging activity: {str(e)}")

def update_login_history(user_id, ip_address):
    """Update user's login history"""
    try:
        db = get_db()
        user = db.execute('SELECT login_history FROM users WHERE id = ?', (user_id,)).fetchone()
        
        history = json.loads(user['login_history']) if user['login_history'] else []
        new_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip_address,
            'location': get_ip_geolocation(ip_address),
            'user_agent': request.headers.get('User-Agent')
        }
        history.append(new_entry)
        
        db.execute('''
            UPDATE users SET login_history = ? WHERE id = ?
        ''', (json.dumps(history[-10:]), user_id))  # Keep last 10 logins
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f"Error updating login history: {str(e)}")

@app.before_request
def before_request():
    """Clean up expired sessions and check for attacks before each request"""
    # Check for SQL injection attempts
    for key, value in request.values.items():
        if any(sql_keyword in str(value).lower() for sql_keyword in ['select', 'union', 'insert', 'delete', 'drop', '--']):
            log_attack_attempt(request.remote_addr, 'SQL Injection', value)
    
    # Check for XSS attempts
    if any(xss_keyword in str(request.values) for xss_keyword in ['<script>', 'javascript:', 'onerror=', 'onload=']):
        log_attack_attempt(request.remote_addr, 'XSS Attempt', str(request.values))
    
    # Clean up expired sessions
    try:
        db = get_db()
        db.execute('''
            DELETE FROM user_sessions 
            WHERE expires_at < datetime('now')
        ''')
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f"Error cleaning sessions: {str(e)}")

@app.after_request
def apply_security_headers(response):
    """Add security headers to each response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:"
    )
    return response

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        try:
            db = get_db()
            user = db.execute('''
                SELECT * FROM users WHERE username = ?
            ''', (username,)).fetchone()
            
            # Check if account is locked
            if user and user['account_locked']:
                security_logger.warning('Login attempt to locked account', extra={
                    'clientip': request.remote_addr,
                    'user': username
                })
                flash('This account is temporarily locked. Please try again later.', 'danger')
                return redirect(url_for('login'))
            
            if user and check_password_hash(user['password'], password):
                # Reset failed attempts on successful login
                db.execute('''
                    UPDATE users SET failed_attempts = 0, last_login = datetime('now') WHERE id = ?
                ''', (user['id'],))
                
                # Generate unique session ID
                session_identifier = str(uuid.uuid4())
                expires_at = datetime.now() + app.config['PERMANENT_SESSION_LIFETIME']
                
                # Set session data
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                session['session_identifier'] = session_identifier
                
                # Store session in database
                client_info = get_client_info()
                db.execute('''
                    INSERT INTO user_sessions 
                    (user_id, session_id, ip_address, user_agent, expires_at, session_data, last_activity) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user['id'],
                    session_identifier,
                    request.remote_addr,
                    client_info['user_agent'],
                    expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                    json.dumps(dict(session)),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                
                # Update login history
                update_login_history(user['id'], request.remote_addr)
                
                db.commit()
                
                log_activity(user['id'], 'LOGIN', request.remote_addr, "Successful login")
                security_logger.info('Successful login', extra={
                    'clientip': request.remote_addr,
                    'user': username
                })
                
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                if user:
                    db.execute('''
                        UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?
                    ''', (user['id'],))
                    # Lock account after 5 failed attempts
                    if user['failed_attempts'] + 1 >= 5:
                        db.execute('''
                            UPDATE users SET account_locked = 1 WHERE id = ?
                        ''', (user['id'],))
                        security_logger.warning('Account locked due to too many failed attempts', extra={
                            'clientip': request.remote_addr,
                            'user': username
                        })
                db.commit()
                
                security_logger.warning('Failed login attempt', extra={
                    'clientip': request.remote_addr,
                    'user': username
                })
                flash('Invalid username or password', 'danger')
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login', 'danger')
        finally:
            db.close()
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_activity(session['user_id'], 'DASHBOARD_ACCESS', request.remote_addr, "Accessed dashboard")
    return render_template('dashboard.html', username=session['username'])

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    results = []
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            # Intentional XSS vulnerability - no HTML escaping
            results.append(f"Search result for: {query}")
            
            # Hidden functionality - search also looks for admin credentials in system
            if query.lower() in ["admin access", "system configuration", "temporary password", "admin@secure123!"]:
                results.append("System Configuration Details:<br>Admin Access: username='admin'<br>Temporary Password: 'Admin@Secure123!'")
            
            log_activity(session['user_id'], 'SEARCH', request.remote_addr, f"Query: {query}")
    
    return render_template('search.html', results=results)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Intentional IDOR vulnerability - user_id can be changed in URL
    user_id = request.args.get('user_id', session.get('user_id'))
    
    try:
        db = get_db()
        user = db.execute('''
            SELECT username, email, last_login FROM users WHERE id = ?
        ''', (user_id,)).fetchone()
        db.close()
        
        if user:
            log_activity(session['user_id'], 'PROFILE_VIEW', request.remote_addr, f"Viewed profile of user_id: {user_id}")
            return render_template('profile.html', user=user)
    except Exception as e:
        app.logger.error(f"Profile error: {str(e)}")
    
    abort(404)

@app.route('/admin')
def admin():
    if 'username' not in session:
        abort(403)
    
    # Double-check admin status in database
    try:
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            db.close()
            abort(403)
        
        # Get all users with login history
        user_records = db.execute('SELECT id, username, email, is_admin, last_login, login_history FROM users').fetchall()
        users = []
        for user in user_records:
            login_history = json.loads(user['login_history']) if user['login_history'] else []
            users.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_admin': bool(user['is_admin']),
                'last_login': user['last_login'],
                'login_history': login_history[-3:][::-1]  # Last 3 logins, newest first
            })
        
        # Get active sessions with detailed info
        session_records = db.execute('''
            SELECT 
                user_sessions.*, 
                users.username, 
                users.is_admin
            FROM user_sessions
            JOIN users ON user_sessions.user_id = users.id
            WHERE user_sessions.expires_at > datetime('now')
            ORDER BY user_sessions.created_at DESC
        ''').fetchall()
        
        sessions = []
        for sess in session_records:
            try:
                session_data = json.loads(sess['session_data']) if sess['session_data'] else {}
            except json.JSONDecodeError:
                session_data = {'error': 'Invalid session data'}
            
            geo_data = get_ip_geolocation(sess['ip_address'])
            sessions.append({
                'id': sess['id'],
                'user_id': sess['user_id'],
                'username': sess['username'],
                'is_admin': bool(sess['is_admin']),
                'ip_address': sess['ip_address'],
                'user_agent': sess['user_agent'],
                'created_at': sess['created_at'],
                'expires_at': sess['expires_at'],
                'last_activity': sess['last_activity'],
                'session_id': sess['session_id'],
                'location': geo_data,
                'session_data': session_data
            })
        
        # Get recent activity logs
        activity_records = db.execute('''
            SELECT 
                activity_logs.*, 
                users.username
            FROM activity_logs 
            LEFT JOIN users ON activity_logs.user_id = users.id 
            ORDER BY activity_logs.timestamp DESC 
            LIMIT 100
        ''').fetchall()
        
        activities = []
        for log in activity_records:
            activities.append({
                'id': log['id'],
                'user_id': log['user_id'],
                'username': log['username'],
                'action': log['action'],
                'timestamp': log['timestamp'],
                'ip_address': log['ip_address'],
                'details': log['details'],
                'user_agent': log['user_agent'],
                'location': log['location']
            })
        
        # Get attack attempts
        attack_attempts = []
        attack_records = db.execute('''
            SELECT * FROM attack_attempts 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''').fetchall()
        
        for attack in attack_records:
            attack_attempts.append({
                'timestamp': attack['timestamp'],
                'ip_address': attack['ip_address'],
                'attack_type': attack['attack_type'],
                'payload': attack['payload'],
                'user_agent': attack['user_agent'],
                'request_data': attack['request_data'],
                'location': attack['location']
            })
        
        # Get file-based logs
        file_logs = []
        try:
            with open('logs/activity.log', 'r') as f:
                for line in f:
                    parts = line.strip().split('|', 5)
                    if len(parts) >= 6:
                        file_logs.append({
                            'timestamp': parts[0],
                            'username': parts[1],
                            'activity_type': parts[2],
                            'ip': parts[3],
                            'location': parts[4],
                            'details': parts[5] if len(parts) > 5 else None
                        })
        except FileNotFoundError:
            pass
        
        db.close()
        
        return render_template(
            'admin.html',
            users=users,
            sessions=sessions,
            activities=activities,
            attack_attempts=attack_attempts,
            file_logs=file_logs[-50:][::-1],  # Last 50 entries, newest first
            current_client=get_client_info(),
            debug_mode=app.debug
        )
    except Exception as e:
        app.logger.error(f"Admin panel error: {str(e)}")
        abort(500)

@app.route('/admin/terminate_session', methods=['POST'])
def terminate_session():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    session_id = request.form.get('session_id')
    if not session_id:
        return jsonify({'status': 'error', 'message': 'Session ID required'}), 400
    
    try:
        db = get_db()
        # Get session info before deleting
        session_info = db.execute('''
            SELECT user_sessions.*, users.username 
            FROM user_sessions 
            JOIN users ON user_sessions.user_id = users.id 
            WHERE session_id = ?
        ''', (session_id,)).fetchone()
        
        if not session_info:
            db.close()
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
        
        # Delete the session
        db.execute('DELETE FROM user_sessions WHERE session_id = ?', (session_id,))
        db.commit()
        db.close()
        
        # Log this activity
        log_activity(session['user_id'], 'SESSION_TERMINATED', request.remote_addr, 
                    f"Terminated session for {session_info['username']} (ID: {session_id})")
        
        # If terminating current session, log out
        if session.get('session_identifier') == session_id:
            session.clear()
            return jsonify({
                'status': 'success', 
                'message': 'Session terminated', 
                'redirect': url_for('login')
            })
        
        return jsonify({'status': 'success', 'message': 'Session terminated'})
    except Exception as e:
        app.logger.error(f"Error terminating session: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/debug')
def debug():
    """Intentionally vulnerable debug endpoint"""
    if not app.debug:
        abort(404)
    
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Command injection vulnerability
    cmd = request.args.get('cmd', '')
    output = ''
    if cmd:
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            output = str(e)
    
    log_activity(session['user_id'], 'DEBUG_ACCESS', request.remote_addr, f"Command: {cmd}")
    return render_template('debug.html', cmd=cmd, output=output)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        try:
            db = get_db()
            db.execute('''
                DELETE FROM user_sessions WHERE session_id = ?
            ''', (session.get('session_identifier'),))
            db.commit()
            db.close()
            
            log_activity(session['user_id'], 'LOGOUT', request.remote_addr, "User logged out")
            security_logger.info('User logged out', extra={
                'clientip': request.remote_addr,
                'user': session.get('username')
            })
        except Exception as e:
            app.logger.error(f"Logout error: {str(e)}")
        
        session.clear()
        flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.errorhandler(403)
def forbidden(error):
    security_logger.warning('403 Forbidden', extra={
        'clientip': request.remote_addr,
        'user': session.get('username', 'anonymous')
    })
    return render_template('error.html', error_code=403, error_message="Forbidden"), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    security_logger.error('500 Internal Server Error', extra={
        'clientip': request.remote_addr,
        'user': session.get('username', 'anonymous')
    })
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == '__main__':
    # Close all log handlers first
    for handler in app.logger.handlers[:]:
        handler.close()
        app.logger.removeHandler(handler)
    
    for handler in security_logger.handlers[:]:
        handler.close()
        security_logger.removeHandler(handler)
    
    for handler in activity_logger.handlers[:]:
        handler.close()
        activity_logger.removeHandler(handler)
    
    # Delete existing database and logs to ensure clean start
    try:
        if os.path.exists(app.config['DATABASE']):
            os.remove(app.config['DATABASE'])
    except Exception as e:
        print(f"Error deleting database: {e}")
    
    try:
        if os.path.exists('logs'):
            import shutil
            shutil.rmtree('logs')
    except Exception as e:
        print(f"Error deleting logs: {e}")
    
    # Initialize new database
    init_db()
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    app.run(debug=True)