import os
import sqlite3
import logging
import requests
import uuid
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires after 1 hour
app.config['DATABASE'] = 'database.db'

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')

# Access logs
access_handler = RotatingFileHandler('logs/access.log', maxBytes=10240, backupCount=10)
access_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
access_handler.setLevel(logging.INFO)
app.logger.addHandler(access_handler)

# Security logs
security_handler = RotatingFileHandler('logs/security.log', maxBytes=10240, backupCount=10)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s SECURITY: %(message)s [IP: %(clientip)s] [User: %(user)s]'
))
security_logger = logging.getLogger('security')
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

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
        ''')
        
        # Create users table
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0,
            last_login DATETIME
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
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create sessions table with proper columns
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
            FOREIGN KEY (user_id) REFERENCES users (id)
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
        
        db.commit()
        db.close()

# Initialize the database
init_db()

def get_ip_geolocation(ip_address):
    try:
        if ip_address == '127.0.0.1':
            return {'city': 'Localhost', 'country': 'Development'}
        
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

@app.before_request
def before_request():
    """Clean up expired sessions before each request"""
    if 'session_identifier' in session:
        try:
            db = get_db()
            db.execute('''
                DELETE FROM user_sessions 
                WHERE expires_at < datetime('now') OR session_id = ?
            ''', (session['session_identifier'],))
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

def log_activity(user_id, action, ip_address, details=None):
    """Log user activity to the database"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO activity_logs (user_id, action, ip_address, details) 
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, ip_address, details))
        db.commit()
        db.close()
    except Exception as e:
        app.logger.error(f"Error logging activity: {str(e)}")

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
            
            if user and check_password_hash(user['password'], password):
                # Generate unique session ID
                session_identifier = str(uuid.uuid4())
                expires_at = datetime.now() + app.config['PERMANENT_SESSION_LIFETIME']
                
                # Set session data
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['session_identifier'] = session_identifier
                
                # Store session in database
                db.execute('''
                    INSERT INTO user_sessions 
                    (user_id, session_id, ip_address, user_agent, expires_at, session_data) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user['id'],
                    session_identifier,
                    request.remote_addr,
                    request.headers.get('User-Agent'),
                    expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                    str(dict(session))
                ))
                
                # Update last login
                db.execute('''
                    UPDATE users SET last_login = datetime('now') WHERE id = ?
                ''', (user['id'],))
                
                db.commit()
                
                log_activity(user['id'], 'LOGIN', request.remote_addr)
                security_logger.info('Successful login', extra={
                    'clientip': request.remote_addr,
                    'user': username
                })
                
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
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
    
    log_activity(session['user_id'], 'DASHBOARD_ACCESS', request.remote_addr)
    return render_template('dashboard.html', username=session['username'])

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    results = []
    if request.method == 'POST':
        query = html.escape(request.form.get('query', '').strip())
        if query:
            results.append(f"Search result for: {query}")
            log_activity(session['user_id'], 'SEARCH', request.remote_addr, f"Query: {query}")
    
    return render_template('search.html', results=results)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')  # Only allow viewing own profile
    try:
        db = get_db()
        user = db.execute('''
            SELECT username, email, last_login FROM users WHERE id = ?
        ''', (user_id,)).fetchone()
        db.close()
        
        if user:
            log_activity(session['user_id'], 'PROFILE_VIEW', request.remote_addr)
            return render_template('profile.html', user=user)
    except Exception as e:
        app.logger.error(f"Profile error: {str(e)}")
    
    abort(404)

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('is_admin'):
        abort(403)
    
    try:
        db = get_db()
        
        # Get all users
        users = db.execute('SELECT * FROM users').fetchall()
        
        # Get activity logs with session data - fixed query
        logs = []
        log_records = db.execute('''
            SELECT 
                activity_logs.*, 
                users.username,
                user_sessions.session_data
            FROM activity_logs 
            LEFT JOIN users ON activity_logs.user_id = users.id 
            LEFT JOIN user_sessions ON 
                activity_logs.user_id = user_sessions.user_id AND
                abs(strftime('%s', activity_logs.timestamp) - strftime('%s', user_sessions.created_at)) < 5
            ORDER BY activity_logs.timestamp DESC 
            LIMIT 100
        ''').fetchall()
        
        for log in log_records:
            logs.append({
                'id': log['id'],
                'user_id': log['user_id'],
                'username': log['username'],
                'action': log['action'],
                'timestamp': log['timestamp'],
                'ip_address': log['ip_address'],
                'details': log['details'],
                'location': get_ip_geolocation(log['ip_address']),
                'session_cookie': log['session_data']
            })
        
        # Get active sessions - fixed query
        session_info = []
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
        
        for sess in session_records:
            session_info.append({
                'user_id': sess['user_id'],
                'username': sess['username'],
                'is_admin': sess['is_admin'],
                'ip_address': sess['ip_address'],
                'user_agent': sess['user_agent'],
                'created_at': sess['created_at'],
                'expires_at': sess['expires_at'],
                'session_data': sess['session_data']
            })
        
        db.close()
        
        return render_template(
            'admin.html',
            users=users,
            logs=logs,
            session_info=session_info,
            debug_mode=app.debug
        )
    except Exception as e:
        app.logger.error(f"Admin panel error: {str(e)}")
        abort(500)

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
            
            log_activity(session['user_id'], 'LOGOUT', request.remote_addr)
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
    app.run(debug=True)