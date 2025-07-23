import os

# Generate a secret key
SECRET_KEY = os.urandom(24)

# Database configuration
DATABASE = 'database.db'

# Security settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Should be True in production with HTTPS
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour