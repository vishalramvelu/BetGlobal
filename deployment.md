# Pre-Deployment Security & Configuration Checklist

## 🚨 CRITICAL SECURITY ISSUES (FIX BEFORE DEPLOYMENT)

### 1. Hardcoded Admin Password
**File:** `app.py:684`
```python
if password == "theothegoat6969":
```
**❌ CRITICAL:** Admin password is hardcoded in source code
**✅ Fix:**
```python
# Use environment variable and hash
admin_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')
if admin_password_hash and check_password_hash(admin_password_hash, password):
```

### 2. Weak Default Secrets
**Files:** `app.py:13, app.py:27`
```python
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", "super-secret-salt")
```
**❌ CRITICAL:** Predictable defaults will be used if env vars not set
**✅ Fix:** Remove defaults, require environment variables
```python
app.secret_key = os.environ['SESSION_SECRET']  # Will fail if not set
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']
```

### 3. Debug Mode Enabled
**File:** `main.py:4`
```python
app.run(host='0.0.0.0', port=5001, debug=True)
```
**❌ CRITICAL:** Debug mode exposes sensitive information
**✅ Fix:**
```python
debug_mode = os.environ.get('FLASK_ENV') != 'production'
app.run(host='0.0.0.0', port=5001, debug=debug_mode)
```

### 4. Missing CSRF Protection
**Impact:** All forms vulnerable to Cross-Site Request Forgery
**✅ Fix:** Add Flask-WTF CSRF protection
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

### 5. No Rate Limiting
**Impact:** Vulnerable to brute force attacks and spam
**✅ Fix:** Add Flask-Limiter
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"]
)

@limiter.limit("5 per minute")
@app.route('/api/create-bet', methods=['POST'])
def api_create_bet():
    # existing code
```

## 🔒 HIGH PRIORITY SECURITY FIXES

### 6. Security Headers Missing
**✅ Fix:** Add Flask-Talisman for security headers
```python
from flask_talisman import Talisman

Talisman(app, {
    'force_https': True,
    'strict_transport_security': True,
    'content_security_policy': {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' cdn.jsdelivr.net unpkg.com cdn.replit.com",
        'style-src': "'self' 'unsafe-inline' cdn.jsdelivr.net cdn.replit.com",
        'font-src': "'self' cdn.jsdelivr.net",
        'img-src': "'self' data:"
    }
})
```

### 7. Insecure Session Configuration
**✅ Fix:** Add secure session settings
```python
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
```

### 8. Admin Panel Security
**File:** `app.py:59-67`
**Issues:**
- No session timeout
- No admin role system
- No audit logging

**✅ Fix:**
```python
@admin_required
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect(url_for('admin_login'))
        
        # Check session timeout (30 minutes)
        if datetime.utcnow() - session.get('admin_login_time', datetime.min) > timedelta(minutes=30):
            session.pop('admin_authenticated', None)
            flash('Admin session expired', 'error')
            return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function
```

### 9. Excessive Debug Logging
**File:** `app.py:9`
```python
logging.basicConfig(level=logging.DEBUG)
```
**✅ Fix:**
```python
log_level = logging.INFO if os.environ.get('FLASK_ENV') == 'production' else logging.DEBUG
logging.basicConfig(level=log_level)
```

## ⚠️ MEDIUM PRIORITY FIXES

### 10. Money Handling Precision
**File:** `models.py` - Using FLOAT for money
**Issue:** Precision errors in financial calculations
**✅ Fix:**
```python
from decimal import Decimal
from sqlalchemy import DECIMAL

class User(db.Model):
    balance = db.Column(DECIMAL(10, 2), default=100.00)
    total_profit = db.Column(DECIMAL(10, 2), default=0.00)

class Bet(db.Model):
    amount = db.Column(DECIMAL(10, 2), nullable=False)
    odds = db.Column(DECIMAL(5, 2), nullable=False)
```

### 11. Input Validation Gaps
**Issues:**
- No server-side validation of deposit/withdrawal limits
- No maximum bet amount enforcement
- Username validation only in forms, not models

**✅ Fix:** Add model-level validation
```python
from sqlalchemy.orm import validates

class User(db.Model):
    @validates('balance')
    def validate_balance(self, key, balance):
        if balance < 0:
            raise ValueError("Balance cannot be negative")
        return balance

class Bet(db.Model):
    @validates('amount')
    def validate_amount(self, key, amount):
        if amount <= 0:
            raise ValueError("Bet amount must be positive")
        if amount > 10000:  # Max bet limit
            raise ValueError("Bet amount cannot exceed $10,000")
        return amount
```

### 12. Error Handling Improvements
**✅ Fix:** Add proper error handlers
```python
@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('errors/500.html'), 500
```

### 13. Database Security
**Current:** SQLite with no encryption
**✅ Fix for Production:**
```python
# Use PostgreSQL with connection encryption
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['DATABASE_URL'] + "?sslmode=require"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "connect_args": {"sslmode": "require"}
}
```

## 💳 STRIPE INTEGRATION REQUIREMENTS

### Stripe Account Setup
1. **Create Stripe Account**: Sign up for Stripe and complete verification
2. **Enable Stripe Connect**: Required for user withdrawals to bank accounts
3. **Configure Webhooks**: Set up endpoints for payment confirmations
4. **Get API Keys**: Obtain publishable and secret keys for live mode

### Stripe Configuration in App
```python
# Already implemented in app.py:
import stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Endpoints already implemented:
# - /create-checkout-session (deposits)
# - /success and /cancelled (payment handling)
# - /connect/create-account (bank account linking)
# - /create-payout (withdrawals)
```

### Stripe Environment Variables
```bash
# Test Mode (for development)
export STRIPE_PUBLISHABLE_KEY="pk_test_..."
export STRIPE_SECRET_KEY="sk_test_..."

# Live Mode (for production)
export STRIPE_PUBLISHABLE_KEY="pk_live_..."
export STRIPE_SECRET_KEY="sk_live_..."
export STRIPE_ENDPOINT_SECRET="whsec_..."  # For webhook verification
```

### Database Schema (Already Applied)
- Added `stripe_account_id` column to User model
- Migration file: `946499a935be_add_stripe_account_id_to_user_model.py`
- Run `flask db upgrade` on production to apply

## 🔧 PRODUCTION CONFIGURATION REQUIREMENTS

### Environment Variables (Required)
```bash
# Secrets (REQUIRED)
export SESSION_SECRET="your-256-bit-secret-key"
export SECURITY_PASSWORD_SALT="your-unique-salt"
export ADMIN_PASSWORD_HASH="$pbkdf2-sha256$..."

# Flask Configuration
export FLASK_ENV=production
export DATABASE_URL="postgresql://user:pass@host:port/db"

# Stripe Configuration (REQUIRED for payment processing)
export STRIPE_PUBLISHABLE_KEY="pk_live_..."
export STRIPE_SECRET_KEY="sk_live_..."
export STRIPE_ENDPOINT_SECRET="whsec_..."

# Email Configuration
export MAIL_SERVER=smtp.your-provider.com
export MAIL_PORT=587
export MAIL_USE_TLS=true
export MAIL_USERNAME=your-email@domain.com
export MAIL_PASSWORD=your-app-password
export MAIL_DEFAULT_SENDER=noreply@playstakes.com

# Optional
export SENTRY_DSN=your-sentry-dsn  # For error tracking
```

### Web Server Configuration
**❌ Don't use:** Flask development server
**✅ Use:** Gunicorn + Nginx
```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
```

### HTTPS/SSL Setup
**Required:** SSL certificate and HTTPS enforcement
```nginx
# Nginx configuration
server {
    listen 80;
    server_name playstakes.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name playstakes.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 MONITORING & LOGGING

### 1. Error Tracking
```python
# Add Sentry for error tracking
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

if os.environ.get('SENTRY_DSN'):
    sentry_sdk.init(
        dsn=os.environ['SENTRY_DSN'],
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0
    )
```

### 2. Access Logging
```python
# Add request logging
import uuid
from flask import g

@app.before_request
def before_request():
    g.request_id = str(uuid.uuid4())
    logger.info(f"Request {g.request_id}: {request.method} {request.path}")

@app.after_request
def after_request(response):
    logger.info(f"Response {g.request_id}: {response.status_code}")
    return response
```

## 🗄️ DATABASE DEPLOYMENT

### Migration Strategy
```python
# Use Flask-Migrate for database migrations
from flask_migrate import Migrate

migrate = Migrate(app, db)

# Commands for initial deployment:
# flask db init
# flask db migrate -m "Initial migration"
# flask db upgrade

# Commands for Stripe integration (ALREADY DONE in current codebase):
# flask db migrate -m "Add stripe_account_id to User model"
# flask db upgrade
```

### Backup Strategy
```bash
# Automated PostgreSQL backups
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump $DATABASE_URL > backup_$DATE.sql
aws s3 cp backup_$DATE.sql s3://your-backup-bucket/
```

## 🚀 DEPLOYMENT CHECKLIST

### Pre-Deployment (Critical)
- [ ] Remove hardcoded admin password
- [ ] Set all required environment variables (including Stripe keys)
- [ ] Disable debug mode
- [ ] Add CSRF protection
- [ ] Implement rate limiting
- [ ] Configure HTTPS/SSL
- [ ] Add security headers
- [ ] Set secure session configuration
- [ ] Fix deprecated datetime.utcnow() calls
- [ ] Remove unused imports and variables

### Production Setup
- [ ] Use PostgreSQL instead of SQLite
- [ ] Set up Gunicorn + Nginx
- [ ] Configure SSL certificate
- [ ] Set up database backups
- [ ] Configure monitoring (Sentry)
- [ ] Set up log rotation
- [ ] Configure email provider
- [ ] Test all notification types
- [ ] Run database migrations (including Stripe integration migration)
- [ ] Test Stripe payment integration in live mode
- [ ] Configure Stripe webhook endpoints

### Security Testing
- [ ] Run security scanner (Bandit)
- [ ] Test rate limiting
- [ ] Verify HTTPS enforcement
- [ ] Test CSRF protection
- [ ] Validate input sanitization
- [ ] Test admin panel security
- [ ] Verify password hashing

### Performance Testing
- [ ] Load test with multiple users
- [ ] Database query optimization
- [ ] Static file caching
- [ ] CDN setup for static assets

## 🛡️ SECURITY BEST PRACTICES

### 1. Regular Security Updates
```bash
# Keep dependencies updated
pip install --upgrade flask flask-security-too sqlalchemy
```

### 2. Security Scanning
```bash
# Install and run Bandit
pip install bandit
bandit -r . -f json -o security-report.json
```

### 3. Audit Logging
```python
# Log all admin actions
@app.before_request
def log_admin_actions():
    if request.endpoint and request.endpoint.startswith('admin_'):
        logger.warning(f"Admin action: {request.endpoint} by {session.get('admin_user', 'unknown')}")
```

## 📝 POST-DEPLOYMENT

### 1. Monitoring Setup
- Set up uptime monitoring
- Configure performance monitoring
- Set up error alerting

### 2. Regular Maintenance
- Weekly security updates
- Monthly backup verification
- Quarterly security review

### 3. Compliance
- GDPR compliance (if EU users)
- Financial regulations compliance
- Terms of service updates

---

**⚠️ CRITICAL WARNING:** Do not deploy to production until ALL critical security issues are resolved. The hardcoded admin password alone makes the application unsuitable for production deployment.