# =� Play Stakes Deployment Guide

## Quick Start

1. **Set up environment variables**:
   ```bash
   python3 setup_env.py
   ```

2. **Run deployment checklist**:
   ```bash
   python3 deployment_checklist.py
   ```

3. **Fix any issues and re-run checklist until all checks pass**

4. **Deploy to production**

## =� Pre-Deployment Checklist

###  Critical Security Issues (MUST BE COMPLETED)

- [x] Remove hardcoded admin password - now uses `ADMIN_PASSWORD_HASH` env var
- [x] Remove default secret key fallbacks - requires `SESSION_SECRET` and `SECURITY_PASSWORD_SALT`
- [x] Configure production mode - `FLASK_ENV=production` disables debug
- [x] Add CSRF protection - Flask-WTF CSRFProtect enabled
- [x] Implement rate limiting - Flask-Limiter with 5/min on sensitive endpoints
- [x] Add security headers - Flask-Talisman with CSP and HTTPS enforcement
- [x] Configure secure sessions - HttpOnly, SameSite, HTTPS-only cookies
- [x] Fix deprecated datetime calls - timezone-aware datetime handling
- [x] Add input validation - Model-level validation for User and Bet models

### =' Environment Setup

#### Required Environment Variables
```bash
# Security (CRITICAL)
SESSION_SECRET=your-256-bit-secret-key
SECURITY_PASSWORD_SALT=your-unique-salt
ADMIN_PASSWORD_HASH=pbkdf2:sha256:...

# Flask
FLASK_ENV=production

# Database
DATABASE_URL=postgresql://user:pass@host:port/db

# Stripe (REQUIRED)
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_ENDPOINT_SECRET=whsec_...

# Email
MAIL_SERVER=smtp.your-provider.com
MAIL_USERNAME=your-email@domain.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@playstakes.com
```

#### Generate Secure Values
```bash
# Session secret (256-bit)
openssl rand -hex 32

# Security salt (128-bit) 
openssl rand -hex 16

# Admin password hash
python3 -c "
from werkzeug.security import generate_password_hash
password = input('Enter admin password: ')
print(generate_password_hash(password))
"
```

### <� Production Setup

#### 1. Database Migration
```bash
# Initialize migrations (if not already done)
flask db init

# Create migration for current schema
flask db migrate -m "Initial production migration"

# Apply migrations
flask db upgrade
```

#### 2. Web Server (Gunicorn + Nginx)
```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app

# Nginx configuration
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 3. SSL/HTTPS Setup
- Obtain SSL certificate (Let's Encrypt recommended)
- Configure nginx for HTTPS
- Test HTTPS redirect functionality

#### 4. Stripe Configuration
- Create live Stripe account
- Enable Stripe Connect for user withdrawals
- Set up webhook endpoints
- Test payment flow with live keys

### =� Security Verification

#### Run Security Audit
```bash
# Complete security audit
python3 test_security.py

# Deployment checklist
python3 deployment_checklist.py
```

#### Manual Security Checks
- [ ] Admin panel requires authentication
- [ ] Rate limiting active on login/API endpoints
- [ ] HTTPS enforced in production
- [ ] CSRF tokens required for forms
- [ ] Security headers present
- [ ] No debug info exposed
- [ ] Database access restricted
- [ ] Error pages don't leak info

### =� Monitoring Setup

#### Error Tracking (Optional)
```bash
# Install Sentry
pip install sentry-sdk[flask]

# Add to environment
SENTRY_DSN=your-sentry-dsn
```

#### Log Management
```bash
# Configure log rotation
/etc/logrotate.d/playstakes:
/var/log/playstakes/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 644 www-data www-data
}
```

### =� Database Backup

#### Automated Backups
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump $DATABASE_URL > backup_$DATE.sql
aws s3 cp backup_$DATE.sql s3://your-backup-bucket/
```

#### Backup Schedule
```bash
# Add to crontab
0 2 * * * /path/to/backup.sh
```

## =� Production Deployment Steps

### 1. Final Pre-Deployment
```bash
# Run complete checklist
python3 deployment_checklist.py

# Verify all tests pass
python3 test_security.py

# Check for security vulnerabilities
pip install pip-audit
pip-audit
```

### 2. Server Setup
```bash
# Update system
sudo apt update && sudo apt upgrade

# Install dependencies
sudo apt install nginx postgresql python3-pip

# Create application user
sudo useradd -m -s /bin/bash playstakes
sudo usermod -aG www-data playstakes
```

### 3. Application Deployment
```bash
# Clone repository (or upload files)
git clone https://github.com/your-repo/play-stakes.git
cd play-stakes

# Install Python dependencies
pip3 install -r requirements.txt

# Set up environment
# Create .env file with production values

# Run migrations
flask db upgrade

# Test application
python3 -c "from app import app; print('App loads successfully')"
```

### 4. Service Configuration
```bash
# Create systemd service
sudo nano /etc/systemd/system/playstakes.service

[Unit]
Description=Play Stakes WSGI App
After=network.target

[Service]
User=playstakes
Group=www-data
WorkingDirectory=/home/playstakes/play-stakes
Environment="PATH=/home/playstakes/play-stakes/venv/bin"
ExecStart=/home/playstakes/play-stakes/venv/bin/gunicorn --workers 4 --bind unix:playstakes.sock -m 007 app:app
Restart=always

[Install]
WantedBy=multi-user.target

# Start service
sudo systemctl daemon-reload
sudo systemctl start playstakes
sudo systemctl enable playstakes
```

### 5. Final Verification
```bash
# Check service status
sudo systemctl status playstakes

# Test endpoints
curl -I https://yourdomain.com
curl -I https://yourdomain.com/admin/login

# Monitor logs
sudo journalctl -u playstakes -f
```

## =' Troubleshooting

### Common Issues

#### Environment Variables Not Loading
- Ensure `.env` file exists and has correct permissions (600)
- Verify `python-dotenv` is installed
- Check environment variable names (case-sensitive)

#### Database Connection Errors
- Verify `DATABASE_URL` format
- Check database server is running
- Ensure user has correct permissions
- Test connection manually

#### Stripe Integration Issues
- Verify API keys are for correct environment (live vs test)
- Check webhook endpoints are configured
- Ensure Stripe Connect is enabled
- Test with small amounts first

#### Rate Limiting Too Strict
- Adjust limits in `app.py`
- Consider using Redis for rate limit storage
- Monitor rate limit logs

### Security Incident Response
1. Immediately revoke compromised credentials
2. Check logs for unauthorized access
3. Update all secrets
4. Review access patterns
5. Notify users if data affected

## =� Support

### Emergency Contacts
- **Technical Issues**: [Your contact]
- **Security Issues**: [Security contact]
- **Infrastructure**: [DevOps contact]

### Monitoring Dashboards
- **Application Health**: [Monitoring URL]
- **Error Tracking**: [Sentry URL]
- **Infrastructure**: [Server monitoring URL]

---

## � Critical Warnings

1. **NEVER** deploy without running the security checklist
2. **ALWAYS** use HTTPS in production
3. **NEVER** commit `.env` files to version control
4. **ALWAYS** use live Stripe keys for production
5. **NEVER** disable security features in production
6. **ALWAYS** backup database before major changes

---

*Last updated: Generated automatically with deployment tools*