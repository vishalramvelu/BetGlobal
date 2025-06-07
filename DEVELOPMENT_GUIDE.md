# 🛠️ Play Stakes Development Guide

## Quick Start for Local Development

### 1. Create Development Environment

```bash
# Create a development branch
git checkout -b development

# Create local development environment file
cp .env .env.development
```

### 2. Configure Development Settings

Edit `.env.development` with local settings:

```bash
# Development Environment
FLASK_ENV=development
FLASK_DEBUG=True

# Local Database (SQLite for development)
DATABASE_URL=sqlite:///instance/bets_dev.db

# Security (can use simpler values for dev)
SESSION_SECRET=dev-session-secret-key-not-for-production
SECURITY_PASSWORD_SALT=dev-salt-for-testing-only
ADMIN_PASSWORD_HASH=pbkdf2:sha256:600000$dev$hash  # Generate with script below

# Stripe Test Keys (NEVER use live keys in development)
STRIPE_PUBLISHABLE_KEY=pk_test_your_test_key
STRIPE_SECRET_KEY=sk_test_your_test_key
STRIPE_ENDPOINT_SECRET=whsec_test_your_webhook_secret

# Email (suppress in development)
MAIL_SUPPRESS_SEND=True
MAIL_DEFAULT_SENDER=dev@playstakes.local
```

### 3. Development Setup Script

Create `setup_dev.py`:

```python
#!/usr/bin/env python3
"""Development environment setup script"""

import os
import shutil
from werkzeug.security import generate_password_hash

def setup_development():
    print("🛠️  Setting up development environment...")
    
    # Create development database
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # Generate development admin password
    dev_password = "admin123"  # Simple password for development
    admin_hash = generate_password_hash(dev_password)
    
    print(f"✅ Development admin password: {dev_password}")
    print(f"✅ Admin hash: {admin_hash}")
    
    # Create .env.development if it doesn't exist
    if not os.path.exists('.env.development'):
        with open('.env.development', 'w') as f:
            f.write(f"""# Development Environment
FLASK_ENV=development
FLASK_DEBUG=True

# Local Database
DATABASE_URL=sqlite:///instance/bets_dev.db

# Security (DEV ONLY - NOT FOR PRODUCTION)
SESSION_SECRET=dev-session-secret-key-not-for-production
SECURITY_PASSWORD_SALT=dev-salt-for-testing-only
ADMIN_PASSWORD_HASH={admin_hash}

# Stripe Test Keys
STRIPE_PUBLISHABLE_KEY=pk_test_your_test_key_here
STRIPE_SECRET_KEY=sk_test_your_test_key_here
STRIPE_ENDPOINT_SECRET=whsec_test_your_webhook_secret

# Email (suppressed in development)
MAIL_SUPPRESS_SEND=True
MAIL_DEFAULT_SENDER=dev@playstakes.local
""")
        print("✅ Created .env.development file")
    
    print("\n🎉 Development environment ready!")
    print("\nNext steps:")
    print("1. Update Stripe test keys in .env.development")
    print("2. Run: python3 run_dev.py")
    print(f"3. Admin login: admin123")

if __name__ == "__main__":
    setup_development()
```

### 4. Development Runner Script

Create `run_dev.py`:

```python
#!/usr/bin/env python3
"""Development server runner"""

import os
from dotenv import load_dotenv

def run_development():
    print("🚀 Starting Play Stakes Development Server...")
    
    # Load development environment
    if os.path.exists('.env.development'):
        load_dotenv('.env.development', override=True)
        print("✅ Loaded development environment")
    else:
        print("❌ .env.development not found. Run setup_dev.py first")
        return
    
    # Import and run the app
    from app import app
    
    print("🌐 Server starting at: http://localhost:5000")
    print("🔧 Admin panel: http://localhost:5000/admin/login")
    print("📧 Email suppressed (check console for reset codes)")
    print("\n💡 Press Ctrl+C to stop the server")
    
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        use_reloader=True
    )

if __name__ == "__main__":
    run_development()
```

## 🔄 Development Workflow

### Daily Development Process

1. **Start Development Session**
```bash
# Switch to development branch
git checkout development

# Pull latest changes
git pull origin main

# Start development server
python3 run_dev.py
```

2. **Feature Development**
```bash
# Create feature branch
git checkout -b feature/new-betting-feature

# Make your changes
# Test locally at http://localhost:5000

# Commit changes
git add .
git commit -m "Add new betting feature"
```

3. **Testing & Verification**
```bash
# Run security tests
python3 test_security.py

# Test your specific feature
# Check admin panel functionality
# Verify email flows (codes shown in console)
```

4. **Merge to Production**
```bash
# Switch to main (production) branch
git checkout main

# Merge your feature
git merge feature/new-betting-feature

# Push to production
git push origin main

# Deploy to production server
# (Follow DEPLOYMENT_GUIDE.md)
```

### 🧪 Testing Features

#### Database Testing
```bash
# Reset development database
rm instance/bets_dev.db
python3 -c "from app import app; app.app_context().push(); from database import db; db.create_all()"

# Or use Flask migrations
flask db upgrade
```

#### Email Testing
- All emails are suppressed in development
- Reset codes and verification emails are logged to console
- Check terminal output for email content

#### Stripe Testing
- Use Stripe test cards: `4242424242424242`
- Test webhooks with Stripe CLI: `stripe listen --forward-to localhost:5000/webhook`

#### Admin Panel Testing
- Access: http://localhost:5000/admin/login
- Default password: `admin123` (from setup script)

### 🔧 Development Tools

#### File Watching (Auto-restart)
The development server automatically restarts when you change files.

#### Debug Mode Features
- Detailed error pages
- Interactive debugger
- Automatic reloading
- SQL query logging

#### Database Browser
```python
# Quick database inspection
python3 -c "
from app import app
app.app_context().push()
from models import User, Bet
print('Users:', User.query.count())
print('Bets:', Bet.query.count())
"
```

## 🚀 Deployment Pipeline

### Manual Deployment
```bash
# 1. Test locally
python3 run_dev.py
# Test all features

# 2. Run security checks
python3 test_security.py
python3 deployment_checklist.py

# 3. Merge to main
git checkout main
git merge development
git push origin main

# 4. Deploy to production
# (SSH to server and pull changes)
```

### Environment Differences

| Feature | Development | Production |
|---------|-------------|------------|
| Database | SQLite (local) | PostgreSQL |
| Debug Mode | Enabled | Disabled |
| HTTPS | Not required | Enforced |
| Email | Suppressed | Live sending |
| Stripe | Test keys | Live keys |
| Rate Limiting | Relaxed | Strict |
| Error Pages | Detailed | Generic |

## 🐛 Debugging Tips

### Common Development Issues

#### Port Already in Use
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9
```

#### Database Locked
```bash
# Reset SQLite database
rm instance/bets_dev.db
python3 -c "from app import app; app.app_context().push(); from database import db; db.create_all()"
```

#### Import Errors
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Reinstall dependencies
pip3 install -r requirements.txt
```

### Development Console Commands

```python
# Quick user creation
from app import app
app.app_context().push()
from models import User, user_datastore
from flask_security import hash_password

user = user_datastore.create_user(
    username='testuser',
    email='test@example.com',
    password=hash_password('password123'),
    balance=1000.0
)
```

## 📝 Development Best Practices

### Code Changes
- Always test locally before merging
- Use meaningful commit messages
- Keep features small and focused
- Test both happy path and error cases

### Security Testing
- Never commit real API keys
- Test with invalid inputs
- Verify rate limiting works
- Check authentication flows

### Database Changes
- Use Flask migrations for schema changes
- Test migrations on development database first
- Backup production before applying migrations

### Performance
- Test with realistic data volumes
- Monitor memory usage during development
- Check database query efficiency

## 🔄 Git Workflow Summary

```bash
# Setup (once)
git checkout -b development
python3 setup_dev.py

# Daily workflow
git checkout development
git pull origin main
python3 run_dev.py

# Feature development
git checkout -b feature/feature-name
# ... make changes ...
git commit -am "Add feature description"

# Deploy to production
git checkout main
git merge feature/feature-name
git push origin main
```

---

## 🚨 Important Notes

1. **Never use production credentials in development**
2. **Always test features locally before deploying**
3. **Use test Stripe keys for payment testing**
4. **Keep development and production databases separate**
5. **Review security checklist before each deployment**

---

*Happy coding! 🎉*