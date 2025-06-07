#!/usr/bin/env python3
"""Development environment setup script"""

import os
from werkzeug.security import generate_password_hash

def setup_development():
    print("🛠️  Setting up development environment...")
    
    # Create development database directory
    if not os.path.exists('instance'):
        os.makedirs('instance')
        print("✅ Created instance directory")
    
    # Generate development admin password
    dev_password = "admin123"  # Simple password for development
    admin_hash = generate_password_hash(dev_password)
    
    print(f"✅ Development admin password: {dev_password}")
    print(f"✅ Admin hash generated")
    
    # Create .env.development if it doesn't exist
    if not os.path.exists('.env.development'):
        with open('.env.development', 'w') as f:
            f.write(f"""# Development Environment - DO NOT USE IN PRODUCTION
FLASK_ENV=development
FLASK_DEBUG=True

# Local Database (SQLite for easy development)
DATABASE_URL=sqlite:///instance/bets_dev.db

# Security (DEV ONLY - NOT FOR PRODUCTION)
SESSION_SECRET=dev-session-secret-key-not-for-production-use-only
SECURITY_PASSWORD_SALT=dev-salt-for-testing-only-change-for-production
ADMIN_PASSWORD_HASH={admin_hash}

# Stripe Test Keys (Replace with your test keys)
STRIPE_PUBLISHABLE_KEY=pk_test_replace_with_your_stripe_test_publishable_key
STRIPE_SECRET_KEY=sk_test_replace_with_your_stripe_test_secret_key
STRIPE_ENDPOINT_SECRET=whsec_replace_with_your_stripe_test_webhook_secret

# Email Configuration (suppressed in development)
MAIL_SUPPRESS_SEND=True
MAIL_DEFAULT_SENDER=dev@playstakes.local
MAIL_SERVER=localhost
MAIL_PORT=587
MAIL_USE_TLS=False
MAIL_USERNAME=
MAIL_PASSWORD=
""")
        print("✅ Created .env.development file")
        print("⚠️  Update Stripe test keys in .env.development before testing payments")
    else:
        print("ℹ️  .env.development already exists")
    
    # Create .gitignore entry for development files
    gitignore_content = """
# Development files
.env.development
instance/bets_dev.db
"""
    
    if os.path.exists('.gitignore'):
        with open('.gitignore', 'r') as f:
            existing_content = f.read()
        
        if '.env.development' not in existing_content:
            with open('.gitignore', 'a') as f:
                f.write(gitignore_content)
            print("✅ Updated .gitignore for development files")
    
    print("\n🎉 Development environment ready!")
    print("\nNext steps:")
    print("1. Update Stripe test keys in .env.development")
    print("2. Run: python3 run_dev.py")
    print(f"3. Admin panel: http://localhost:5000/admin/login (password: {dev_password})")
    print("4. Main app: http://localhost:5000")
    print("\n💡 Development Tips:")
    print("- Database: SQLite (instance/bets_dev.db)")
    print("- Emails: Suppressed (check console for codes)")
    print("- Debug mode: Enabled (auto-restart on file changes)")
    print("- Use test Stripe cards: 4242424242424242")

if __name__ == "__main__":
    setup_development()