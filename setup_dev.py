#!/usr/bin/env python3
"""Development environment setup script"""

import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

def setup_development():
    print("🛠️  Setting up development environment...")
    
    # Create development database directory
    if not os.path.exists('instance'):
        os.makedirs('instance')
        print("✅ Created instance directory")
    
    # Ensure proper permissions for instance directory
    os.chmod('instance', 0o755)
    
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
DATABASE_URL=sqlite:///{os.getcwd()}/instance/bets_dev.db

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
    
    # Initialize development database
    print("\n🗄️  Initializing development database...")
    init_database()
    
    print("\n🎉 Development environment ready!")
    print("\nNext steps:")
    print("1. Update Stripe test keys in .env.development")
    print("2. Run: python3 run_dev.py")
    print(f"3. Admin panel: http://localhost:5000/admin/login (password: {dev_password})")
    print("4. Main app: http://localhost:5000")
    print("\n💡 Development Tips:")
    print("- Database: SQLite (instance/bets_dev.db)")
    print("- Sample users: testuser1/testuser2 (password: password123)")
    print("- Emails: Suppressed (check console for codes)")
    print("- Debug mode: Enabled (auto-restart on file changes)")
    print("- Use test Stripe cards: 4242424242424242")

def init_database():
    """Initialize development database with tables and sample data"""
    try:
        # Load development environment
        load_dotenv('.env.development', override=True)
        
        # Initialize the app and database
        from app import app
        
        with app.app_context():
            from database import db
            
            # Create all tables
            db.create_all()
            print("✅ Development database tables created")
            
            # Create sample users if none exist
            from models import User
            from app import user_datastore
            from flask_security import hash_password
            from datetime import datetime, timezone
            
            if User.query.count() == 0:
                # Create sample users
                user1 = user_datastore.create_user(
                    username='testuser1',
                    email='test1@example.com',
                    password=hash_password('password123'),
                    balance=1000.0,
                    active=True,
                    confirmed_at=datetime.now(timezone.utc)
                )
                
                user2 = user_datastore.create_user(
                    username='testuser2', 
                    email='test2@example.com',
                    password=hash_password('password123'),
                    balance=500.0,
                    active=True,
                    confirmed_at=datetime.now(timezone.utc)
                )
                
                db.session.commit()
                print("✅ Created sample users (testuser1, testuser2) with password: password123")
            else:
                print("ℹ️  Users already exist in database")
                
        print("✅ Database initialization complete")
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        print("💡 This is normal on first run - database will be created when app starts")

if __name__ == "__main__":
    setup_development()