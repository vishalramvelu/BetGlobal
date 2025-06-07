#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Environment Setup Script for Play Stakes
Generates secure environment variables and creates .env file
"""

import os
import secrets
import getpass
from werkzeug.security import generate_password_hash

def generate_secret_key():
    """Generate a secure 256-bit secret key"""
    return secrets.token_hex(32)

def generate_salt():
    """Generate a secure salt"""
    return secrets.token_hex(16)

def generate_admin_password():
    """Generate admin password hash"""
    print("\n= Admin Password Setup")
    print("=" * 50)
    
    while True:
        password = getpass.getpass("Enter admin password (hidden): ")
        confirm = getpass.getpass("Confirm admin password (hidden): ")
        
        if password != confirm:
            print("L Passwords don't match. Try again.")
            continue
        
        if len(password) < 8:
            print("L Password must be at least 8 characters. Try again.")
            continue
        
        return generate_password_hash(password)

def create_env_file():
    """Create .env file with generated values"""
    print("\n=� Play Stakes Environment Setup")
    print("=" * 50)
    
    # Check if .env already exists
    env_path = ".env"
    if os.path.exists(env_path):
        response = input("�  .env file already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            return
    
    print("\n=� Generating secure environment variables...")
    
    # Generate secure values
    session_secret = generate_secret_key()
    security_salt = generate_salt()
    admin_hash = generate_admin_password()
    
    print("\n=� Email Configuration")
    print("=" * 30)
    mail_server = input("Mail server (default: smtp.gmail.com): ").strip() or "smtp.gmail.com"
    mail_port = input("Mail port (default: 587): ").strip() or "587"
    mail_username = input("Mail username/email: ").strip()
    mail_password = getpass.getpass("Mail password (App password recommended): ")
    mail_sender = input("Default sender email: ").strip()
    
    print("\n=� Stripe Configuration")
    print("=" * 25)
    print("Get these from your Stripe Dashboard:")
    stripe_pk = input("Stripe Publishable Key (pk_test_... or pk_live_...): ").strip()
    stripe_sk = input("Stripe Secret Key (sk_test_... or sk_live_...): ").strip()
    stripe_webhook = input("Stripe Webhook Secret (optional, whsec_...): ").strip()
    
    print("\n=�  Database Configuration")
    print("=" * 28)
    db_choice = input("Database type (1=SQLite, 2=PostgreSQL) [1]: ").strip() or "1"
    
    if db_choice == "2":
        db_host = input("PostgreSQL host: ").strip()
        db_port = input("PostgreSQL port (default: 5432): ").strip() or "5432"
        db_name = input("Database name: ").strip()
        db_user = input("Database username: ").strip()
        db_pass = getpass.getpass("Database password: ")
        database_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    else:
        database_url = "sqlite:///instance/bets.db"
    
    # Create .env content
    env_content = f"""# Play Stakes Environment Variables
# Generated on {os.popen('date').read().strip()}

# CRITICAL SECURITY VARIABLES (REQUIRED)
SESSION_SECRET={session_secret}
SECURITY_PASSWORD_SALT={security_salt}
ADMIN_PASSWORD_HASH={admin_hash}

# Flask Configuration
FLASK_ENV=development
# For production, change to: FLASK_ENV=production

# Database Configuration
DATABASE_URL={database_url}

# Stripe Configuration (REQUIRED for payment processing)
STRIPE_PUBLISHABLE_KEY={stripe_pk}
STRIPE_SECRET_KEY={stripe_sk}
STRIPE_ENDPOINT_SECRET={stripe_webhook}

# Email Configuration
MAIL_SERVER={mail_server}
MAIL_PORT={mail_port}
MAIL_USE_TLS=true
MAIL_USERNAME={mail_username}
MAIL_PASSWORD={mail_password}
MAIL_DEFAULT_SENDER={mail_sender}

# Optional - Error Tracking
# SENTRY_DSN=your-sentry-dsn-for-error-tracking

# Optional - Redis for session storage (production recommended)
# REDIS_URL=redis://localhost:6379/0
"""
    
    # Write .env file
    with open(env_path, 'w') as f:
        f.write(env_content)
    
    # Set appropriate permissions
    os.chmod(env_path, 0o600)  # Read/write for owner only
    
    print(f"\n Environment file created: {env_path}")
    print("= File permissions set to 600 (owner read/write only)")
    
    print("\n<� Next Steps:")
    print("1. Review the generated .env file")
    print("2. For production: Change FLASK_ENV=production")
    print("3. Test your Stripe keys in Stripe Dashboard")
    print("4. Verify email settings work")
    print("5. Run: python3 main.py")
    
    print("\n�  SECURITY REMINDERS:")
    print("- Never commit .env to version control")
    print("- Use strong, unique passwords")
    print("- Enable 2FA on all accounts")
    print("- Regularly rotate secrets in production")

def main():
    try:
        create_env_file()
    except KeyboardInterrupt:
        print("\n\n�  Setup cancelled by user.")
    except Exception as e:
        print(f"\nL Error during setup: {e}")

if __name__ == "__main__":
    main()