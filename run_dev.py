#!/usr/bin/env python3
"""Development server runner"""

import os
import sys
from dotenv import load_dotenv

# Windows consoles default to cp1252, which cannot encode the emoji below.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def postgres_is_reachable(db_url, timeout=1.5):
    """Open a TCP socket to the Postgres host/port in DATABASE_URL."""
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(db_url)
    host = parsed.hostname or 'localhost'
    port = parsed.port or 5432
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_development():
    print("🚀 Starting Play Stakes Development Server...")
    print("=" * 50)
    
    # Check if development environment exists
    if not os.path.exists('.env.development'):
        print("❌ .env.development not found.")
        print("📝 Run setup first: python3 setup_dev.py")
        return
    
    # Load development environment
    load_dotenv('.env.development', override=True)
    print("✅ Loaded development environment (.env.development)")
    
    # Verify development mode
    if os.getenv('FLASK_ENV') != 'development':
        print("⚠️  Warning: FLASK_ENV is not set to 'development'")
    
    # Check database
    db_url = os.getenv('DATABASE_URL', '')
    if 'postgres' in db_url:
        print(f"✅ Using development database: {db_url}")
        if not postgres_is_reachable(db_url):
            print("❌ Cannot reach the development Postgres server.")
            print("📝 Start it with: docker compose -f docker-compose.dev.yml up -d")
            return
        print("✅ Postgres is reachable")
    elif 'sqlite' in db_url:
        print(f"✅ Using development database: {db_url}")
    else:
        print(f"⚠️  Warning: Unrecognised DATABASE_URL: {db_url}")
    
    # Import and initialize the app
    try:
        # Ensure instance directory exists
        if not os.path.exists('instance'):
            os.makedirs('instance', mode=0o755)
            print("✅ Created instance directory")
        
        from app import app
        
        # Initialize development database
        try:
            from setup_dev import init_database
            print("🗄️  Initializing development database...")
            init_database()
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            print("💡 This is usually normal on first run - continuing anyway...")
            # Don't return here - let the app start even if DB init fails
        
    except Exception as e:
        print(f"❌ Error initializing app: {e}")
        print("💡 Troubleshooting:")
        print("   1. Try: pip3 install -r requirements.txt")
        print("   2. Check if instance directory exists and is writable")
        print("   3. Run: python3 setup_dev.py again")
        return
    
    print("\n🌐 Development Server Info:")
    print("   Main app: http://localhost:5000")
    print("   Admin panel: http://localhost:5000/admin/login")
    print("   Admin password: admin123")
    print("\n📧 Email Configuration:")
    print("   Emails suppressed (check console for codes)")
    print("   Reset codes will appear in terminal output")
    print("\n💳 Stripe Testing:")
    print("   Use test card: 4242424242424242")
    print("   Any future date, any CVC")
    print("\n🔧 Development Features:")
    print("   Auto-restart on file changes")
    print("   Detailed error pages")
    print("   Debug toolbar available")
    print("\n" + "=" * 50)
    print("💡 Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Run the development server
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=True,
            use_reloader=True,
            use_debugger=True
        )
    except KeyboardInterrupt:
        print("\n👋 Development server stopped")
    except Exception as e:
        print(f"\n❌ Server error: {e}")

if __name__ == "__main__":
    run_development()