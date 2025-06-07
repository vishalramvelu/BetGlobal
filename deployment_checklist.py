#!/usr/bin/env python3
"""
Deployment Checklist for Play Stakes
"""

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("WARNING: python-dotenv not installed, environment variables from .env file will not be loaded")

def check_critical_env_vars():
    """Check critical environment variables"""
    required = ['SESSION_SECRET', 'SECURITY_PASSWORD_SALT', 'ADMIN_PASSWORD_HASH']
    missing = [var for var in required if not os.environ.get(var)]
    
    print("Environment Variables:")
    if missing:
        print(f"MISSING: {', '.join(missing)}")
        return False
    else:
        print("PASS: All critical variables set")
        return True

def check_flask_env():
    """Check Flask environment"""
    flask_env = os.environ.get('FLASK_ENV', 'development')
    print(f"Flask Environment: {flask_env}")
    return flask_env == 'production'

def check_stripe_config():
    """Check Stripe configuration"""
    pk = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    sk = os.environ.get('STRIPE_SECRET_KEY', '')
    
    print("Stripe Configuration:")
    if pk.startswith('pk_live_') and sk.startswith('sk_live_'):
        print("PASS: Live Stripe keys configured")
        return True
    elif pk.startswith('pk_test_') or sk.startswith('sk_test_'):
        print("WARNING: Test Stripe keys (okay for development)")
        return True
    else:
        print("FAIL: Invalid or missing Stripe keys")
        return False

def main():
    """Run deployment checklist"""
    print("Play Stakes Deployment Checklist")
    print("=" * 40)
    
    checks = [
        check_critical_env_vars(),
        check_flask_env(),
        check_stripe_config()
    ]
    
    passed = sum(checks)
    total = len(checks)
    
    print(f"\nResults: {passed}/{total} checks passed")
    
    if passed == total:
        print("SUCCESS: Ready for deployment!")
        return 0
    else:
        print("WARNING: Please fix issues before deployment")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())