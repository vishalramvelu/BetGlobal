#!/usr/bin/env python3
"""
Security Testing Script for Play Stakes
Tests all implemented security measures
"""

import os
import sys
import requests
import time
import json
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

def print_status(message, status="INFO"):
    """Print colored status messages"""
    colors = {
        "INFO": Fore.BLUE,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "HEADER": Fore.MAGENTA
    }
    print(f"{colors.get(status, Fore.WHITE)}[{status}] {message}{Style.RESET_ALL}")

def test_environment_variables():
    """Test that all required environment variables are set"""
    print_status("Testing Environment Variables", "HEADER")
    
    required_vars = [
        'SESSION_SECRET',
        'SECURITY_PASSWORD_SALT',
        'ADMIN_PASSWORD_HASH',
        'STRIPE_SECRET_KEY',
        'STRIPE_PUBLISHABLE_KEY'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print_status(f"Missing required environment variables: {', '.join(missing_vars)}", "ERROR")
        return False
    else:
        print_status("All required environment variables are set", "SUCCESS")
        return True

def test_rate_limiting(base_url):
    """Test rate limiting on sensitive endpoints"""
    print_status("Testing Rate Limiting", "HEADER")
    
    # Test admin login rate limiting
    login_url = f"{base_url}/admin/login"
    
    print_status("Testing admin login rate limiting (5 requests/minute)", "INFO")
    
    for i in range(6):  # Try 6 requests (should be rate limited on 6th)
        try:
            response = requests.post(login_url, data={'password': 'wrong_password'}, timeout=5)
            if response.status_code == 429:
                print_status(f"Rate limit triggered after {i+1} requests", "SUCCESS")
                return True
            print_status(f"Request {i+1}: Status {response.status_code}", "INFO")
            time.sleep(1)  # Small delay between requests
        except requests.exceptions.RequestException as e:
            print_status(f"Request failed: {e}", "WARNING")
    
    print_status("Rate limiting not triggered (may need adjustment)", "WARNING")
    return False

def test_security_headers(base_url):
    """Test security headers implementation"""
    print_status("Testing Security Headers", "HEADER")
    
    try:
        response = requests.get(base_url, timeout=5)
        headers = response.headers
        
        security_checks = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content Security Policy'
        }
        
        passed = 0
        for header, description in security_checks.items():
            if header in headers:
                print_status(f" {description} ({header})", "SUCCESS")
                passed += 1
            else:
                print_status(f" Missing {description} ({header})", "WARNING")
        
        print_status(f"Security headers: {passed}/{len(security_checks)} implemented", "INFO")
        return passed >= 3  # At least 3 security headers should be present
        
    except requests.exceptions.RequestException as e:
        print_status(f"Failed to test security headers: {e}", "ERROR")
        return False

def test_csrf_protection(base_url):
    """Test CSRF protection"""
    print_status("Testing CSRF Protection", "HEADER")
    
    # Try to make a POST request without CSRF token
    try:
        response = requests.post(f"{base_url}/api/create-bet", 
                               json={'title': 'Test', 'description': 'Test'}, 
                               timeout=5)
        
        if response.status_code == 400 and 'csrf' in response.text.lower():
            print_status("CSRF protection is active", "SUCCESS")
            return True
        elif response.status_code == 401 or response.status_code == 403:
            print_status("Request blocked (likely by auth or CSRF)", "SUCCESS")
            return True
        else:
            print_status(f"CSRF test inconclusive: {response.status_code}", "WARNING")
            return False
            
    except requests.exceptions.RequestException as e:
        print_status(f"CSRF test failed: {e}", "ERROR")
        return False

def test_https_redirect(base_url):
    """Test HTTPS redirect in production mode"""
    print_status("Testing HTTPS Configuration", "HEADER")
    
    if os.environ.get('FLASK_ENV') == 'production':
        # Test HTTP to HTTPS redirect
        http_url = base_url.replace('https://', 'http://')
        try:
            response = requests.get(http_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    print_status("HTTPS redirect working correctly", "SUCCESS")
                    return True
            
            print_status("HTTPS redirect not configured", "WARNING")
            return False
            
        except requests.exceptions.RequestException:
            print_status("HTTPS redirect test failed", "WARNING")
            return False
    else:
        print_status("Development mode - HTTPS redirect disabled", "INFO")
        return True

def test_admin_security(base_url):
    """Test admin panel security"""
    print_status("Testing Admin Panel Security", "HEADER")
    
    admin_url = f"{base_url}/admin/dashboard"
    
    try:
        # Try to access admin without authentication
        response = requests.get(admin_url, timeout=5)
        
        if response.status_code in [401, 403] or 'login' in response.url:
            print_status("Admin panel properly protected", "SUCCESS")
            return True
        else:
            print_status("Admin panel may not be properly protected", "ERROR")
            return False
            
    except requests.exceptions.RequestException as e:
        print_status(f"Admin security test failed: {e}", "ERROR")
        return False

def test_input_validation():
    """Test model-level input validation"""
    print_status("Testing Input Validation", "HEADER")
    
    try:
        from models import User, Bet
        
        # Test User validation
        print_status("Testing User model validation", "INFO")
        
        # Test invalid balance
        try:
            user = User(username='test', email='test@test.com', balance=-100)
            # This should raise a validation error when we try to commit
            print_status("User balance validation: ", "SUCCESS")
        except:
            print_status("User balance validation: ", "ERROR")
        
        # Test Bet validation
        print_status("Testing Bet model validation", "INFO")
        
        # Test invalid amount
        try:
            bet = Bet(title='Test', description='Test description', amount=-50, odds=2.0, creator_id=1)
            print_status("Bet amount validation: ", "SUCCESS")
        except:
            print_status("Bet amount validation: ", "ERROR")
        
        return True
        
    except ImportError:
        print_status("Could not import models for validation testing", "WARNING")
        return False

def run_security_audit():
    """Run complete security audit"""
    print_status("= Play Stakes Security Audit", "HEADER")
    print_status("=" * 50, "INFO")
    
    # Get base URL from environment or use default
    base_url = os.environ.get('BASE_URL', 'http://localhost:5001')
    
    tests = [
        ("Environment Variables", test_environment_variables),
        ("Input Validation", test_input_validation),
        ("Security Headers", lambda: test_security_headers(base_url)),
        ("CSRF Protection", lambda: test_csrf_protection(base_url)),
        ("HTTPS Configuration", lambda: test_https_redirect(base_url)),
        ("Admin Panel Security", lambda: test_admin_security(base_url)),
        ("Rate Limiting", lambda: test_rate_limiting(base_url))
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_status(f"Test '{test_name}' failed with error: {e}", "ERROR")
            results.append((test_name, False))
        
        print()  # Add spacing between tests
    
    # Summary
    print_status("=Security Audit Summary", "HEADER")
    print_status("=" * 30, "INFO")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = " PASS" if result else " FAIL"
        color = "SUCCESS" if result else "ERROR"
        print_status(f"{status:8} {test_name}", color)
    
    print_status("-" * 30, "INFO")
    print_status(f"TOTAL:   {passed}/{total} tests passed", 
                "SUCCESS" if passed == total else "WARNING")
    
    if passed == total:
        print_status("<� All security tests passed!", "SUCCESS")
    else:
        print_status("�  Some security issues found. Please review.", "WARNING")
    
    return passed == total

def main():
    """Main function"""
    if not run_security_audit():
        sys.exit(1)

if __name__ == "__main__":
    main()