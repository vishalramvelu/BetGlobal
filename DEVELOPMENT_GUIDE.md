# 🛠️ Development Guide

## 🚀 Quick Start

### 1. One-Command Setup
```bash
python3 setup_dev.py
```

This single command will:
- ✅ Create instance directory and database
- ✅ Generate `.env.development` with secure defaults 
- ✅ Set up admin credentials (admin123)
- ✅ Create sample users (testuser1/testuser2, password: password123)
- ✅ Configure development environment

### 2. Update Stripe Keys (Optional)
Edit `.env.development` and replace these placeholders:
```env
STRIPE_PUBLISHABLE_KEY=pk_test_your_actual_key_here
STRIPE_SECRET_KEY=sk_test_your_actual_key_here
```

### 3. Run Development Server
```bash
python3 run_dev.py
```

## 🌐 Access Points

- **Main App**: http://localhost:5000
- **Admin Panel**: http://localhost:5000/admin/login

## 🔑 Default Credentials

### Sample Users
- **testuser1**: password123 (balance: $1000)
- **testuser2**: password123 (balance: $500)

### Admin
- **Password**: admin123

## 💳 Testing Payments

Use Stripe test cards:
- **Card Number**: 4242424242424242
- **Expiry**: Any future date
- **CVC**: Any 3 digits

## 🗃️ Database

- **Type**: SQLite (development)
- **Location**: `instance/bets_dev.db`
- **Auto-created**: Yes, with sample data

## 🔧 Development Features

- **Auto-restart**: File changes trigger server reload
- **Debug mode**: Detailed error pages
- **Email suppressed**: Check console for email content
- **Rate limiting**: Disabled in development

## 📝 Common Commands

```bash
# Fresh setup (first time)
python3 setup_dev.py

# Start development server  
python3 run_dev.py

# Reset database (if needed)
rm instance/bets_dev.db
python3 setup_dev.py
```

## 🚨 Troubleshooting

### Database Errors
If you see database initialization errors:
1. Delete `instance/bets_dev.db`
2. Run `python3 setup_dev.py` again

### Import Errors
```bash
pip3 install -r requirements.txt
```

### Permission Errors
```bash
chmod 755 instance/
```

