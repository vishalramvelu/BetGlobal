# 🚀 Quick Start - Development Workflow

## First Time Setup (Run Once)

```bash
# 1. Setup development environment
python3 setup_dev.py

# 2. Start development server
python3 run_dev.py
```

## Daily Development Workflow

```bash
# Start development
python3 run_dev.py

# Your app will be at:
# http://localhost:5000          (main app)
# http://localhost:5000/admin    (admin panel)
```

## Making Changes

1. **Edit files** - server auto-restarts on changes
2. **Test locally** - verify your changes work
3. **Commit to git** when ready for production

```bash
git add .
git commit -m "Your change description"
git push origin main
```

## Key Development Features

- **Auto-restart** - server restarts when you edit files
- **SQLite database** - no PostgreSQL setup needed
- **Email suppression** - codes shown in terminal
- **Test Stripe keys** - safe payment testing
- **Debug mode** - detailed error pages

## Production vs Development

| Feature | Development | Production |
|---------|-------------|------------|
| Database | SQLite (local file) | PostgreSQL |
| Emails | Suppressed (console) | Real emails sent |
| Stripe | Test keys | Live keys |
| HTTPS | Not required | Required |
| Debug | Enabled | Disabled |

## Common Commands

```bash
# Setup development
python3 setup_dev.py

# Run development server
python3 run_dev.py

# Reset development database
rm instance/bets_dev.db
python3 run_dev.py  # Will recreate database

# Run security tests
python3 test_security.py
```

## Getting Help

- 📖 Full guide: `DEVELOPMENT_GUIDE.md`
- 🚀 Production deployment: `DEPLOYMENT_GUIDE.md`
- 🐛 Issues? Check development guide troubleshooting section