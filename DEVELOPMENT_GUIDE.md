# 🛠️ Development Guide

## 🚀 Quick Start

### 1. Start the Database (Docker)
```bash
docker compose -f docker-compose.dev.yml up -d
```

Runs Postgres 16 in a container named `betglobal-postgres-dev`, published on
**host port 5433** (not 5432, so it does not collide with any Postgres already
running on your machine). Data lives in the `betglobal_pgdata` Docker volume and
survives `down`/`up`.

### 2. One-Command Setup
```bash
python3 setup_dev.py
```

This single command will:
- ✅ Generate `.env.development` from defaults (if missing)
- ✅ Set up admin credentials (admin123)
- ✅ Create all tables in the Postgres dev database
- ✅ Seed sample users
- ✅ Configure development environment

If you already have a `.env.development` from the old SQLite setup, copy the new
one instead: `cp .env.development.example .env.development` (then re-add your
`ADMIN_PASSWORD_HASH` and Stripe keys).

### 3. Update Stripe Keys (Optional)
Edit `.env.development` and replace these placeholders:
```env
STRIPE_PUBLISHABLE_KEY=pk_test_your_actual_key_here
STRIPE_SECRET_KEY=sk_test_your_actual_key_here
```

### 4. Run Development Server
```bash
python3 run_dev.py
```

`run_dev.py` checks that Postgres is reachable before booting and tells you to
start the container if it is not.

## 🌐 Access Points

- **Main App**: http://localhost:5000
- **Admin Panel**: http://localhost:5000/admin/login

## 🔑 Default Credentials

### Sample Users
Seeded automatically the first time the app connects to an empty database:
- **john_doe** / john@example.com: password123
- **jane_smith** / jane@example.com: password123

### Admin
- **Password**: admin123

## 💳 Testing Payments

Use Stripe test cards:
- **Card Number**: 4242424242424242
- **Expiry**: Any future date
- **CVC**: Any 3 digits

## 🗃️ Database

- **Type**: Postgres 16 in Docker (`docker-compose.dev.yml`)
- **Connection**: `postgresql+psycopg2://betglobal:betglobal_dev@localhost:5433/betglobal_dev`
- **Container**: `betglobal-postgres-dev`
- **Volume**: `betglobal_pgdata` (persists across restarts)
- **Auto-created**: Yes, tables and sample data on first run

### Handy commands
```bash
# Open a psql shell
docker exec -it betglobal-postgres-dev psql -U betglobal -d betglobal_dev

# Stop the database (keeps data)
docker compose -f docker-compose.dev.yml down

# Stop and wipe the data volume
docker compose -f docker-compose.dev.yml down -v
```

### Migrations
`app.py` does not load `.env.development` itself, so the Flask CLI needs the env
injected:
```bash
FLASK_APP=app.py python -m dotenv -f .env.development run -- flask db migrate -m "message"
FLASK_APP=app.py python -m dotenv -f .env.development run -- flask db upgrade
```
The dev database is stamped at the current migration head, so `db migrate`
produces correct diffs.

## 🔧 Development Features

- **Auto-restart**: File changes trigger server reload
- **Debug mode**: Detailed error pages
- **Email suppressed**: Check console for email content
- **Rate limiting**: Disabled in development

## 📝 Common Commands

```bash
# Start the database
docker compose -f docker-compose.dev.yml up -d

# Fresh setup (first time)
python3 setup_dev.py

# Start development server  
python3 run_dev.py

# Reset database (wipes all dev data)
docker compose -f docker-compose.dev.yml down -v
docker compose -f docker-compose.dev.yml up -d
python3 setup_dev.py
```

## 🚨 Troubleshooting

### Database Errors
If you see database initialization errors:
1. Check the container is healthy: `docker ps --filter name=betglobal-postgres-dev`
2. Reset it: `docker compose -f docker-compose.dev.yml down -v && docker compose -f docker-compose.dev.yml up -d`
3. Run `python3 setup_dev.py` again

### Port 5433 Already In Use
Change the host side of the port mapping in `docker-compose.dev.yml`
(`"5433:5432"` → `"5434:5432"`) and update the port in `DATABASE_URL` to match.

### Import Errors
```bash
pip3 install -r requirements.txt
```
