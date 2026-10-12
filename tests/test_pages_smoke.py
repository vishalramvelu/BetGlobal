"""Render every page of the site against a throwaway SQLite database.

Guards the front end: a Jinja error, a missing url_for endpoint or a broken
block name fails the test. Run with ``python -m pytest tests/test_app_smoke.py -q``.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix="betglobal-smoke-")
os.environ.setdefault("FLASK_ENV", "development")
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_TMP, "smoke.db")).replace("\\", "/")
os.environ.setdefault("SESSION_SECRET", "smoke-session-secret")
os.environ.setdefault("SECURITY_PASSWORD_SALT", "smoke-password-salt")
os.environ.setdefault("MAIL_SUPPRESS_SEND", "true")

from werkzeug.security import generate_password_hash  # noqa: E402

os.environ["ADMIN_PASSWORD_HASH"] = generate_password_hash("admin123")

from app import app, user_datastore  # noqa: E402
from database import db  # noqa: E402
from flask_security import hash_password  # noqa: E402
from models import Bet, Transaction  # noqa: E402


@pytest.fixture(scope="module")
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SECURITY_CSRF_PROTECT_MECHANISMS=[])
    app.config["RATELIMIT_ENABLED"] = False
    with app.app_context():
        db.drop_all()
        db.create_all()
        alice = user_datastore.create_user(
            username="alice", email="alice@example.com",
            password=hash_password("password123"), balance=1000.0, active=True,
        )
        bob = user_datastore.create_user(
            username="bob", email="bob@example.com",
            password=hash_password("password123"), balance=500.0, active=True,
        )
        db.session.commit()
        bets = [
            Bet(title="Bitcoin closes above $120k", description="Settled on the Dec 31 close.",
                amount=100.0, odds=1.8, category="Finance", creator_id=alice.id, status="open"),
            Bet(title="Lakers win the opener", description="Regulation plus overtime counts.",
                amount=50.0, odds=1.0, category="Sports", creator_id=bob.id, status="open"),
            Bet(title="Rain in Austin on Friday", description="Any measurable rain at KAUS.",
                amount=20.0, odds=2.0, category="Weather", creator_id=bob.id,
                acceptor_id=alice.id, status="accepted"),
            Bet(title="Disputed launch date", description="Launch happens before Q3 ends.",
                amount=30.0, odds=1.5, category="Technology", creator_id=alice.id,
                acceptor_id=bob.id, status="disputed", creator_decision="creator_wins",
                dispute_reason="The launch slipped."),
            Bet(title="Taker must respond", description="Awaiting the taker's confirmation.",
                amount=10.0, odds=1.0, category="Other", creator_id=bob.id,
                acceptor_id=alice.id, status="awaiting_resolution", creator_decision="creator_wins"),
        ]
        db.session.add_all(bets)
        db.session.add(Transaction(user_id=alice.id, transaction_type="deposit", amount=250.0,
                                   description="Card deposit"))
        db.session.commit()
    with app.test_client() as c:
        yield c


def _ok(resp, *needles):
    assert resp.status_code == 200, resp.status_code
    body = resp.get_data(as_text=True)
    assert "<html" in body
    for n in needles:
        assert n in body, f"missing {n!r}"
    return body


# ----------------------------------------------------------------- public --
@pytest.mark.parametrize("path, needle", [
    ("/landing", "Bet against people"),
    ("/login", 'name="email"'),
    ("/register", 'name="username"'),
    ("/forgot-password", 'name="email"'),
    ("/how-it-works", "How a bet runs"),
    ("/fees", "What it costs"),
    ("/contact", "Contact support"),
    ("/terms", "Terms of Service"),
    ("/privacy", "Privacy"),
    ("/admin/login", 'name="password"'),
])
def test_public_pages_render(client, path, needle):
    _ok(client.get(path), needle)


def test_root_redirects_guest_to_landing(client):
    r = client.get("/")
    assert r.status_code in (301, 302) and "/landing" in r.headers["Location"]


def test_member_pages_require_login(client):
    for path in ("/bets", "/dashboard", "/wallet", "/create-bet"):
        r = client.get(path)
        assert r.status_code in (301, 302), path


# ----------------------------------------------------------------- member --
def test_member_pages_render(client):
    r = client.post("/login", data={"email": "alice@example.com", "password": "password123"},
                    follow_redirects=False)
    assert r.status_code in (302, 303), r.get_data(as_text=True)[:500]

    body = _ok(client.get("/bets"), "data-bet-id", "accept-bet-btn", "betDetailsModal")
    assert "Bitcoin closes above" in body
    _ok(client.get("/bets?status=accepted"), "Rain in Austin")
    _ok(client.get("/bets?status=open&search=zzz-nothing"), "No bets found")

    body = _ok(client.get("/dashboard"), "disputeModal", 'id="submitDispute"', "Needs your response")
    assert "resolveCreatorBet" in body

    _ok(client.get("/wallet"), 'id="stripeAmount"', "Transaction history", "Card deposit")
    _ok(client.get("/wallet?period=week"), "Transaction history")

    body = _ok(client.get("/create-bet"), 'id="createBetForm"', 'id="pvTitle"', 'name="odds"')
    assert "data-sidebar-toggle" in body and 'id="userMenuPanel"' in body

    # content pages inside the member shell
    _ok(client.get("/contact"), "data-sidebar-toggle")
    _ok(client.get("/terms"), "data-sidebar-toggle")

    client.get("/logout")


# ------------------------------------------------------------------ admin --
def test_admin_pages_render(client):
    r = client.post("/admin/login", data={"password": "admin123"})
    assert r.status_code in (302, 303)
    _ok(client.get("/admin/dashboard"), "Total users")
    _ok(client.get("/admin/disputes"), "Disputed launch date", "resolveDispute")
    _ok(client.get("/admin/statistics"), "Volume by category")
    _ok(client.get("/admin/database"), "alice@example.com")
    client.get("/admin/logout")


# ------------------------------------------------------------ static files --
def test_static_assets_served(client):
    body = client.get("/landing").get_data(as_text=True)
    hrefs = re.findall(r'href="(/static/[^"]+\.css)"', body)
    assert hrefs, "no stylesheet linked"
    for href in hrefs:
        assert client.get(href).status_code == 200, href
    for src in re.findall(r'src="(/static/[^"]+\.js)"', body):
        assert client.get(src).status_code == 200, src
