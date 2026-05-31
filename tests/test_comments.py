"""
Security tests for Feature 2 (Photo Comments) — Task 9.2.

Each test's docstring identifies the R3.x requirement from Task 8.2
and the OWASP Top 10:2025 category it evaluates, so the marker can
map each test directly to a security requirement.

Run with: pytest -v tests/test_comments.py
"""
import io
import pytest

from project import create_app, db
from project.models import User, Photo, Comment


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    test_app = create_app(test_config={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "UPLOAD_DIR": str(upload_dir),
        "SECRET_KEY": "test-only-key",
        "WTF_CSRF_ENABLED": False,
        # Disable Flask-Limiter for most assertions so we can exercise
        # the security logic without hitting a 429 wall.
        "RATELIMIT_ENABLED": False,
    })
    with test_app.app_context():
        db.create_all()
        yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def fixtures(app):
    """Seed alice, bob (regular users), admin, and one photo owned by alice."""
    with app.app_context():
        alice = User(email="alice@example.com", username="alice", is_admin=False)
        alice.set_password("AlicePassword2026!")
        bob = User(email="bob@example.com", username="bob", is_admin=False)
        bob.set_password("BobPassword2026!")
        admin = User(email="admin@example.com", username="admin", is_admin=True)
        admin.set_password("AdminPassword2026!")
        db.session.add_all([alice, bob, admin])
        db.session.commit()

        photo = Photo(
            name="alice photo", caption="c", description="d",
            file="a.jpg", owner_id=alice.id,
        )
        db.session.add(photo)
        db.session.commit()
        return {
            "alice": alice.id,
            "bob": bob.id,
            "admin": admin.id,
            "photo": photo.id,
        }


def _login(client, email, password):
    return client.post("/login",
                       data={"email": email, "password": password},
                       follow_redirects=False)


# ---------------------------------------------------------------------------
# Comment model integrity  (R3.2 / R3.4)
# ---------------------------------------------------------------------------

def test_comment_model_fields(app, fixtures):
    """R3.2 / R3.4 — Comment row stores user_id, photo_id, content, created_at."""
    with app.app_context():
        c = Comment(
            photo_id=fixtures["photo"],
            user_id=fixtures["alice"],
            content="hello world",
        )
        db.session.add(c); db.session.commit()
        loaded = db.session.get(Comment, c.id)
        assert loaded.user_id == fixtures["alice"]
        assert loaded.photo_id == fixtures["photo"]
        assert loaded.content == "hello world"
        assert loaded.created_at is not None


# ---------------------------------------------------------------------------
# Authentication boundary  (R3.1 / A07:2025)
# ---------------------------------------------------------------------------

def test_anonymous_user_cannot_add_comment(client, fixtures):
    """R3.1 / A07:2025 — unauthenticated comment POST redirects to /login."""
    r = client.post(f"/comment/add/{fixtures['photo']}",
                    data={"content": "drive-by"},
                    follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_anonymous_user_cannot_delete_comment(client, fixtures, app):
    """R3.1 / R3.6 / A07:2025 — unauthenticated delete redirects to /login."""
    with app.app_context():
        c = Comment(photo_id=fixtures["photo"],
                    user_id=fixtures["alice"],
                    content="hi")
        db.session.add(c); db.session.commit()
        cid = c.id
    r = client.post(f"/comment/{cid}/delete", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# ---------------------------------------------------------------------------
# Happy path  (R3.1, R3.2, R3.3, R3.4, R3.7)
# ---------------------------------------------------------------------------

def test_authenticated_user_can_add_comment(client, fixtures, app):
    """R3.1 / R3.2 / R3.4 — valid POST creates exactly one comment."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post(f"/comment/add/{fixtures['photo']}",
                    data={"content": "great photo"},
                    follow_redirects=False)
    assert r.status_code in (200, 302)
    with app.app_context():
        comments = Comment.query.filter_by(
            photo_id=fixtures["photo"], user_id=fixtures["alice"]
        ).all()
        assert len(comments) == 1
        assert comments[0].content == "great photo"


# ---------------------------------------------------------------------------
# Server-side input validation  (R3.4 / CWE-20)
# ---------------------------------------------------------------------------

def test_empty_comment_is_rejected(client, fixtures, app):
    """R3.4 / CWE-20 — blank comment text is rejected; no row inserted."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post(f"/comment/add/{fixtures['photo']}",
                    data={"content": "   "},  # whitespace only
                    follow_redirects=False)
    assert r.status_code in (200, 302, 400)
    with app.app_context():
        # No comment should have been created.
        assert Comment.query.count() == 0


def test_oversized_comment_is_rejected(client, fixtures, app):
    """R3.4 / CWE-20 — comments beyond 500 chars are rejected."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    huge = "x" * 1001
    r = client.post(f"/comment/add/{fixtures['photo']}",
                    data={"content": huge},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 400)
    with app.app_context():
        assert Comment.query.count() == 0


# ---------------------------------------------------------------------------
# Photo existence validation  (R3.2)
# ---------------------------------------------------------------------------

def test_comment_on_missing_photo_returns_404(client, fixtures, app):
    """R3.2 — cannot comment on a non-existent photo (returns 404)."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/comment/add/99999",
                    data={"content": "hi"},
                    follow_redirects=False)
    assert r.status_code == 404
    with app.app_context():
        assert Comment.query.count() == 0


# ---------------------------------------------------------------------------
# Authorisation: owner-or-admin delete  (R3.6 / A01:2025)
# ---------------------------------------------------------------------------

def test_user_can_delete_own_comment(client, fixtures, app):
    """R3.6 — author may delete their own comment."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    with app.app_context():
        c = Comment(photo_id=fixtures["photo"],
                    user_id=fixtures["alice"],
                    content="mine")
        db.session.add(c); db.session.commit()
        cid = c.id
    r = client.post(f"/comment/{cid}/delete", follow_redirects=False)
    assert r.status_code in (200, 302)
    with app.app_context():
        assert db.session.get(Comment, cid) is None


def test_user_cannot_delete_other_users_comment(client, fixtures, app):
    """R3.6 / A01:2025 — non-owner non-admin gets 403; comment retained."""
    with app.app_context():
        c = Comment(photo_id=fixtures["photo"],
                    user_id=fixtures["alice"],
                    content="alice's")
        db.session.add(c); db.session.commit()
        cid = c.id
    _login(client, "bob@example.com", "BobPassword2026!")
    r = client.post(f"/comment/{cid}/delete", follow_redirects=False)
    assert r.status_code == 403
    with app.app_context():
        assert db.session.get(Comment, cid) is not None


def test_admin_can_delete_any_comment(client, fixtures, app):
    """R3.6 — admin can delete any comment."""
    with app.app_context():
        c = Comment(photo_id=fixtures["photo"],
                    user_id=fixtures["alice"],
                    content="alice's")
        db.session.add(c); db.session.commit()
        cid = c.id
    _login(client, "admin@example.com", "AdminPassword2026!")
    r = client.post(f"/comment/{cid}/delete", follow_redirects=False)
    assert r.status_code in (200, 302)
    with app.app_context():
        assert db.session.get(Comment, cid) is None


def test_delete_missing_comment_returns_404(client, fixtures):
    """R3.6 — deleting a non-existent comment returns 404, no stack trace."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/comment/99999/delete")
    assert r.status_code == 404
    assert b"Traceback" not in r.data


# ---------------------------------------------------------------------------
# CSRF  (R3.3 / V7 / CWE-352)
# ---------------------------------------------------------------------------

def test_add_comment_without_csrf_token_is_rejected(tmp_path, fixtures=None):
    """R3.3 / CWE-352 — POST without CSRF token is rejected when CSRF is on."""
    upload_dir = tmp_path / "uploads"; upload_dir.mkdir()
    test_app = create_app(test_config={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "UPLOAD_DIR": str(upload_dir),
        "SECRET_KEY": "test-only-key",
        "WTF_CSRF_ENABLED": True,
        "RATELIMIT_ENABLED": False,
    })
    with test_app.app_context():
        db.create_all()
        u = User(email="csrf@example.com", username="csrfuser", is_admin=False)
        u.set_password("Strong-Password-2026!")
        p = Photo(name="t", caption="c", description="d",
                  file="t.jpg", owner_id=1)
        db.session.add_all([u]); db.session.commit()
        p.owner_id = u.id
        db.session.add(p); db.session.commit()
        photo_id = p.id

    c = test_app.test_client()
    c.post("/login", data={"email": "csrf@example.com",
                           "password": "Strong-Password-2026!"})
    r = c.post(f"/comment/add/{photo_id}", data={"content": "hi"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Output escaping  (R3.5 / V11 / CWE-79)
# ---------------------------------------------------------------------------

def test_comment_with_script_tag_is_escaped_on_render(client, fixtures, app):
    """R3.5 / CWE-79 — stored comment with <script> renders as HTML entities."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    payload = "<script>alert('xss')</script>"
    client.post(f"/comment/add/{fixtures['photo']}",
                data={"content": payload})
    r = client.get("/")
    body = r.data
    # The raw bytes should NOT be present; the escaped form should be.
    assert b"<script>alert('xss')</script>" not in body
    assert b"&lt;script&gt;" in body


# ---------------------------------------------------------------------------
# Rate limiting  (R3.8 / A07:2025 / CWE-770)
# ---------------------------------------------------------------------------

def test_rate_limit_caps_comment_creation(tmp_path, fixtures=None):
    """R3.8 / CWE-770 — 11th comment in one minute is rejected (HTTP 429)."""
    upload_dir = tmp_path / "uploads"; upload_dir.mkdir()
    test_app = create_app(test_config={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "UPLOAD_DIR": str(upload_dir),
        "SECRET_KEY": "test-only-key",
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": True,
    })
    with test_app.app_context():
        db.create_all()
        u = User(email="rate@example.com", username="rate", is_admin=False)
        u.set_password("Strong-Password-2026!")
        db.session.add(u); db.session.commit()
        p = Photo(name="t", caption="c", description="d",
                  file="t.jpg", owner_id=u.id)
        db.session.add(p); db.session.commit()
        photo_id = p.id

    c = test_app.test_client()
    c.post("/login", data={"email": "rate@example.com",
                           "password": "Strong-Password-2026!"})

    # Burst 10 successful comments.
    for i in range(10):
        c.post(f"/comment/add/{photo_id}", data={"content": f"c{i}"})
    # The 11th in the same minute must be throttled.
    r = c.post(f"/comment/add/{photo_id}", data={"content": "over"})
    assert r.status_code == 429
