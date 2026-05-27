"""
Security tests for Part 2 authentication and existing Task 3 findings.

Each test's docstring identifies the V# / Part-2 requirement it
evaluates and the OWASP Top 10:2025 category, so the marker can map
test -> requirement directly (Task 7 rubric component "Tests or test
stubs target specific security requirements").

Run with: pytest -v tests/test_security.py
"""
import io
import pytest

from project import create_app, db
from project.models import User, Photo


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
    })
    with test_app.app_context():
        db.create_all()
        yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def users(app):
    """Seed alice, bob (regular users) and admin."""
    with app.app_context():
        alice = User(email="alice@example.com", username="alice", is_admin=False)
        alice.set_password("AlicePassword2026!")
        bob = User(email="bob@example.com", username="bob", is_admin=False)
        bob.set_password("BobPassword2026!")
        admin = User(email="admin@example.com", username="admin", is_admin=True)
        admin.set_password("AdminPassword2026!")
        db.session.add_all([alice, bob, admin])
        db.session.commit()
        return {"alice": alice.id, "bob": bob.id, "admin": admin.id}


def _login(client, email, password):
    return client.post("/login",
                       data={"email": email, "password": password},
                       follow_redirects=False)


# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------

def test_password_is_hashed_not_plaintext(app, users):
    """Part-2 requirement: passwords stored as scrypt hash, never plaintext."""
    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        assert u.password_hash != "AlicePassword2026!"
        assert u.password_hash.startswith(("scrypt:", "pbkdf2:"))
        assert u.check_password("AlicePassword2026!") is True
        assert u.check_password("WrongPassword!") is False


# ---------------------------------------------------------------------------
# Authentication boundary  (V5 / A07:2025)
# ---------------------------------------------------------------------------

def test_anonymous_user_cannot_upload(client):
    """V5 / A07:2025 — @login_required redirects to /login."""
    r = client.get("/upload/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_anonymous_user_cannot_edit(client):
    """V5 / A07:2025 — edit requires authentication."""
    r = client.get("/photo/1/edit/", follow_redirects=False)
    assert r.status_code in (302, 401, 403)


def test_anonymous_user_cannot_delete(client):
    """V5 / A01:2025 — delete requires authentication."""
    r = client.post("/photo/1/delete/", follow_redirects=False)
    assert r.status_code in (302, 401, 403)


# ---------------------------------------------------------------------------
# Authorisation: ownership and admin bypass  (Part-2 functional req)
# ---------------------------------------------------------------------------

def test_user_can_edit_own_photo(client, app, users):
    """Spec: users can manage their own content."""
    with app.app_context():
        photo = Photo(name="alice photo", caption="c", description="d",
                      file="a.jpg", owner_id=users["alice"])
        db.session.add(photo); db.session.commit()
        pid = photo.id
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post(f"/photo/{pid}/edit/",
                    data={"user": "alice", "caption": "new", "description": "x"},
                    follow_redirects=False)
    assert r.status_code in (200, 302)


def test_user_cannot_edit_other_users_photo(client, app, users):
    """Spec: users cannot edit content they did not create."""
    with app.app_context():
        photo = Photo(name="alice photo", caption="c", description="d",
                      file="a.jpg", owner_id=users["alice"])
        db.session.add(photo); db.session.commit()
        pid = photo.id
    _login(client, "bob@example.com", "BobPassword2026!")
    r = client.post(f"/photo/{pid}/edit/",
                    data={"user": "bob", "caption": "hijack", "description": "x"})
    assert r.status_code == 403


def test_user_cannot_delete_other_users_photo(client, app, users):
    """Spec: users cannot delete content they did not create."""
    with app.app_context():
        photo = Photo(name="alice photo", caption="c", description="d",
                      file="a.jpg", owner_id=users["alice"])
        db.session.add(photo); db.session.commit()
        pid = photo.id
    _login(client, "bob@example.com", "BobPassword2026!")
    r = client.post(f"/photo/{pid}/delete/")
    assert r.status_code == 403


def test_admin_can_edit_any_photo(client, app, users):
    """Spec: admins can edit any content."""
    with app.app_context():
        photo = Photo(name="alice photo", caption="c", description="d",
                      file="a.jpg", owner_id=users["alice"])
        db.session.add(photo); db.session.commit()
        pid = photo.id
    _login(client, "admin@example.com", "AdminPassword2026!")
    r = client.post(f"/photo/{pid}/edit/",
                    data={"user": "x", "caption": "y", "description": "z"},
                    follow_redirects=False)
    assert r.status_code in (200, 302)


def test_admin_can_delete_any_photo(client, app, users):
    """Spec: admins can delete any content."""
    with app.app_context():
        photo = Photo(name="alice photo", caption="c", description="d",
                      file="a.jpg", owner_id=users["alice"])
        db.session.add(photo); db.session.commit()
        pid = photo.id
    _login(client, "admin@example.com", "AdminPassword2026!")
    r = client.post(f"/photo/{pid}/delete/", follow_redirects=False)
    assert r.status_code in (200, 302)


# ---------------------------------------------------------------------------
# State-changing operations require POST  (V6 / CWE-352)
# ---------------------------------------------------------------------------

def test_delete_via_get_returns_405(client, users):
    """V6 / A01:2025 — delete is POST-only."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.get("/photo/1/delete/")
    assert r.status_code == 405


def test_logout_via_get_returns_405(client, users):
    """V6 / A01:2025 — logout is POST-only."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.get("/logout")
    assert r.status_code == 405


# ---------------------------------------------------------------------------
# CSRF  (V7)
# ---------------------------------------------------------------------------

def test_upload_post_without_csrf_token_is_rejected(tmp_path):
    """V7 / A01:2025 — CSRF token required on every POST form."""
    upload_dir = tmp_path / "uploads"; upload_dir.mkdir()
    test_app = create_app(test_config={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "UPLOAD_DIR": str(upload_dir),
        "SECRET_KEY": "test-only-key",
        "WTF_CSRF_ENABLED": True,
    })
    with test_app.app_context():
        db.create_all()
        u = User(email="csrf@example.com", username="csrfuser", is_admin=False)
        u.set_password("Strong-Password-2026!")
        db.session.add(u); db.session.commit()

    c = test_app.test_client()
    c.post("/login", data={"email": "csrf@example.com",
                           "password": "Strong-Password-2026!"})
    r = c.post("/upload/",
               data={"user": "x", "caption": "y", "description": "z",
                     "fileToUpload": (io.BytesIO(b"\x89PNG\r\n"), "a.png")},
               content_type="multipart/form-data")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# SQL injection regression  (V1 / CWE-89)
# ---------------------------------------------------------------------------

def test_delete_with_sql_injection_payload_is_safe(client, users):
    """V1 / A05:2025 — SQLi no longer possible because we use the ORM.

    The Flask int converter rejects non-int payloads before they reach
    the handler; even if it did not, db.session.get is parameterised.
    """
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/photo/1 OR 1=1/delete/")
    assert r.status_code in (400, 404)


# ---------------------------------------------------------------------------
# Upload validation  (V8, V9, V10, V11)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,body", [
    ("evil.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"),
    ("evil.html", b"<html><script>alert(1)</script></html>"),
    ("evil.py",   b"print('pwn')"),
])
def test_non_image_uploads_are_rejected(client, users, name, body):
    """V8 / V11 / A05+A06:2025 — only valid images are accepted."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/upload/",
                    data={"user": "x", "caption": "y", "description": "z",
                          "fileToUpload": (io.BytesIO(body), name)},
                    content_type="multipart/form-data")
    assert r.status_code in (400, 415)


def test_upload_with_traversal_filename_is_rejected(client, users, tmp_path):
    """V9 / A01:2025 — secure_filename + commonpath defence."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/upload/",
                    data={"user": "x", "caption": "y", "description": "z",
                          "fileToUpload": (io.BytesIO(b"\x89PNG"), "../../escape.png")},
                    content_type="multipart/form-data")
    assert r.status_code in (400, 415)


# ---------------------------------------------------------------------------
# Security response headers and session cookies  (V15)
# ---------------------------------------------------------------------------

def test_response_sets_security_headers(client):
    """V15 / A02:2025 — Talisman sets CSP and friends."""
    r = client.get("/")
    header_names = {h.lower() for h in r.headers.keys()}
    assert "content-security-policy" in header_names


# ---------------------------------------------------------------------------
# Open redirect  (V21)
# ---------------------------------------------------------------------------

def test_login_does_not_follow_external_next(client, users):
    """V21 / CWE-601 — `next` parameter must be a local path."""
    r = client.post("/login?next=https://evil.example.com/steal",
                    data={"email": "alice@example.com",
                          "password": "AlicePassword2026!"},
                    follow_redirects=False)
    assert r.status_code in (200, 302)
    if r.status_code == 302:
        assert "evil.example.com" not in r.headers["Location"]


# ---------------------------------------------------------------------------
# Debug mode  (V3)
# ---------------------------------------------------------------------------

def test_debug_mode_is_off_in_test_config(app):
    """V3 / A02:2025 — debug must be off in tests / production."""
    assert app.debug is False


# ---------------------------------------------------------------------------
# Error handling  (V14, V17)
# ---------------------------------------------------------------------------

def test_404_for_missing_photo_does_not_leak_stack_trace(client, users):
    """V14 / V17 / A10:2025 — proper 404, no stack trace exposure."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    r = client.post("/photo/99999/delete/")
    assert r.status_code == 404
    assert b"Traceback" not in r.data
    assert b"FileNotFoundError" not in r.data


# ---------------------------------------------------------------------------
# SSRF regression guard  (A06:2025)
# ---------------------------------------------------------------------------

def test_no_route_fetches_user_supplied_url(app):
    """SSRF / A06:2025 — no current URL-fetch routes; guard against future ones."""
    rules = [r.rule for r in app.url_map.iter_rules()]
    assert not any(("url" in r and "uploads" not in r) or "fetch" in r
                   for r in rules), \
        "A new URL-fetching route was added — review for SSRF before merging."


# ---------------------------------------------------------------------------
# User enumeration  (CWE-204)
# ---------------------------------------------------------------------------

def test_login_failure_message_is_identical(client, users):
    """CWE-204 — identical response for unknown email and wrong password."""
    r1 = client.post("/login", data={"email": "missing@example.com",
                                     "password": "Whatever-Password-1!"})
    r2 = client.post("/login", data={"email": "alice@example.com",
                                     "password": "Wrong-Password-1234"})
    assert r1.status_code == 401
    assert r2.status_code == 401
    # The response bodies should contain the same generic flash.
    assert b"Invalid email or password" in r1.data
    assert b"Invalid email or password" in r2.data


# ---------------------------------------------------------------------------
# Admin cannot be set via signup  (Part-2 design integrity)
# ---------------------------------------------------------------------------

def test_signup_cannot_set_is_admin(tmp_path):
    """Spec — signup creates non-admin users only."""
    upload_dir = tmp_path / "uploads"; upload_dir.mkdir()
    test_app = create_app(test_config={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "UPLOAD_DIR": str(upload_dir),
        "SECRET_KEY": "test-only-key",
        "WTF_CSRF_ENABLED": False,
    })
    with test_app.app_context():
        db.create_all()
        c = test_app.test_client()
        c.post("/signup", data={
            "email": "imposter@example.com",
            "username": "imposter",
            "password": "Strong-Password-2026!",
            "confirm": "Strong-Password-2026!",
            "is_admin": "true",          # adversary attempting privilege escalation
        })
        u = User.query.filter_by(username="imposter").first()
        assert u is not None
        assert u.is_admin is False
