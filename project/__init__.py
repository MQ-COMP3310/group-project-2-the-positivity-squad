"""
Flask application factory — Part 2 (Authentication) implementation.

This file wires together Flask-Login, Flask-WTF (CSRF), Flask-Talisman
(security headers), and Flask-Limiter (rate limiting), and configures
secure session cookies. Each secure-coding decision is tagged with the
V# from Task 3 it closes.

Sources cited (also in the Task 3 References list):
- Flask-Login docs: https://flask-login.readthedocs.io/
- Flask-WTF CSRF:    https://flask-wtf.readthedocs.io/en/1.2.x/csrf/
- Flask-Talisman:    https://github.com/wntrblm/flask-talisman
- Flask-Limiter:     https://flask-limiter.readthedocs.io/
- Werkzeug security: https://werkzeug.palletsprojects.com/en/3.0.x/utils/

AI assistance: structure and security comments drafted with Anthropic
Claude (claude-opus-4-7) and verified against the linked documentation
before commit.
"""
import os
import logging
from datetime import timedelta
from pathlib import Path

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])


def create_app(test_config=None):
    app = Flask(__name__)

    # SECURE (V2 / CWE-798): SECRET_KEY loaded from environment, not hard-coded.
    # The fallback is for local dev only; CI and production MUST export
    # SECRET_KEY. A real deployment would refuse to start if it is missing.
    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "dev-only-replace-in-prod-" + os.urandom(8).hex()
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///photos.db"
    CWD = Path(os.path.dirname(__file__))
    app.config["UPLOAD_DIR"] = CWD / "uploads"

    # SECURE (V10 / CWE-770): cap upload size. Werkzeug rejects with 413
    # Payload Too Large before reading the body fully, bounding memory.
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

    # SECURE (V15 / CWE-614): session cookie hardening.
    # Secure=True requires HTTPS — kept True in production; False in dev
    # so cookies still work over http://localhost.
    app.config["SESSION_COOKIE_SECURE"] = not app.debug
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

    # SECURE: explicit Cache-Control on responses (partially addresses
    # CVE-2026-27205 conditions — see Task 3 3(b)).
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    if test_config is not None:
        app.config.update(test_config)

    db.init_app(app)
    # SECURE (V7 / CWE-352): CSRF tokens enforced on every POST form.
    csrf.init_app(app)
    limiter.init_app(app)

    # SECURE (V15 / CWE-1021): security response headers via Flask-Talisman.
    # CSP defends against any residual XSS (V11). HSTS forces HTTPS in prod.
    # Talisman is optional at import time so tests can run without it.
    try:
        from flask_talisman import Talisman
        Talisman(
            app,
            content_security_policy={
                "default-src": "'self'",
                "script-src": "'self'",
                "style-src": "'self' 'unsafe-inline'",
                "img-src": "'self' data:",
                "object-src": "'none'",
                "base-uri": "'none'",
                "frame-ancestors": "'none'",
            },
            force_https=not app.debug and not app.testing,
            strict_transport_security=True,
            session_cookie_secure=not app.debug,
            referrer_policy="same-origin",
        )
    except ImportError:
        app.logger.warning("flask-talisman not installed; security headers not set")

    # SECURE (V5 / CWE-306): unauthenticated requests to @login_required
    # routes are redirected to /login by the LoginManager.
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"
    # SECURE: session protection — Flask-Login regenerates session token
    # on login, mitigating session fixation.
    login_manager.session_protection = "strong"

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # SECURE (V1): db.session.get is parameterised (ORM, not raw SQL).
        return db.session.get(User, int(user_id))

    # Register blueprints.
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # SECURE (V19 / A09:2025 / CWE-778): structured logging.
    # Auth events, uploads, edits, deletes, and authorization failures
    # are recorded by the blueprints with actor, action, and outcome.
    if not app.testing:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        )

    return app
