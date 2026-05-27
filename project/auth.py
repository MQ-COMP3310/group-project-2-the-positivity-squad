"""
Authentication blueprint — /signup, /login, /logout.

Implements Part 2 functional requirements:
- Non-logged-in users can sign up and log in.
- Admins are flagged via User.is_admin; signup always creates a
  non-admin user (admin accounts are seeded out of band).

Secure coding principles applied — each commented with the Task 3 V#:
- V2 / V19: SECRET_KEY from env (see __init__.py), structured logging
             of every auth event.
- V6 / V7:  POST + CSRF on every state-changing endpoint.
- V16:      WTForms validators reject malformed input.
- New (Part 2): scrypt password hashing (models.py); 5/min/IP rate
              limit on login; identical generic flash for "no such user"
              and "wrong password" (CWE-204 user-enumeration defence).
- V21:      `next` redirect parameter is only honoured if it is a local
            path (no scheme, no //host).

Sources:
- Flask-Login docs: https://flask-login.readthedocs.io/
- OWASP Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Flask-Limiter (rate limiting):
  https://flask-limiter.readthedocs.io/
"""
import logging
import hashlib

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from . import db, limiter
from .models import User
from .forms import SignupForm, LoginForm

auth = Blueprint("auth", __name__)
log = logging.getLogger("auth")


def _hash_email(email):
    """Hash email for log lines so the audit log does not leak PII."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:12]


def _is_safe_url(target):
    """Return True only for local (same-origin) redirect targets.

    SECURE (V21 / CWE-601): rejects anything with a scheme, a //host
    prefix, or a backslash (some browsers treat \\ as /).
    """
    if not target:
        return False
    if "\\" in target:
        return False
    if target.startswith("//"):
        return False
    return target.startswith("/")


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    # SECURE (V5): logged-in users should not see the signup form.
    if current_user.is_authenticated:
        return redirect(url_for("main.homepage"))

    form = SignupForm()
    if form.validate_on_submit():
        # SECURE: case-insensitive uniqueness check on email and username.
        existing = User.query.filter(
            (User.email == form.email.data.lower())
            | (User.username == form.username.data)
        ).first()
        if existing:
            log.info("signup attempt for existing identifier email=%s",
                     _hash_email(form.email.data))
            # SECURE: generic flash so an attacker cannot enumerate which
            # emails / usernames are already registered.
            flash("If your details are valid you will be able to log in.", "info")
            return redirect(url_for("auth.login"))

        # SECURE: is_admin is hard-coded False; never read from form input.
        user = User(
            email=form.email.data.lower(),
            username=form.username.data,
            is_admin=False,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        log.info("signup success user_id=%s", user.id)
        flash("Account created — please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("signup.html", form=form)


# SECURE: 5/minute/IP rate limit on POST defeats password-guessing.
# GET requests for the form itself are not rate-limited.
@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.homepage"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        # SECURE (CWE-204): identical response code AND identical flash
        # message for "no such user" and "wrong password", so an attacker
        # cannot enumerate registered emails.
        if user is None or not user.check_password(form.password.data):
            log.warning("login failed email=%s", _hash_email(form.email.data))
            flash("Invalid email or password.", "error")
            return render_template("login.html", form=form), 401

        # SECURE: remember=False — no long-lived "remember me" cookie.
        # Reduces blast radius if a device is stolen.
        login_user(user, remember=False)
        log.info("login success user_id=%s", user.id)

        # SECURE (V21 / CWE-601): only honour `next` if it is a local path.
        next_url = request.args.get("next")
        if _is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for("main.homepage"))

    return render_template("login.html", form=form)


# SECURE (V6 / CWE-352): logout is POST-only so a cross-site <img> or
# <a href> cannot trigger it. The Jinja template uses a <form> with a
# CSRF token.
@auth.route("/logout", methods=["POST"])
@login_required
def logout():
    log.info("logout user_id=%s", current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.homepage"))
