# Task 7 — Authentication Implementation

This document explains the Part 2 / Task 7 changes and maps them to the
rubric components. Submit the file paths listed under "Code locations"
as the implementation evidence.

## What was added or changed

### New files
| Path | Purpose |
|---|---|
| `project/auth.py` | `/signup`, `/login`, `/logout` blueprint |
| `project/forms.py` | Flask-WTF form classes with validators |
| `project/templates/login.html` | Login page |
| `project/templates/signup.html` | Signup page |
| `tests/test_security.py` | 22 security tests with docstrings naming each requirement |
| `tests/__init__.py` | makes `tests/` a package |
| `TASK7_README.md` | this file |

### Modified files
| Path | What changed |
|---|---|
| `project/__init__.py` | LoginManager, CSRFProtect, Limiter, Talisman, secure cookies, env SECRET_KEY |
| `project/models.py` | New `User` model with scrypt password; `Photo.owner_id` foreign key |
| `project/main.py` | `@login_required`, ownership/admin checks, ORM-only, secure upload, POST-only delete |
| `project/templates/index.html` | Hide edit/delete from non-owners; delete uses POST form |
| `project/templates/partials/header.html` | Show login state + POST logout |
| `project/templates/upload.html` | Flask-WTF CSRF token + form fields |
| `project/templates/edit.html` | Flask-WTF CSRF token + form fields |
| `requirements.txt` | Added flask-wtf, flask-limiter, flask-talisman, Pillow, email-validator; bumped flask to 3.1.3 |
| `initialise_db.py` | Seeds admin + alice; photos owned by alice |

## How to run

```powershell
# from project root, with venv activated
pip install -r requirements.txt
python initialise_db.py     # drops + recreates DB, seeds admin + alice + photos
python run.py               # starts the app
```

Then browse to http://localhost:8000/ and:
- Click "Login" → log in as `alice@example.com` / `ChangeMeAlice2026!`
- Upload a photo
- Log out
- Log in as `admin@example.com` / `ChangeMeAdmin2026!` and verify you can edit/delete alice's content

To run the tests:

```powershell
pip install pytest
pytest -v tests/test_security.py
```

## Rubric mapping

| Rubric component | Marks | Where to find it |
|---|---|---|
| Implementation reflects design | /3 | Endpoints + ownership/admin logic in `auth.py` and `main.py`; matches the design summary in this README (and Task 5 once written) |
| Access-control rules implemented | /2 | `@login_required` on every state-changing route; ownership/admin check in `editPhoto` and `deletePhoto` (`main.py`) |
| Code comments identify secure principles | /2 | `# SECURE (V#)` comments throughout all `project/*.py` files |
| Tests target security requirements | /2 | `tests/test_security.py` — each test docstring names the V# / spec requirement |
| Sources, tools, GAIT cited | /1 | Module docstrings at the top of every `project/*.py` file cite Flask-Login, Flask-WTF, Werkzeug, Pillow, OWASP cheatsheets, and the Anthropic Claude assistance |

## Secure coding principles applied (with location in code)

| Principle | Where | Closes |
|---|---|---|
| `SECRET_KEY` from environment | `__init__.py` L37 | V2 |
| Password hashing (scrypt) | `models.py` `User.set_password` | New Part-2 req |
| Account lockout / rate limiting | `auth.py` `@limiter.limit("5 per minute")` | New Part-2 req |
| Generic auth error message | `auth.py` `login` | CWE-204 |
| Session fixation defence | `__init__.py` `session_protection="strong"` | New Part-2 req |
| Secure session cookies | `__init__.py` (Secure/HttpOnly/SameSite/Lifetime) | V15 |
| Security headers (CSP/HSTS/...) | `__init__.py` (Talisman) | V15 |
| CSRF on every POST form | `__init__.py` + every form template | V6, V7 |
| Authentication boundary | `@login_required` decorators | V5 |
| Authorisation: ownership/admin | `editPhoto`, `deletePhoto` in `main.py` | V5 + Part-2 req |
| ORM-only DB access | `main.py` (replaces raw `text(...)`) | V1 |
| POST-only state-changing ops | `main.py` and `auth.py` | V6 |
| Secure file upload (extension whitelist + Pillow verify) | `forms.py` `UploadForm` + `main.py` | V8 |
| `secure_filename` + UUID + `commonpath` | `main.py` `newPhoto` | V9, V12, V13 |
| Upload size cap | `__init__.py` `MAX_CONTENT_LENGTH = 5MB` | V10 |
| CSP defence-in-depth against XSS | `__init__.py` Talisman policy | V11 |
| Proper 404 + try/except | `main.py` `db.session.get(...) or abort(404)` | V14, V17 |
| Open redirect prevention | `auth.py` `_is_safe_url` + `redirect(url_for(...))` | V21 |
| Audit logging | `auth.py`, `main.py` (login, signup, upload, edit, delete) | V19 |
| Input validation at boundary | `forms.py` validators | V16 |
| Privilege escalation defence | `auth.py` signup: `is_admin=False` hard-coded | New Part-2 req |

## Sources cited (also in Task 3 References)

- Flask-Login: https://flask-login.readthedocs.io/
- Flask-WTF (CSRF): https://flask-wtf.readthedocs.io/en/1.2.x/csrf/
- Flask-Talisman: https://github.com/wntrblm/flask-talisman
- Flask-Limiter: https://flask-limiter.readthedocs.io/
- Werkzeug security: https://werkzeug.palletsprojects.com/en/3.0.x/utils/
- Pillow: https://pillow.readthedocs.io/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Top 10:2025: https://owasp.org/Top10/2025/

## AI assistance

Implementation structure and security comments were drafted with the
assistance of Anthropic Claude (model `claude-opus-4-7`). Every
suggestion was verified against the linked documentation and the
project source code before being committed. No AI-generated code was
used verbatim without verification.
