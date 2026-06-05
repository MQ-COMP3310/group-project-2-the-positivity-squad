# Flask Photo Gallery
**Main branch for marking: `main`**

A photo sharing web application built with Python and HTML/CSS. Alongside security analysis, the team developed the following features:
1. Authentication & Authorisation
2. Upvote/Downvote System
3. Photo Comment System

---

## Requirements

- Python 3.10.13 to 3.13.5 (Only have been tested and developed in these versions)
- pip
- sqlite3

---

## Setup

### 1. Create and activate a virtual environment

**macOS / Linux:**
```bash
python3 -m venv env
source env/bin/activate
```

**Windows:**
```powershell
python -m venv env
env\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Dependencies include: Flask, Flask-Login, Flask-WTF, Flask-Limiter, Flask-Talisman, SQLAlchemy, Werkzeug, Pillow, pytest, and email-validator.

---

## Database setup

Initialise (or reset) the database and seed it with sample data:

```bash
python initialise_db.py
```

### Default and seeded accounts
Feel free to use these sample accounts to tests the application.

| Role  | Email                  | Password              |
|-------|------------------------|-----------------------|
| Admin | admin@example.com      | ChangeMeAdmin2026!    |
| User  | alice@example.com      | ChangeMeAlice2026!    |


## Running the application

```bash
python run.py
```

Browse to [http://localhost:8000/](http://localhost:8000/).


## Running the tests

**Authentication & Authorisation**
```bash
pip install pytest
pytest -v tests/test_security.py
```

**Upvote/Downvote System**
```bash
pip install pytest
pytest -v tests/test_vote.py
```

**Photo Comments System**
```bash
pip install pytest
pytest -v tests/test_comments.py
```

---

# Usage

## As a guest (not logged in)
Browse to http://localhost:8000/ to view all photos and their comments

## As a regular user
- Click Sign Up to create an account, or Login with an existing one
- Click Upload to add a photo (JPEG, PNG, GIF + max 20 MB)
- Click Edit or Delete on any of your own photos to manage them
- Vote on any photo using the upvote (▲) or downvote (▼) buttons
- Post a comment on any photo using the comment form below it
- Delete any comment you authored using the delete button next to it
- Click Logout when done

## As an admin

- Log in with the seeded admin account (admin@example.com / ChangeMeAdmin2026!)
- Admins can edit or delete any user's photos
- Admins can delete any comment

---

# Project structure overview
You may reference the report to reference updated and changed lines/files (specifically Tables 15, 22, 23, 29 and 30) or previous commits.

```
.
├── project/
│   ├── __init__.py          # App factory: LoginManager, CSRF, Limiter, Talisman, cookies
│   ├── auth.py              # /signup, /login, /logout blueprint
│   ├── main.py              # Photo routes + Vote routes + Comment Routes
│   ├── models.py            # User (scrypt) + Photo + Vote + Comment ORM models
│   ├── forms.py             # Flask-WTF form classes with validators 
│   └── templates/
│       ├── index.html		# Photo + Vote + Comment UI
│       ├── login.html		# Login UI
│       ├── signup.html		# Sign Up UI
│       ├── upload.html
│       ├── edit.html
│       └── partials/
│           └── header.html
├── tests/
│   ├── __init__.py
│   └── test_comments.py     # Test photo comment system
│   └── test_security.py     # Test authentication & authorisation
│   └── test_vote.py			# Test vote
├── initialise_db.py
├── run.py
├── requirements.txt
├── TASK 7.md
├── ASSIGNMENT2_README.md
```


## References

- [Flask-Login](https://flask-login.readthedocs.io/)
- [Flask-WTF (CSRF)](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/)
- [Flask-Talisman](https://github.com/wntrblm/flask-talisman)
- [Flask-Limiter](https://flask-limiter.readthedocs.io/)
- [Werkzeug security utilities](https://werkzeug.palletsprojects.com/en/3.0.x/utils/)
- [Pillow](https://pillow.readthedocs.io/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)

---

## AI assistance

Implementation structure and security comments were drafted with assistance from Anthropic Claude. All suggestions were verified against the linked documentation and the project source code before being committed. No AI-generated code was used verbatim without verification.