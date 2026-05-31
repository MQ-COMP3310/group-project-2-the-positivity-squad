"""
Flask-WTF form classes for server-side input validation.

Each form's validators close finding V16 (Improper Input Validation,
CWE-20) by enforcing length, type, and required-field constraints at the
request boundary. Invalid input becomes a 400 response with a re-rendered
form, not a 500 KeyError.

Source: https://flask-wtf.readthedocs.io/en/1.2.x/
"""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp


class SignupForm(FlaskForm):
    """Sign-up form. Always creates a non-admin user."""

    # SECURE (V16): server-side validation cannot be bypassed by editing
    # the HTML form. Email validator requires the `email-validator` pkg.
    email = StringField("Email", validators=[
        DataRequired(),
        Email(),
        Length(max=120),
    ])
    username = StringField("Username", validators=[
        DataRequired(),
        Length(min=3, max=50),
        # SECURE: restrict username characters. Defends against log forging
        # (newline injection into log lines) and visually-deceptive
        # usernames (homoglyph attacks on the admin panel).
        Regexp(r"^[A-Za-z0-9_]+$",
               message="Username may contain letters, numbers and underscores only."),
    ])
    # SECURE (Part-2 req): 12-character minimum password length, in line
    # with OWASP ASVS L1. Long-enough passwords beat hash-cracking even
    # without strict complexity rules. EqualTo checks the confirmation
    # field to defend against typos.
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=12, max=128,
               message="Password must be 12 to 128 characters."),
    ])
    confirm = PasswordField("Confirm password", validators=[
        DataRequired(),
        EqualTo("password", message="Passwords must match."),
    ])
    submit = SubmitField("Sign up")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
        DataRequired(),
        Email(),
        Length(max=120),
    ])
    # No length validator here — we deliberately accept any password so
    # the timing / response for "no such user" matches "wrong password"
    # exactly (CWE-204 user-enumeration defence).
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class UploadForm(FlaskForm):
    # SECURE (V8 / CWE-434): whitelist file extensions at the form layer.
    # Pillow magic-byte verification in the handler is a second line of
    # defence in case an attacker bypasses this with a renamed file.
    fileToUpload = FileField("Photo", validators=[
        FileRequired(),
        FileAllowed(["jpg", "jpeg", "png", "webp"],
                    "Only JPG, PNG or WEBP images are allowed."),
    ])
    user = StringField("User", validators=[
        DataRequired(), Length(max=50),
    ])
    caption = StringField("Caption", validators=[
        DataRequired(), Length(max=250),
    ])
    description = TextAreaField("Description", validators=[
        DataRequired(), Length(max=600),
    ])
    submit = SubmitField("Upload")


class EditForm(FlaskForm):
    user = StringField("User", validators=[
        DataRequired(), Length(max=50),
    ])
    caption = StringField("Caption", validators=[
        DataRequired(), Length(max=250),
    ])
    description = TextAreaField("Description", validators=[
        DataRequired(), Length(max=600),
    ])
    submit = SubmitField("Save")

class CommentForm(FlaskForm):
    """Photo comment submission form."""

    # SECURE (R3.4 / CWE-20): validates comment input and limits
    # comment length.
    content = TextAreaField("Comment", validators=[
        DataRequired(),
        Length(min=1, max=500),
    ])

    submit = SubmitField("Post Comment") 