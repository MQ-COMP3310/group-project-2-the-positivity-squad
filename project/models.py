"""
Database models.

Part 2 (Authentication) changes:
- New User model with scrypt-hashed password (new Part-2 requirement).
- Photo.owner_id added to enable ownership-based authorisation (closes V5).

Sources:
- Werkzeug password hashing (scrypt with random salt):
  https://werkzeug.palletsprojects.com/en/3.0.x/utils/#module-werkzeug.security
- Flask-Login UserMixin: https://flask-login.readthedocs.io/en/latest/#your-user-class
"""
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db


class User(UserMixin, db.Model):
    """A registered user.

    Inherits UserMixin so Flask-Login can ask is_authenticated / get_id().
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    # SECURE (Part-2 requirement): only the password HASH is persisted.
    # Plaintext passwords are never stored. The 255-char column gives
    # room for the scrypt parameters + salt + hash.
    password_hash = db.Column(db.String(255), nullable=False)
    # SECURE (V5): admin flag is_admin gates the "admin can edit/delete
    # anything" behaviour. The /signup endpoint always sets this to False;
    # admins are created out-of-band by the seed script or by a manual
    # database update.
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    photos = db.relationship("Photo", backref="owner", lazy="dynamic")
    
    # SECURE (R3.2): allows comments to be traced back to creators.
    comments = db.relationship(
    "Comment",
    backref="author",
    lazy="dynamic"
)


    def set_password(self, password):
        # SECURE: werkzeug.security uses scrypt with a per-password random
        # salt by default. Never call this with an empty / None password.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Constant-time comparison via werkzeug.
        return check_password_hash(self.password_hash, password)
    
    


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    caption = db.Column(db.String(250), nullable=False)
    file = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(600), nullable=True)
    # SECURE (V5): every photo has exactly one owner. Authorisation in
    # main.py compares photo.owner_id with current_user.id, with an
    # admin bypass for users where is_admin == True.
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    
     # SECURE (R3.2): comments belong to photos and are removed when
     # the photo is deleted.
    comments = db.relationship(
    "Comment",
    backref="photo",
    lazy="dynamic",
    cascade="all, delete-orphan"
)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # SECURE (R3.2): every comment must belong to an existing photo.
    photo_id = db.Column(
        db.Integer,
        db.ForeignKey("photo.id"),
        nullable=False
    )

    # SECURE (R3.2): comments are associated with the authenticated
    # user that created them.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    # SECURE (R3.4 / CWE-20): comment length is restricted.
    content = db.Column(
        db.String(500),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )    

    @property
    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "caption": self.caption,
            "file": self.file,
            "desc": self.description,
            "owner_id": self.owner_id,
        }
