"""
Database models.

Part 2 (Authentication) changes:
- New User model with scrypt-hashed password (new Part-2 requirement).
- Photo.owner_id added to enable ownership-based authorisation (closes V5).

Part 3 changes:
- Feature 1 (Upvote/Downvote): Vote model with UNIQUE constraint on
  (photo_id, user_id) — enforces R2.2 / R2.8 at the database layer.
- Feature 2 (Photo Comments): Comment model linking each comment to one
  user and one photo — enforces R3.1 / R3.2.

Sources:
- Werkzeug password hashing (scrypt with random salt):
  https://werkzeug.palletsprojects.com/en/3.0.x/utils/#module-werkzeug.security
- Flask-Login UserMixin: https://flask-login.readthedocs.io/en/latest/#your-user-class
- SQLAlchemy UniqueConstraint:
  https://docs.sqlalchemy.org/en/20/core/constraints.html#sqlalchemy.schema.UniqueConstraint
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
    # SECURE (R2.1, R2.8): vote belongs to an authenticated user; cascade
    # delete keeps the vote table consistent if the user is removed.
    votes = db.relationship(
        "Vote", backref="user", lazy="dynamic",
        cascade="all, delete-orphan",
    )
    # SECURE (R3.2): comments are traced back to their author. Cascade
    # delete keeps the comment table consistent if the user is removed.
    comments = db.relationship(
        "Comment", backref="author", lazy="dynamic",
        cascade="all, delete-orphan",
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
    # SECURE (R2.2): votes attached to a photo; cascade so a deleted
    # photo never leaves orphaned vote rows.
    votes = db.relationship(
        "Vote", backref="photo", lazy="dynamic",
        cascade="all, delete-orphan",
    )
    # SECURE (R3.2): comments belong to a photo; cascade so a deleted
    # photo never leaves orphaned comments.
    comments = db.relationship(
        "Comment", backref="photo", lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="Comment.created_at.asc()",
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


class Vote(db.Model):
    """A single authenticated user's vote on a photo (Feature 1)."""

    # SECURE (R2.1, R2.2, R2.8): Each vote is associated with an
    # authenticated user, making votes traceable.
    id = db.Column(db.Integer, primary_key=True)
    photo_id = db.Column(
        db.Integer, db.ForeignKey("photo.id"),
        nullable=False, index=True,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"),
        nullable=False, index=True,
    )
    # 1 for upvote, -1 for downvote. Server validates value via AnyOf().
    value = db.Column(db.Integer, nullable=False)
    # SECURE (R2.2): database-level UNIQUE constraint guarantees one
    # vote per (photo, user). Application code may still race-update,
    # but the DB will reject any insert that would duplicate.
    __table_args__ = (
        db.UniqueConstraint(
            "photo_id", "user_id",
            name="unique_vote_per_user_per_photo",
        ),
    )


class Comment(db.Model):
    """A single comment posted by an authenticated user on a photo (Feature 2)."""

    id = db.Column(db.Integer, primary_key=True)
    # SECURE (R3.2): every comment must belong to an existing photo.
    photo_id = db.Column(
        db.Integer, db.ForeignKey("photo.id"),
        nullable=False, index=True,
    )
    # SECURE (R3.2): comments are associated with the authenticated
    # user that created them — provides non-repudiation.
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"),
        nullable=False, index=True,
    )
    # SECURE (R3.4 / CWE-20): comment length is hard-capped at the
    # column level. The form layer enforces the same limit at validate.
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False,
    )
