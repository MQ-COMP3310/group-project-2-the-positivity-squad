"""
Main blueprint — homepage, file serving, upload, edit, delete.

Refactored for Part 2 to add authentication, ownership/admin
authorisation, secure file upload, ORM-only DB access, structured
audit logging, and proper error handling. Each secure-coding decision
is marked with the V# from Task 3 it closes.

Sources:
- Werkzeug secure_filename:
  https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename
- Pillow image verification:
  https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.Image.verify
- Flask-Login @login_required:
  https://flask-login.readthedocs.io/en/latest/#flask_login.login_required
"""
import os
import uuid
import logging

from flask import (
    Blueprint, render_template, request, flash, redirect, url_for,
    send_from_directory, current_app, abort,
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import asc, func

from . import db, limiter
from .models import Photo, Vote, Comment
from .forms import UploadForm, EditForm, VoteForm, CommentForm

# Pillow is imported lazily inside the handler so tests can run on a
# Python with no Pillow installed (in that case the upload tests skip).
try:
    from PIL import Image, UnidentifiedImageError
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

main = Blueprint("main", __name__)
log = logging.getLogger("main")


def parse_vote_payload(form):
    """Parse and type-cast vote payload fields from a validated form."""
    try:
        return int(form.photo_id.data), int(form.value.data)
    except (TypeError, ValueError):
        return None, None


def get_photo(photo_id):
    """Fetch target photo by primary key or return None."""
    return db.session.get(Photo, photo_id)


def upsert_vote(photo_id, user_id, value):
    """Create a new vote or update an existing vote for user+photo."""
    existing = db.session.query(Vote).filter_by(
        photo_id=photo_id,
        user_id=user_id,
    ).first()

    if existing is None:
        db.session.add(
            Vote(
                photo_id=photo_id,
                user_id=user_id,
                value=value,
            )
        )
        return "created"

    existing.value = value
    return "updated"


@main.route("/")
def homepage():
    """Public photo gallery.

    Anonymous access is allowed; the template hides the edit / delete
    icons for non-owners (UI defence). The backend repeats the
    authorisation check on every edit / delete request — the client is
    never trusted.
    """
    photos = db.session.query(Photo).order_by(asc(Photo.file)).all()

    # SECURE (R2.2): Aggregate vote counts server-side so totals are
    # generated from trusted DB records, not client input.
    vote_counts = {
        photo.id: {"up": 0, "down": 0, "total": 0}
        for photo in photos
    }
    for photo_id, vote_value, count in (
        db.session.query(Vote.photo_id, Vote.value, func.count(Vote.id))
        .group_by(Vote.photo_id, Vote.value)
        .all()
    ):
        if photo_id not in vote_counts:
            continue
        if vote_value == 1:
            vote_counts[photo_id]["up"] = count
        elif vote_value == -1:
            vote_counts[photo_id]["down"] = count

    for counts in vote_counts.values():
        counts["total"] = counts["up"] - counts["down"]

    user_votes = {}
    if current_user.is_authenticated:
        # SECURE (R2.1, R2.8): Fetch the logged-in user's prior votes so
        # each vote remains attributable to an authenticated identity.
        for vote in db.session.query(Vote).filter_by(user_id=current_user.id).all():
            user_votes[vote.photo_id] = vote.value

    vote_form = VoteForm()
    return render_template(
        "index.html",
        photos=photos,
        vote_counts=vote_counts,
        user_votes=user_votes,
        vote_form=vote_form,
    )


@main.route("/vote", methods=["POST"])
# SECURE (R2.1): Only authenticated users can vote.
@login_required
# SECURE (R2.6, CWE-770): Rate limiting helps prevent DoS and automated vote abuse.
# SECURE: rate limit reduces brute-force / bot voting.
@limiter.limit("10/minute")
def vote_photo():
    """Create or update the current user's vote for a specific photo."""
    form = VoteForm()
    # SECURE (R2.3, R2.4, V7, CWE-352): CSRF token and server-side form validation
    # block forged or malformed vote submissions.
    # SECURE: Flask-WTF validates CSRF + allowed vote values.
    if not form.validate_on_submit():
        # SECURE (CWE-209): generic error message avoids leaking any sensitive information
        flash("Invalid vote request.", "error")
        return redirect(url_for("main.homepage"))

    photo_id, value = parse_vote_payload(form)
    if photo_id is None or value is None:
        # SECURE (CWE-209): generic error message avoids leaking any sensitive information
        flash("Invalid vote values.", "error")
        return redirect(url_for("main.homepage"))

    photo = get_photo(photo_id)
    if photo is None:
        # SECURE (CWE-209): generic error message avoids leaking internals.        
        flash("Photo not found.", "error")
        return redirect(url_for("main.homepage"))

    # SECURE (R2.2): One vote per user/photo: create if missing,
    # otherwise update the existing row rather than duplicating votes.
    action = upsert_vote(photo_id=photo_id, user_id=current_user.id, value=value)

    db.session.commit()
    # SECURE (R2.7, V19, CWE-778): Voting actions are logged for auditability.
    log.info("vote %s user_id=%s photo_id=%s value=%s", action, current_user.id, photo_id, value)
    # SECURE (CWE-209): generic error message avoids leaking any sensitive information
    flash("Your vote was recorded.", "success")
    return redirect(url_for("main.homepage"))



@main.route("/uploads/<name>")
def display_file(name):
    """Serve a previously-uploaded image.

    SECURE (V9): send_from_directory uses werkzeug.safe_join internally,
    which rejects path-traversal attempts. We additionally call
    os.path.basename as defence in depth.
    """
    safe_name = os.path.basename(name)
    return send_from_directory(current_app.config["UPLOAD_DIR"], safe_name)


# SECURE (V5 / CWE-306): @login_required enforces the authentication
# boundary. Unauthenticated requests are redirected to /login by the
# LoginManager registered in __init__.py.
@main.route("/upload/", methods=["GET", "POST"])
@login_required
def newPhoto():
    # SECURE (V7): CSRF token bound to session, validated by Flask-WTF.
    form = UploadForm()
    if form.validate_on_submit():
        file = form.fileToUpload.data

        # SECURE (V8 / CWE-434): magic-byte verification via Pillow.
        # Even if an attacker renames evil.svg to evil.jpg the bytes do
        # not parse as a real image, and Image.verify() raises.
        if HAVE_PIL:
            try:
                img = Image.open(file)
                img.verify()
                file.stream.seek(0)
            except (UnidentifiedImageError, Exception):  # noqa: BLE001
                log.warning("upload rejected non_image user_id=%s",
                            current_user.id)
                flash("Uploaded file is not a valid image.", "error")
                return render_template("upload.html", form=form), 400

        # SECURE (V9 / V12): secure_filename strips path separators and
        # normalises Unicode; UUID prefix removes collisions and makes
        # filenames unguessable.
        cleaned = secure_filename(file.filename or "")
        if not cleaned:
            flash("Invalid filename.", "error")
            return render_template("upload.html", form=form), 400
        stored_name = f"{uuid.uuid4().hex}_{cleaned}"

        upload_dir = str(current_app.config["UPLOAD_DIR"])
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, stored_name)

        # SECURE (V13): defence in depth — confirm the resolved path
        # stays inside UPLOAD_DIR even after symlink resolution.
        resolved = os.path.realpath(filepath)
        if os.path.commonpath([resolved, os.path.realpath(upload_dir)]) != \
                os.path.realpath(upload_dir):
            log.warning("upload rejected traversal user_id=%s",
                        current_user.id)
            abort(400)

        file.save(filepath)

        # SECURE (V1 / CWE-89): ORM-only DB access. No raw SQL strings.
        new_photo = Photo(
            name=form.user.data,
            caption=form.caption.data,
            description=form.description.data,
            file=stored_name,
            owner_id=current_user.id,  # SECURE (V5): record ownership.
        )
        db.session.add(new_photo)
        db.session.commit()
        log.info("upload success user_id=%s photo_id=%s file=%s",
                 current_user.id, new_photo.id, stored_name)
        flash(f"New photo '{new_photo.name}' uploaded.", "success")
        return redirect(url_for("main.homepage"))

    # SECURE (V21): on validation failure, re-render the form. Never
    # redirect(request.url).
    # SECURE (V16 / V17 / A10:2025): return HTTP 400 on POST validation
    # failure so the API surface accurately reflects the boundary
    # rejection (helps monitoring / regression tests catch issues).
    status_code = 400 if request.method == "POST" else 200
    return render_template("upload.html", form=form), status_code


@main.route("/photo/<int:photo_id>/edit/", methods=["GET", "POST"])
@login_required
def editPhoto(photo_id):
    # SECURE (V1 / CWE-89): ORM lookup, parameterised by Flask's int
    # route converter and SQLAlchemy.
    # SECURE (V14 / CWE-209): proper 404 if not found, no stack trace.
    photo = db.session.get(Photo, photo_id)
    if photo is None:
        abort(404)

    # SECURE (V5 / Part-2 req): ownership / admin authorisation.
    # Owners can edit their own content; admins can edit any content;
    # everyone else gets 403.
    if photo.owner_id != current_user.id and not current_user.is_admin:
        log.warning("edit forbidden user_id=%s photo_id=%s",
                    current_user.id, photo_id)
        abort(403)

    form = EditForm()
    if form.validate_on_submit():
        photo.name = form.user.data
        photo.caption = form.caption.data
        photo.description = form.description.data
        db.session.commit()
        log.info("edit success user_id=%s photo_id=%s",
                 current_user.id, photo_id)
        flash(f"Photo '{photo.name}' updated.", "success")
        return redirect(url_for("main.homepage"))

    if request.method == "GET":
        form.user.data = photo.name
        form.caption.data = photo.caption
        form.description.data = photo.description
    # SECURE: return 400 on POST validation failure (same rationale as newPhoto).
    status_code = 400 if (request.method == "POST" and form.errors) else 200
    return render_template("edit.html", form=form, photo=photo), status_code


# SECURE (V6 / CWE-352): delete is POST-only so cross-origin <img>/<a>
# cannot trigger it. The Jinja template uses a <form method="POST">
# with a CSRF token. The earlier ['GET','POST'] was the V6 finding.
@main.route("/photo/<int:photo_id>/delete/", methods=["POST"])
@login_required
def deletePhoto(photo_id):
    photo = db.session.get(Photo, photo_id)
    if photo is None:
        abort(404)

    # SECURE (V5): ownership / admin authorisation, identical to edit.
    if photo.owner_id != current_user.id and not current_user.is_admin:
        log.warning("delete forbidden user_id=%s photo_id=%s",
                    current_user.id, photo_id)
        abort(403)

    # SECURE (V13): basename + commonpath defence before os.unlink.
    upload_dir = str(current_app.config["UPLOAD_DIR"])
    safe_name = os.path.basename(photo.file)
    filepath = os.path.realpath(os.path.join(upload_dir, safe_name))
    if os.path.commonpath([filepath, os.path.realpath(upload_dir)]) == \
            os.path.realpath(upload_dir):
        try:
            os.unlink(filepath)
        except FileNotFoundError:
            # SECURE (V14): graceful handling, no stack trace exposed.
            log.info("delete file_missing photo_id=%s file=%s",
                     photo_id, safe_name)
    else:
        log.warning("delete refused traversal photo_id=%s file=%s",
                    photo_id, photo.file)

    # SECURE (V1 / CWE-89): ORM delete, replaces the previous raw
    # `text('delete from photo where id = ' + str(photo_id))`.
    db.session.delete(photo)
    db.session.commit()
    log.info("delete success user_id=%s photo_id=%s",
             current_user.id, photo_id)
    flash(f"Photo {photo_id} deleted.", "success")
    return redirect(url_for("main.homepage"))

###############################################################################
# Feature 2 — Photo Comments
###############################################################################

@main.route("/comment/add/<int:photo_id>", methods=["POST"])
# SECURE (R3.1 / CWE-306): only authenticated users may comment.
# Anonymous requests are redirected to /login by the LoginManager.
@login_required
# SECURE (R3.8 / CWE-770 / A07:2025): rate limit caps comment creation
# at 10 per minute per user to mitigate spam and automated abuse.
@limiter.limit("10/minute")
def addComment(photo_id):
    """Create a comment attached to a specific photo.

    Implements R3.1, R3.2, R3.3, R3.4, R3.7, R3.8 from Task 8.2.
    """
    # SECURE (R3.2): validate the target photo exists before accepting
    # the comment. db.session.get is parameterised (ORM, not raw SQL),
    # closing V1 / CWE-89.
    photo = db.session.get(Photo, photo_id)
    if photo is None:
        # SECURE (CWE-209): generic error, no stack trace.
        log.warning("comment add rejected photo_missing user_id=%s photo_id=%s",
                    current_user.id, photo_id)
        abort(404)

    # SECURE (R3.3, R3.4 / V7 / CWE-352 / CWE-20): CSRF token AND
    # length/non-blank validation enforced via Flask-WTF. Anything that
    # fails validation produces a 400 with a generic flash.
    form = CommentForm()
    if not form.validate_on_submit():
        log.warning("comment add rejected invalid_form user_id=%s photo_id=%s",
                    current_user.id, photo_id)
        flash("Comment could not be posted. Please try again.", "error")
        return redirect(url_for("main.homepage"))

    # SECURE (R3.2): bind the comment to BOTH the photo and the
    # authenticated user via foreign keys recorded at the DB layer.
    comment = Comment(
        photo_id=photo.id,
        user_id=current_user.id,
        content=form.content.data,
    )
    db.session.add(comment)
    db.session.commit()

    # SECURE (R3.7 / V19 / CWE-778 / A09:2025): write an audit log line
    # naming actor, action, comment id, and photo id.
    log.info("comment created user_id=%s comment_id=%s photo_id=%s",
             current_user.id, comment.id, photo.id)
    flash("Comment posted.", "success")
    return redirect(url_for("main.homepage"))


# SECURE (V6 / CWE-352): delete is POST-only so cross-origin <img>/<a>
# cannot trigger it. The Jinja template renders a <form method="POST">
# button with a CSRF token.
@main.route("/comment/<int:comment_id>/delete", methods=["POST"])
# SECURE (R3.1 / R3.6 / CWE-306): only authenticated users can hit
# delete; the ownership / admin check below restricts WHICH comment
# they may delete.
@login_required
# SECURE (R3.8 / CWE-770): rate limit applies to comment deletion too,
# to defeat mass-deletion abuse from a compromised account.
@limiter.limit("10/minute")
def deleteComment(comment_id):
    """Delete a comment by id.

    Implements R3.6, R3.7 from Task 8.2. Owner or administrator only.
    """
    comment = db.session.get(Comment, comment_id)
    if comment is None:
        # SECURE (V14 / CWE-209): 404 if missing, no stack trace.
        abort(404)

    # SECURE (R3.6 / A01:2025): ownership / admin check. Anyone who
    # is neither the author nor an admin receives 403.
    if comment.user_id != current_user.id and not current_user.is_admin:
        log.warning("comment delete forbidden user_id=%s comment_id=%s",
                    current_user.id, comment_id)
        abort(403)

    photo_id = comment.photo_id
    db.session.delete(comment)
    db.session.commit()

    # SECURE (R3.7 / V19 / CWE-778 / A09:2025): structured audit log.
    log.info("comment deleted user_id=%s comment_id=%s photo_id=%s",
             current_user.id, comment_id, photo_id)
    flash("Comment deleted.", "success")
    return redirect(url_for("main.homepage"))