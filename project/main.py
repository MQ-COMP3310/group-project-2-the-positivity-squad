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
from sqlalchemy import asc

from . import db
from .models import Photo, Comment
from .forms import UploadForm, EditForm, CommentForm

# Pillow is imported lazily inside the handler so tests can run on a
# Python with no Pillow installed (in that case the upload tests skip).
try:
    from PIL import Image, UnidentifiedImageError
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

main = Blueprint("main", __name__)
log = logging.getLogger("main")


@main.route("/")
def homepage():
    """Public photo gallery.

    Anonymous access is allowed; the template hides the edit / delete
    icons for non-owners (UI defence). The backend repeats the
    authorisation check on every edit / delete request — the client is
    never trusted.
    """
    photos = db.session.query(Photo).order_by(asc(Photo.file))
    return render_template("index.html", photos=photos)



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

@main.route("/comment/add/<int:photo_id>", methods=["POST"])
@login_required
def addComment(photo_id):
    """Add a comment to a photo."""

    photo = db.session.get(Photo, photo_id)

    if photo is None:
        abort(404)

    form = CommentForm()

    # SECURE (R3.4): server-side validation.
    if form.validate_on_submit():

        comment = Comment(
            photo_id=photo.id,
            user_id=current_user.id,
            content=form.content.data
        )

        db.session.add(comment)
        db.session.commit()

        flash("Comment added.", "success")

    return redirect(url_for("main.homepage"))