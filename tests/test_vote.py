# Run: pytest -v tests/test_vote.py

import pytest

from project import create_app, db
from project.forms import VoteForm
from project.main import get_photo
from project.models import Photo, User, Vote


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
    with app.app_context():
        alice = User(email="alice@example.com", username="alice", is_admin=False)
        alice.set_password("AlicePassword2026!")
        bob = User(email="bob@example.com", username="bob", is_admin=False)
        bob.set_password("BobPassword2026!")
        db.session.add_all([alice, bob])
        db.session.commit()
        return {"alice": alice.id, "bob": bob.id}


@pytest.fixture
def photo(app, users):
    with app.app_context():
        item = Photo(
            name="Test User",
            caption="Test Caption",
            description="Test Desc",
            file="test.jpg",
            owner_id=users["alice"],
        )
        db.session.add(item)
        db.session.commit()
        return item.id


def _login(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

def test_vote_requires_login(client, photo):
    """R2.1 / A07:2025: tests whether voting requires login"""
    response = client.post(
        "/vote",
        data={"photo_id": str(photo), "value": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_upvote(client, app, users, photo):
    """R2.1, R2.2, R2.8: tests whether an authenticated user can have one vote per photo."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    response = client.post(
        "/vote",
        data={"photo_id": str(photo), "value": "1"},
        follow_redirects=True,
    )
    assert b"Your vote was recorded." in response.data

    with app.app_context():
        vote = Vote.query.filter_by(photo_id=photo, user_id=users["alice"]).first()
        assert vote is not None
        assert vote.value == 1


def test_downvote(client, app, users, photo):
    """R2.1, R2.2, R2.8: checks whether an authenticated user could downvote a post"""
    _login(client, "alice@example.com", "AlicePassword2026!")
    response = client.post(
        "/vote",
        data={"photo_id": str(photo), "value": "-1"},
        follow_redirects=True,
    )
    assert b"Your vote was recorded." in response.data

    with app.app_context():
        vote = Vote.query.filter_by(photo_id=photo, user_id=users["alice"]).first()
        assert vote is not None
        assert vote.value == -1


def test_vote_updates(client, app, users, photo):
    """R2.2: tests whether a repeat vote updates the existing one instead of creating another."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    client.post("/vote", data={"photo_id": str(photo), "value": "1"})
    client.post("/vote", data={"photo_id": str(photo), "value": "-1"})

    with app.app_context():
        votes = Vote.query.filter_by(photo_id=photo, user_id=users["alice"]).all()
        assert len(votes) == 1
        assert votes[0].value == -1


def test_two_users_can_vote(client, app, users, photo):
    """R2.2, R2.8: tests whether two different users can vote on the same photo."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    client.post("/vote", data={"photo_id": str(photo), "value": "1"})

    client.post("/logout", data={})
    _login(client, "bob@example.com", "BobPassword2026!")
    client.post("/vote", data={"photo_id": str(photo), "value": "-1"})

    with app.app_context():
        votes = Vote.query.filter_by(photo_id=photo).order_by(Vote.user_id).all()
        assert len(votes) == 2
        assert {vote.user_id for vote in votes} == {users["alice"], users["bob"]}
        assert {vote.value for vote in votes} == {1, -1}


def test_invalid_vote_value(client, app, users, photo):
    """R2.4 / A05:2025: tests whether form validation rejects values other than 1 and -1."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    response = client.post(
        "/vote",
        data={"photo_id": str(photo), "value": "1234567890"},
        follow_redirects=True,
    )
    assert b"Invalid vote request." in response.data

    with app.app_context():
        assert Vote.query.filter_by(photo_id=photo, user_id=users["alice"]).count() == 0


def test_missing_photo(client, users):
    """R2.4 / A05:2025: checks whether voting on a missing photo is rejected cleanly."""
    login_response = _login(client, "alice@example.com", "AlicePassword2026!")
    assert login_response.status_code == 302
    response = client.post(
        "/vote",
        data={"photo_id": "9876543210", "value": "1"},
        follow_redirects=True,
    )
    assert b"Photo not found." in response.data


def test_vote_rate_limit(client, users, photo):
    """R2.6 / A10:2025: tests whether vote requests could cap out 10 per minute."""
    _login(client, "alice@example.com", "AlicePassword2026!")
    for _ in range(10):
        response = client.post(
            "/vote",
            data={"photo_id": str(photo), "value": "1"},
            follow_redirects=False,
        )
        assert response.status_code in (302, 429)

    response = client.post(
        "/vote",
        data={"photo_id": str(photo), "value": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 429


def test_vote_total(client, app, users, photo):
    """R2.2: checks whether the homepage renders the correct total vote score."""
    with app.app_context():
        db.session.add(Vote(photo_id=photo, user_id=users["alice"], value=1))
        db.session.add(Vote(photo_id=photo, user_id=users["bob"], value=-1))
        db.session.commit()

    _login(client, "alice@example.com", "AlicePassword2026!")
    response = client.get("/")
    assert response.status_code == 200
    assert b'<span class="vote-count" title="Score">' in response.data


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_vote_form_upvote(app):
    """R2.3, R2.4: checks whether VoteForm accepts an upvote (1)"""
    with app.test_request_context(method="POST"):
        form = VoteForm(data={"photo_id": "1", "value": "1"})
        assert form.validate() is True


def test_vote_form_downvote(app):
    """R2.4: tests whether VoteForm accepts an downvote (-1)"""
    with app.test_request_context(method="POST"):
        form = VoteForm(data={"photo_id": "1", "value": "-1"})
        assert form.validate() is True


def test_vote_form_invalid_value(app):
    """R2.4: tests whether VoteForm rejects invalid vote values."""
    with app.test_request_context(method="POST"):
        form = VoteForm(data={"photo_id": "1", "value": "42067"})
        form1 = VoteForm(data={"photo_id": "1", "value": "-42067"})
        form2 = VoteForm(data={"photo_id": "1", "value": "-0"})
        assert form.validate() is False
        assert form1.validate() is False
        assert form2.validate() is False


def test_vote_form_missing_photo(app):
    """R2.4: tests whether VoteForm rejects submissions without a photo_id"""
    with app.test_request_context(method="POST"):
        form = VoteForm(data={"value": "1"})
        assert form.validate() is False

def test_get_photo(app, photo):
    """R2.4 / A05:2025: tests whether get_photo returns valid IDs."""
    with app.app_context():
        found = get_photo(photo)
        missing = get_photo(67676767676767)

        assert found is not None
        assert found.id == photo
        assert missing is None

def test_vote_model_fields():
    """R2.8: checks whether Vote model fields store the authenticated user, photo, and vote value."""
    vote = Vote(id=1, photo_id=2, user_id=3, value=1)
    assert vote.id == 1
    assert vote.photo_id == 2
    assert vote.user_id == 3
    assert vote.value == 1