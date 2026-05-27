"""
Initialise database for Part 2 — seeds an admin and a regular user,
then assigns all sample photos to the regular user.

Run with: python initialise_db.py

Creates two accounts:
- admin@example.com / ChangeMeAdmin2026! (is_admin=True)
- alice@example.com / ChangeMeAlice2026! (is_admin=False)

SECURE: the passwords here are placeholders for local development only.
For any deployment, change them via the application or by running an
out-of-band password reset. Never commit real credentials.
"""
from project import db, create_app
from project.models import User, Photo


def populate_db():
    # Admin account — created out of band, NOT through /signup which
    # always sets is_admin=False.
    admin = User(email="admin@example.com", username="admin", is_admin=True)
    admin.set_password("ChangeMeAdmin2026!")
    db.session.add(admin)

    alice = User(email="alice@example.com", username="alice", is_admin=False)
    alice.set_password("ChangeMeAlice2026!")
    db.session.add(alice)

    db.session.commit()

    seed = [
        ("William Warby", "Gentoo penguin",
         "A penguin with an orange beak standing next to a rock.",
         "william-warby-_A_vtMMRLWM.jpg"),
        ("Javier Patino Loira", "Common side-blotched lizard",
         "A close up of a lizard on a rock.",
         "javier-patino-loira-nortqDjv7ak.jpg"),
        ("Jordie Rubies", "Griffin vulture flying",
         "A large bird flying through a blue sky.",
         "jordi-rubies-2wNkdL2oIyU.jpg"),
        ("Jakub Neskora", "Jaguar",
         "A close up of a leopard near a rock.",
         "jakub-neskora-jloJvr74Fcc.jpg"),
        ("William Warby", "Japanese macaque",
         "A monkey sitting on top of a wooden post.",
         "william-warby-ndWikw_TPfc.jpg"),
        ("Ahmed Ali", "Berlin",
         "Oberbaumbrucke and the Berlin skyline.",
         "ahmed-ali-Zl7bVVMEfg.jpg"),
        ("Hanvin Cheong", "Nakano",
         "A group of people walking across a street.",
         "hanvin-cheong-9rBj8QYOL1Q.jpg"),
        ("Ekaterina Bogdan", "Bologna",
         "A bike parked next to a pole.",
         "ekaterina-bogdan-BKJWsGB5h1s.jpg"),
        ("Damian Ochrymowicz", "Nazare, Portugal",
         "Coastline.",
         "damian-ochrymowicz-GZQ7tKmEd9c.jpg"),
        ("Dima DallAcqua", "Alcatraz Island",
         "A close up of a green plant.",
         "dima-dallacqua-U8TAGVPFJc4.jpg"),
        ("Edgar", "Oporto, Portugal",
         "A man sitting on a bench at a train station.",
         "edgar-Q0g5Thf7Ank.jpg"),
    ]

    for name, caption, description, file in seed:
        db.session.add(Photo(
            name=name, caption=caption, description=description,
            file=file, owner_id=alice.id,
        ))
    db.session.commit()


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        populate_db()
        print("Database initialised.")
        print("  Admin: admin@example.com / ChangeMeAdmin2026!")
        print("  User:  alice@example.com / ChangeMeAlice2026!")
