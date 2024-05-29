from nec import db
from nec import app

with app.app_context():
    db.create_all()