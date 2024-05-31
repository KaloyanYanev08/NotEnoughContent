from nec import db
from nec import app

with app.app_context():
    db.drop_all()
    db.create_all()