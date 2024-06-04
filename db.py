from nec import db, app, create_superuser, create_default_accesses

with app.app_context():
    db.drop_all()
    db.create_all()
    create_default_accesses()