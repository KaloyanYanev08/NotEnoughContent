from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

#Initialize app and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)

#Define models (will change soon)
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return '<Task %r>' % self.id

#Create the database tables
with app.app_context():
    db.create_all()

#routes (links)
@app.route('/')
def index():
    return render_template('index.html')

#Run
if __name__ == "__main__":
    app.run(debug=True)
