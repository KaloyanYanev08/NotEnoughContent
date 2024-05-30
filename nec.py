from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, form
from flask_admin.contrib.sqla import ModelView
from wtforms import FileField, TextAreaField, SelectField
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'femboysAreHot'
app.config['UPLOAD_FOLDER'] = '.images/'

db = SQLAlchemy(app)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class Img(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    mimetype = db.Column(db.String(100))
    img = db.Column(db.LargeBinary)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))

    def __init__(self, name, mimetype, img, article_id):
        self.name = name
        self.mimetype = mimetype
        self.img = img
        self.article_id = article_id


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    access_id = db.Column(db.Integer, db.ForeignKey('access.id'), nullable=False)
    access = db.relationship('Access', backref='articles')
    picture = db.relationship('Img', uselist=False, backref='article')  # One-to-one relationship with Img

    def __init__(self, title, description, access_id, picture=None):
        self.title = title
        self.description = description
        self.access_id = access_id
        self.picture = picture

class Paragraph(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)

# Command: Save picture data
def save_picture_data(article, picture):
    if picture:
        filename = secure_filename(picture.filename)
        picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        img = Img(name=filename, mimetype=picture.mimetype, article_id=article.id)
        db.session.add(img)
        db.session.commit()

# Query: Get all access options
def get_all_access_options():
    return Access.query.all()

# Query: Get article by ID
def get_article_by_id(article_id):
    return Article.query.get(article_id)

# Create the database tables
with app.app_context():
    db.create_all()

# Initialize Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

class ArticleForm(form.BaseForm):
    description = TextAreaField('Description')
    access_id = SelectField('Access')

class ArticleView(ModelView):
    form_extra_fields = {
        'picture_data': FileField('Picture')
    }
    form_base_class = ArticleForm
    column_list = ('title', 'picture_data', 'description_id', 'access_id')

    def create_form(self, obj=None):
        form = super().create_form(obj)
        form.access_id.choices = [(a.id, a.name) for a in get_all_access_options()]
        return form

admin.add_view(ArticleView(Article, db.session))
admin.add_view(ModelView(Access, db.session))
admin.add_view(ModelView(Paragraph, db.session))

# Routes
@app.route('/')
def index():
    articles = Article.query.all()
    return render_template('index.html', articles=articles)

@app.route('/create_article', methods=['POST'])
def create_article():
    title = request.form['title']
    description = request.form['description']
    access_id = request.form['access_id']
    picture = request.files['picture_data']

    if not picture:
        return 'No picture uploaded', 400
    
    article = Article(title=title, description=description, access_id=access_id)
    db.session.add(article)
    db.session.commit()

    save_picture_data(article, picture)

    return 'Article created successfully!'

# Run
if __name__ == "__main__":
    app.run(debug=True)
