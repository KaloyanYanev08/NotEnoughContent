from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, form
from flask_admin.contrib.sqla import ModelView
from wtforms import FileField, TextAreaField, SelectField

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'femboysAreHot'
db = SQLAlchemy(app)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    picture_data = db.Column(db.LargeBinary, nullable=False)
    access_id = db.Column(db.Integer, db.ForeignKey('access.id'), nullable=False)
    paragraphs = db.relationship('Paragraph', backref='article', lazy=True)

class Paragraph(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)

# Command: Save picture data
def save_picture_data(article, picture):
    if picture:
        picture_data = picture.read()
        article.picture_data = picture_data



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
        description_id = TextAreaField('Description')
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
    access_id = request.form['access_id']
    picture = request.files['picture_data']

    article = Article(title=title, access_id=access_id)

    save_picture_data(article, picture)

    db.session.add(article)
    db.session.commit()

    return 'Article created successfully!'

#Run
if __name__ == "__main__":
    app.run(debug=True)
