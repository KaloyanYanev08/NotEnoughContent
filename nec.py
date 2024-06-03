from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from wtforms import FileField, TextAreaField, SelectField, StringField, Form
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'femboysAreHot'

db = SQLAlchemy(app)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class Img(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    mimetype = db.Column(db.String(100))
    img_base64 = db.Column(db.Text)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))

    def __init__(self, name, mimetype, img_base64, article_id):
        self.name = name
        self.mimetype = mimetype
        self.img_base64 = img_base64
        self.article_id = article_id

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    access_id = db.Column(db.Integer, db.ForeignKey('access.id'), nullable=False)

    def __init__(self, title, description, access_id):
        self.title = title
        self.description = description
        self.access_id = access_id

class Paragraph(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)

def save_picture_data(article_id, picture):
    if picture:
        filename = picture.filename
        mimetype = picture.mimetype
        img_base64 = base64.b64encode(picture.read()).decode('utf-8')
        
        print(f"Processing picture: {filename}, mimetype: {mimetype}")
        print(f"Base64 encoded image: {img_base64[:30]}...")  # Print first 30 characters for brevity
        
        img = Img(name=filename, mimetype=mimetype, img_base64=img_base64, article_id=article_id)
        db.session.add(img)
        db.session.commit()
        print("Image saved to database.")

def get_all_access_options():
    return Access.query.all()

def get_article_by_id(article_id):
    return Article.query.get(article_id)

with app.app_context():
    db.drop_all()
    db.create_all()

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

class ArticleForm(Form):
    title = StringField('Title')
    description = TextAreaField('Description')
    access_id = SelectField('Access', coerce=int)

class ArticleView(ModelView):
    form_extra_fields = {
        'picture_data': FileField('Picture')
    }
    
    form_columns = ('title', 'description', 'access_id', 'picture_data')
    
    def create_form(self, obj=None):
        form = super().create_form(obj)
        form.access_id.choices = [(a.id, a.name) for a in get_all_access_options()]
        return form

    def edit_form(self, obj=None):
        form = super().edit_form(obj)
        form.access_id.choices = [(a.id, a.name) for a in get_all_access_options()]
        return form

    def on_model_change(self, form, model, is_created):
        if form.picture_data.data:
            picture = form.picture_data.data
            article_id = model.id
            save_picture_data(article_id, picture)

admin.add_view(ArticleView(Article, db.session))
admin.add_view(ModelView(Access, db.session))
admin.add_view(ModelView(Paragraph, db.session))

@app.route('/')
def index():
    articles = Article.query.all()
    for article in articles:
        article.picture = Img.query.filter_by(article_id=article.id).first()
    return render_template('index.html', articles=articles)

@app.route('/create_article', methods=['GET', 'POST'])
def create_article():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        access_id = request.form['access_id']
        picture = request.files['picture_data']

        if not picture:
            return 'No picture uploaded', 400

        print(f"Uploaded picture: {picture.filename}")

        article = Article(title=title, description=description, access_id=access_id)
        db.session.add(article)
        db.session.commit()

        article = Article.query.filter_by(title=title).first()

        save_picture_data(article.id, picture)

        return 'Article created successfully!'
    else:
        access_options = get_all_access_options()
        return render_template('create_article.html', access_options=access_options)

if __name__ == "__main__":
    app.run(debug=True)
