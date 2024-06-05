from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from wtforms import FileField, TextAreaField, SelectField, StringField, Form, FieldList, FormField
import base64
from werkzeug.security import generate_password_hash
import pkg_resources
print(pkg_resources.__file__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'femboysAreHot'

db = SQLAlchemy(app)

#class Role(db.Model, RoleMixin):
#    id = db.Column(db.Integer, primary_key=True)
#    name = db.Column(db.String(20), unique=True, nullable=False)


class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class ProfileImg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    mimetype = db.Column(db.String(100))
    img_base64 = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, name, mimetype, img_base64, user_id):
        self.name = name
        self.mimetype = mimetype
        self.img_base64 = img_base64
        self.user_id = user_id

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(25), nullable=True)
    role = db.Column(db.Integer, db.ForeignKey('access.id'), nullable=False, default=1)
    superuser = db.Column(db.Boolean, default=False)

    def __init__(self, username, email, password, superuser=False, role=1):
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.superuser = superuser

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
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))

def save_picture_data(article_id, picture):
    if picture:
        filename = picture.filename
        mimetype = picture.mimetype
        img_base64 = base64.b64encode(picture.read()).decode('utf-8')
        
        img = Img(name=filename, mimetype=mimetype, img_base64=img_base64, article_id=article_id)
        db.session.add(img)
        db.session.commit()

def get_all_access_options():
    return Access.query.all()

def get_article_by_id(article_id):
    return Article.query.get(article_id)

def create_superuser(username, email, password):
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print("User already exists.")
        return

    hashed_password = generate_password_hash(password)

    superuser = User(username=username, email=email, password=hashed_password, superuser=True, role=3)
    db.session.add(superuser)
    db.session.commit()

    print("Superuser created successfully.")

def create_default_accesses():
    accesses = [
        Access(name="User"),
        Access(name="Team"),
        Access(name="Owner")
    ]
    db.session.bulk_save_objects(accesses)
    db.session.commit()

with app.app_context():
    db.drop_all()
    db.create_all()
    create_default_accesses()

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

class ParagraphForm(Form):
    title = StringField('Paragraph Title')
    body = TextAreaField('Paragraph Body')

class ArticleForm(Form):
    title = StringField('Title')
    description = TextAreaField('Description')
    access_id = SelectField('Access', coerce=int)
    paragraphs = FieldList(FormField(ParagraphForm), min_entries=1)

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

class UserView(ModelView):
        column_list = ['username', 'email', 'nickname', 'role', 'superuser']
        form_columns = ['username', 'email', 'password', 'nickname', 'role', 'superuser']
        form_extra_fields = {
            'password': StringField('Password'),
        }

class ImgView(ModelView):
    column_list = ['name', 'mimetype', 'article_id']
    form_columns = ['name', 'mimetype', 'img_base64', 'article_id']
    can_view_details = True
    column_details_list = ['name', 'mimetype', 'img_base64', 'article_id']

class ProfileImgView(ModelView):
    column_list = ['name', 'mimetype', 'user_id']
    form_columns = ['name', 'mimetype', 'img_base64', 'user_id']
    can_view_details = True
    column_details_list = ['name', 'mimetype', 'img_base64', 'user_id']

admin.add_view(UserView(User, db.session))
admin.add_view(ArticleView(Article, db.session))
admin.add_view(ModelView(Access, db.session))
admin.add_view(ModelView(Paragraph, db.session))
admin.add_view(ImgView(Img, db.session))
admin.add_view(ProfileImgView(ProfileImg, db.session))

@app.route('/')
def index():
    articles = Article.query.all()
    for article in articles:
        article.picture = Img.query.filter_by(article_id=article.id).first()
        article.paragraphs = Paragraph.query.filter_by(article_id=article.id).all()
    return render_template('index.html', articles=articles)

@app.route('/create_article', methods=['GET', 'POST'])
def create_article():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        access_id = request.form['access_id']
        picture = request.files['picture_data']

        article = Article(title=title, description=description, access_id=access_id)
        db.session.add(article)
        db.session.commit()

        article_id = article.id
        save_picture_data(article_id, picture)

        print(request.form.to_dict(flat=False))

        paragraphs_data = request.form.to_dict(flat=False)
        paragraph_titles = [key for key in paragraphs_data.keys() if key.startswith('paragraphs[') and key.endswith('].title')]

        for key in paragraph_titles:
            index = key.split('[')[1].split(']')[0]
            para_title = paragraphs_data[f'paragraphs[{index}].title'][0]
            para_body = paragraphs_data[f'paragraphs[{index}].body'][0]
            if para_title and para_body:
                paragraph = Paragraph(title=para_title, body=para_body, article_id=article_id)
                db.session.add(paragraph)

        db.session.commit()

        return 'Article created successfully!'
    else:
        access_options = get_all_access_options()
        return render_template('create_article.html', access_options=access_options)

if __name__ == "__main__":
    app.run(debug=True)
