from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from wtforms import FileField, TextAreaField, SelectField, StringField, FieldList, FormField, PasswordField, SubmitField, ValidationError,HiddenField
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import pkg_resources
from sqlalchemy.exc import IntegrityError

print(pkg_resources.__file__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'femboysAreHot'

db = SQLAlchemy(app)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class ProfileImg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    mimetype = db.Column(db.String(100))
    img_base64 = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship('User', backref=db.backref('profile_img', uselist=False), uselist=False)

    def __init__(self, name, mimetype, img_base64, user_id):
        self.name = name
        self.mimetype = mimetype
        self.img_base64 = img_base64
        self.user_id = user_id

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(25), nullable=True)
    bio = db.Column(db.String(750), nullable=True)
    role = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, default=1)
    superuser = db.Column(db.Boolean, default=False)

    def __init__(self, username, email, password, superuser=False, role=1, bio=None):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role
        self.superuser = superuser
        self.bio = bio

    def check_password(self, password):
        return check_password_hash(self.password, password)


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
    paragraphs = db.relationship('Paragraph', backref='article', lazy=True)

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
        old_picture = Img.query.filter_by(article_id=article_id).first()
        if old_picture:
            db.session.delete(old_picture)
            db.session.commit()

        filename = picture.filename
        mimetype = picture.mimetype
        img_base64 = base64.b64encode(picture.read()).decode('utf-8')

        img = Img(name=filename, mimetype=mimetype, img_base64=img_base64, article_id=article_id)
        db.session.add(img)
        db.session.commit()
        
def save_profile_picture(user, picture_data):
    if picture_data:
        if user.profile_img:
            db.session.delete(user.profile_img)
            db.session.commit()

        filename = secure_filename(picture_data.filename)
        mimetype = picture_data.mimetype
        img_base64 = base64.b64encode(picture_data.read()).decode('utf-8')

        profile_img = ProfileImg(name=filename, mimetype=mimetype, img_base64=img_base64, user_id=user.id)
        db.session.add(profile_img)
        db.session.commit()

        user.profile_img = profile_img
        db.session.commit()

def get_all_access_options():
    return Access.query.all()

def get_article_by_id(article_id):
    return Article.query.get(article_id)

def create_default_accesses():
    if Access.query.count() == 0 and Role.query.count() == 0:
        accesses = [
            Access(name="Public"),
            Access(name="Private"),
            Access(name="Unlisted")
        ]
        roles = [
            Role(name="User"),
            Role(name="Team"),
            Role(name="Owner")
        ]
        db.session.bulk_save_objects(accesses)
        db.session.bulk_save_objects(roles)
        db.session.commit()
        print("Default accesses and roles created successfully.")
    else:
        print("Default accesses and roles already exist in the database.")

with app.app_context():
    db.drop_all()
    db.create_all()
    create_default_accesses()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or not current_user.superuser:
            return redirect(url_for('index'))
        return super(MyAdminIndexView, self).index()

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.superuser

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Role, db.session))
admin.add_view(MyModelView(Article, db.session))
admin.add_view(MyModelView(Access, db.session))
admin.add_view(MyModelView(Paragraph, db.session))

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    superuser = SelectField('Superuser', coerce=bool, validators=[DataRequired()])
    submit = SubmitField('Submit')

class UserEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    nickname = StringField('Nickname', validators=[Length(max=25)])
    bio = TextAreaField('Bio', validators=[Length(max=750)])
    picture_data = FileField('Profile Picture')
    submit = SubmitField('Save')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ParagraphForm(FlaskForm):
    id = HiddenField('id')
    title = StringField('Paragraph Title', validators=[DataRequired()])
    body = TextAreaField('Paragraph Body', validators=[DataRequired()])

class ArticleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    access_id = SelectField('Access', coerce=int, validators=[DataRequired()])
    paragraphs = FieldList(FormField(ParagraphForm), min_entries=1)
    picture_data = FileField('Picture')

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

class UserView(MyModelView):
    column_list = ['username', 'email', 'nickname', 'role', 'superuser', 'profile_img']
    form_columns = ['username', 'email', 'password', 'nickname', 'role', 'superuser', 'profile_img']

    def _profile_img_formatter(view, context, model, name):
        if model.profile_img:
            return f'<img src="data:{model.profile_img.mimetype};base64,{model.profile_img.img_base64}" style="max-width:100px;max-height:100px">'
        return ''

    column_formatters = {
        'profile_img': _profile_img_formatter
    }

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    articles = Article.query.all()
    for article in articles:
        article.picture = Img.query.filter_by(article_id=article.id).first()
        article.paragraphs = Paragraph.query.filter_by(article_id=article.id).all()
    return render_template('index.html', articles=articles, user=current_user)

@app.route('/create_article', methods=['GET', 'POST'])
@login_required
def create_article():
    if current_user.role != 3:
        return redirect(url_for('index'))

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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if request.method == 'POST' and form.validate_on_submit():
        existing_users_count = User.query.count()
        
        if existing_users_count == 0:
            new_user = User(username=form.username.data, email=form.email.data, password=form.password.data, superuser=True, role=3)
        else:
            new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print("User found: ", user.username)
            if user.check_password(form.password.data):
                print("Password check passed")
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                print("Password check failed")
        else:
            print("User not found")
        flash('Login failed. Check your email and password.', 'danger')
    
    response = make_response(render_template('login.html', form=form))
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    if current_user.role != 3:
        return redirect(url_for('index'))
    
    article = Article.query.get_or_404(article_id)
    form = ArticleForm(obj=article)

    access_options = get_all_access_options() or []
    form.access_id.choices = [(access.id, access.name) for access in access_options]

    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(article)
        
        for idx, para_form in enumerate(form.paragraphs):
            para_title = para_form.title.data
            para_body = para_form.body.data
            
            if idx < len(article.paragraphs):
                existing_para = article.paragraphs[idx]
                existing_para.title = para_title
                existing_para.body = para_body
            else:
                new_para = Paragraph(title=para_title, body=para_body, article_id=article.id)
                db.session.add(new_para)

        if len(form.paragraphs) < len(article.paragraphs):
            for idx in range(len(form.paragraphs), len(article.paragraphs)):
                db.session.delete(article.paragraphs[idx])
        
        if form.picture_data.data:
            picture = form.picture_data.data
            save_picture_data(article.id, picture)

        db.session.commit()
        flash('Article updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_article.html', form=form, article=article)

@app.route('/user/<int:user_id>')
@login_required
def view_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)

@app.route('/edit_profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    
    if current_user.role != 3 and current_user.id != user_id:
        abort(403)
        
    form = UserEditForm(obj=user)

    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)

        existing_user = User.query.filter(User.username == form.username.data, User.id != user.id).first()
        if existing_user:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('edit_user_profile', user_id=user.id))

        try:
            if form.picture_data.data:
                save_profile_picture(user, form.picture_data.data)

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('view_user_profile', user_id=user.id))
        except IntegrityError as e:
            db.session.rollback()
            flash('Error updating profile. Please try again later.', 'danger')
            app.logger.error(f'IntegrityError: {str(e)}')

    return render_template('edit_profile.html', form=form, user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if request.method == 'POST' and form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        if current_user.check_password(current_password):
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('view_user_profile', user_id=current_user.id))
        else:
            flash('Current password is incorrect.', 'danger')

    return render_template('change_password.html', form=form)

@app.route('/delete_article/<int:article_id>', methods=['DELETE'])
@login_required
def delete_article(article_id):
    if request.method == 'DELETE':
        article = Article.query.get_or_404(article_id)

        if current_user.role != 3:
            return redirect(url_for('index'))

        for paragraph in article.paragraphs:
            db.session.delete(paragraph)

        img = Img.query.filter_by(article_id=article_id).first()
        if img:
            db.session.delete(img)

        db.session.delete(article)
        db.session.commit()

        flash('Article deleted successfully!', 'success')
        return redirect(url_for('index'))

    else:
        abort(405)

@app.route('/promote_user/<int:user_id>')
@login_required
def promote_user(user_id):
    if current_user.role != 3:
        return redirect(url_for('view_user_profile', user_id=user_id))

    user = User.query.get_or_404(user_id)
    if user.role == 1:
        user.role = 2
        db.session.commit()
        flash(f'User {user.username} promoted to Role 2.', 'success')
    elif user.role == 2:
        user.role = 3
        db.session.commit()
        flash(f'User {user.username} promoted to Role 3.', 'success')
    else:
        flash('User is already at the highest role.', 'warning')

    return redirect(url_for('view_user_profile', user_id=user_id))

@app.route('/demote_user/<int:user_id>')
@login_required
def demote_user(user_id):
    if current_user.role != 3:
        return redirect(url_for('view_user_profile', user_id=user_id))

    user = User.query.get_or_404(user_id)
    if user.role == 3:
        flash('Cannot demote a Role 3 user. Only superusers can do this.', 'danger')
    elif user.role == 2:
        user.role = 1
        db.session.commit()
        flash(f'User {user.username} demoted to Role 1.', 'success')
    else:
        flash('User is already at the lowest role.', 'warning')

    return redirect(url_for('view_user_profile', user_id=user_id))

if __name__ == "__main__":
    app.run(debug=True)
