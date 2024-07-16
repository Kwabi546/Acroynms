from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from sqlalchemy.exc import IntegrityError
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///acronyms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Acronym(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    acronym = db.Column(db.String(10), unique=True, nullable=False)
    meaning = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500))  # Allows for a longer description, nullable by default

class AcronymForm(FlaskForm):
    acronym = StringField('Acronym', validators=[DataRequired()])
    meaning = StringField('Meaning', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Add Acronym')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def company_email_check(form, field):
    if not field.data.endswith('@spscommerce.com'):
        raise ValidationError('Please use your company email address.')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(), company_email_check])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        is_admin = form.email.data == "asafo@spscommerce.com"  # Replace with your email
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, is_admin=is_admin)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('This email is already registered. Please use a different email.', 'danger')
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
@login_required
def home():
    form = AcronymForm()
    return render_template('index.html', form=form)

@app.route('/add', methods=['POST'])
@login_required
def add_acronym():
    form = AcronymForm()
    if form.validate_on_submit():
        acronym = form.acronym.data
        meaning = form.meaning.data
        description = form.description.data  # Capture the description from the form
        new_acronym = Acronym(acronym=acronym.upper(), meaning=meaning, description=description)
        db.session.add(new_acronym)
        db.session.commit()
        return redirect(url_for('acronyms'))
    return render_template('index.html', form=form)

@app.route('/acronyms')
@login_required
def acronyms():
    form = AcronymForm()
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Define how many items each page should display
    query = request.args.get('q', '')
    if query:
        acronyms = Acronym.query.filter(
            db.or_(
                Acronym.acronym.like('%' + query + '%'),
                Acronym.meaning.like('%' + query + '%'),
                Acronym.description.like('%' + query + '%')
            )
        ).paginate(page=page, per_page=per_page, error_out=False)
    else:
        acronyms = Acronym.query.order_by(Acronym.acronym).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('acronyms.html', acronyms=acronyms.items, pagination=acronyms, form=form)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_acronym(id):
    acronym = Acronym.query.get_or_404(id)
    form = AcronymForm()
    if not current_user.is_admin:
        flash('You do not have permission to edit acronyms.', 'danger')
        return redirect(url_for('acronyms'))
    if request.method == 'POST' and form.validate_on_submit():
        acronym.acronym = form.acronym.data
        acronym.meaning = form.meaning.data
        acronym.description = form.description.data
        db.session.commit()
        return redirect(url_for('acronyms'))
    elif request.method == 'GET':
        form.acronym.data = acronym.acronym
        form.meaning.data = acronym.meaning
        form.description.data = acronym.description
    return render_template('edit_acronym.html', acronym=acronym, form=form)

@app.route('/delete/<int:id>', methods=['GET'])
@login_required
def delete_acronym(id):
    acronym = Acronym.query.get_or_404(id)
    if not current_user.is_admin:
        flash('You do not have permission to delete acronyms.', 'danger')
        return redirect(url_for('acronyms'))
    db.session.delete(acronym)
    db.session.commit()
    return redirect(url_for('acronyms'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for our data models within the application context
    app.run(debug=True)
