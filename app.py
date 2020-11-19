from flask import Flask,render_template,request,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import  StringField,PasswordField,BooleanField,TextField
from wtforms.validators import   Email ,Length, email_validator, DataRequired
from email_validator import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.init_view = 'login'



class User(UserMixin, db.Model):
    id =db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(15),unique=True)
    email = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(50), unique=True)
    com = db.relationship('Comments',backref='owner')

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    comment = db.Column(db.String(200), nullable=False)
    posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer,db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(),Length(min=4,max=15)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=5, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired("Please enter your email address."), Email("This field requires a valid email address")])
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=5, max=80)])



@app.route('/')
def index1():

    return  render_template('index1.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return  '<H1> INVALID USERNAME OR PASSWORD </H1>'

    return  render_template('login.html',form=form)

@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return  render_template("uvod.html")
    return  render_template('signup.html',form=form)

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    result = Comments.query.all()

    return render_template('dashboard.html', result=result, username=current_user.username)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return  redirect(url_for('index1'))


@app.route('/process',methods=['POST'])
def process():

    comment = request.form['comment']
    posted = datetime.utcnow()

    signature = Comments(username=current_user.username,comment=comment,posted=posted)
    db.session.add(signature)
    db.session.commit()

    result = Comments.query.all()
    return render_template('dashboard.html',result=result,username=current_user.username)



if __name__== "__main__":
    app.run(port=5001)