from flask import Flask,render_template,request,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import  StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import Length, DataRequired
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'alesek'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.init_view = 'login'

class RegisterForm(FlaskForm):
   username = StringField('username',validators=[DataRequired('Username is required'), Length(min=5, max=15, message="Invalid username, 5-15 characters required")])
   password = PasswordField('password',validators=[DataRequired('Password is required'),Length(min=5, max=80)])
   submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
   username = StringField('username',validators=[DataRequired('Username is required'), Length(min=5, max=15, message="Invalid username, 5-15 characters required")])
   password = PasswordField('password',validators=[DataRequired('Password is required'),Length(min=5, max=80)])
   remember =BooleanField('remember me')
   submit = SubmitField('Log In')


class Person(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(15), unique=True)

    comm = db.relationship('Comments',backref='owner')

class Comments(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(15))
    comment = db.Column(db.String(200),nullable=False)
    posted = db.Column(db.DateTime,nullable=False,default=datetime.utcnow)

    owner_id = db.Column(db.Integer, db.ForeignKey('person.id'))

@login_manager.user_loader
def load_user(user_id):
    return Person.query.get(int(user_id))

@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Person(username=form.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return  render_template("uvod.html")
    return  render_template('signup.html',form=form)


@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Person.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
        return  '<H1> INVALID USERNAME OR PASSWORD </H1>'
    return  render_template('login.html',form=form)

@app.route('/')
def uvod():

    return  render_template('uvod.html')

@app.route('/index',methods=['GET','POST'])
@login_required
def index():
        result = Comments.query.all()
        return render_template('index.html', result=result, username=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return  redirect(url_for('uvod'))

@app.route('/process',methods=['POST'])
def process():

    comment = request.form['comment']
    posted = datetime.utcnow()

    signature = Comments(username=current_user.username,comment=comment,posted=posted)
    db.session.add(signature)
    db.session.commit()

    result = Comments.query.all()
    return render_template('index.html', posted=posted,result=result,username=current_user.username)

if __name__ == "__main__":
    app.run()
    app.run(debug=True)
