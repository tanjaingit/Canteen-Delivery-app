from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)

app.config[ 'SECRET_KEY'] = 'abc123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    enroll = db.Column(db.String, primary_key = True)
    name = db.Column(db.String)    
    email = db.Column(db.String, unique = True) 
    number = db.Column(db.Integer) 
    psw = db.Column(db.String(80)) 

    def get_id(self):
        return self.enroll

class Item(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)    
    price = db.Column(db.Integer) 


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(enroll=user_id).first()

class LoginForm(FlaskForm):
    enroll = StringField('enroll')
    psw = PasswordField('psw', validators = [InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    name = StringField('name', validators = [InputRequired()])
    enroll = StringField('enroll')
    email = StringField('email', validators = [InputRequired()])
    number = StringField('number', validators = [InputRequired(), Length(min=10, max=10)])
    psw = PasswordField('psw', validators = [InputRequired(), Length(min=8, max=80)])









@app.route("/", methods=['GET', 'POST'])
def index():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(enroll = form.enroll.data).first()
        if user:
            if check_password_hash(user.psw, form.psw.data):
                login_user(user)    #, remember=form.remember.data
                return redirect(url_for('menupg'))

        return '<h1> Invalid enroll or password </h1>'

    return render_template('index.html', form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_psw = generate_password_hash(form.psw.data, method = 'sha256') 
        new_user = User(name = form.name.data, enroll = form.enroll.data, email = form.email.data, number = form.number.data, psw = hashed_psw)
        db.session.add(new_user)
        db.session.commit()

        # flash('you are now registered !')
        if current_user.is_authenticated:
            return redirect(url_for('index'))        
        
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


############################
@app.route("/menupg", methods=['GET', 'POST'])
@login_required
def menupg():
    items = Item.query.all()
    return render_template('menupg.html',items=items)
    #return render_template('menupg.html')
    if request.method == 'POST':
        def addToCart():
            return '<h1>Product: </h1>'



@app.route("/mybill")
@login_required
def mybill():
    return render_template('mybill.html')



if __name__ == '__main__':
    app.run(debug=True)





