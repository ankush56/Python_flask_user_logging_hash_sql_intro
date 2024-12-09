import flask
import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

### Login Manager Starts ###
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB with the UserMixin
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        # Get data from form
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        # Find if email already exists
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            # Hash the plain password before adding to DB
            password = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            #Register new User object
            user = User(
                name=name,
                email=email,
                password=password,
            )

            # Add commit to DB
            db.session.add(user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            #Login the user using 'login_user' method from LoginManager class
            login_user(user)

            #After login redirect to this page
            return redirect(url_for("secrets"))
        else:
            flash('Email is already registered')
            return redirect(url_for("login"))

    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #Get input data from form
        email = request.form.get("email")
        password = request.form.get("password")

        # # Find user by email entered
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # Check if email exists. If it doesnt user object wont be found
        if user:
            # Return type: bool, check_password_hash
            # Check stored password hash against entered password hashed.
            #user.password--> Hashed pass in db, password-->password fetched from form
            if check_password_hash(user.password, password):
                # If password match, Login the user using 'login_user' method from LoginManager class
                login_user(user)
                # After login redirect to this page
                return redirect(url_for("secrets"))
            else:
                flash('Logged failed. Please check if PASSWORD is correct')
                return redirect(url_for("login"))
        else:
            flash('Logged failed. Please check if EMAIL is correct')
            return redirect(url_for("login"))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    # Passing the name from the current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)

@app.route('/logout')
def logout():
    #Login the user using 'logout_user' method from LoginManager class
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
def download():
    return send_from_directory(
        'static/files', 'cheat_sheet.pdf', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
