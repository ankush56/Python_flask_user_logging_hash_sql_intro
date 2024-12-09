### Flask Flash
```
In main.py add -> flash(msg)
 flash('You were successfully logged in')
 
 e.g
 def login():
    if request.method == 'POST':
        #Get input data from form
        email = request.form.get("email")
        password = request.form.get("password")

        # # Find user by email entered
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # Return type: bool, check_password_hash
        # Check stored password hash against entered password hashed.
        #user.password--> Hashed pass in db, password-->password fetched from form
        if check_password_hash(user.password, password):
            # If password match, Login the user using 'login_user' method from LoginManager class
            login_user(user)
            # After login redirect to this page
            return redirect(url_for("secrets"))
        else:
            flash('Logged failed. Please check if email or password is correct')
            return redirect(url_for("login"))
    return render_template("login.html")
```  
> # In html use same block, it will be generic to get flash masssages
Login.html
```

  <div class="flash">
    <p >
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <ul class=flashes>
          {% for message in messages %}
            <li>{{ message }}</li>
          {% endfor %}
          </ul>
        {% endif %}
      {% endwith %}
      {% block body %}{% endblock %}
    </p>
  </div>    
```

> # -------------------------------------------------------
### Login Manager 
> Doc- https://flask-login.readthedocs.io/en/latest/

> Install - pip install flask-login

Main.py
> LoginManager class has inbuilt methods for login_user, logout_user
```
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_login import LoginManager

login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# CREATE TABLE IN DB with the UserMixin
#USERMIXIN
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

> Login user like this
        # Log in and authenticate user after adding details to database.
        #Login the user using 'login_user' method from LoginManager class
        login_user(user)

        #After login redirect to this page
        return redirect(url_for("secrets"))

Full  code-    
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        # Get data from form
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

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
    return render_template("register.html")    
```


> # -------------------------------------------------------
### Secret Hashing
> Doc- https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.generate_password_hash
> https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security

```
        # Hash the plain password before adding to DB
        password = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
```
> Check password hash
> 
> Method- check_password_hash(hashpw_from_db, password_from_form)
```
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #Get input data from form
        email = request.form.get("email")
        password = request.form.get("password")

        # # Find user by email entered
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # Return type: bool, check_password_hash
        # Check stored password hash against entered password hashed.
        #user.password--> Hashed pass in db, password-->password fetched from form
        if check_password_hash(user.password, password):
            # If password match, Login the user using 'login_user' method from LoginManager class
            login_user(user)
            # After login redirect to this page
            return redirect(url_for("secrets"))
        else:
            flash('Logged failed. Please check if email or password is correct')
            return redirect(url_for("login"))
    return render_template("login.html")
```
### check user logged in -
current_user.is_authenticated
```
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

```

#### Enable pages acccess only if user is logged in
> use--> @login_required
```
e.g-
@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    # Passing the name from the current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)

```