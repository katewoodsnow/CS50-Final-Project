import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, staff_login_required


# Configure application create an instance of a flask app
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

     # Forget any user_id
    session.clear()

    # user submitted the form via post
    if request.method == "POST":

        # error check that user filled out first name field
        if not request.form.get("first_name"):
            return apology("Please provide a first name")

        # error check that user filled out last name field
        if not request.form.get("last_name"):
            return apology("Please provide a last name")

        # error check that user filled out email field
        if not request.form.get("email"):
            return apology("Please provide an email address")

        # error check that user filled out mobile field
        if not request.form.get("phone"):
            return apology("Please provide a phone number")

        # error check that user filled out the username field
        if not request.form.get("username"):
            return apology("Please provide a username")

        # error check that user filled out password field
        elif not request.form.get("password"):
            return apology("Please provide a password")

        # error check that user filled out password confirmation field
        elif not request.form.get("confirmation"):
            return apology("Please provide a password confirmation")

        # error check that password and password confirmation matched
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Please ensure your password confirmation matches")

        username = db.execute("SELECT * fROM users WHERE username = :username",
                             username = request.form.get("username"))

         # check username doesn't already exist
        if len(username)!=0:
            return apology("This username already exists")

        # enter the users details into database by accessing and executing
        results = db.execute("INSERT INTO users (username, password, first_name, last_name, email, mobile, user_role) VALUES(:username, :password, :first_name, :last_name, :email, :mobile, :user_role)",
                             username=request.form.get("username"),
                             password=generate_password_hash(request.form.get("password")),
                             first_name=request.form.get("first_name"),
                             last_name=request.form.get("last_name"),
                             email=request.form.get("email"),
                             mobile=request.form.get("phone"),
                             user_role = "user",
                             )

        # check username doesn't already exist
        if not results:
            return apology("This username already exists")

        # remember the user
        session["user_id"] = results

          # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        session["first_name"] = rows[0]["first_name"]

        flash("Successfully registered")

        # direct user to homepage
        return redirect("/")

    # direct user to route (html page) using flask function render_template
    else:
        return render_template("register.html")


@app.route("/register_staff", methods=["GET", "POST"])
def register_staff():

    """Register admin"""

    # user submitted the form via post
    if request.method == "POST":

        # error check that user filled out first name field
        if not request.form.get("first_name"):
            return apology("Please provide a first name")

        # error check that user filled out last name field
        if not request.form.get("last_name"):
            return apology("Please provide a last name")

        # error check that user filled out email field
        if not request.form.get("email"):
            return apology("Please provide an email address")

        # error check that user filled out mobile field
        if not request.form.get("phone"):
            return apology("Please provide a phone number")

        # error check that user filled out the username field
        if not request.form.get("username"):
            return apology("Please provide a username")

        # error check that user filled out password field
        elif not request.form.get("password"):
            return apology("Please provide a password")

        # error check that user filled out password confirmation field
        elif not request.form.get("confirmation"):
            return apology("Please provide a password confirmation")

         # error check that user filled out user role field
        elif not request.form.get("user_role"):
            return apology("Please provide a user role")

        # error check that password and password confirmation matched
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Please ensure your password confirmation matches")

        username = db.execute("SELECT * fROM users WHERE username = :username",
                             username = request.form.get("username"))

         # check username doesn't already exist
        if len(username)!=0:
            return apology("This username already exists")

        # enter the users details into database by accessing and executing
        results = db.execute("INSERT INTO users (username, password, first_name, last_name, email, mobile, user_role) VALUES(:username, :password, :first_name, :last_name, :email, :mobile, :user_role)",
                             username=request.form.get("username"),
                             password=generate_password_hash(request.form.get("password")),
                             first_name=request.form.get("first_name"),
                             last_name=request.form.get("last_name"),
                             email=request.form.get("email"),
                             mobile=request.form.get("phone"),
                             user_role =request.form.get("user_role"),
                             )

        # remember the user
        session["user_id"] = results

          # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        session["first_name"] = rows[0]["first_name"]

        flash("Successfully registered")

        # direct user to homepage
        return redirect("staff_dashboard")

    # direct user to route (html page) using flask function render_template
    else:
        return render_template("register_staff.html")

@app.route("/register_child", methods=["GET", "POST"])
@login_required
def register_child():
    """Register child"""

     # user submitted the form via post
    if request.method == "POST":

        # error check that user filled out first name field
        if not request.form.get("first_name"):
            return apology("Please provide a first name")

        # error check that user filled out last name field
        if not request.form.get("last_name"):
            return apology("Please provide a last name")

        # error check that user filled out email field
        if not request.form.get("child_age"):
            return apology("Please provide a date of birth")

        # error check that user filled out mobile field
        if not request.form.get("phone"):
            return apology("Please provide a phone number")

        # enter the users details into database by accessing and executing
        results = db.execute("INSERT INTO child (first_name, last_name, child_age, illness, allergies, phone, id) VALUES(:first_name, :last_name, :child_age, :illness, :allergies, :phone, :id)",
                             first_name=request.form.get("first_name"),
                             last_name=request.form.get("last_name"),
                             child_age=request.form.get("child_age"),
                             illness=request.form.get("illness"),
                             allergies=request.form.get("allergies"),
                             phone=request.form.get("phone"),
                             id=session['user_id'],
                             )

        # remember the user
        session["user_id"] = results

        # direct user to homepage
        return redirect("/")

    # direct user to route (html page) using flask function render_template
    else:
        return render_template("register_child.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        session["first_name"] = rows[0]["first_name"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/staff_login", methods=["GET", "POST"])
def staff_login():
    """admin page to edit child's development"""

     # Forget any admin_id
    session.clear()

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(username) != 1  or not check_password_hash(username[0]["password"], request.form.get("password")):
            return apology("Username and password are incorrect", 403)

        # Query database for username with admin permission
        permission = db.execute("SELECT * FROM users WHERE username = :username AND user_role = :user_role",
                          username=request.form.get("username"),
                          user_role = "admin")

        if not permission:
             return apology("You do not have permission to access this site")

        # Remember which user has logged in
        session["user_id"] = username[0]["user_id"]

        #Remember the name of the user who is logged in
        session["first_name"] = username[0]["first_name"]

        session["user_role"] = "admin"

        # Redirect admin user to admin dashboard
        return redirect("staff_dashboard")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("staff_login.html")

@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    # get the username entered by the user
    username=request.args.get("username")

    # get the usernames that already exist in the database
    names = db.execute("SELECT FROM users where username = :username", username=username)

    # if username is entered and not in the database already username is allowed
    if not names:
        return jsonify(True)
    else:
        # otherwise it is not allowed
        return jsonify(False)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/")
def index():

    return render_template("index.html")

@app.route("/about")
def about():
    """Information and continue to meet the team"""
    return render_template("/about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    """contact page, user can book a visit, form handler"""
    # user submitted the form via post
    if request.method == "POST":

        # error check that user filled out first name field
        if not request.form.get("first_name"):
            return apology("Please provide a first name")

        # error check that user filled out last name field
        if not request.form.get("last_name"):
            return apology("Please provide a last name")

        # error check that user filled out email field
        if not request.form.get("email"):
            return apology("Please provide an email address")

        # error check that user filled out mobile field
        if not request.form.get("phone"):
            return apology("Please provide a phone number")

        # error check that user filled out the username field
        if not request.form.get("child_name"):
            return apology("Please provide child's name")

        # error check that user filled out password field
        elif not request.form.get("child_age"):
            return apology("Please provide child's age")

        # error check that user filled out password confirmation field
        elif not request.form.get("sessions"):
            return apology("Please provide number of sessions you would like your child to attend")

        # error check that user filled out password confirmation field
        elif not request.form.get("message"):
            return apology("Please provide a message")

        # direct user to homepage
        return redirect("contact")

    # direct user to route (html page) using flask function render_template
    else:
        return render_template("contact.html")

@app.route("/child_detail")
@login_required
def child_detail():
    """Show child's details for each parent logged in"""
    child_detail = db.execute("SELECT *, strftime('%Y', 'now') - strftime('%Y',child_age) as Age from child WHERE id = :id",
                         id=session["user_id"])

    return render_template("child_detail.html", child_detail=child_detail)

@app.route("/pricing")
def pricing():
    """page showing prices"""

    return render_template("pricing.html")

@app.route("/meet_the_team")
def meet_the_team():
    """page showing the team and images"""

    return render_template("meet_the_team.html")

@app.route("/staff_dashboard")
@staff_login_required
def staff_dashboard():
    """Show all child's details for any staff ,ember logged in"""
    staff_child_detail = db.execute("SELECT *, strftime('%Y', 'now') - strftime('%Y',child_age) as Age from child")

    return render_template("staff_dashboard.html", staff_child_detail=staff_child_detail)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
