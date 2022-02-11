
from flask import Flask, request ,redirect,url_for, render_template, request, session, flash
from cs50 import SQL
from flask_session import Session
from tempfile import mkdtemp
from sqlalchemy.sql.expression import select
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import login_required,apology
from twilio.twiml.messaging_response import MessagingResponse
from flask_sqlalchemy import SQLAlchemy
  

app = Flask(__name__)

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
db = SQL("sqlite:///users.db")

@app.route('/')
def index():

        return render_template("index.html")

@app.route("/sms", methods=['POST'])
def sms_reply():
    """Respond to incoming calls with a simple text message."""
    # Fetch the message
    msg = request.form.get('Body')

    # Create reply
    resp = MessagingResponse()
    resp.message("You said: {}".format(msg))

    return str(resp)
      

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        first_name= request.form.get("f_name")
        last_name= request.form.get("l_name")
        user = request.form.get("user")
        role = request.form.get("role")
        message = request.form['text']

        # Ensure username was submitted
        if not first_name or not last_name :
            return apology("Please provide your name", 403)

        # Ensure necessary data was submitted
        elif not user:
            return apology("please provide data", 403)
        elif not role:
            return apology("please provide current role", 403)
        elif not message:
            return apology("please provide some comments", 403)


        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("contact.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    
    """Log user in"""
    session.clear()
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return ("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        user = db.execute("SELECT username FROM users WHERE id = ?",session["user_id"] )
        session["username"] = user[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
       
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")      

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password=request.form.get("password")
        c_password=request.form.get("confirmation")

        #show apology if some error was occured
        if not username:
            return apology("must provide username",400)
        elif not password or not  c_password :
            return apology("must provide password" ,400)
        elif len(username) < 6:
            return apology("Make sure your username is at least 6 letters",400)
        elif len(password) < 8:
            return apology("Make sure your password is at least 8 letters",400)

        #MAKE SURE BOTH PASSWORD MATCH
        elif  password !=  c_password:
            return apology("both password  must match", 400)

    
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(rows) >= 1:
            return apology("username already exists" , 400)
            
        # Start session
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",username=request.form.get("username"),
                             hash=generate_password_hash(request.form.get("password")))

        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        #Storing current username
        user = db.execute("SELECT username FROM users WHERE id = ?",session["user_id"] )
        session["username"] = user[0]["username"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")




if __name__ == "__main__":
    app.run(debug=True)
