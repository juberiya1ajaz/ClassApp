

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
from os import path
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user 


app = Flask(__name__)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# create db for tasks  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
dbt = SQLAlchemy(app)

# db model 
class Tasks(dbt.Model):
    id = dbt.Column(dbt.Integer, primary_key=True)
    title = dbt.Column(dbt.String(100), nullable=False)
    content = dbt.Column(dbt.Text, nullable=False)
    date_created = dbt.Column(dbt.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
            return f"Post('{self.title}', '{self.content}')"
dbt.create_all(app=app)

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
    tasks_lst = list()
    tasks_content = dbt.session.query(Tasks.content).all()
    tasks_title = dbt.session.query(Tasks.title).all()


    for i,  in tasks_content: 
            tasks_lst.append(i)
    resp.message(f'Hello, Your tasks are \n { tasks_lst}')

    return str(resp)


# add tasks 
 
@app.route("/tasks", methods=['POST', 'GET'])
def add_tasks():
    if request.method == 'POST':
        name = request.form.get("name")
        body = request.form.get("desc")

        new_task = Tasks(title=name, content=body)
        dbt.session.add(new_task)
        dbt.session.commit()
        return render_template('msg.html')
    else:
        return render_template('tasks.html',)
      

@app.route("/contact", methods=["GET", "POST"])
def contact():
        return render_template("contact.html")




# authentication
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
    return redirect("/")      


# register 
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



@app.route("/delete" , methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        user_id=session["user_id"]
       # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        db.execute('DELETE FROM users WHERE id = ?', (user_id))
        session.clear()

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("del_account.html")





if __name__ == "__main__":
    app.run(debug=True)
