'''
Student: Garrick Macas
Completed: 12/05/21
Description update: The website was updated to have a login, register and
logout functionality and logic. A webpage was added to show the ability
to use tables.

Description as of 11/28/21: The purpose of webpage.py is to implement
the fundamentals of building a webpage for UMGC's SDEV300 course. webpage.py
contains four functions implementing URL URI's and routing to html implemented
pages. There is a single date/time update function that is called during each
visit to a page.
'''
import datetime
import os
import re
import sys
import pandas as pd
from flask import Flask, render_template, url_for, redirect, flash, request, session
from passlib.handlers.sha2_crypt import sha256_crypt

app = Flask(__name__)
app.secret_key = b'D=%C/zsY-P>wK5TwyL\\&Mu"/>r(}K@D~&z@8BmpL!,H\"\'Q`*VjZ]e^"6C%r7kw""YC+zh' \
                 b'T"CQRE]r;K;&#a2fe9vf\\%#)8L;8gd^7FU!eGQ,$!%azwAy>Td&nsJ.a"a'
app.permanent_session_lifetime = datetime.timedelta(minutes=10)
user_db_csv = os.path.join(sys.path[0] + "\\" + "username_information_database.csv")
login_log_csv = os.path.join(sys.path[0] + "\\" + "login_log.csv")
common_password_txt = os.path.join(sys.path[0] + "\\" + "CommonPassword.txt")

@app.route('/')
def index():
    '''Redirects to the home page'''
    return redirect(url_for("login"))

@app.route('/login/', methods=['GET','POST'])
def login():
    '''Directs to login.html which is the login page'''
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        if error is None:
            account_found = False
            login_success = False
            user_db = pd.read_csv(user_db_csv)
            db_index = user_db[user_db['username'] == username].index.values
            if db_index >= 0:
                account_found = True
                db_password = str(user_db.at[db_index[0],'password'])
                del user_db
                login_success = sha256_crypt.verify(password, db_password)

                if sha256_crypt.verify(password, db_password):
                    session.permanent = True
                    session["username"] = username
            login_db = pd.read_csv(login_log_csv)
            data_frame = {'date': datetime.datetime.now().strftime("%d/%m/%Y"),
                          'time': datetime.datetime.now().strftime("%H:%M:%S"),
                          'ip': request.remote_addr,
                          'username': username,
                          'login_success': str(login_success)}
            login_db = login_db.append(data_frame, ignore_index=True)
            login_db.to_csv("login_log.csv", sep=',', encoding='utf-8', index=False)
            del login_db
            if account_found:
                error = ("Password is incorrect.")
            else:
                error = ("User account not found. "
                      "Click register button to make a user account.")
        if account_found and login_success:
            redirect(url_for("home"))
        flash(error)
    else:
        if "username" in session:
            return redirect(url_for("home"))

    return render_template('login.html', name=update_date())

@app.route('/register/', methods=['GET','POST'])
def register():
    '''Directs to login.html which is the register page'''
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        error = check_password(username, password, confirm_password)

        if error is None:
            hashed_password = sha256_crypt.hash(password)
            user_db = pd.read_csv(user_db_csv)
            data_frame = {'username': username, 'password': hashed_password}
            user_db = user_db.append(data_frame, ignore_index=True)
            user_db.to_csv("username_information_database.csv", sep=',',
                           encoding='utf-8', index=False)
            del user_db
            return redirect(url_for("login"))
        flash(error)
    else:
        if "username" in session:
            return redirect(url_for("home"))

    return render_template('register.html', name=update_date())

@app.route("/logout/")
def logout():
    '''Pops the session when the logout button is clicked'''
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route('/reset/', methods=['GET','POST'])
def reset():
    '''Directs to reset.html which is the home page'''
    if "username" in session:
        if request.method == "POST":
            username = session["username"]
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]

            error = check_password(username, password, confirm_password)
            hashed_password = sha256_crypt.hash(password)

            if error is None:
                hashed_password = sha256_crypt.hash(password)
                user_db = pd.read_csv(user_db_csv)
                db_index = user_db[user_db['username'] == username].index.values
                user_db.at[db_index[0], 'password'] = hashed_password
                user_db.to_csv("username_information_database.csv", sep=',',
                               encoding='utf-8', index=False)
                del user_db
                return redirect(url_for("home"))
            flash(error)

        return render_template('reset.html', name=update_date(), account=session["username"])
    return redirect(url_for("login"))

@app.route('/home/')
def home():
    '''Directs to home.html which is the home page'''
    if "username" in session:
        return render_template('home.html', name=update_date(), account=session["username"])
    return redirect(url_for("login"))

@app.route('/guineasguidetothegalaxy/')
def guineasguidetothegalaxy():
    '''Directs to one of there pages with content'''
    if "username" in session:
        return render_template('guinreasguidetothegalaxy.html', name=update_date())
    return redirect(url_for("login"))

@app.route('/mellowandbyte/')
def mellowandbyte():
    '''Directs to one of there pages with content'''
    if "username" in session:
        return render_template('mellowandbyte.html', name=update_date())
    return redirect(url_for("login"))

@app.route('/memes/')
def memes():
    '''Directs to one of there pages with content'''
    if "username" in session:
        return render_template('memes.html', name=update_date())
    return redirect(url_for("login"))

@app.route('/tables/')
def tables():
    '''Directs to one of there pages with content'''
    if "username" in session:
        return render_template('tables.html', name=update_date())
    return redirect(url_for("login"))

def update_date():
    '''Update function to get current date and time'''
    date = datetime.datetime.now().strftime("Date: %d/%m/%Y Time: %H:%M:%S")
    return date

def check_password(username, password, confirm_password):
    '''Check_password function check for password complexity'''
    error = None
    common_password_found = False

    common_passwords = open(common_password_txt, "r")
    for line in common_passwords:
        if password == line.strip():
            common_password_found = True
            break
    common_passwords.close()

    if common_password_found:
        error = "Password must not be a common password."
    elif not username:
        error = "Username is required."
    elif not password:
        error = "Password is required."
    elif not confirm_password:
        error = "Password confirmation is required."
    elif not password == confirm_password:
        error = "Passwords do not match."
    elif len(password) < 12:
        error = "Password must be at least 12 characters long."
    elif re.search(r"\d", password) is None:
        error = "Password must have at least 1 number."
    elif re.search(r"[A-Z]", password) is None:
        error = "Password must have at least 1 capital letter."
    elif re.search(r"[a-z]", password) is None:
        error = "Password must have at least 1 lowercase letter."
    elif re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None:
        error = "Password must have at least 1 special character"

    return error

if __name__ == "__main__":
    app.run()
