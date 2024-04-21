import threading

from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_socketio import SocketIO
import bleach
import string
import os
import psycopg2
import hashlib
import asyncio
import random
from email.message import EmailMessage
import smtplib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("app_secret_key")  # Replace with your own secret key

valid_chars = "".join([string.digits, string.ascii_letters, "_"])
valid_pass_chars = "".join([string.digits, string.ascii_letters, string.punctuation])


def token_generator(size=36, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def email_alert(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['subject'] = subject
    msg['to'] = to

    user = os.getenv('nr_user')
    msg['from'] = user
    password = os.getenv('nr_pass')

    server = smtplib.SMTP("smtp.forwardemail.net", 2587)
    server.starttls()
    server.login(user, password)
    server.send_message(msg)

    server.quit()


socketio = SocketIO(app)

messages = ''

users_online = 0


@app.route('/login')
def login():
    if request.args.get('message') is not None:
        message = request.args.get('message')
        return render_template('login.html', message=message)
    return render_template("login.html")


@app.route('/signup')
def signup():
    if request.args.get('message') is not None:
        message = request.args.get('message')
        return render_template('signup.html', message=message)
    return render_template("signup.html")


@app.route('/logout')
async def logout():
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('token', '', expires=0)
    return resp


@app.route('/')
async def mainpage():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning")
        return redirect(request.url)
    c = conn.cursor()
    if request.cookies.get('token') is None:
        conn.close()
        return redirect(url_for('login'))
    return render_template('home.html', msgs=messages, users=users_online, usersnum=users_online)


@app.route('/validatelogin', methods=['POST', 'GET'])
async def validatelogin():
    username = request.form['username']
    password = request.form['password']
    h = hashlib.new("SHA256")
    h.update(bytes(password, encoding="utf-8"))
    hashed_password = h.hexdigest()
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        await asyncio.sleep(4)
        print(request.url)
        return (redirect(url_for('login', message="Server failed to connect to database. Try again in a few seconds.")))
    c = conn.cursor()
    c.execute("SELECT * FROM usercred WHERE (username = %s OR email = %s) AND password = %s",
              [str(username), str(username), str(hashed_password)])
    result = c.fetchone()
    if result is None:
        conn.close()
        return redirect(url_for('login', message="Incorrect Username or Password"))
    settoken = result[2]
    c.execute("SELECT veriemail FROM usercred WHERE (username = %s OR email = %s)", [str(username), str(username)])
    result = c.fetchone()
    if result[0] is None:
        conn.close()
        return redirect(url_for('login', message="Please verify your email"))

    conn.close()
    response = make_response(redirect(url_for('mainpage')))

    response.set_cookie("token", settoken)
    return response


@app.route('/validatesignup', methods=['POST', 'GET'])
async def validatesignup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password == confirm_password:
        try:
            conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                    password=os.getenv("sqlpassword"), port=5432)
        except:
            print("Failed to connect user to database. Trying again in 4 seconds", "warning")
            await asyncio.sleep(4)
            return redirect(request.url)
        c = conn.cursor()
        c.execute("SELECT * FROM usercred WHERE username = %s", [str(username.lower())])
        result = c.fetchone()
        if result is None:
            for char in username:
                if char not in valid_chars:
                    conn.close()
                    return redirect(url_for('signup',
                                            message="Invalid character(s) in username (Only letters, numbers and underscores)"))

            c.execute("SELECT * FROM usercred WHERE email = %s", [str(email)])
            result = c.fetchone()
            if result is None:
                for char in password:
                    if char not in valid_pass_chars:
                        conn.close()
                        return redirect(url_for('signup',
                                                message="Invalid character(s) in password (Only letters, numbers and punctuation)"))

                if len(username) < 2 or len(username) > 22:
                    conn.close()
                    return redirect(url_for('signup', message="Username needs to be between 2 - 22 characters"))

                if len(password) < 8 or len(password) > 52:
                    conn.close()
                    return redirect(url_for('signup', message="Password need to be between 8 - 52 characters"))

                sign_up_token = token_generator()
                h = hashlib.new("SHA256")
                h.update(bytes(password, encoding="utf-8"))
                hashed_password = h.hexdigest()
                c.execute("INSERT INTO usercred (username, password, token, email) VALUES (%s, %s, %s, %s)",
                          [username.lower(), hashed_password, sign_up_token, email])
                email_token = token_generator()
                c.execute("INSERT INTO emailtokens (token, email) VALUES (%s, %s)", [email_token, email])
                conn.commit()
                conn.close()
                print(email)
                email_thread = threading.Thread(target=email_alert, args=("Welcome to bubble",
                                                                          f"To get started on Bubble, click this link to verify your email: https://bub.foxthing.xyz/verifyemail?token={email_token}",
                                                                          f"{email}"))
                email_thread.start()
                # system_message(f"{username.lower()} signed up with a invalid email", "error")
                return redirect(url_for('login', message="Check your email for a verification message"))

            elif result is not None:
                conn.close()
                return redirect(url_for('signup', message="Email is taken"))

        elif result is not None:
            conn.close()
            return redirect(url_for('signup', message="Username is taken"))

    elif not password == confirm_password:
        return redirect(url_for('signup', message="Passwords do not match"))


@app.route('/verifyemail')
async def verifyemail():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning")
        await asyncio.sleep(4)
        return redirect(request.url)

    c = conn.cursor()
    if request.args.get('token') is None:
        conn.close()
        return redirect(url_for('login'))
    else:
        email_token = request.args.get('token')
        c.execute("SELECT * FROM emailtokens WHERE token = %s ", [email_token])
        result = c.fetchone()
        if result is None:
            conn.close()
            return redirect(url_for('login'))
        else:
            c.execute("DELETE FROM emailtokens WHERE token = %s", [email_token])
            c.execute("UPDATE usercred SET veriemail = 'YES' WHERE email = %s", [result[1]])
            conn.commit()
            conn.close()
            return redirect(url_for('login', message="Your email has been verified. You can now log in."))


@socketio.on('connect')
def handle_connect():
    global users_online
    print('Client connected')
    users_online += 1
    print(users_online)
    socketio.emit('userconnect', users_online)


@socketio.on('disconnect')
def handel_disconnect():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning", )
        socketio.emit("error", "Server could not contact database, Try again in a few seconds", room=request.sid)
    global users_online
    print('Client disconnected')
    users_online -= 1
    print(users_online)
    token = request.cookies.get("token")
    c = conn.cursor()
    c.execute("SELECT username FROM usercred WHERE token = %s", [str(token)])
    username = c.fetchone()[0]
    socketio.emit('anouconnect', f'{username} just left ):')
    socketio.emit('userdisconnect', users_online)


@socketio.on('announceonline')
def announceonline():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning", )
        socketio.emit("error", "Server could not contact database, Try again in a few seconds", room=request.sid)
    token = request.cookies.get("token")
    c = conn.cursor()
    print(token)
    c.execute("SELECT username FROM usercred WHERE token = %s", [str(token)])
    username = c.fetchone()[0]
    socketio.emit('anouconnect', f'{username} just joined!')

@socketio.on('announceoffline')
def announceonline():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning", )
        socketio.emit("error", "Server could not contact database, Try again in a few seconds", room=request.sid)
    token = request.cookies.get("token")
    c = conn.cursor()
    c.execute("SELECT username FROM usercred WHERE token = %s", [str(token)])
    username = c.fetchone()[0]
    socketio.emit('anouconnect', f'{username} just left ):')




@app.route('/message', methods=["POST", "GET"])
def handle_message():
    try:
        conn = psycopg2.connect(host=os.getenv("sqlhost"), dbname=os.getenv("sqldbname"), user=os.getenv("sqluser"),
                                password=os.getenv("sqlpassword"), port=5432)
    except:
        print("Failed to connect user to database. Trying again in 4 seconds", "warning", )
        socketio.emit("error", "Server could not contact database, Try again in a few seconds", room=request.sid)
    c = conn.cursor()
    global messages
    data = request.json
    print('Received message:', data)
    if data["token"] == '':
        socketio.emit('error', 'Error sending message', room=request.sid)
        conn.close()
    elif data["message"] == '':
        socketio.emit('error', f"You can't say nothing", room=request.sid)
        conn.close()
    else:
        c.execute("SELECT username FROM usercred WHERE token = %s", [str(data["token"])])
        username = c.fetchone()[0]
        if username == '':
            socketio.emit('error', f"Error sending message", room=request.sid)
            conn.close()
        socketio.emit('response',
                      f'<strong><p class="usernamecontent">{bleach.clean(username)}: </p></strong><p class="messagecontent">{bleach.clean(data["message"])}</p>')
        msgstage = f'<div class="messagecontainer"><strong><p class="usernamecontent">{bleach.clean(username)}: </p></strong><p class="messagecontent">{bleach.clean(data["message"])}</p></div>'
        messages = messages + msgstage
        conn.close()
    return "", 201


@app.errorhandler(Exception)
def error(e):
    return render_template("error.html")


if __name__ == '__main__':
    socketio.run(app)
