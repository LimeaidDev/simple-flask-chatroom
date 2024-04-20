from flask import Flask, render_template, request
from flask_socketio import SocketIO
import bleach
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your own secret key

valid_chars = "".join([string.digits, string.ascii_letters, "_"])
valid_pass_chars = "".join([string.digits, string.ascii_letters, string.punctuation])

socketio = SocketIO(app)

messages = ''

users_online = 0

@app.route('/login')


@app.route('/')
def index():
    return render_template('home.html', msgs=messages, users=users_online, usersnum=users_online)

@socketio.on('connect')
def handle_connect():
    global users_online
    print('Client connected')
    users_online += 1
    print(users_online)
    socketio.emit('userconnect', users_online)

@socketio.on('disconnect')
def handel_disconnect():
    global users_online
    print('Client disconnected')
    users_online -= 1
    print(users_online)
    socketio.emit('userdisconnect', users_online)

@socketio.on('message')
def handle_message(data):
    global messages
    print('Received message:', data)
    if data["user"] == '':
        socketio.emit('error', 'You need a username to chat', room=request.sid)
    elif data["message"] == '':
        socketio.emit('error', f"You can't say nothing", room=request.sid)
    else:
        invalid_user = False
        for char in data["user"]:
            if char not in valid_chars:
                invalid_user = True
        if invalid_user == True:
            socketio.emit('error', 'Your username is invalid', room=request.sid)
        else:
            socketio.emit('response', f'<strong><p class="usernamecontent">{bleach.clean(data["user"])}: </p></strong><p class="messagecontent">{bleach.clean(data["message"])}</p>')
            msgstage = f'<div class="messagecontainer"><strong><p class="usernamecontent">{bleach.clean(data["user"])}: </p></strong><p class="messagecontent">{bleach.clean(data["message"])}</p></div>'
            messages = messages + msgstage

if __name__ == '__main__':

    socketio.run(app)