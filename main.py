from flask import Flask, render_template, request
from flask_socketio import SocketIO
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your own secret key

socketio = SocketIO(app)

messages = ''

@app.route('/')
def index():
    return render_template('index.html', msgs=messages)

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('userconnect')

@socketio.on('disconnect')
def handel_disconnect():
    print('Client disconnected')
    socketio.emit('userdisconnect')

@socketio.on('message')
def handle_message(data):
    global messages
    print('Received message:', data)
    if data["user"] == '':
        socketio.emit('error', 'You need a username to chat', room=request.sid)
    elif data["message"] == '':
        socketio.emit('error', f"You can't say nothing {request.remote_addr}", room=request.sid)
    else:
        socketio.emit('response', f'{bleach.clean(data["user"])}: {bleach.clean(data["message"])}')
        msgstage = f'<p class="message">{bleach.clean(data["user"])}: {bleach.clean(data["message"])}</p>'
        messages = msgstage + messages

if __name__ == '__main__':

    socketio.init_app(app, allow_unsafe_werkzeug=True, cors_allowed_origins="*")