from flask import Flask, request, jsonify, g
import sqlite3, bcrypt, os, jwt
from datetime import datetime, timedelta
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)

secret_key = os.urandom(24)
app.config['SECRET_KEY'] = secret_key # for session encryption

# connect to the SQLite database
conn = sqlite3.connect('ums.db')
cursor = conn.cursor()

# create the user and tasks table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        due_date TEXT,
        status TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')
conn.commit()
conn.close()


# db connection functions

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('ums.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()


# user authentication decorator
def authenticate_user(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            kwargs['user_id'] = decoded_token['user_id']
            return func(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token.'}), 401

    wrapper.__name__ = func.__name__
    return wrapper


# register new user
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    # hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists.'}), 400

    return jsonify({'message': 'User registered successfully.'}), 201


# login user
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'Invalid username or password.'}), 401

    # verify the password

    if bcrypt.checkpw(str(password).encode('utf-8'), user[2]):
        # generate a token
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'exp': datetime.utcnow() + timedelta(hours=5)  # token expires in 5 hour
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token}), 200
    return jsonify({'error': 'Invalid username or password.'}), 401


# add a new task
@app.route('/tasks', methods=['POST'])
@authenticate_user
def create_task(user_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    due_date = data.get('due_date')
    status = data.get('status')

    if not title:
        return jsonify({'error': 'Title is required.'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO tasks (title, description, due_date, status, user_id) VALUES (?, ?, ?, ?, ?)',
            (title, description, due_date, status, user_id)
        )
        db.commit()
        task_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Invalid user.'}), 400

    return jsonify({'message': 'Task created successfully.', 'task_id': task_id}), 201


# get a particular task
@app.route('/tasks/<int:task_id>', methods=['GET'])
@authenticate_user
def get_task(user_id, task_id):
    # retrieve a single task by its ID and check if it belongs to the user
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id))
    task = cursor.fetchone()

    if not task:
        return jsonify({'error': 'Task not found.'}), 404

    # convert the task tuple into a dictionary
    task_dict = {
        'id': task[0],
        'title': task[1],
        'description': task[2],
        'due_date': task[3],
        'status': task[4]
    }

    return jsonify(task_dict), 200

# update a particular task
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@authenticate_user
def update_task(user_id, task_id):
    # retrieve the task from the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id))
    task = cursor.fetchone()

    if not task:
        return jsonify({'error': 'Task not found.'}), 404

    # parse the request data
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    due_date = data.get('due_date')
    status = data.get('status')

    # update the task in the database
    cursor.execute('UPDATE tasks SET title = ?, description = ?, due_date = ?, status = ? WHERE id = ?',
                   (title, description, due_date, status, task_id))
    db.commit()

    return jsonify({'message': 'Task updated successfully.'}), 200


# delete a tsak 
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@authenticate_user
def delete_task(user_id, task_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id))
    task = cursor.fetchone()

    if not task:
        return jsonify({'error': 'Task not found.'}), 404
    
    # delete the task from the database
    cursor.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    db.commit()

    return jsonify({'message': 'Task deleted successfully.'}), 200


# get all tasks for a user
@app.route('/tasks', methods=['GET'])
@authenticate_user
def list_tasks(user_id):
    # pagination
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    offset = (page - 1) * per_page

    # retrieve all tasks
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM tasks WHERE user_id = ? LIMIT ? OFFSET ?', (user_id, per_page, offset))
    tasks = cursor.fetchall()

    task_list = []
    for task in tasks:
        task_dict = {
            'id': task[0],
            'title': task[1],
            'description': task[2],
            'due_date': task[3],
            'status': task[4]
        }
        task_list.append(task_dict)

    return jsonify(task_list), 200


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found.'}), 404


# admin to see all users
@app.route('/admin', methods=['POST'])
def main_admin():
    data = request.get_json()
    admin_username = data.get('admin_username')
    admin_password = data.get('admin_password')

    if admin_username != "admin" or admin_password != "12345":
        return jsonify({'error': 'Invalid Credentials'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'username': str(user[1]),
            'password': str(user[2])
        })
    print(user_list)
    return jsonify(user_list), 201


if __name__ == '__main__':
    app.run()
