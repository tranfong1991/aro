from flask import Flask, request, abort, jsonify, g, url_for
from flask.ext.httpauth import HTTPBasicAuth
from models import User
from database import init_db, db_session

app = Flask(__name__)
app.config['SECRET_KEY'] = '102030405060708090'
auth = HTTPBasicAuth()


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/')
def hello_world():
    # db_session.query(User).filter_by(username='test').delete()
    # db_session.commit()
    # u = User('test', 'email')
    # db_session.add(u)
    # db_session.commit()
    users = db_session.query(User).all()
    for user in users:
        print(repr(user))
    return repr(users)


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # existing user
    user = User(username=username)
    user.hash_password(password)
    db_session.add(user)
    db_session.commit()
    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


if __name__ == '__main__':
    app.run(debug=True)
    init_db()
