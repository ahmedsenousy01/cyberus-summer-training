from flask import Flask, send_from_directory, jsonify, request, current_app
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
from src.models.User import User
from src.models.Post import Post
from src.middleware.jwt_middleware import jwt_required
import jwt
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "public"))
app.config.from_pyfile("config.py")
CORS(app)
db.init_app(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

#
# User Routes
#
@app.route('/api/users/register', methods=["POST"])
def register_user():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    password_hash = generate_password_hash(password)

    # Perform validation and create a new user
    user = User(name=name, email=email, password_hash=password_hash, role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/users/login', methods=["POST"])
@limiter.limit('20 per minute')
def login_user():
    data = request.get_json()
    email = data.get('email')
    password =data.get('password')

    # Check if the user exists in the database
    user = User.query.filter_by(email=email).first()
    if not (user and check_password_hash(user.password_hash, password)):
        return jsonify({'message': 'Invalid email or password'}), 401

    # Generate a JWT token
    secret = current_app.config.get("JWT_SECRET_KEY")
    payload = {'id': user.id, 'role': user.role}
    token = jwt.encode(payload, secret, algorithm='HS256')

    return jsonify({'message': 'success','token': token}), 200


@app.route('/api/users/', methods=['GET'])
@jwt_required
def get_all_users(decoded_token):
    users = User.query.all()
    response = [{'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role} for user in users]
    return jsonify(response)

@app.route('/api/users/<int:id>', methods=["GET"])
@jwt_required
def get_user_by_id(id, decoded_token):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    response = {'id': user.id, 'name': user.name, 'email': user.email, 'role': user.role}
    return jsonify(response)


@app.route('/api/users/<int:id>', methods=["DELETE"])
@jwt_required
def delete_user(id, decoded_token):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if decoded_token['role'] != 'admin':
        return jsonify({'message': 'You don\'t have the privilege to perform this action'}), 401

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'}), 200


@app.route('/api/users/<int:id>', methods=["PUT"])
@jwt_required
def update_user(id, decoded_token):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if decoded_token['role'] != 'admin':
        return jsonify({'message': 'You don\'t have the previlege to perform this action'}), 401

    data = request.get_json()
    user.name = data.get('name')
    user.email = data.get('email')
    user.role = data.get('role')

    db.session.commit()

    return jsonify({'message': 'User updated successfully'}), 200


#
# Post Routes
#
@app.route('/api/posts/', methods=["POST"])
@jwt_required
def create_post(decoded_token):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    user_id = decoded_token.get('id')  # Get user ID from decoded token

    user = User.query.get(user_id)
    if user:
        post = Post(title=title, content=content, created_by=user.id)
        db.session.add(post)
        db.session.commit()
        return jsonify({'message': 'Post created successfully'}), 201

    return jsonify({'message': 'User not found'}), 404


@app.route('/api/posts/', methods=["GET"])
def get_all_posts():
    posts = Post.query.all()
    response = [{'id': post.id, 'title': post.title, 'content': post.content, 'created_by': post.created_by} for post in posts]
    return jsonify(response)

@app.route('/api/posts/my', methods=['GET'])
@jwt_required
def get_my_posts(decoded_token):
    posts = Post.query.filter_by(created_by=decoded_token.get('id')).all()
    response = [{'id': post.id, 'title': post.title, 'content': post.content, 'created_by': post.created_by} for post in posts]
    return jsonify(response)

@app.route('/api/posts/<int:id>', methods=["GET"])
def get_post_by_id(id):
    post = Post.query.get(id)
    if not post:
        return jsonify({'message': 'Post not found'}), 404

    response = {'id': post.id, 'title': post.title, 'content': post.content}
    return jsonify(response)

@app.route('/api/posts/<int:id>', methods=["PUT"])
@jwt_required
def update_post(id, decoded_token):
    post = Post.query.get(id)
    if not post:
        return jsonify({'message': 'Post not found'}), 404

    data = request.get_json()
    if (decoded_token['id'] == post.created_by) or (decoded_token['role'] == 'admin'):
        post.title = data.get('title')
        post.content = data.get('content')
        db.session.commit()
        return jsonify({'message': 'Post updated successfully'}), 200

    return jsonify({'message': 'You do not have permission to edit this post'}), 403



@app.route('/api/posts/<int:id>', methods=["DELETE"])
@jwt_required
def delete_post(id, decoded_token):
    post = Post.query.get(id)
    if not post:
        return jsonify({'message': 'Post not found'}), 404

    if (decoded_token['id'] == post.created_by) or (decoded_token['role'] == 'admin'):
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200

    return jsonify({'message': 'You do not have permission to delete this post'}), 403


# Serve the frontend app (ReactJs)
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if not path or not os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, 'index.html')
    return send_from_directory(app.static_folder, path)


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    response = jsonify({'error': error.name, 'message': error.description})
    response.status_code = error.code
    return response

if(__name__ == '__main__'):
    with app.app_context():
        db.create_all()
    app.run(debug=True)
