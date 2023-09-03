import jwt
from functools import wraps
from flask import request, jsonify, current_app

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Missing JWT token'}), 401

        # Extracting the token from the 'Bearer <token>' format
        token = token.split(' ')[1] if len(token.split(' ')) > 1 else None

        if not token:
            return jsonify({'message': 'Invalid JWT token'}), 401

        # Verifying the token using the secret from app.config
        secret = current_app.config.get('JWT_SECRET_KEY')

        if not secret:
            return jsonify({'message': 'JWT secret not found in configuration'}), 500

        try:
            # Verify the token using the secret
            decoded_token = jwt.decode(token, secret, algorithms=['HS256'])
            
        except jwt.exceptions.InvalidTokenError as e:
            return jsonify({'message': 'Invalid JWT token', 'error': str(e)}), 401

        # Pass the decoded token to the decorated function
        kwargs['decoded_token'] = decoded_token
        return f(*args, **kwargs)

    return decorated_function