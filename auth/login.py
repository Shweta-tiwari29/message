import azure.functions as func
import logging
import json
import jwt
import bcrypt
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import os
import html

if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

login_bp = func.Blueprint()

# Load environment variables
MONGO_URI = os.environ.get('MONGO_URI')
JWT_SECRET = os.environ.get('JWT_SECRET')

if not MONGO_URI or not JWT_SECRET:
    raise ValueError("MONGO_URI and JWT_SECRET must be set in environment variables.")

DB_NAME = "organic"
COLLECTION_NAME = "users"

# Connect to MongoDB
mongo_client = MongoClient(MONGO_URI)
db = mongo_client[DB_NAME]
users_collection = db[COLLECTION_NAME]

@login_bp.route(route="login", auth_level=func.AuthLevel.ANONYMOUS)
def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse('Invalid JSON input', status_code=400)

    email = html.escape(req_body.get('email', '').strip())
    password = req_body.get('password', '').strip()

    # Validation checks for email and password
    if not email or not password:
        return func.HttpResponse('Please provide an email and password.', status_code=400)

    try:
        # Check if user exists using parameterized query
        user = users_collection.find_one({'email': email})
        if not user:
            return func.HttpResponse('User not found.', status_code=401)

        # Compare password with hashed password in the database
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return func.HttpResponse('Invalid credentials.', status_code=401)

        # Update user's online status and last login time
        current_time = datetime.now(timezone.utc)
        users_collection.update_one(
            {'email': email},
            {'$set': {'online_status': 'online', 'last_login': current_time}}
        )

        # Generate JWT for the authenticated user
        token = jwt.encode({
            'userId': str(user['_id']),
            'email': email,
            'exp': current_time + timedelta(days=2)
        }, JWT_SECRET, algorithm='HS512')

        # Prepare the user response data
        user_data = {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'isEmailVerified': user['isEmailVerified'],
            'friends': user.get('friends', []),
            'chats': user.get('chats', []),
            'online_status': 'online',  # Set to online since user just logged in
            'last_login': current_time.isoformat()
        }
        
        # Add isAdmin field only if the user is an admin
        if user.get('isAdmin'):
            user_data['isAdmin'] = True

        # Return the token and user information
        response_data = {
            'message': 'Login successful',
            'token': token,
            'user': user_data
        }

        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
