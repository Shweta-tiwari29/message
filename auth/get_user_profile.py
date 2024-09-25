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

get_user_profile_bp = func.Blueprint()

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

def authenticate_token(token):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS512"])
        user_email = decoded_token['email']
        user = users_collection.find_one({'email': user_email})
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@get_user_profile_bp.route(route="user/profile", auth_level=func.AuthLevel.ANONYMOUS)
def get_user_profile(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing user profile request.')

    try:
        # Extract the JWT token from the request headers
        token = req.headers.get('Authorization')
        if not token:
            return func.HttpResponse('Token is missing.', status_code=400)

        # Remove the 'Bearer ' prefix from the token if it exists
        token = token.replace('Bearer ', '')

        # Authenticate the token and retrieve the user
        user = authenticate_token(token)
        if not user:
            return func.HttpResponse('Invalid or expired token.', status_code=401)

        # Prepare the user response data
        user_data = {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'isEmailVerified': user['isEmailVerified'],
            'online_status': user.get('online_status', 'offline'),
            'friends': user.get('friends', []),
            'chats': user.get('chats', []),
            'last_login': user.get('last_login', None)
        }

        # Return the user profile information
        response_data = {
            'message': 'User profile fetched successfully',
            'user': user_data
        }

        return func.HttpResponse(json.dumps(response_data), mimetype="application/json", status_code=200)

    except Exception as e:
        logging.error(f"An error occurred while fetching user profile: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
