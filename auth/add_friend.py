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

add_friend_bp = func.Blueprint()

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

@add_friend_bp.route(route="user/add-friend", auth_level=func.AuthLevel.ANONYMOUS)
def add_friend(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing add friend request.')

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

        # Get the friend’s email or username from the request body
        req_body = req.get_json()
        friend_email = html.escape(req_body.get('friend_email', '').strip())
        friend_username = html.escape(req_body.get('friend_username', '').strip())

        # Validation checks
        if not friend_email and not friend_username:
            return func.HttpResponse('Please provide either a friend\'s email or username.', status_code=400)

        # Find the friend in the database by email or username
        query = {'$or': []}
        if friend_email:
            query['$or'].append({'email': friend_email})
        if friend_username:
            query['$or'].append({'username': friend_username})

        friend = users_collection.find_one(query)
        if not friend:
            return func.HttpResponse('Friend not found.', status_code=404)

        # Check if the friend is already in the user's friends list
        if friend['_id'] in user.get('friends', []):
            return func.HttpResponse('Friend is already in your friends list.', status_code=400)

        # Add the friend to the user's friends list
        users_collection.update_one(
            {'email': user['email']},
            {'$addToSet': {'friends': friend['_id']}}
        )

        return func.HttpResponse('Friend added successfully.', status_code=200)

    except Exception as e:
        logging.error(f"An error occurred while adding friend: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
