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

send_message_bp = func.Blueprint()

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

@send_message_bp.route(route="user/send-message", auth_level=func.AuthLevel.ANONYMOUS)
def send_message(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing send message request.')

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

        # Get the message details from the request body
        req_body = req.get_json()
        recipient_email = html.escape(req_body.get('recipient_email', '').strip())
        message_content = req_body.get('message', '').strip()

        # Validation checks
        if not recipient_email or not message_content:
            return func.HttpResponse('Recipient email and message content are required.', status_code=400)

        # Find the recipient in the database
        recipient = users_collection.find_one({'email': recipient_email})
        if not recipient:
            return func.HttpResponse('Recipient not found.', status_code=404)

        # Create a message object
        message = {
            'sender_id': str(user['_id']),
            'recipient_id': str(recipient['_id']),
            'content': message_content,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Store the message in the user's chats (you may want to store this in a separate messages collection)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$addToSet': {'chats': message}}
        )

        # Optionally, store the message in the recipient's chats as well
        users_collection.update_one(
            {'_id': recipient['_id']},
            {'$addToSet': {'chats': message}}
        )

        return func.HttpResponse('Message sent successfully.', status_code=200)

    except Exception as e:
        logging.error(f"An error occurred while sending message: {e}")
        return func.HttpResponse(f"An error occurred: {e}", status_code=500)
