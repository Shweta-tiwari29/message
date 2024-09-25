import azure.functions as func
from auth.login import login_bp
from auth.signup import signup_bp
from auth.logout import logout_bp  # Importing logout blueprint
from auth.get_user_profile import get_user_profile_bp  # Importing get user profile blueprint
from auth.add_friend import add_friend_bp  # Importing add friend blueprint
from auth.send_message import send_message_bp  # Importing send message blueprint
from auth.fetch_chats import fetch_chats_bp  # Importing fetch chats blueprint

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

## Authentication Functions
app.register_functions(login_bp)
app.register_functions(signup_bp)

## User Management Functions
app.register_functions(logout_bp)  # Register logout function
app.register_functions(get_user_profile_bp)  # Register get user profile function
app.register_functions(add_friend_bp)  # Register add friend function
app.register_functions(send_message_bp)  # Register send message function
app.register_functions(fetch_chats_bp)  # Register fetch chats function
