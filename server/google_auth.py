from flask import Blueprint, redirect, url_for, jsonify
from flask_login import login_user
from authlib.integrations.flask_client import OAuth
from app import db
from models import User
from config import Config
import auth_service

google_auth_bp = Blueprint("google_auth", __name__)

oauth = OAuth()
oauth.init_app(db)

# Register the OpenID Connect Client
google = oauth.register(
    name="google",
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    server_metadata_url=Config.GOOGLE_DISCOVERY_URL,  # OIDC Discovery
    client_kwargs={"scope": "openid email profile"},
)

@google_auth_bp.route("/login")
def google_login():
    """Initiates the login with OpenID Connect."""
    redirect_uri = url_for("google_auth.google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@google_auth_bp.route("/callback")
def google_callback():
    """Handles the Google OpenID Connect callback."""
    token = google.authorize_access_token()  # Exchanges code for token
    id_token_str = token.get("id_token")  # Extract ID token for user info

    if not id_token_str:
        return jsonify({"message": "Invalid ID token"}), 400

    try:
        # Validate ID token
        request = requests.Request()
        decoded_token = id_token.verify_oauth2_token(id_token_str, request, Config.GOOGLE_CLIENT_ID)

        # Extract user info from validated token
        email = decoded_token.get("email")
        google_id = decoded_token.get("sub")  # Subject (unique identifier)

        if not email or not google_id:
            return jsonify({"message": "Invalid user info in ID token"}), 400

        # Check if the user exists in the database
        user = User.query.filter_by(email=email).first()
        if not user:
            # Register a new user if not found
            user = auth_service.create_new_user(email, None, google_id, Config.USER_ROLE)

        # Generate JWT for the user
        jwt_token = auth_service.generate_jwt(user)
        return jsonify({"message": "Login successful", "token": jwt_token})

    except ValueError as e:
        # ID token validation failed
        return jsonify({"message": "Invalid ID token", "error": str(e)}), 400
