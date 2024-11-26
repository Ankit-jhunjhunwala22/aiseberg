import jwt
import auth_service
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, jwt_refresh_token_required
from app import db
from models import User
from config import Config

auth_bp = Blueprint("auth", __name__)

#register with email/password
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    return auth_service.register_user(data)

#assign role if required
@jwt_required()
@app.route('/assign-role', methods=['POST'])
@auth_service.role_required([Config.ADMIN_ROLE])
def assign_role():
    data = request.get_json()
    user_id = data.get('user_id')
    role_names = data.get('role_names', [])
    if not role_names:
        return jsonify({"error": "No roles specified"}), 400
    
    return auth_service.assign_role(target_user_id, role_names)

#login via email and password
@auth_bp.route("/login", methods=["POST"])
def login():
    """Handle email/password login with automatic lockout."""
    email = request.json.get("email")
    password = request.json.get("password")
    return auth_service.login_with_email_password(email, password)


@auth_bp.route("/refresh", methods=["POST"])
@jwt_refresh_token_required
def refresh_token():
    """
    Handle refresh token requests to issue a new access token and optionally a new refresh token.
    """
    # Get the current user's identity from the refresh token
    payload = get_jwt_identity()  # Get user ID from JWT

    # Create a new access token
    new_access_token = auth_service.generate_access_token(payload.user_id)

    # Optionally create a new refresh token
    new_refresh_token = auth_service.generate_refresh_token(payload.user_id)

    return jsonify({
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }), 200


# Password Reset: Request
@auth_bp.route("/password-reset-request", methods=["POST"])
def password_reset_request():
    """Generate and send a password reset token, only for email sign-up users."""
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    # Check if the user registered via email (i.e., no Google ID)
    if user.google_id is not None:
        return jsonify({"error": "Password reset is not available for Google sign-in users"}), 400

    return auth_service.request_password_reset(email)


# Password Reset: Update Password
@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """Reset the user's password."""
    reset_token = request.json.get("token")
    new_password = request.json.get("password")
    return auth_service.reset_password(reset_token, new_password)