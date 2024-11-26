from datetime import datetime, timedelta
from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import User, Role, UserRole, db  # Assuming appropriate models exist
import jwt


class AuthService:
    """Authentication service"""

    _instance = None  # Class-level instance variable

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AuthService, cls).__new__(cls)
        return cls._instance

    @staticmethod
    def generate_access_token(user_id):
        """Generate an access token with roles and user data."""
        return create_access_token(
            identity={
                "user_id": user.id,
            },
            expires_delta=timedelta(hours=Config.ACCESS_TOKEN_TTL),
        )

    @staticmethod
    def generate_refresh_token(user_id):
        """Generate a refresh token."""
        return create_refresh_token(identity={"user_id": user.id}, expires_delta=timedelta(hours=Config.REFRESH_TOKEN_TTL),)


    @staticmethod
    def has_permission(user, required_permission):
        """
        Checks if a user has a specific permission based on their role.
        
        Args:
            user (User): The user object (assumes it includes roles and permissions).
            required_permission (str): The permission required for the operation.
        
        Returns:
            bool: True if the user has the required permission, False otherwise.
        """
        if not user:
            return False

        # Retrieve user roles
        user_roles = user.roles
        for role in user_roles:
            if required_permission in role.permissions:
                return True

        return False

    @staticmethod
    def permission_required(*required_permissions):
        """
        A decorator to enforce permission checks for multiple possible permissions.

        Args:
            *required_permissions (str): A list of permissions where having any one of them suffices.
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                payload = get_jwt_identity()  # Get user ID from JWT
                user = User.query.get(payload.user_id)  # Fetch user from the database

                # Check if user has at least one required permission
                if not any(self.has_permission(user, permission) for permission in required_permissions):
                    return jsonify({"error": "You do not have permission to access this resource."}), 403

                return f(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def role_required(required_roles):
        """
        A decorator to enforce role checks. Allows access only if the user has one of the required roles.

        Args:
            required_roles (list): A list of roles that are allowed to access the endpoint.
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                payload = get_jwt_identity()  # Get user ID from JWT
                user = User.query.get(payload.user_id)  # Fetch the user from the database
                # Check if the user has one of the required roles
                user_roles = [role.name for role in user.roles]
                if not any(role in user_roles for role in required_roles):
                    return jsonify({"error": "You do not have permission to access this resource."}), 403

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def is_admin(self):
        """Check if the current user is an admin."""
        payload = get_jwt_identity()  # Get user ID from JWT
        current_user = User.query.get(payload.user_id)  # Fetch the user from the database
        roles = current_user.get("roles", [])
        return Config.ADMIN_ROLE in roles

    def register_user(self, email, password, role_name=Config.USER_ROLE):
        """Register a new user."""
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Check if the user exists
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "User with this email already exists"}), 400

        # Assign default role if not provided
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' does not exist"}), 400

        # Hash the password and save the user
        hashed_password = generate_password_hash(password)
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Assign role
        user_role = UserRole(user_id=user.id, role_id=role.id)
        db.session.add(user_role)
        db.session.commit()

        return jsonify({"message": "User registered successfully."}), 201


    def assign_role(self, target_user_id, role_names):
        """Assign a role to a user."""
        if not self.is_admin():
            return jsonify({"error": "You are not authorized to assign roles."}), 403

        target_user = User.query.get(target_user_id)
        roles = Role.query.filter(Role.name.in_(role_names)).all()
        if len(roles) != len(role_names):
            return jsonify({"error": "One or more roles not found"}), 404
        
        # Assign roles to user
        for role in roles:
            if role not in user.roles:
                user.roles.append(role)
        
        db.session.commit()
        return jsonify({"message": f"Roles {role_names} assigned to user."}), 200


    def login_with_email_password(self, email, password):
        """Authenticate a user with email and password."""
        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"message": "Invalid credentials"}), 401

        # Handle account lockout
        now = datetime.utcnow()
        if user.is_locked and user.last_failed_attempt + timedelta(minutes=Config.LOCKOUT_DURATION) > now:
            return jsonify({"message": "Account is locked. Try again later."}), 403

        if not check_password_hash(user.password, password):
            user.failed_attempts += 1
            user.last_failed_attempt = now
            if user.failed_attempts >= Config.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
            db.session.commit()
            return jsonify({"message": "Invalid credentials"}), 401

        # Reset failed attempts and lock status on successful login
        user.failed_attempts = 0
        user.is_locked = False
        db.session.commit()

        # Generate tokens
        access_token = self.generate_access_token(user.id)
        refresh_token = self.generate_refresh_token(user.id)

        return jsonify({"message": "Login successful", "access_token": access_token, "refresh_token": refresh_token})

    def refresh_tokens(self, refresh_token):
        """Generate new access and refresh tokens."""
        try:
            decoded = jwt.decode(refresh_token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            user_id = decoded.get("user_id")
            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "Invalid refresh token."}), 401

            new_access_token = self.generate_access_token(user.id)
            new_refresh_token = self.generate_refresh_token(user.id)

            return jsonify({"access_token": new_access_token, "refresh_token": new_refresh_token})

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Refresh token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid refresh token."}), 401

    def request_password_reset(self, email):
        """Send a password reset link."""
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"message": "User with this email does not exist."}), 404

        reset_token = jwt.encode(
            {"user_id": user.id, "exp": datetime.utcnow() + timedelta(minutes=30)},
            Config.JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM,
        )

        # Simulate email sending
        print(f"Password reset link: http://localhost:5000/reset-password?token={reset_token}")

        return jsonify({"message": "Password reset link sent to your email."}), 200

    def reset_password(self, reset_token, new_password):
        """Reset the user's password."""
        try:
            decoded = jwt.decode(reset_token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            user_id = decoded.get("user_id")

            user = User.query.get(user_id)
            if not user:
                return jsonify({"message": "Invalid token."}), 400

            user.password = generate_password_hash(new_password)
            db.session.commit()

            return jsonify({"message": "Password reset successfully."}), 200

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired."}), 400
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token."}), 400


# Usage
auth_service = AuthService()  # Always returns the same instance