from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Nullable for Google users
    is_locked = db.Column(db.Boolean, default=False)
    google_id = db.Column(db.String(200), nullable=True)  # Google user identifier

    # Fields for account lockout mechanism
    failed_attempts = db.Column(db.Integer, default=0)  # Number of failed attempts
    last_failed_attempt = db.Column(db.DateTime, nullable=True)  # Time of last failure

    roles = db.relationship('Role', secondary='user_roles')

    refresh_token = db.Column(db.String(128), nullable=True)
    refresh_token_expiry = db.Column(db.DateTime, nullable=True)

class UserRole(db.Model):
    __tablename__ = 'user_roles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary='role_permissions')

class Permission(db.Model):
    __tablename__ = 'permission'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'

    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False)



class FileMetadata(db.Model):
    __tablename__ = 'file_metadata'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255), nullable=False)  # Original file name
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to the uploading user
    upload_date = db.Column(db.DateTime, nullable=False)  # File upload timestamp
    iv = db.Column(db.String(64), nullable=False)  # Initialization vector for encryption
    s3_url = db.Column(db.String(512), nullable=False)  # Encrypted file location in S3
    owner = db.relationship('User', backref=db.backref('files', lazy=True))
    checksum = db.Column(db.String(64), nullable=False) 