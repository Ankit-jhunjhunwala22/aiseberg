class Config:
    SECRET_KEY = "your_secret_key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///auth_system.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Google OpenID Connect
    GOOGLE_CLIENT_ID = "your_google_client_id"
    GOOGLE_CLIENT_SECRET = "your_google_client_secret"
    GOOGLE_DISCOVERY_URL = (
        "https://accounts.google.com/.well-known/openid-configuration"
    )

    # JWT Configurations
    JWT_SECRET = "your_jwt_secret"
    JWT_ALGORITHM = "HS256"

    MAX_FAILED_ATTEMPTS = 5  # Maximum allowed failed attempts
    LOCKOUT_DURATION = 15  # Lockout period in minutes

    USER_ROLE = "User"
    ADMIN_ROLE = "Admin"

    VIEW_OWN_PERMISSION = "View_own"
    VIEW_ALL_PERMISSION = "View_all"
    UPLOAD_PERMISSION = "Upload"

    ACCESS_TOKEN_TTL = 1 # unit is in hour
    REFRESH_TOKEN_TTL = 168 # unit is in hour

    FILE_SIZE_LIMIT = 5 # UNIT IN MB