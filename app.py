from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")
    
    db.init_app(app)
    login_manager.init_app(app)

    from server.auth import auth_bp
    from server.google_auth import google_auth_bp
    from server.google_auth import file_upload_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(google_auth_bp, url_prefix="/google")
    app.register_blueprint(file_upload_bp, url_prefix="/files")

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)