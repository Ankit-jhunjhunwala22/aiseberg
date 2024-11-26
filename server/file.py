from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import file_service
import auth_service

file_upload_bp = Blueprint('files', __name__)

@file_upload_bp.route('/upload', methods=['POST'])
@jwt_required()
@auth_service.permission_required(Config.UPLOAD_PERMISSION)
def upload_file():
    """Handles file upload."""
    file = request.files.get('file')
    # Call the file upload method
    return file_service.upload_file(file)

@file_upload_bp.route('/<file_id>', methods=['GET'])
@jwt_required()
@auth_service.permission_required(Config.VIEW_ALL_PERMISSION, Config.VIEW_OWN_PERMISSION)
def view_file(file_id):
    """View a file by ID."""
    return file_service.view_file(file_id)


@file_upload_bp.route('', methods=['GET'])
@jwt_required()
@auth_service.permission_required(Config.VIEW_ALL_PERMISSION, Config.VIEW_OWN_PERMISSION)
def view_all_file():
    """View a file by ID."""
    return file_service.view_all_files()