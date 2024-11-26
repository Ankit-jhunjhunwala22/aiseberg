import os
from io import BytesIO
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flask import jsonify, Response
from flask_jwt_extended import get_jwt_identity
from werkzeug.utils import secure_filename
import boto3
from config import Config
from models import db, FileMetadata

s3_client = boto3.client('s3', region_name=Config.AWS_REGION) # AWS S3 Client Setup

class FileService:
    """Singleton class to handle file upload, encryption, and metadata storage."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        """Ensure that only one instance of FileService exists."""
        if not cls._instance:
            cls._instance = super(FileService, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def encrypt_file(self, file_data):
        """Encrypt the file data."""
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_data = cipher.encrypt(file_data.ljust((len(file_data) // 16 + 1) * 16))  # Pad to multiple of 16
        return encrypted_data, iv

    def decrypt_file(self, encrypted_data, iv):
        """Decrypt the file data."""
        key = get_random_bytes(32)  # This should match the encryption key used during upload
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.rstrip(b"\0")  # Remove padding


    def upload_file(self, file):
            """
            Handles file upload, encryption, and metadata storage with chunked file upload and incremental size checking.
            - File is encrypted before storage.
            - Metadata is stored in MySQL.
            - Encrypted file is stored in S3.
            - Checksum is generated and validated for data integrity.
            """
            try:
                if not file:
                    return jsonify({"error": "No file uploaded"}), 400

                # Extract user information from the JWT
                payload = get_jwt_identity()  # Get user ID from JWT

                # Secure the filename
                filename = secure_filename(file.filename)

                # Create a buffer to accumulate the encrypted data
                encrypted_data_accumulated = BytesIO()

                # Initialize total size of the file
                total_file_size = 0

                # Initialize the checksum generator (SHA256)
                checksum = hashlib.sha256()

                # Read the file in chunks
                while chunk := file.read(1024 * 1024):  # 1 MB chunks
                    chunk_size = len(chunk)
                    total_file_size += chunk_size

                    # Check if total size exceeds 5 MB
                    if total_file_size > Config.FILE_SIZE_LIMIT * 1024 * 1024:  # 5 MB
                        return jsonify({"error": "File exceeds the maximum size of 5 MB"}), 400

                    # Update checksum with the chunk
                    checksum.update(chunk)

                    # Encrypt the chunk
                    encrypted_chunk, iv = self.encrypt_file(chunk)

                    # Accumulate encrypted data
                    encrypted_data_accumulated.write(encrypted_chunk)

                # Finalize the encrypted file data
                encrypted_data = encrypted_data_accumulated.getvalue()

                # Store checksum as part of file metadata (in hex format)
                file_checksum = checksum.hexdigest()

                # Store file metadata in MySQL
                file_metadata = FileMetadata(
                    filename=filename,
                    upload_date=datetime.utcnow(),
                    owner_id=payload.user_id,  # Associate file with the uploader
                    iv=base64.b64encode(iv).decode('utf-8'),
                    checksum=file_checksum  # Store checksum
                )
                db.session.add(file_metadata)
                db.session.commit()

                # Store the encrypted file in S3
                s3_bucket_name = Config.AWS_S3_BUCKET_NAME
                file_key = f"encrypted/{file_metadata.id}_{filename}"
                s3_client.put_object(Body=encrypted_data, Bucket=s3_bucket_name, Key=file_key)

                return jsonify({"message": "File uploaded successfully", "file_id": file_metadata.id}), 201

            except Exception as e:
                return jsonify({"error": f"Failed to upload the file: {str(e)}"}), 500


    def view_file(self, file_id):
            """
            Retrieve and decrypt a file by ID:
            - Admins (VIEW_ALL_PERMISSION) can view any file.
            - Regular users (VIEW_OWN_PERMISSION) can only view files they own.
            - Verifies file integrity using checksum.
            """
            try:
                # Extract user identity and permissions from JWT
                payload = get_jwt_identity()
                current_user_id = payload.user_id

                # Retrieve file metadata
                file_metadata = FileMetadata.query.get(file_id)
                if not file_metadata:
                    return jsonify({'error': 'File not found'}), 404

                # Check permissions (VIEW_ALL_PERMISSION for Admin, VIEW_OWN_PERMISSION for regular users)
                if Config.VIEW_OWN_PERMISSION in [perm.name for perm in User.query.get(current_user_id).permissions]:
                    if file_metadata.owner_id != current_user_id:
                        return jsonify({'error': 'You can only view your own files.'}), 403

                # Retrieve the encrypted file from S3
                s3_bucket_name = Config.AWS_S3_BUCKET_NAME
                file_key = f"encrypted/{file_metadata.id}_{file_metadata.filename}"
                encrypted_data = s3_client.get_object(Bucket=s3_bucket_name, Key=file_key)['Body'].read()

                # Decrypt the file data
                decrypted_data = self.decrypt_file(encrypted_data, base64.b64decode(file_metadata.iv))

                # Compute checksum of the decrypted data
                checksum = hashlib.sha256()
                checksum.update(decrypted_data)
                calculated_checksum = checksum.hexdigest()

                # Compare with stored checksum
                if calculated_checksum != file_metadata.checksum:
                    return jsonify({'error': 'File integrity verification failed. Data may have been altered.'}), 400

                # Return the decrypted file content as a binary stream
                return Response(
                    decrypted_data,
                    content_type='application/octet-stream',  # Modify this based on actual file type
                    headers={"Content-Disposition": f"attachment; filename={file_metadata.filename}"}
                ), 200

            except s3_client.exceptions.NoSuchKey:
                return jsonify({'error': 'File not found in storage'}), 404
            except Exception as e:
                return jsonify({'error': f'Failed to retrieve or decrypt the file: {str(e)}'}), 500


    def view_all_files(self):
            """
            Retrieve metadata for all files accessible to the user.
            If the user has 'VIEW_ALL_PERMISSION', all files are shown.
            Otherwise, only files owned by the user are displayed.
            Includes checksum verification for file integrity.
            """
            try:
                payload = get_jwt_identity()  # Extract the user's identity from the token
                current_user_id = payload.get('user_id')

                # Retrieve the current user from the database
                current_user = User.query.get(current_user_id)
                if not current_user:
                    return jsonify({'error': 'User not found'}), 404

                roles = current_user.get('roles', [])
                permissions = current_user.get('permissions', [])

                # Check if the user has 'VIEW_ALL_PERMISSION'
                if Config.VIEW_ALL_PERMISSION in permissions:
                    # Retrieve all files in the system
                    files = FileMetadata.query.all()
                else:
                    # Retrieve only files owned by the current user
                    files = FileMetadata.query.filter_by(owner_id=current_user_id).all()

                if not files:
                    return jsonify({'message': 'No files found'}), 404

                # Serialize metadata for response
                files_data = []
                for file in files:
                    # Retrieve the encrypted file from S3
                    s3_bucket_name = Config.AWS_S3_BUCKET_NAME
                    file_key = f"encrypted/{file.id}_{file.filename}"

                    try:
                        encrypted_data = s3_client.get_object(Bucket=s3_bucket_name, Key=file_key)['Body'].read()

                        # Calculate checksum for the encrypted file data
                        checksum = hashlib.sha256()
                        checksum.update(encrypted_data)
                        calculated_checksum = checksum.hexdigest()

                        # Compare with stored checksum
                        if calculated_checksum != file.checksum:
                            files_data.append({
                                'id': file.id,
                                'filename': file.filename,
                                'checksum_status': 'Integrity check failed',
                            })
                        else:
                            files_data.append({
                                'id': file.id,
                                'filename': file.filename,
                                'checksum_status': 'Integrity check passed',
                            })

                    except Exception as e:
                        files_data.append({
                            'id': file.id,
                            'filename': file.filename,
                            'checksum_status': f'Error fetching or verifying checksum: {str(e)}'
                        })

                return jsonify({'files': files_data}), 200

            except Exception as e:
                return jsonify({'error': f'Failed to retrieve files: {str(e)}'}), 500


# Usage
file_service = FileService()  # Always returns the same instance