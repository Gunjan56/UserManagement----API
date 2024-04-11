import os
from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.main.validators.validators import Validators
from app.utils.allowed_file import allowed_file
from app.utils.error_response import error_response
from app.utils.success_response import success_response
from werkzeug.utils import secure_filename
from app.model.model import db, User

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        error_response(404, 'User not found')

    if request.method == 'GET':
        followers_count = user.count_followers()
        following_count = user.count_following()

        return jsonify({
            'username': user.username,
            'email': user.email,
            'profile_picture': user.profile_picture,
            'followers': followers_count,
            'following': following_count
        }), 200
  
    elif request.method == 'PUT':
        data = request.json

        validation_result = Validators.check_profile_update_required_fields(data)
        if validation_result["status"] != 200:
            return jsonify(validation_result), validation_result["status"]

        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)

        db.session.commit()

        return success_response(200, 'success', 'Profile updated successfully')

    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()

        return success_response(200, 'success', 'User deleted successfully')


@profile_bp.route('/picture', methods=['PUT'])
@jwt_required()
def update_profile_picture():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        error_response(404, 'User not found')

    if 'profile_picture' not in request.files:
        error_response(400, 'No profile picture provided')

    profile_picture = request.files['profile_picture']

    if profile_picture.filename == '':
        error_response(400, 'No selected file')

    allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
    if profile_picture and allowed_file(profile_picture.filename, allowed_extensions):
        filename = secure_filename(profile_picture.filename)
        profile_picture.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        temp_path = current_app.config['TEMP_PATH'] + str(filename)
        user.profile_picture = temp_path
        db.session.commit()

        return success_response(200, 'success', 'Profile picture updated successfully')
    else:
        error_response(400, 'Invalid file type for profile picture')