from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
from app.model.model import db, User
from app.main.validators.validators import Validators
from app.utils.send_mail import send_reset_password_email
from app.utils.login_mail import send_login_notification_email
from app.utils.error_response import error_response
from app.utils.success_response import success_response

import base64

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    validation_result = Validators.check_user_required_fields(data)
    if validation_result["status"] == 200:
        user = User.query.filter_by(username=data.get('username'), email=data.get('email')).first()

        if user:
            return error_response(400,"User already registered")

        hashed_password = generate_password_hash(data.get('password'))

        new_user = User(
            username=data.get('username'),
            email=data.get('email'),
            password=hashed_password,
            profile_picture=data.get('profile_picture')
        )

        db.session.add(new_user)
        db.session.commit()

        return success_response(201, 'success', "User registered successfully")
    else:
        return jsonify(validation_result), validation_result["status"]

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    validation_result = Validators.check_login_required_fields(data)
    if validation_result["status"] == 200:
        username = data.get('username')
        user = User.query.filter_by(username=username).first()

        if not user:
            return error_response(401, 'Invalid username or password')

        if not check_password_hash(user.password, data['password']):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            db.session.commit()

            if user.failed_login_attempts > 2 and not user.notification_sent:
                send_login_notification_email(user.email)
                user.notification_sent = True  
                db.session.commit()

            return error_response(401, '!!!Warning!!!, mail sent to users account')

        
        user.failed_login_attempts = 0
        user.notification_sent = False  
        db.session.commit()

        access_token = create_access_token(identity=user.id)

        return jsonify(access_token=access_token), 200
    else:
        return jsonify(validation_result), validation_result["status"]

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    is_password_changed = data.get('is_password_changed')
    user = User.query.filter_by(email=email).first()
    is_password_changed = User.query.filter_by(is_password_changed=is_password_changed).first()

    if user:
        reset_token = base64.b64encode(email.encode('utf-8')).decode('utf-8')
        link = current_app.config['CHANGE_PASS']
        reset_link = f'{link}{reset_token}'
        send_reset_password_email(email, reset_link)
        user.is_password_changed = False
        db.session.commit()

        return success_response(201, 'success', 'Reset password link sent to your email')

    else:
        return error_response(404, 'User not found')

@auth_bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data['new_password']
    confirm_password = data['confirm_password']
    is_password_changed = data.get('is_password_changed')

    if new_password != confirm_password:
        return error_response(400, 'New password and confirm password do not match')

    email = base64.b64decode(token).decode('utf-8')
    is_password_changed = User.query.filter_by(is_password_changed=is_password_changed).first()
    user = User.query.filter_by(email=email).first()
    if user.is_password_changed == True:
        return error_response(400, "link expired or used wait for sometime to generate new link")
    if user:
        user.password = generate_password_hash(new_password)
        user.is_password_changed = True
        db.session.commit()
        return success_response(200, 'success','Password reset successfully')
    else:
        return error_response(404, 'User not found')

