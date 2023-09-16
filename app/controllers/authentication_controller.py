from datetime import timedelta

import flask_jwt_extended
from flask import current_app, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import get_jti, get_jwt, get_jwt_identity, jwt_required
from flask_login import login_required, current_user
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError
from werkzeug.exceptions import BadRequest, Unauthorized, default_exceptions

from app.databases.redis import redis_connection
from app.services.notification import Notification
from app.services.user_management import UserManager
from helpers.utils import hash_password, verify_password


@jwt_required()
@login_required
def index():
    return jsonify(current_user=get_jwt_identity()), 200


def register(user_input):
    # Sanitize user input
    cleaned_data = sanitize(["email", "username", "password", "confirm_password"], user_input)
    email = cleaned_data["email"]
    username = cleaned_data["username"]
    password = cleaned_data["password"]
    confirm_password = cleaned_data["confirm_password"]

    # Validate user input
    if password != confirm_password:
        raise BadRequest("Password and confirm password do not match.")

    # Hash password
    hashed_password = hash_password(password)

    # Send request to user management service for user creation if the provided data is valid
    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, msg = user_manager.create_user(username, email, hashed_password)
    if status_code != 201:
        raise default_exceptions[status_code](msg)

    # Generate token
    identity = cleaned_data["username"]
    refresh_token = create_refresh_token(identity=identity)
    refresh_jti = get_jti(refresh_token)
    additional_claims = {"refresh_jti": refresh_jti}
    access_token = create_access_token(identity=identity, additional_claims=additional_claims)

    # Generate verification token
    additional_claims = {"verification_token": True}
    verification_token = create_access_token(identity=identity,
                                             additional_claims=additional_claims,
                                             expires_delta=timedelta(hours=24))

    # Create the verification link
    verification_link = f"https://{current_app.config['HOST']}/verify-email?token={verification_token}"

    # Email confirmation
    notification = Notification(current_app.config["NOTIFICATION_URL"], current_app.config["NOTIFICATION_API_KEY"])
    status_code, msg = notification.send_confirm_email(username, email, verification_link)
    if status_code != 200:
        raise default_exceptions[status_code](msg)

    return jsonify(access_token=access_token, refresh_token=refresh_token), 201


@jwt_required()
@login_required
def request_verification_email():
    # Check if the user is verified
    if current_user.verified:
        return jsonify(msg="User has already been verified."), 409

    # Generate verification token
    additional_claims = {"verification_token": True}
    verification_token = create_access_token(identity=current_user.username,
                                             additional_claims=additional_claims,
                                             expires_delta=timedelta(hours=24))

    # Create the verification link
    verification_link = f"https://{current_app.config['HOST']}/verify-email?token={verification_token}"

    # Email confirmation
    notification = Notification(current_app.config["NOTIFICATION_URL"], current_app.config["NOTIFICATION_API_KEY"])
    status_code, msg = notification.send_verification_email(current_user.username,
                                                            current_user.email,
                                                            verification_link)
    if status_code != 200:
        raise default_exceptions[status_code](msg)

    return jsonify(msg="Successfully sent the verification email."), 200


def verify_email(verification_token):
    try:
        decoded_token = flask_jwt_extended.decode_token(verification_token)
    except InvalidSignatureError:
        return jsonify(msg="Bad Request. Please request a new email verification link."), 400
    except ExpiredSignatureError:
        return jsonify(msg="Email verification link has expired. Please request a new link."), 400

    if not decoded_token.get("verification_token", False):
        return jsonify(msg="Bad Request. Please request a new email verification link."), 400

    # Verify if the token has been revoked
    jwt_redis_blocklist = redis_connection.connection
    result = jwt_redis_blocklist.get(decoded_token.get("jti", ""))
    if result is not None:
        return jsonify(msg="The email verification token is not valid."), 400

    # Revoke reset token
    jwt_redis_blocklist = redis_connection.connection
    jwt_redis_blocklist.set(decoded_token.get("jti"), "", ex=timedelta(hours=24))

    username = decoded_token.get("sub")

    # Send request to user management service for update user's verified field
    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, msg = user_manager.update_user(username, {"verified": True})
    if status_code != 200:
        raise default_exceptions[status_code](msg)

    return jsonify(msg="Email verification successful."), 200


def login(credentials):
    # Sanitize user input
    cleaned_data = sanitize(["email", "password", "remember_me"], credentials)
    email = cleaned_data.get("email")
    password = cleaned_data.get("password")
    remember_me = cleaned_data.get("remember_me", False)

    # Validate user credentials
    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, user_data = user_manager.get_user_by_id(email)
    if status_code == 404:
        raise Unauthorized("Invalid username or password")
    if status_code != 200:
        raise default_exceptions[status_code](user_data)

    # Check if the provided password matches the hashed password
    hashed_password = user_data.get("hashed_password")
    if not hashed_password or not verify_password(password, hashed_password):
        raise Unauthorized("Invalid username or password")

    # Generate token
    identity = user_data.get("username")
    additional_claims = {"remember_me": remember_me}
    refresh_token = create_refresh_token(identity=identity, additional_claims=additional_claims)

    refresh_jti = get_jti(refresh_token)
    additional_claims = {"refresh_jti": refresh_jti, "remember_me": remember_me}
    access_token = create_access_token(identity=identity, additional_claims=additional_claims)

    return jsonify(access_token=access_token, refresh_token=refresh_token), 200


@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()  # username
    refresh_jti = get_jwt()["jti"]
    remember_me = get_jwt()["remember_me"]

    if not remember_me:
        return jsonify(msg="Your session has expired. Please log in again."), 302

    jwt_redis_blocklist = redis_connection.connection
    jwt_redis_blocklist.set(refresh_jti, "", ex=current_app.config["JWT_REFRESH_TOKEN_EXPIRES"])

    additional_claims = {"remember_me": remember_me}
    new_refresh_token = create_refresh_token(identity=identity, additional_claims=additional_claims)

    new_refresh_jti = get_jti(new_refresh_token)
    additional_claims = {"refresh_jti": new_refresh_jti, "remember_me": remember_me}
    new_access_token = create_access_token(identity=identity, additional_claims=additional_claims)

    return jsonify(access_token=new_access_token, refresh_token=new_refresh_token), 200


@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    refresh_jti = get_jwt()["refresh_jti"]

    jwt_redis_blocklist = redis_connection.connection
    jwt_redis_blocklist.set(jti, "", ex=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"])
    jwt_redis_blocklist.set(refresh_jti, "", ex=current_app.config["JWT_REFRESH_TOKEN_EXPIRES"])

    return jsonify(msg="User logged out successfully"), 200


def reset_password(reset_request):
    # Sanitize user input
    cleaned_data = sanitize(["email"], reset_request)
    email = cleaned_data["email"]

    # Check if user exists or not
    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, user_data = user_manager.get_user_by_id(email)
    if status_code == 404:
        return jsonify(msg="Successfully sent the password reset email."), 200
    if status_code != 200:
        raise default_exceptions[status_code](user_data)

    # Generate password reset token
    identity = user_data.get("username")
    additional_claims = {"reset_token": True}
    reset_token = create_access_token(identity=identity,
                                      additional_claims=additional_claims,
                                      expires_delta=timedelta(hours=24))

    # Generate reset_link
    reset_link = f"https://{current_app.config['HOST']}/confirm-reset-password?token={reset_token}"

    # Email confirmation
    notification = Notification(current_app.config["NOTIFICATION_URL"], current_app.config["NOTIFICATION_API_KEY"])
    status_code, msg = notification.send_password_reset_email(identity, email, reset_link)
    if status_code != 200:
        raise default_exceptions[status_code](msg)

    return jsonify(msg="Successfully sent the password reset email."), 200


def confirm_password_reset(reset_confirmation):
    # Sanitize user input
    cleaned_data = sanitize(["new_password", "confirm_new_password", "reset_token"], reset_confirmation)
    new_password = cleaned_data.get("new_password")
    confirm_new_password = cleaned_data.get("confirm_new_password")

    # Validate user input
    if new_password != confirm_new_password:
        raise BadRequest("New password and confirm new password do not match.")

    reset_token = cleaned_data.get("reset_token")
    try:
        decoded_token = flask_jwt_extended.decode_token(reset_token)
    except InvalidSignatureError:
        return jsonify(msg="Bad Request. Please request a new password reset link."), 400
    except ExpiredSignatureError:
        return jsonify(msg="Password reset link has expired. Please request a new link."), 400

    if not decoded_token.get("reset_token", False):
        return jsonify(msg="Bad Request. Please request a new password reset link."), 400

    # Verify if the token has been revoked
    jwt_redis_blocklist = redis_connection.connection
    result = jwt_redis_blocklist.get(decoded_token.get("jti", ""))
    if result is not None:
        return jsonify(msg="The password reset token is not valid."), 400

    # Revoke reset token
    jwt_redis_blocklist = redis_connection.connection
    jwt_redis_blocklist.set(decoded_token.get("jti"), "", ex=timedelta(hours=24))

    username = decoded_token.get("sub")

    # Hash new password
    hashed_password = hash_password(new_password)

    # Send request to user management service for update user's password
    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, msg = user_manager.update_user(username, {"password_hash": hashed_password})
    if status_code != 200:
        raise default_exceptions[status_code](msg)

    return jsonify(msg="Password changed successfully."), 200


def sanitize(allowed_fields, user_data):
    # Create a new dictionary to store the cleaned data
    cleaned_data = {}

    # Iterate through the user-provided dictionary
    for key, value in user_data.items():
        # Check if the field is in the allowed_fields list
        if key in allowed_fields:
            # If it's allowed, add it to the cleaned_data dictionary
            cleaned_data[key] = value

    # Return the cleaned data
    return cleaned_data
