from flask_jwt_extended import JWTManager
from flask import jsonify

jwt_manager = JWTManager()


@jwt_manager.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    remember_me = jwt_data["remember_me"]
    if remember_me:
        if jwt_data.get("type") == "access":
            return jsonify(msg="Your session has expired. "
                               "Please use your refresh token to get a new access token."), 302
    return jsonify(msg="Your session has expired. Please log in again."), 302
