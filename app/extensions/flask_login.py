from flask import current_app
from flask_jwt_extended import get_jwt_identity
from flask_login import LoginManager
from werkzeug.exceptions import default_exceptions

from app.services.user_management import UserManager
from helpers.utils import create_user_from_data

login_manager = LoginManager()


@login_manager.request_loader
def load_user_from_request(request):
    identity = get_jwt_identity()  # username

    user_manager = UserManager(current_app.config["USER_MANAGEMENT_URL"], current_app.config["USER_MANAGEMENT_API_KEY"])
    status_code, user_data = user_manager.get_user_by_id(identity)

    if status_code == 200:
        user = create_user_from_data(user_data)

        return user

    if status_code != 200:
        raise default_exceptions[status_code](user_data)

    # Finally, return None if user is not logged in
    return None
