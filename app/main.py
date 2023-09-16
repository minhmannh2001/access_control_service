from app import create_app
from app.databases.redis import redis_connection
from app.extensions.jwt_manager import jwt_manager

app = create_app()
redis_connection.init_app(app)


@jwt_manager.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    """
    Callback function to check if a JWT exists in the redis blocklist
    :param jwt_header:
    :param jwt_payload:
    :return: True if the JWT exists in the redis blocklist; otherwise, return False
    """
    jti = jwt_payload["jti"]
    jwt_redis_blocklist = redis_connection.connection
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None


if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"])


