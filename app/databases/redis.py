import redis
from redis import ConnectionPool


class RedisConnection:
    def __init__(self):
        self.app = None
        self.redis_pool = None
        self.connection = None

    def init_app(self, app):
        self.app = app
        redis_host = app.config.get('REDIS_HOST', 'localhost')
        redis_port = app.config.get('REDIS_PORT', 6379)
        redis_db = app.config.get('REDIS_DB', 0)
        self.redis_pool = ConnectionPool(host=redis_host, port=redis_port, db=redis_db)
        self.connection = redis.StrictRedis(connection_pool=self.redis_pool, decode_responses=True)


redis_connection = RedisConnection()

