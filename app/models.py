from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash, verified):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.verified = verified

    def __repr__(self):
        return f"<User {self.username}>"

    def get_id(self):
        return str(self.user_id)
