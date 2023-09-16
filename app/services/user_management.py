import requests
from flask import current_app
import time
from werkzeug.exceptions import InternalServerError
import json


class UserManager:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.request = requests.Session()
        self.request.headers.update({"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})

    def create_user(self, username, email, password):
        logger = current_app.logger
        try:
            logger.debug(f"Creating new user: {username}")
            logger.debug(f"Request URL: {self.base_url}/user")

            body = {
                "username": username,
                "email": email,
                "password": password
            }

            start_time = time.time()
            res = self.request.post(url=f"{self.base_url}/user", json=body, verify=False)
            duration = time.time() - start_time

            logger.debug(f"User creation request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 201:
                logger.info(f"User created successfully")
            else:
                logger.error(f"User creation failed with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while creating user: {str(e)}")
            raise InternalServerError("Cannot create a new user due to an internal server error.")

    def get_user(self):
        pass

    def get_user_by_id(self, user_id):
        logger = current_app.logger
        try:
            logger.debug(f"Getting user by ID: {user_id}")
            logger.debug(f"Request URL: {self.base_url}/users/{user_id}")

            start_time = time.time()
            res = self.request.get(url=f"{self.base_url}/users/{user_id}", verify=False)
            duration = time.time() - start_time

            logger.debug(f"Get user request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 200:
                logger.info(f"User retrieved successfully")
                user_data = res.json()
                return res.status_code, user_data
            elif res.status_code == 403:
                logger.error(f"Access denied: User or Service does not have permission to retrieve this user")
            elif res.status_code == 404:
                logger.info(f"User with ID {user_id} not found")
            else:
                logger.error(f"Failed to retrieve user with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while retrieving user: {str(e)}")
            raise InternalServerError("Cannot retrieve user due to an internal server error.")

    def get_users(self):
        pass

    def update_user(self, user_id, new_data):
        logger = current_app.logger
        try:
            logger.debug(f"Updating user with ID: {user_id}")
            logger.debug(f"Request URL: {self.base_url}/users/{user_id}")

            start_time = time.time()
            res = self.request.put(url=f"{self.base_url}/users/{user_id}", json=new_data, verify=False)
            duration = time.time() - start_time

            logger.debug(f"Update user request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 200:
                logger.info(f"User updated successfully")
                user_data = res.json()
                return res.status_code, user_data
            elif res.status_code == 403:
                logger.error(f"Access denied: User or Service does not have permission to update this user")
            elif res.status_code == 404:
                logger.error(f"User with ID {user_id} not found")
            else:
                logger.error(f"Failed to update user with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while updating user: {str(e)}")
            raise InternalServerError("Cannot update user due to an internal server error.")

    def delete_user(self, user_id):
        pass

