import json
import time

import requests
from flask import current_app
from werkzeug.exceptions import InternalServerError


class Notification:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.request = requests.Session()
        self.request.headers.update({"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})

    def send_confirm_email(self, username, email, verification_link):
        logger = current_app.logger
        try:
            logger.debug(f"Sending confirmation email to {email}")
            logger.debug(f"Request URL: {self.base_url}/send-confirm-email")

            email_data = {
                "username": username,
                "email": email,
                "verification_link": verification_link
            }

            start_time = time.time()
            res = self.request.post(url=f"{self.base_url}/send-confirm-email", json=email_data, verify=False)
            duration = time.time() - start_time

            logger.debug(f"Confirmation email sending request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 200:
                logger.info(f"Confirmation email sent successfully")
            else:
                logger.error(f"Confirmation email sending failed with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while sending confirmation email: {str(e)}")
            raise InternalServerError("Cannot send confirmation email due to an internal server error.")

    def send_password_reset_email(self, username, email, reset_link):
        logger = current_app.logger
        try:
            logger.debug(f"Sending password reset email to {email}")
            logger.debug(f"Request URL: {self.base_url}/send-password-reset-email")

            email_data = {
                "username": username,
                "email": email,
                "reset_link": reset_link
            }

            start_time = time.time()
            res = self.request.post(url=f"{self.base_url}/send-password-reset-email", json=email_data, verify=False)
            duration = time.time() - start_time

            logger.debug(f"Password reset email sending request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 200:
                logger.info(f"Password reset email sent successfully")
            else:
                logger.error(f"Password reset email sending failed with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while sending password reset email: {str(e)}")
            raise InternalServerError("Cannot send password reset email due to an internal server error.")

    def send_verification_email(self, username, email, verification_link):
        logger = current_app.logger
        try:
            logger.debug(f"Sending verification email to {email}")
            logger.debug(f"Request URL: {self.base_url}/send-verification-email")

            email_data = {
                "username": username,
                "email": email,
                "verification_link": verification_link
            }

            start_time = time.time()
            res = self.request.post(url=f"{self.base_url}/send-verification-email", json=email_data, verify=False)
            duration = time.time() - start_time

            logger.debug(f"Verification email sending request took {duration:.2f} seconds")
            logger.debug(f"Response Status Code: {res.status_code}")
            logger.debug(f"Response Data: {res.json()}")

            if res.status_code == 200:
                logger.info(f"Verification email sent successfully")
            else:
                logger.error(f"Verification email sending failed with status code {res.status_code}")
                logger.error(f"Response Data: {res.json()}")

            msg = json.loads(res.content).get("msg", None)
            if msg is None:
                msg = json.loads(res.content).get("detail", None)
            return res.status_code, msg

        except Exception as e:
            logger.error(f"Error occurred while sending verification email: {str(e)}")
            raise InternalServerError("Cannot send verification email due to an internal server error.")
