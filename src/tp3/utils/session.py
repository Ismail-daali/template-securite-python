
import requests

from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.
    """

    def __init__(self, url):
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""

        self.http = requests.Session()
        self.response = None

        self.host = ""
        self.port = 0
        self.key = ""

    def prepare_request(self):
        """
        Prepares the request for sending by capturing
        and solving the captcha.
        """
        response = self.http.get(self.url, timeout=5)
        response.raise_for_status()

        captcha = Captcha(self.url)
        captcha.http = self.http

        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = ""

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        self.response = self.http.post(
            self.url,
            data={
                "captcha": self.captcha_value
            },
            timeout=5
        )

    def process_response(self):
        """
        Processes the response.
        """
        if self.response is None:
            return False

        if self.response.status_code != 200:
            return False

        try:
            data = self.response.json()
        except ValueError:
            return False

        required = ("flag1", "host", "port", "key")

        if not all(field in data for field in required):
            return False

        self.valid_flag = data["flag1"]
        self.host = data["host"]
        self.port = int(data["port"])
        self.key = data["key"]

        return True

    def get_flag(self):
        """
        Returns the valid flag.
        """
        return self.valid_flag
