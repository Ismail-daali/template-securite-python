import re
from io import BytesIO

import pytesseract
import requests
from PIL import Image


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        image = self.image.convert("L")
        image = image.resize((image.width * 3, image.height * 3))
        image = image.point(lambda pixel: 0 if pixel < 140 else 255)

        texte = pytesseract.image_to_string(
            image,
            config="--psm 8 -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        )
        self.value = re.sub(r"\s+", "", texte)

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        reponse = requests.get(self.url, timeout=10)
        self.image = Image.open(BytesIO(reponse.content))

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value