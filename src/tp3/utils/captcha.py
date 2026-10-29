
import io
from urllib.parse import urljoin

import pytesseract

import os

if os.name == "nt":
    tesseract_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.isfile(tesseract_path):
        pytesseract.pytesseract.tesseract_cmd = tesseract_path

import requests
from PIL import Image, ImageEnhance, ImageOps


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""
        self.http = None

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        client = self.http if self.http is not None else requests

        response = client.get(
            urljoin(self.url, "/captcha.png"),
            timeout=5
        )
        response.raise_for_status()

        self.image = Image.open(
            io.BytesIO(response.content)
        ).convert("RGB")

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        if not isinstance(self.image, Image.Image):
            raise ValueError("Aucune image CAPTCHA disponible")

        image = ImageOps.grayscale(self.image)
        image = ImageEnhance.Contrast(image).enhance(3)

        # Agrandissement pour faciliter la reconnaissance.
        image = image.resize(
            (image.width * 3, image.height * 3)
        )

        # Suppression du bruit gris.
        image = image.point(
            lambda pixel: 255 if pixel > 150 else 0
        )

        result = pytesseract.image_to_string(
            image,
            config=(
                "--psm 7 "
                "-c tessedit_char_whitelist="
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            )
        )

        self.value = "".join(
            character
            for character in result.upper()
            if character.isalnum()
        )

    def get_value(self):
        """
        Fonction retournant la valeur du captcha.
        """
        return self.value
