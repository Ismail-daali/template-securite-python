import base64
import re
import socket
from urllib.parse import urljoin

import requests

from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""

        self.payload = {}
        self.champ = "captcha"
        self.action = url
        self.response = None

        self.host = ""
        self.port = 0
        self.key = ""

    def prepare_request(self):
        """
        Prépare la requête : récupère le formulaire et résout le captcha.
        """
        page = requests.get(self.url, timeout=10)
        html = page.text

        self.payload = {}
        for balise in re.findall(r"<input[^>]*>", html):
            nom = re.search(r'name="([^"]+)"', balise)
            if not nom:
                continue

            if 'type="hidden"' in balise:
                valeur = re.search(r'value="([^"]*)"', balise)
                self.payload[nom.group(1)] = valeur.group(1) if valeur else ""
            elif 'type="submit"' not in balise and self.champ == "captcha":
                self.champ = nom.group(1)

        action = re.search(r'<form[^>]*action="([^"]*)"', html)
        self.action = urljoin(self.url, action.group(1)) if action else self.url

        image = re.search(r'<img[^>]*src="([^"]+)"', html)
        captcha = Captcha(urljoin(self.url, image.group(1)))
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = self.captcha_value
        self.payload[self.champ] = self.captcha_value

    def submit_request(self):
        """
        Envoie le flag et captcha.
        """
        self.response = requests.post(self.action, data=self.payload, timeout=10)

    def process_response(self):
        """
        Traite la réponse : récupère le drapeau, l'hôte et la clé.
        """
        html = self.response.text

        drapeau = re.search(r"ESGI\{[^}]+\}", html)
        if not drapeau:
            logger.info("Captcha refusé")
            return False

        self.valid_flag = drapeau.group(0)

        cible = re.search(r"(?<!//)([a-zA-Z0-9.\-]+):(\d{2,5})", html)
        if cible:
            self.host = cible.group(1)
            self.port = int(cible.group(2))

        cle = re.search(
            r"(?:key|cle|cl[ée]|xor)[^a-zA-Z0-9]{0,6}([a-zA-Z0-9_\-]{2,64})",
            html,
            re.IGNORECASE,
        )
        if cle:
            self.key = cle.group(1)

        return True

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag


def decode_jeton(jeton, cle):
    """
    Décode un jeton : XOR avec la clé puis base64.
    """
    try:
        chiffre = bytes(
            caractere ^ cle[i % len(cle)]
            for i, caractere in enumerate(jeton.encode())
        )
        return base64.b64decode(chiffre + b"=" * (-len(chiffre) % 4)).decode()
    except Exception:
        pass

    try:
        chiffre = base64.b64decode(jeton + "=" * (-len(jeton) % 4))
        return bytes(
            octet ^ cle[i % len(cle)]
            for i, octet in enumerate(chiffre)
        ).decode()
    except Exception:
        return None


def run_network(host, port, cle):
    """
    Joue la boucle de décodage chronométrée et renvoie le drapeau final.
    """
    sock = socket.create_connection((host, port), timeout=15)
    flux = sock.makefile("r", encoding="utf-8", errors="replace")

    while True:
        ligne = flux.readline()
        if not ligne:
            break

        ligne = ligne.strip()
        if not ligne:
            continue

        drapeau = re.search(r"ESGI\{[^}]+\}", ligne)
        if drapeau:
            return drapeau.group(0)

        jeton = re.search(r"[A-Za-z0-9+/=]{8,}", ligne)
        if not jeton:
            continue

        reponse = decode_jeton(jeton.group(0), cle)
        if reponse is None:
            continue

        sock.sendall((reponse + "\n").encode())

    return ""