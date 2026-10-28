
import argparse
from pathlib import Path

import requests

from src.tp3.utils.config import logger, snapshot_082462
from src.tp3.utils.session import Session, run_network


def find_endpoint(target):
    """
    Recherche l'endpoint caché à partir de la wordlist.
    Affiche les réponses HTTP intéressantes.
    """
    wordlist = Path(__file__).parent / "wordlist.txt"

    with open(wordlist, "r", encoding="utf-8") as fichier:
        mots = [
            ligne.strip()
            for ligne in fichier
            if ligne.strip() and not ligne.startswith("#")
        ]

    logger.info("Nombre de chemins à tester : %s", len(mots))

    for numero, mot in enumerate(mots, start=1):
        url = target + "/" + mot.lstrip("/")

        logger.info(
            "[%s/%s] Test de : %s",
            numero,
            len(mots),
            url
        )

        try:
            reponse = requests.get(
                url,
                timeout=5,
                allow_redirects=True
            )

            logger.info(
                "Statut HTTP : %s",
                reponse.status_code
            )

        except requests.RequestException as erreur:
            logger.warning(
                "Erreur sur %s : %s",
                url,
                erreur
            )
            continue

        # Afficher tous les endpoints potentiels
        if reponse.status_code != 404:
            logger.info(
                "Endpoint potentiel : %s (HTTP %s)",
                url,
                reponse.status_code
            )

            logger.debug(
                "Contenu : %s",
                reponse.text[:300]
            )

        # Vérifier si la page contient un CAPTCHA
        if (
            reponse.status_code == 200
            and "captcha" in reponse.text.lower()
        ):
            logger.info("Endpoint CAPTCHA trouvé : %s", url)
            return url

    logger.error("Aucun endpoint CAPTCHA trouvé")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="TP3 - Breach the target"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Adresse de la cible"
    )

    args = parser.parse_args()

    snapshot_082462(args.target)

    logger.info("Starting TP3")

    target = args.target.rstrip("/")

    logger.info("Cible : %s", target)
    logger.info("Recherche de l'endpoint...")

    url = find_endpoint(target)

    if url is None:
        logger.error("Aucun endpoint trouvé")
        return

    logger.info("Initialisation de la session...")

    session = Session(url)
    essais = 0

    while True:
        logger.info(
            "Tentative CAPTCHA : %s",
            essais + 1
        )

        session.prepare_request()
        session.submit_request()

        if session.process_response():
            break

        essais += 1

        if essais > 30:
            logger.error("CAPTCHA non résolu")
            return

    logger.info("Smell good !")

    flag1 = session.get_flag()

    logger.info("Flag for %s : %s", url, flag1)

    print(f"[+] FLAG1: {flag1}")

    if not session.host or not session.key:
        logger.error("Host ou clé introuvable")
        return

    logger.info("Démarrage de la communication réseau...")

    drapeau_final = run_network(
        session.host,
        session.port,
        session.key.encode()
    )

    print(f"[+] FLAG_FINAL: {drapeau_final}")


if __name__ == "__main__":
    main()
