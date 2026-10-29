
    import argparse
    import base64
    import socket
    from pathlib import Path
    from urllib.parse import urljoin

    import requests

    from src.tp3.utils.config import logger
    from src.tp3.utils.session import Session

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def find_endpoint(target):
        """
        Discover the hidden endpoint using the wordlist.
        Test several HTTP paths concurrently.
        """
        wordlist = Path(__file__).parent / "wordlist.txt"

        if not wordlist.is_file():
            raise FileNotFoundError(
                f"Wordlist introuvable : {wordlist}"
            )

        with wordlist.open("r", encoding="utf-8") as file:
            paths = [
                line.strip()
                for line in file
                if line.strip()
                and not line.lstrip().startswith("#")
            ]

        logger.info("Fuzzing de %d chemins", len(paths))

        def check_path(path):
            url = urljoin(
                target.rstrip("/") + "/",
                path.lstrip("/")
            )

            try:
                response = requests.get(
                    url,
                    timeout=3,
                    allow_redirects=False
                )

                if (
                    response.status_code == 200
                    and "captcha" in response.text.lower()
                ):
                    return url

            except requests.RequestException:
                pass

            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(check_path, path)
                for path in paths
            ]

            for future in as_completed(futures):
                endpoint = future.result()

                if endpoint is not None:
                    logger.info(
                        "Endpoint trouvé : %s",
                        endpoint
                    )
                    return endpoint

        return None



    def xor_decode(data, key):
        """
        Decode data using a repeating XOR key.
        """
        return bytes(
            byte ^ key[index % len(key)]
            for index, byte in enumerate(data)
        )


    def run_network(host, port, key_hex):
        """
        Solve the TCP challenge.
        """
        key = bytes.fromhex(key_hex)

        if not key:
            raise ValueError("Clé XOR vide")

        with socket.create_connection(
            (host, int(port)),
            timeout=5
        ) as connection:

            connection.settimeout(5)

            with connection.makefile("rb") as reader:
                introduction = reader.readline()
                logger.info(
                    "TCP : %s",
                    introduction.decode(
                        errors="replace"
                    ).strip()
                )

                for round_number in range(1, 4):
                    encoded = reader.readline().strip()

                    if not encoded:
                        raise RuntimeError(
                            "Connexion TCP interrompue"
                        )

                    decoded = base64.b64decode(
                        encoded,
                        validate=True
                    )

                    plaintext = xor_decode(decoded, key)

                    connection.sendall(
                        plaintext + b"\n"
                    )

                    logger.info(
                        "Round TCP %d terminé",
                        round_number
                    )

                final_response = reader.readline().decode(
                    errors="replace"
                ).strip()

        if not final_response.startswith("OK "):
            raise RuntimeError(
                f"Réponse TCP inattendue : {final_response}"
            )

        return final_response[3:]


    def main():
        parser = argparse.ArgumentParser(
            description="TP3 - Breach the target"
        )

        parser.add_argument(
            "--target",
            required=True,
            help="URL HTTP de la cible"
        )

        args = parser.parse_args()

        logger.info("Starting TP3")

        target = args.target.rstrip("/")

        endpoint = find_endpoint(target)

        if endpoint is None:
            logger.error(
                "Aucun endpoint CAPTCHA trouvé"
            )
            return

        session = Session(endpoint)

        for attempt in range(1, 31):
            logger.info(
                "Tentative CAPTCHA %d/30",
                attempt
            )

            try:
                session.prepare_request()

                logger.info(
                    "CAPTCHA reconnu : %s",
                    session.captcha_value
                )

                if len(session.captcha_value) != 5:
                    continue

                session.submit_request()

                if session.process_response():
                    break

            except (
                requests.RequestException,
                ValueError
            ) as error:
                logger.warning(
                    "Erreur CAPTCHA : %s",
                    error
                )

        else:
            logger.error(
                "Impossible de résoudre le CAPTCHA"
            )
            return

        print(f"[+] FLAG1: {session.get_flag()}")

        try:
            final_flag = run_network(
                session.host,
                session.port,
                session.key
            )
        except (
            OSError,
            ValueError,
            RuntimeError
        ) as error:
            logger.error(
                "Erreur TCP : %s",
                error
            )
            return

        print(f"[+] FLAG_FINAL: {final_flag}")


    if __name__ == "__main__":
        main()
