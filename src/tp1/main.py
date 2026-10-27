"""Module du projet TP1 IDS/IPS."""

import argparse
import json

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main() -> None:
    """Analyser un fichier PCAP et générer les rapports JSON et PDF."""
    parser = argparse.ArgumentParser(description="TP1 IDS/IPS")

    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out", default="report.json")

    args = parser.parse_args()

    logger.info("Starting TP1")

    capture = Capture(pcap_path=args.pcap)
    capture.capture_traffic()

    capture.analyse()

    resultat = {
        "protocols": capture.protocol_counts,
        "attacks": capture.attacks,
        "flag": capture.flag,
    }

    with open(args.out, "w", encoding="utf-8") as fichier:
        json.dump(resultat, fichier, indent=4)

    logger.info("Rapport JSON généré : " + args.out)

    summary = capture.get_summary()
    report = Report(capture, "report.pdf", summary)
    report.generate("graph")
    report.generate("array")
    report.save("report.pdf")


if __name__ == "__main__":
    main()
