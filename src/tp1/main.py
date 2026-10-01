import argparse
import json
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    parser = argparse.ArgumentParser(description="Analyseur IDS/IPS - TP1")
    parser.add_argument("--pcap", help="Chemin du fichier PCAP à analyser")
    parser.add_argument("--out", default="report.json", help="Chemin du JSON de sortie")
    parser.add_argument("--iface", help="Interface réseau")
    args = parser.parse_args()

    # 1. Chargement & Analyse
    capture = Capture(pcap_path=args.pcap)
    capture.capture_traffic()
    capture.analyse()

    summary = capture.get_summary()

    # 2. Rapport JSON
    output_json = {
        "protocols": capture.protocol_counts,
        "attacks": capture.attacks,
        "flag": capture.flag
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output_json, f, indent=2)

    # 3. Rapport PDF
    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()