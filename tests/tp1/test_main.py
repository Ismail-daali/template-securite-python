import json
import sys
from unittest.mock import patch

from tp1.main import main


def test_main(tmp_path):
    fichier_pcap = tmp_path / "capture.pcap"
    fichier_json = tmp_path / "report.json"

    with (
        patch.object(
            sys,
            "argv",
            [
                "tp1",
                "--pcap",
                str(fichier_pcap),
                "--out",
                str(fichier_json),
            ],
        ),
        patch("tp1.main.Capture") as mock_capture,
        patch("tp1.main.Report") as mock_report,
    ):
        capture = mock_capture.return_value
        capture.protocol_counts = {"TCP": 10, "ARP": 2}
        capture.attacks = [{"type": "port_scan", "attacker": "10.0.0.5"}]
        capture.flag = "ESGI{test}"
        capture.get_summary.return_value = "Résumé du test"

        main()

    capture.capture_traffic.assert_called_once()
    capture.analyse.assert_called_once()
    mock_report.assert_called_once_with(capture, "report.pdf", "Résumé du test")

    rapport = mock_report.return_value
    rapport.generate.assert_any_call("graph")
    rapport.generate.assert_any_call("array")
    rapport.save.assert_called_once_with("report.pdf")

    assert fichier_json.exists()

    with fichier_json.open(encoding="utf-8") as fichier:
        resultat = json.load(fichier)

    assert resultat["protocols"] == {"TCP": 10, "ARP": 2}
    assert resultat["attacks"] == [{"type": "port_scan", "attacker": "10.0.0.5"}]
    assert resultat["flag"] == "ESGI{test}"
