"""Module du projet TP1 IDS/IPS."""

from pathlib import Path
from unittest.mock import MagicMock

from src.tp1.utils.report import Report


def test_report_init() -> None:
    """Vérifie le comportement de report init."""
    capture = MagicMock()
    report = Report(capture, "test.pdf", "Test summary")

    assert report.capture == capture
    assert report.filename == "test.pdf"
    assert report.summary == "Test summary"
    assert report.title == "Rapport IDS / IPS"


def test_concat_report() -> None:
    """Vérifie le comportement de concat report."""
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = "Test Array"
    report.graph = "Test Graph"

    result = report.concat_report()

    assert "Test Title" in result
    assert "Test summary" in result
    assert "Test Array" in result


def test_save(tmp_path: Path) -> None:
    """Vérifie le comportement de save."""
    capture = MagicMock()
    capture.protocol_counts = {"TCP": 10, "UDP": 5, "ARP": 2}

    fichier = tmp_path / "test.pdf"

    report = Report(capture, str(fichier), "Test summary")
    report.generate("graph")
    report.generate("array")
    report.save(str(fichier))

    assert fichier.exists()
    assert fichier.stat().st_size > 0

    with open(fichier, "rb") as f:
        assert f.read(4) == b"%PDF"


def test_generate_graph() -> None:
    """Vérifie le comportement de generate graph."""
    report = Report(MagicMock(), "test.pdf", "Test summary")

    report.generate("graph")

    assert report.graph is True


def test_generate_array() -> None:
    """Vérifie le comportement de generate array."""
    capture = MagicMock()
    capture.protocol_counts = {"TCP": 5, "UDP": 2}

    report = Report(capture, "test.pdf", "Test summary")
    report.generate("array")

    assert "TCP" in report.array
    assert "UDP" in report.array


def test_generate_invalid_param() -> None:
    """Vérifie le comportement de generate invalid param."""
    report = Report(MagicMock(), "test.pdf", "Test summary")

    report.generate("invalid")

    assert report.graph is False
    assert report.array == ""


def test_get_stats() -> None:
    """Vérifie le comportement de get stats."""
    capture = MagicMock()
    capture.protocol_counts = {"Ethernet": 3, "TCP": 2}
    report = Report(capture, "test.pdf", "Résumé")
    assert report.get_stats() == {"Ethernet": 3, "TCP": 2}


def test_save_uses_requested_filename(tmp_path: Path) -> None:
    """Vérifie le comportement de save uses requested filename."""
    capture = MagicMock()
    capture.protocol_counts = {"Ethernet": 2, "TCP": 1}
    report = Report(capture, "old.pdf", "Résumé")
    target = tmp_path / "new.pdf"
    report.generate("array")
    report.save(str(target))
    assert target.read_bytes().startswith(b"%PDF")
