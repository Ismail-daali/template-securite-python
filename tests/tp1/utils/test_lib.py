"""Module du projet TP1 IDS/IPS."""

from src.tp1.utils.lib import choose_interface, hello_world


def test_when_hello_world_then_return_hello_world() -> None:
    # Given
    """Vérifie le comportement de when hello world then return hello world."""
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_choose_interface_then_return_empty_string() -> None:
    # When
    """Vérifie le comportement de when choose interface then return empty string."""
    result = choose_interface()

    # Then
    assert result == ""
