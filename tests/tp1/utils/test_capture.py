from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether, Raw

from src.tp1.utils.capture import Capture


def test_capture_init():
    capture = Capture(pcap_path="test.pcap")

    assert capture.pcap_path == "test.pcap"
    assert capture.summary == ""
    assert len(capture.packets) == 0
    assert capture.attacks == []


def test_capture_traffic(tmp_path):
    from scapy.all import wrpcap

    fichier = tmp_path / "test.pcap"
    paquet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)
    wrpcap(str(fichier), [paquet])

    capture = Capture(pcap_path=str(fichier))
    capture.capture_traffic()

    assert len(capture.packets) == 1


def test_sort_network_protocols():
    capture = Capture(pcap_path="test.pcap")

    capture.packets = [
        Ether() / IP() / TCP(dport=80),
        Ether() / IP() / TCP(dport=443),
        Ether() / ARP(),
    ]

    result = capture.sort_network_protocols()

    assert capture.protocol_counts["TCP"] == 2
    assert capture.protocol_counts["ARP"] == 1
    assert capture.protocol_counts["IP"] == 2
    assert capture.protocol_counts["HTTP"] == 1
    assert "TCP: 2" in result


def test_get_all_protocols():
    capture = Capture(pcap_path="test.pcap")
    capture.packets = [Ether() / IP() / TCP(dport=80), Ether() / ARP()]

    result = capture.get_all_protocols()

    assert "TCP" in result
    assert "IP" in result
    assert "ARP" in result
    assert "HTTP" in result


def test_analyse():
    capture = Capture(pcap_path="test.pcap")

    with patch.object(capture, "_gen_summary", return_value="Test summary"):
        capture.analyse("tcp")

    assert capture.summary == "Test summary"
    assert capture.attacks == []


def test_get_summary():
    capture = Capture(pcap_path="test.pcap")
    capture.summary = "Test summary"

    assert capture.get_summary() == "Test summary"


def test_gen_summary():
    capture = Capture(pcap_path="test.pcap")

    result = capture._gen_summary()

    assert "Protocoles" in result
    assert "TCP: 0" in result
    assert "Flag" in result


def test_detect_port_scan():
    capture = Capture(pcap_path="test.pcap")

    for port in range(20, 35):
        paquet = Ether() / IP(src="10.0.0.5", dst="10.0.0.10") / TCP(dport=port, flags="S")
        capture.packets.append(paquet)

    capture.analyse()

    assert {"type": "port_scan", "attacker": "10.0.0.5"} in capture.attacks


def test_detect_arp_spoofing():
    """Détecter une MAC qui envoie davantage de réponses ARP."""
    capture = Capture(pcap_path="test.pcap")

    capture.packets = [
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="aa:aa:aa:aa:aa:aa",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
    ]

    capture.analyse()

    assert {
        "type": "arp_spoofing",
        "attacker": "bb:bb:bb:bb:bb:bb",
    } in capture.attacks


def test_detect_arp_spoofing_attacker_first():
    """Détecter une MAC suspecte même si elle apparaît en premier."""
    capture = Capture(pcap_path="test.pcap")

    capture.packets = [
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="aa:aa:aa:aa:aa:aa",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
        Ether()
        / ARP(
            op=2,
            psrc="192.168.1.1",
            hwsrc="bb:bb:bb:bb:bb:bb",
        ),
    ]

    capture.analyse()

    assert {
        "type": "arp_spoofing",
        "attacker": "bb:bb:bb:bb:bb:bb",
    } in capture.attacks


def test_detect_sql_injection():
    capture = Capture(pcap_path="test.pcap")

    paquet = (
        Ether()
        / IP(src="10.0.0.9", dst="10.0.0.10")
        / TCP(dport=80)
        / Raw(load=b"GET /login?user=' OR 1=1 HTTP/1.1")
    )

    capture.packets = [paquet]
    capture.analyse()

    assert {"type": "sql_injection", "attacker": "10.0.0.9"} in capture.attacks


def test_ethernet():
    capture = Capture(pcap_path="test.pcap")

    capture.packets = [
        Ether() / IP() / TCP(dport=80),
        Ether() / ARP(),
    ]

    capture.sort_network_protocols()

    assert capture.protocol_counts["Ethernet"] == 2
    assert "Ethernet" in capture.get_all_protocols()
