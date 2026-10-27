import re
from collections import Counter, defaultdict

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap

from tp1.utils.config import logger
from tp1.utils.lib import choose_interface


class Capture:
    def __init__(self, pcap_path: str | None = None) -> None:
        self.pcap_path = pcap_path
        self.interface = None

        if pcap_path is None:
            self.interface = choose_interface()

        self.summary = ""
        self.packets = []
        self.protocol_counts = {}
        self.attacks = []
        self.flag = ""

    def capture_traffic(self) -> None:
        """Lire le fichier PCAP."""
        try:
            if self.pcap_path:
                self.packets = rdpcap(self.pcap_path)

                logger.info("Capture PCAP chargée : " + str(self.pcap_path))
                logger.info("Nombre de packets : " + str(len(self.packets)))
            else:
                logger.info("Interface sélectionnée : " + str(self.interface))

        except Exception as e:
            logger.error("Erreur lors du chargement : " + str(e))
            raise

    def sort_network_protocols(self) -> str:
        """Compter les différents protocoles."""
        tcp = 0
        udp = 0
        icmp = 0
        arp = 0
        ip = 0
        dns = 0
        http = 0
        ethernet = 0

        for packet in self.packets:
            if Ether in packet:
                ethernet += 1

            if TCP in packet:
                tcp += 1

                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    http += 1

            if UDP in packet:
                udp += 1

            if ICMP in packet:
                icmp += 1

            if ARP in packet:
                arp += 1

            if IP in packet:
                ip += 1

            if DNS in packet:
                dns += 1

        self.protocol_counts = {
            "Ethernet": ethernet,
            "ARP": arp,
            "IP": ip,
            "TCP": tcp,
            "UDP": udp,
            "ICMP": icmp,
            "DNS": dns,
            "HTTP": http,
        }

        resultat = "Ethernet: " + str(ethernet)
        resultat += " ARP: " + str(arp)
        resultat += " IP: " + str(ip)
        resultat += " TCP: " + str(tcp)
        resultat += " UDP: " + str(udp)
        resultat += " ICMP: " + str(icmp)
        resultat += " DNS: " + str(dns)
        resultat += " HTTP: " + str(http)

        return resultat

    def get_all_protocols(self) -> str:
        """Récupérer les protocoles présents."""
        resultat = ""

        ethernet_trouver = False
        tcp_trouver = False
        udp_trouver = False
        icmp_trouver = False
        arp_trouver = False
        ip_trouver = False
        dns_trouver = False
        http_trouver = False

        for packet in self.packets:
            if Ether in packet:
                ethernet_trouver = True

            if TCP in packet:
                tcp_trouver = True

                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    http_trouver = True

            if UDP in packet:
                udp_trouver = True

            if ICMP in packet:
                icmp_trouver = True

            if ARP in packet:
                arp_trouver = True

            if IP in packet:
                ip_trouver = True

            if DNS in packet:
                dns_trouver = True

        if ethernet_trouver:
            resultat += "Ethernet "

        if arp_trouver:
            resultat += "ARP "

        if ip_trouver:
            resultat += "IP "

        if tcp_trouver:
            resultat += "TCP "

        if udp_trouver:
            resultat += "UDP "

        if icmp_trouver:
            resultat += "ICMP "

        if dns_trouver:
            resultat += "DNS "

        if http_trouver:
            resultat += "HTTP "

        return resultat

    def analyse(self, protocols: str | None = None) -> None:
        """Analyser le trafic et détecter les attaques."""
        self.attacks = []
        self.flag = ""

        self.sort_network_protocols()

        arp_table = defaultdict(Counter)
        scan_ports = {}

        sqli_patterns = [
            "' or 1=1",
            "%27%20or%201=1",
            "union select",
            "union%20select",
            "drop table",
        ]

        for packet in self.packets:
            # ARP SPOOFING
            if ARP in packet and packet[ARP].op == 2:
                ip_source = packet[ARP].psrc
                mac_source = packet[ARP].hwsrc.lower()

                arp_table[ip_source][mac_source] += 1

            # PORT SCAN
            if IP in packet and TCP in packet and packet[TCP].flags == "S":
                ip_source = packet[IP].src
                port_destination = packet[TCP].dport

                if ip_source not in scan_ports:
                    scan_ports[ip_source] = []

                if port_destination not in scan_ports[ip_source]:
                    scan_ports[ip_source].append(port_destination)

            # SQL INJECTION
            if IP in packet and TCP in packet and Raw in packet and packet[TCP].dport == 80:
                payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
                payload_lower = payload.lower()

                injection_trouvee = any(pattern in payload_lower for pattern in sqli_patterns)

                if injection_trouvee:
                    ip_source = packet[IP].src

                    attaque = {
                        "type": "sql_injection",
                        "attacker": ip_source,
                    }

                    if attaque not in self.attacks:
                        self.attacks.append(attaque)

                    # Chercher le flag dans la requête SQLi
                    match = re.search(
                        r"ESGI\{[^}\s]+\}",
                        payload,
                    )

                    if match:
                        self.flag = match.group(0)

        # RESULTAT ARP SPOOFING
        for ip_source, macs in arp_table.items():
            if len(macs) > 1:
                mac_attaquant = macs.most_common(1)[0][0]

                attaque = {
                    "type": "arp_spoofing",
                    "attacker": mac_attaquant,
                }

                if attaque not in self.attacks:
                    self.attacks.append(attaque)

        # RESULTAT PORT SCAN
        for ip_source, ports in scan_ports.items():
            if len(ports) >= 10:
                attaque = {
                    "type": "port_scan",
                    "attacker": ip_source,
                }

                if attaque not in self.attacks:
                    self.attacks.append(attaque)

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """Retourner le résumé."""
        return self.summary

    def _gen_summary(self) -> str:
        """Générer le résumé."""
        protocoles = self.get_all_protocols()
        nombre = self.sort_network_protocols()

        summary = "Protocoles trouvés : " + protocoles
        summary += "\n" + nombre
        summary += "\nAttaques détectées :"

        if len(self.attacks) == 0:
            summary += "\nAucune attaque détectée"
        else:
            for attaque in self.attacks:
                summary += "\n- "
                summary += attaque["type"]
                summary += " : "
                summary += attaque["attacker"]

        summary += "\nFlag : " + self.flag

        return summary
