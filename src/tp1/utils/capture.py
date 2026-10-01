import re
from scapy.all import rdpcap, TCP, UDP, ICMP, ARP, IP, DNS, Raw
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:

    def __init__(self, pcap_path=None):
        self.pcap_path = pcap_path
        self.interface = choose_interface() if not pcap_path else None
        self.summary = ""
        self.packets = []

        # Structures de données pour les rapports JSON et PDF
        self.protocol_counts = {}
        self.attacks = []
        self.flag = ""

    def capture_traffic(self):
        """
        Lire le fichier PCAP ou écouter sur l'interface
        """
        try:
            if self.pcap_path:
                self.packets = rdpcap(self.pcap_path)
                logger.info("Capture PCAP chargée : " + str(self.pcap_path))
            else:
                logger.info("Capture sur interface " + str(self.interface))

            logger.info("Nombre de packets : " + str(len(self.packets)))

        except Exception as e:
            logger.error("Erreur lors du chargement : " + str(e))

    def sort_network_protocols(self):
        """
        Compter les différents protocoles
        """
        tcp = 0
        udp = 0
        icmp = 0
        arp = 0
        ip = 0
        dns = 0
        http = 0

        for packet in self.packets:

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
            "TCP": tcp,
            "UDP": udp,
            "ICMP": icmp,
            "ARP": arp,
            "IP": ip,
            "DNS": dns,
            "HTTP": http
        }

        resultat = f"TCP: {tcp} UDP: {udp} ICMP: {icmp} ARP: {arp} IP: {ip} DNS: {dns} HTTP: {http}"
        return resultat

    def get_all_protocols(self):
        """
        Récupérer la liste des protocoles sous forme de chaîne
        """
        resultat = ""

        tcp_trouver = False
        udp_trouver = False
        icmp_trouver = False
        arp_trouver = False
        ip_trouver = False
        dns_trouver = False
        http_trouver = False

        for packet in self.packets:

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

        if tcp_trouver:
            resultat += "TCP "
        if udp_trouver:
            resultat += "UDP "
        if icmp_trouver:
            resultat += "ICMP "
        if arp_trouver:
            resultat += "ARP "
        if ip_trouver:
            resultat += "IP "
        if dns_trouver:
            resultat += "DNS "
        if http_trouver:
            resultat += "HTTP "

        return resultat

    def analyse(self, protocols=None):
        """
        Analyse du trafic : comptage des protocoles, détection des attaques et extraction du flag
        """
        # 1. Calcul immédiat du volume par protocole
        self.sort_network_protocols()

        # 2. Suivi pour la détection d'attaques
        arp_table = {}
        scan_ports = {}
        sqli_patterns = ["' OR 1=1", "UNION SELECT", "DROP TABLE", "--"]

        for packet in self.packets:

            # ARP Spoofing (réponses ARP op=2)
            if ARP in packet and packet[ARP].op == 2:
                ip_source = packet[ARP].psrc
                mac_source = packet[ARP].hwsrc

                if ip_source not in arp_table:
                    arp_table[ip_source] = []
                if mac_source not in arp_table[ip_source]:
                    arp_table[ip_source].append(mac_source)

            # Port Scan (tentatives TCP SYN)
            if IP in packet and TCP in packet:
                if packet[TCP].flags == 'S':
                    ip_src = packet[IP].src
                    port_dst = packet[TCP].dport

                    if ip_src not in scan_ports:
                        scan_ports[ip_src] = []
                    if port_dst not in scan_ports[ip_src]:
                        scan_ports[ip_src].append(port_dst)

            # Payload (Injection SQL & Extraction du Flag)
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')

                    # Extraction du flag ESGI{...}
                    if not self.flag:
                        match = re.search(r"ESGI\{[^\}\s]+\}", payload)
                        if match:
                            self.flag = match.group(0)

                    # Injection SQL
                    ip_src = packet[IP].src if IP in packet else "inconnu"
                    for pattern in sqli_patterns:
                        if pattern.lower() in payload.lower():
                            if not any(a["type"] == "sql_injection" and a["attacker"] == ip_src for a in self.attacks):
                                self.attacks.append({
                                    "type": "sql_injection",
                                    "attacker": ip_src
                                })
                            break
                except Exception:
                    pass

        # Traitement des attaques ARP Spoofing (IP associée à plusieurs MAC)
        for ip, macs in arp_table.items():
            if len(macs) > 1:
                for mac in macs:
                    self.attacks.append({
                        "type": "arp_spoofing",
                        "attacker": mac
                    })

        # Traitement des Port Scans (seuil à 10 ports ciblés)
        for ip, ports in scan_ports.items():
            if len(ports) >= 10:
                self.attacks.append({
                    "type": "port_scan",
                    "attacker": ip
                })

        self.summary = self._gen_summary()

    def get_summary(self):
        return self.summary

    def _gen_summary(self):
        """
        Générer le texte de résumé
        """
        protocoles = self.get_all_protocols()
        nombre = self.sort_network_protocols()

        summary = f"Protocoles trouvés : {protocoles}\n{nombre}"
        summary += f"\nAttaques détectées : {len(self.attacks)}"
        summary += f"\nFlag : {self.flag}"

        return summary