from scapy.all import rdpcap, TCP, UDP, ICMP, ARP, IP, DNS
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:

    def __init__(self):
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self):
        """
        lire le fichier pcap
        """
        try:
            fichier = "tp1-grp-a06f1e02-b792-42b2-85cb-c5165fdc2e02-3aa26f.pcap"

            self.packets = rdpcap(fichier)

            logger.info("Capture chargé")
            logger.info("Nombre de packets : " + str(len(self.packets)))

        except Exception as e:
            logger.error("Erreur : " + str(e))

    def sort_network_protocols(self):
        """
        compter les differents protocoles
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
                tcp = tcp + 1

                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    http = http + 1

            if UDP in packet:
                udp = udp + 1

            if ICMP in packet:
                icmp = icmp + 1

            if ARP in packet:
                arp = arp + 1

            if IP in packet:
                ip = ip + 1

            if DNS in packet:
                dns = dns + 1

        resultat = "TCP: " + str(tcp)
        resultat = resultat + " UDP: " + str(udp)
        resultat = resultat + " ICMP: " + str(icmp)
        resultat = resultat + " ARP: " + str(arp)
        resultat = resultat + " IP: " + str(ip)
        resultat = resultat + " DNS: " + str(dns)
        resultat = resultat + " HTTP: " + str(http)

        return resultat

    def get_all_protocols(self):
        """
        recuperer les protocoles
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

        if tcp_trouver == True:
            resultat = resultat + "TCP "

        if udp_trouver == True:
            resultat = resultat + "UDP "

        if icmp_trouver == True:
            resultat = resultat + "ICMP "

        if arp_trouver == True:
            resultat = resultat + "ARP "

        if ip_trouver == True:
            resultat = resultat + "IP "

        if dns_trouver == True:
            resultat = resultat + "DNS "

        if http_trouver == True:
            resultat = resultat + "HTTP "

        return resultat

    def analyse(self, protocols):
        """
        petite analyse
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug("All protocols: " + all_protocols)
        logger.debug("Sorted protocols: " + sort)

        self.summary = self._gen_summary()

    def get_summary(self):
        return self.summary

    def _gen_summary(self):
        """
        faire le resumé
        """
        protocoles = self.get_all_protocols()
        nombre = self.sort_network_protocols()

        summary = "Protocoles trouvé : " + protocoles
        summary = summary + "\n"
        summary = summary + nombre

        return summary