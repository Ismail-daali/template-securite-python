from scapy.all import rdpcap, TCP, UDP, ICMP, ARP
from tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self) -> None:
        """
        recuperer les packets du fichier
        """
        try:
            self.packets = rdpcap(
                "tp1-grp-a06f1e02-b792-42b2-85cb-c5165fdc2e02-3aa26f.pcap"
            )
            print("Capture chargé")
            print("Nombre de packets :", len(self.packets))

        except Exception as e:
            print("Erreur :", e)

    def sort_network_protocols(self) -> str:
        """
        compter les protocols
        """
        tcp = 0
        udp = 0
        icmp = 0
        arp = 0

        for packet in self.packets:
            if TCP in packet:
                tcp += 1
            elif UDP in packet:
                udp += 1
            elif ICMP in packet:
                icmp += 1
            elif ARP in packet:
                arp += 1

        resultat = f"TCP: {tcp}, UDP: {udp}, ICMP: {icmp}, ARP: {arp}"
        return resultat

    def get_all_protocols(self) -> str:
        """
        afficher les protocols trouvé
        """
        protocols = []

        for packet in self.packets:
            if TCP in packet and "TCP" not in protocols:
                protocols.append("TCP")

            if UDP in packet and "UDP" not in protocols:
                protocols.append("UDP")

            if ICMP in packet and "ICMP" not in protocols:
                protocols.append("ICMP")

            if ARP in packet and "ARP" not in protocols:
                protocols.append("ARP")

        return ", ".join(protocols)

    def analyse(self, protocols: str) -> None:
        """
        analyse simple
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        summary = "Protocols trouvé : " + self.get_all_protocols()
        summary += "\n" + self.sort_network_protocols()

        return summary