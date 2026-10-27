from fpdf import FPDF
from scapy.all import TCP, UDP, ICMP, ARP, IP, DNS

from tp1.utils.capture import Capture


class Report:

    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport IDS / IPS"
        self.summary = summary
        self.array = ""
        self.graph = False

    def get_stats(self):
        """
        recuperer les statistiques des protocoles
        """
        stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "IP": 0,
            "DNS": 0,
            "HTTP": 0
        }

        for packet in self.capture.packets:

            if TCP in packet:
                stats["TCP"] = stats["TCP"] + 1

                if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                    stats["HTTP"] = stats["HTTP"] + 1

            if UDP in packet:
                stats["UDP"] = stats["UDP"] + 1

            if ICMP in packet:
                stats["ICMP"] = stats["ICMP"] + 1

            if ARP in packet:
                stats["ARP"] = stats["ARP"] + 1

            if IP in packet:
                stats["IP"] = stats["IP"] + 1

            if DNS in packet:
                stats["DNS"] = stats["DNS"] + 1

        return stats

    def concat_report(self) -> str:
        """
        regrouper les informations du rapport
        """
        content = ""
        content += self.title + "\n"
        content += self.summary + "\n"
        content += self.array

        return content

    def save(self, filename: str) -> None:
        """
        sauvegarder le rapport en PDF
        """
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 10, self.title, ln=True)

        pdf.ln(5)

        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 8, self.summary)

        pdf.ln(5)

        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Statistiques des protocoles", ln=True)

        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 8, self.array)

        if self.graph == True:

            pdf.ln(5)

            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Graphique", ln=True)

            stats = self.get_stats()

            protocoles = list(stats.keys())
            nombres = list(stats.values())

            maximum = max(nombres)

            x = 25
            y_base = 250
            largeur = 15

            for i in range(len(protocoles)):

                hauteur = (nombres[i] / maximum) * 60

                pdf.rect(
                    x,
                    y_base - hauteur,
                    largeur,
                    hauteur,
                    style="F"
                )

                pdf.set_font("Arial", "", 8)

                pdf.set_xy(x, y_base + 2)
                pdf.cell(largeur, 5, protocoles[i], align="C")

                pdf.set_xy(x, y_base - hauteur - 5)
                pdf.cell(
                    largeur,
                    5,
                    str(nombres[i]),
                    align="C"
                )

                x = x + 23

        pdf.output(self.filename)

    def generate(self, param: str) -> None:
        """
        generer le graphique et le tableau
        """

        if param == "graph":
            self.graph = True

        elif param == "array":

            stats = self.get_stats()

            array = ""

            for protocole in stats:
                array += protocole
                array += " : "
                array += str(stats[protocole])
                array += "\n"

            self.array = array