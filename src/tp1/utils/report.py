from fpdf import FPDF


class Report:

    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.summary = summary
        self.pdf = FPDF()

    def generate(self, option):
        if option == "graph":
            pass

        elif option == "array":
            self.pdf.add_page()

            # En-tête
            self.pdf.set_font("Helvetica", "B", 16)
            self.pdf.cell(0, 10, "Rapport d'Analyse Reseau - TP1", new_x="LMARGIN", new_y="NEXT", align="C")
            self.pdf.ln(5)

            # Flag
            self.pdf.set_font("Helvetica", "B", 11)
            flag_text = getattr(self.capture, "flag", None)
            if not flag_text:
                flag_text = "Non trouve"
            self.pdf.cell(0, 8, f"Flag extrait : {flag_text}", new_x="LMARGIN", new_y="NEXT")
            self.pdf.ln(5)

            # Récupération sécurisée des protocoles
            protocols = getattr(self.capture, "protocol_counts", {})
            if not protocols and hasattr(self.capture, "sort_network_protocols"):
                self.capture.sort_network_protocols()
                protocols = getattr(self.capture, "protocol_counts", {})

            # 1. Tableau des volumes par protocole
            self.pdf.set_font("Helvetica", "B", 11)
            self.pdf.cell(0, 8, "1. Volume par protocole", new_x="LMARGIN", new_y="NEXT")

            self.pdf.set_font("Helvetica", "B", 10)
            self.pdf.cell(90, 7, "Protocole", border=1)
            self.pdf.cell(90, 7, "Nombre de paquets", border=1, new_x="LMARGIN", new_y="NEXT")

            self.pdf.set_font("Helvetica", "", 10)
            for proto, count in protocols.items():
                self.pdf.cell(90, 7, str(proto), border=1)
                self.pdf.cell(90, 7, str(count), border=1, new_x="LMARGIN", new_y="NEXT")

            self.pdf.ln(10)

            # 2. Graphique en barres
            if protocols and max(protocols.values(), default=0) > 0:
                self.pdf.set_font("Helvetica", "B", 11)
                self.pdf.cell(0, 8, "2. Graphique des volumes", new_x="LMARGIN", new_y="NEXT")
                self.pdf.ln(2)

                max_count = max(protocols.values())
                max_bar_width = 120

                self.pdf.set_font("Helvetica", "", 9)
                for proto, count in protocols.items():
                    self.pdf.cell(30, 6, f"{proto} ({count})", border=0)

                    bar_width = (count / max_count) * max_bar_width
                    x = self.pdf.get_x()
                    y = self.pdf.get_y() + 1

                    self.pdf.set_fill_color(100, 149, 237)
                    self.pdf.rect(x, y, max(bar_width, 1), 4, style="F")
                    self.pdf.ln(6)

    def save(self, filename):
        self.pdf.output(filename)