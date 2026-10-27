"""Module du projet TP1 IDS/IPS."""

from fpdf import FPDF

from tp1.utils.capture import Capture


class Report:
    """Construit un rapport PDF à partir des résultats de Capture."""

    def __init__(self, capture: Capture, filename: str, summary: str) -> None:
        """Initialise ou exécute __init__."""
        self.capture: Capture = capture
        self.filename: str = filename
        self.title: str = "Rapport IDS / IPS"
        self.summary: str = summary
        self.array: str = ""
        self.graph: bool = False

    def get_stats(self) -> dict[str, int]:
        """Utilise les mêmes statistiques que le rapport JSON."""
        return self.capture.protocol_counts.copy()

    def concat_report(self) -> str:
        """Assemble la version texte du rapport."""
        return f"{self.title}\n{self.summary}\n{self.array}"

    def generate(self, param: str) -> None:
        """Prépare le tableau ou active le graphique."""
        if param == "graph":
            self.graph = True
        elif param == "array":
            self.array = "".join(f"{name} : {count}\n" for name, count in self.get_stats().items())

    def save(self, filename: str) -> None:
        """Enregistre le PDF, y compris quand la capture est vide."""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 8, self.summary)
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Statistiques des protocoles", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 8, self.array)

        if self.graph:
            stats = self.get_stats()
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Graphique", new_x="LMARGIN", new_y="NEXT")
            if stats:
                maximum = max(stats.values(), default=0)
                largeur = min(15, 155 / len(stats))
                pas = 170 / len(stats)
                y_base = min(250, pdf.get_y() + 75)
                for i, (name, count) in enumerate(stats.items()):
                    x = 20 + i * pas
                    hauteur = 60 * count / maximum if maximum else 0
                    if hauteur:
                        pdf.rect(x, y_base - hauteur, largeur, hauteur, style="F")
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_xy(x - 2, y_base + 2)
                    pdf.cell(largeur + 4, 5, name, align="C")
                    pdf.set_xy(x - 2, y_base - hauteur - 5)
                    pdf.cell(largeur + 4, 5, str(count), align="C")
        pdf.output(filename)
