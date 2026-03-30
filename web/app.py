import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request, Response
from orchestrator import run_audit
from weasyprint import HTML

app = Flask(__name__, template_folder="templates")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def save_report(report: dict):
    """Sauvegarde le rapport en JSON dans le dossier results/."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    filename = f"report_{report['id']}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"💾 Rapport sauvegardé : {filepath}")


def load_report(report_id: str) -> dict | None:
    """Charge un rapport JSON depuis le dossier results/."""
    filepath = os.path.join(RESULTS_DIR, f"report_{report_id}.json")
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/audit", methods=["POST"])
def audit():
    target = request.form.get("target", "").strip()
    mode   = request.form.get("mode", "simple")

    if not target.startswith("http"):
        target = "https://" + target

    report = run_audit(target, mode=mode)
    save_report(report)

    return render_template("report.html", report=report)


@app.route("/download/<report_id>")
def download_pdf(report_id: str):
    """Génère et télécharge le rapport en PDF."""
    report = load_report(report_id)
    if not report:
        return "Rapport introuvable", 404

    # Génère le HTML du rapport
    html_content = render_template("report_pdf.html", report=report)

    # Convertit en PDF avec WeasyPrint
    pdf = HTML(string=html_content, base_url=request.base_url).write_pdf()

    filename = f"ShieldScan_Rapport_{report['id']}_{report['target'].replace('http://', '').replace('/', '_')}.pdf"

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
