import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request
from orchestrator import run_audit

app = Flask(__name__, template_folder="templates")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def save_report(report: dict):
    """Sauvegarde le rapport en JSON dans le dossier results/."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    filename = f"report_{report['id']}_{report['date'].replace('/', '-').replace(' ', '_').replace(':', '-')}.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"💾 Rapport sauvegardé : {filepath}")


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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
