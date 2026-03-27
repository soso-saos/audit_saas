import subprocess
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RISK_KEYWORDS = {
    "sql injection":        {"impact": "Critique",  "exploitability": "Facile"},
    "xss":                  {"impact": "Majeur",    "exploitability": "Facile"},
    "cross-site scripting": {"impact": "Majeur",    "exploitability": "Facile"},
    "remote file":          {"impact": "Critique",  "exploitability": "Facile"},
    "local file":           {"impact": "Critique",  "exploitability": "Facile"},
    "directory traversal":  {"impact": "Critique",  "exploitability": "Facile"},
    "path traversal":       {"impact": "Critique",  "exploitability": "Facile"},
    "backup file":          {"impact": "Majeur",    "exploitability": "Facile"},
    "config":               {"impact": "Majeur",    "exploitability": "Facile"},
    "password file":        {"impact": "Critique",  "exploitability": "Facile"},
    "phpinfo":              {"impact": "Important", "exploitability": "Facile"},
    "debug":                {"impact": "Important", "exploitability": "Facile"},
    "admin":                {"impact": "Important", "exploitability": "Facile"},
    "login":                {"impact": "Important", "exploitability": "Facile"},
    "outdated":             {"impact": "Important", "exploitability": "Modérée"},
    "vulnerable":           {"impact": "Majeur",    "exploitability": "Modérée"},
    "cve-":                 {"impact": "Critique",  "exploitability": "Facile"},
    "osvdb":                {"impact": "Important", "exploitability": "Modérée"},
    "default file":         {"impact": "Important", "exploitability": "Facile"},
    "exposed":              {"impact": "Important", "exploitability": "Facile"},
    "disclosure":           {"impact": "Important", "exploitability": "Facile"},
    "clickjack":            {"impact": "Important", "exploitability": "Facile"},
    "directory indexing":   {"impact": "Important", "exploitability": "Facile"},
    "index of":             {"impact": "Important", "exploitability": "Facile"},
    "httponly":             {"impact": "Important", "exploitability": "Facile"},
    "missing":              {"impact": "Mineur",    "exploitability": "Facile"},
}

# Lignes à ignorer absolument (bruit pur)
IGNORE_PATTERNS = [
    "platform:",
    "server:",
    "start time:",
    "end time:",
    "scan terminated",
    "host(s) tested",
    "nikto v",
    "items reported",
    "no cgi",
    "allowed http methods",
    "target ip",
    "target hostname",
    "target port",
    "retrieved x-powered",
]


def _extract_url(target: str) -> str:
    if not target.startswith("http"):
        return "http://" + target
    return target


def _get_risk(line: str) -> dict:
    line_lower = line.lower()
    for keyword, risk in RISK_KEYWORDS.items():
        if keyword in line_lower:
            return risk
    return {"impact": "Mineur", "exploitability": "Modérée"}


def _should_ignore(line: str) -> bool:
    """Filtre les lignes de bruit."""
    line_lower = line.lower().strip()

    # Ligne vide
    if not line_lower:
        return True

    # Doit contenir un numéro de finding nikto [XXXXXX]
    # OU être une ligne de vulnérabilité connue
    has_finding_id = "[" in line and "]" in line

    # Filtre par patterns de bruit
    for pattern in IGNORE_PATTERNS:
        if pattern in line_lower:
            return True

    # Si pas d'ID de finding et pas de mot-clé de risque → bruit
    if not has_finding_id:
        has_risk_keyword = any(k in line_lower for k in RISK_KEYWORDS)
        if not has_risk_keyword:
            return True

    return False


def run(target: str) -> dict:
    url = _extract_url(target)

    results = {
        "module": "Nikto — Vulnérabilités Web",
        "target": url,
        "findings": []
    }

    try:
        print(f"   🔎 Scan nikto sur {url} (timeout : 3 min)...")

        cmd = [
            "nikto",
            "-h", url,
            "-nossl",
            "-maxtime", "120s",
        ]

        output = subprocess.run(
            cmd, capture_output=True, text=True, timeout=200
        )
        raw = output.stdout

        seen = set()
        for line in raw.split("\n"):
            line = line.strip()

            if _should_ignore(line):
                continue

            # Nettoie les préfixes "+ " ou "- "
            clean_line = line.lstrip("+-").strip()
            if not clean_line or clean_line in seen:
                continue
            seen.add(clean_line)

            risk = _get_risk(clean_line)
            label = clean_line[:120] + "..." if len(clean_line) > 120 else clean_line

            results["findings"].append({
                "label": label,
                "description": "Détecté par Nikto — scanner de vulnérabilités web",
                "impact": risk["impact"],
                "exploitability": risk["exploitability"],
                "status": "⚠️  Détecté",
                "source": "nikto",
            })

        if not results["findings"]:
            results["findings"].append({
                "label": "Aucune vulnérabilité détectée par Nikto",
                "description": "Le scan n'a pas trouvé de failles connues",
                "impact": None,
                "exploitability": None,
                "status": "✅ Aucune faille détectée",
            })

    except subprocess.TimeoutExpired:
        results["warning"] = "Scan interrompu après 3 min — résultats partiels"
        if not results["findings"]:
            results["findings"].append({
                "label": "Scan interrompu — résultats partiels",
                "description": "Nikto n'a pas pu terminer dans le temps imparti",
                "impact": None,
                "exploitability": None,
                "status": "⚠️  Timeout",
            })
    except FileNotFoundError:
        results["error"] = "nikto non installé (apt install nikto)"
    except Exception as e:
        results["error"] = str(e)

    return results


if __name__ == "__main__":
    import json
    output = run("http://localhost:8081")
    print(json.dumps(output, indent=2, ensure_ascii=False))
