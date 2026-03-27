import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "label": "HSTS",
        "description": "Force la connexion sécurisée (HTTPS)",
        "impact": "Important",
        "exploitability": "Facile",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "description": "Protège contre le vol de clic (Clickjacking)",
        "impact": "Important",
        "exploitability": "Facile",
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "description": "Empêche la devinette de type de fichier (MIME Sniffing)",
        "impact": "Mineur",
        "exploitability": "Facile",
    },
    "Content-Security-Policy": {
        "label": "CSP",
        "description": "Bloque l'injection de scripts malveillants (XSS)",
        "impact": "Majeur",
        "exploitability": "Facile",
    },
}


def run(target: str) -> dict:
    results = {
        "module": "HTTP Security Headers",
        "target": target,
        "findings": []
    }

    try:
        response = requests.head(
            target,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Security Audit)"}
        )

        for header_name, meta in SECURITY_HEADERS.items():
            present = header_name in response.headers
            value = response.headers.get(header_name, None)

            finding = {
                "header": header_name,
                "label": meta["label"],
                "description": meta["description"],
                "present": present,
                "value": value,
                "impact": meta["impact"] if not present else None,
                "exploitability": meta["exploitability"] if not present else None,
                "status": "✅ Présent" if present else "❌ Absent",
            }
            results["findings"].append(finding)

    except requests.exceptions.ConnectionError:
        results["error"] = f"Impossible de joindre la cible : {target}"
    except requests.exceptions.Timeout:
        results["error"] = f"Timeout — la cible ne répond pas : {target}"

    return results


if __name__ == "__main__":
    import json
    output = run("https://example.com")
    print(json.dumps(output, indent=2, ensure_ascii=False))
