import subprocess
import re
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_wordpress(findings: list) -> bool:
    """
    Détecte si la cible est un WordPress
    en cherchant des indicateurs dans les findings existants.
    """
    wp_signals = [
        "wp-admin", "wp-login", "wp-content",
        "wp-includes", "wordpress", "wpuser"
    ]
    for f in findings:
        # Cherche dans le label et la description
        text = (str(f.get("label", "")) + str(f.get("description", "")) +
                str(f.get("status", ""))).lower()
        if any(signal in text for signal in wp_signals):
            return True
    return False


def run(target: str) -> dict:
    """Lance WPScan sur la cible WordPress détectée."""

    results = {
        "module": "WPScan — Audit WordPress",
        "target": target,
        "findings": []
    }

    try:
        print(f"   🔎 Scan WPScan sur {target} (timeout : 3 min)...")

        cmd = [
            "wpscan",
            "--url", target,
            "--no-banner",
            "--disable-tls-checks",
            "--format", "json",
            "--max-threads", "5",    # Éthique — pas de DDoS
            "--request-timeout", "10",
        ]

        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )

        raw = output.stdout

        # WPScan retourne du JSON
        try:
            data = json.loads(raw)
            findings = _parse_wpscan_json(data, target)
            results["findings"] = findings
        except json.JSONDecodeError:
            # Fallback : parse le texte brut
            findings = _parse_wpscan_text(output.stdout + output.stderr)
            results["findings"] = findings

        if not results["findings"]:
            results["findings"].append({
                "label": "WPScan — Aucune faille détectée",
                "description": "WordPress semble à jour et correctement configuré",
                "impact": None,
                "exploitability": None,
                "status": "✅ Aucune faille WordPress détectée",
            })

    except subprocess.TimeoutExpired:
        results["warning"] = "WPScan interrompu après 3 min"
        if not results["findings"]:
            results["findings"].append({
                "label": "WPScan — Timeout",
                "description": "Le scan n'a pas pu terminer dans le temps imparti",
                "impact": None,
                "exploitability": None,
                "status": "⚠️  Timeout",
            })
    except FileNotFoundError:
        results["error"] = "wpscan non installé (apt install wpscan)"
    except Exception as e:
        results["error"] = str(e)

    return results


def _parse_wpscan_json(data: dict, target: str) -> list:
    """Parse la sortie JSON de WPScan."""
    findings = []

    # Version WordPress
    wp_version = data.get("version", {})
    if wp_version:
        version_number = wp_version.get("number", "inconnue")
        vulnerabilities = wp_version.get("vulnerabilities", [])

        if vulnerabilities:
            for vuln in vulnerabilities:
                title = vuln.get("title", "Vulnérabilité WordPress")
                refs  = vuln.get("references", {})
                cve   = refs.get("cve", [])
                cve_str = f" (CVE-{cve[0]})" if cve else ""

                findings.append({
                    "label": f"WordPress {version_number} — {title[:80]}{cve_str}",
                    "description": f"Version WordPress vulnérable : {version_number}",
                    "impact": "Critique",
                    "exploitability": "Facile",
                    "status": "🔴 Version vulnérable détectée",
                })
        else:
            findings.append({
                "label": f"WordPress version {version_number} détectée",
                "description": "Version WordPress identifiée — vérifier si elle est à jour",
                "impact": "Mineur",
                "exploitability": "Modérée",
                "status": f"ℹ️  Version {version_number}",
            })

    # Plugins vulnérables
    plugins = data.get("plugins", {})
    for plugin_name, plugin_data in plugins.items():
        vulns = plugin_data.get("vulnerabilities", [])
        version = plugin_data.get("version", {}).get("number", "?")

        if vulns:
            for vuln in vulns:
                title = vuln.get("title", "Vulnérabilité plugin")
                refs  = vuln.get("references", {})
                cve   = refs.get("cve", [])
                cve_str = f" (CVE-{cve[0]})" if cve else ""

                findings.append({
                    "label": f"Plugin {plugin_name} v{version} — {title[:70]}{cve_str}",
                    "description": f"Plugin WordPress vulnérable : {plugin_name}",
                    "impact": "Majeur",
                    "exploitability": "Facile",
                    "status": "🔴 Plugin vulnérable détecté",
                })
        else:
            findings.append({
                "label": f"Plugin détecté : {plugin_name} v{version}",
                "description": f"Plugin WordPress installé : {plugin_name}",
                "impact": "Mineur",
                "exploitability": "Modérée",
                "status": f"ℹ️  Plugin présent",
            })

    # Thèmes vulnérables
    themes = data.get("themes", {})
    for theme_name, theme_data in themes.items():
        vulns = theme_data.get("vulnerabilities", [])
        if vulns:
            for vuln in vulns:
                title = vuln.get("title", "Vulnérabilité thème")
                findings.append({
                    "label": f"Thème {theme_name} — {title[:80]}",
                    "description": f"Thème WordPress vulnérable : {theme_name}",
                    "impact": "Majeur",
                    "exploitability": "Facile",
                    "status": "🔴 Thème vulnérable détecté",
                })

    # Utilisateurs exposés
    users = data.get("users", {})
    if users:
        user_list = list(users.keys())
        findings.append({
            "label": f"Utilisateurs exposés : {', '.join(user_list[:5])}",
            "description": "L'énumération des utilisateurs WordPress est possible",
            "impact": "Important",
            "exploitability": "Facile",
            "status": f"⚠️  {len(user_list)} utilisateur(s) trouvé(s)",
        })

    # Xmlrpc activé
    xmlrpc = data.get("main_theme", {})
    if data.get("xmlrpc", {}).get("found"):
        findings.append({
            "label": "XML-RPC activé — attaques bruteforce possibles",
            "description": "XML-RPC permet des attaques par force brute amplifiées",
            "impact": "Important",
            "exploitability": "Facile",
            "status": "⚠️  XML-RPC activé",
        })

    # Readme exposé
    if data.get("readme", {}).get("found"):
        findings.append({
            "label": "readme.html exposé — révèle la version WordPress",
            "description": "Le fichier readme.html expose la version exacte de WordPress",
            "impact": "Mineur",
            "exploitability": "Facile",
            "status": "⚠️  readme.html accessible",
        })

    return findings


def _parse_wpscan_text(raw: str) -> list:
    """Fallback : parse la sortie texte de WPScan."""
    findings = []
    seen = set()

    # Recherche les lignes importantes
    patterns = [
        (r"\[!\] (.+)", "Majeur"),
        (r"\[+\] WordPress version ([\d.]+)", "Mineur"),
        (r"CVE-(\d{4}-\d+)", "Critique"),
    ]

    for line in raw.split("\n"):
        line = line.strip()
        if not line or line in seen:
            continue

        for pattern, impact in patterns:
            match = re.search(pattern, line)
            if match:
                seen.add(line)
                findings.append({
                    "label": line[:120],
                    "description": "Détecté par WPScan",
                    "impact": impact,
                    "exploitability": "Facile",
                    "status": "⚠️  Détecté",
                })
                break

    return findings


if __name__ == "__main__":
    import json as json_lib
    output = run("http://localhost:8080")
    print(json_lib.dumps(output, indent=2, ensure_ascii=False))
