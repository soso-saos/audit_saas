import subprocess
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Champs WHOIS qu'on veut extraire et afficher
WHOIS_FIELDS = {
    "registrar":            "Bureau d'enregistrement",
    "creation date":        "Date de création",
    "expiration date":      "Date d'expiration",
    "updated date":         "Dernière mise à jour",
    "registrant name":      "Propriétaire",
    "registrant email":     "Email du propriétaire",
    "registrant phone":     "Téléphone du propriétaire",
    "registrant organization": "Organisation",
    "name server":          "Serveur DNS",
}

# Champs sensibles : si présents en clair → c'est une faille
SENSITIVE_FIELDS = ["registrant name", "registrant email", "registrant phone"]


def _extract_domain(target: str) -> str:
    """Extrait le domaine depuis une URL complète."""
    domain = target.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].split(":")[0]
    return domain


def run(target: str) -> dict:
    """Analyse les informations WHOIS d'un domaine."""
    domain = _extract_domain(target)

    results = {
        "module": "WHOIS / Informations Domaine",
        "target": domain,
        "findings": []
    }

    try:
        # Lance la commande whois système
        output = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=30
        )
        raw = output.stdout.lower()

        if not raw or "no match" in raw or "not found" in raw:
            results["findings"].append({
                "label": "WHOIS",
                "description": "Aucune information WHOIS disponible",
                "value": "N/A",
                "impact": None,
                "exploitability": None,
                "status": "ℹ️  Domaine local ou introuvable",
                "sensitive": False,
            })
            return results

        # Extraction des champs
        for field_key, field_label in WHOIS_FIELDS.items():
            # Recherche le champ dans la sortie brute
            pattern = rf"{re.escape(field_key)}\s*:\s*(.+)"
            matches = re.findall(pattern, raw)

            if matches:
                value = matches[0].strip()
                is_sensitive = field_key in SENSITIVE_FIELDS

                finding = {
                    "label": field_label,
                    "description": f"Champ WHOIS : {field_key}",
                    "value": value,
                    "sensitive": is_sensitive,
                    # Si données perso exposées → c'est une faille
                    "impact": "Mineur" if is_sensitive else None,
                    "exploitability": "Facile" if is_sensitive else None,
                    "status": (
                        f"⚠️  Exposé publiquement : {value}"
                        if is_sensitive
                        else f"ℹ️  {value}"
                    ),
                }
                results["findings"].append(finding)

        # Si aucun champ trouvé
        if not results["findings"]:
            results["findings"].append({
                "label": "WHOIS",
                "description": "Données WHOIS masquées ou inaccessibles",
                "value": "Masqué",
                "impact": None,
                "exploitability": None,
                "status": "✅ Données personnelles masquées (bonne pratique)",
                "sensitive": False,
            })

    except subprocess.TimeoutExpired:
        results["error"] = "Timeout WHOIS — le serveur ne répond pas"
    except FileNotFoundError:
        results["error"] = "Outil 'whois' non installé (apt install whois)"
    except Exception as e:
        results["error"] = str(e)

    return results


if __name__ == "__main__":
    import json
    # Test sur un vrai domaine
    output = run("https://google.com")
    print(json.dumps(output, indent=2, ensure_ascii=False))
