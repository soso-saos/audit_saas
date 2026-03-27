import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_FILES = [
    {"path": "/.env",              "impact": "Critique",  "exploitability": "Facile",
     "description": "Fichier de configuration exposé (mots de passe, clés API)"},
    {"path": "/.git/config",       "impact": "Majeur",    "exploitability": "Facile",
     "description": "Dépôt Git exposé (accès au code source)"},
    {"path": "/backup.zip",        "impact": "Critique",  "exploitability": "Facile",
     "description": "Archive de sauvegarde accessible publiquement"},
    {"path": "/backup.sql",        "impact": "Critique",  "exploitability": "Facile",
     "description": "Dump de base de données accessible publiquement"},
    {"path": "/wp-config.php.bak", "impact": "Critique",  "exploitability": "Facile",
     "description": "Sauvegarde de configuration WordPress exposée"},
    {"path": "/config.php.bak",    "impact": "Critique",  "exploitability": "Facile",
     "description": "Sauvegarde de configuration exposée"},
    {"path": "/error_log",         "impact": "Important", "exploitability": "Facile",
     "description": "Journal d'erreurs exposé (révèle la structure interne)"},
]

SENSITIVE_KEYWORDS = [
    "/admin", "/backup", "/config", "/private",
    "/secret", "/database", "/wp-admin", "/phpmyadmin"
]


def _check_url(url: str, timeout: int = 10) -> int:
    try:
        r = requests.get(
            url, timeout=timeout, allow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Security Audit)"}
        )
        return r.status_code
    except requests.exceptions.RequestException:
        return 0


def _check_robots(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/robots.txt"
    finding = {
        "file": "robots.txt",
        "url": url,
        "present": False,
        "sensitive_paths": [],
        "impact": None,
        "exploitability": None,
        "description": "Fichier d'instructions pour les robots (Google, etc.)",
    }

    try:
        r = requests.get(
            url, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Security Audit)"}
        )
        if r.status_code == 200:
            finding["present"] = True
            content = r.text.lower()

            for keyword in SENSITIVE_KEYWORDS:
                if keyword in content:
                    finding["sensitive_paths"].append(keyword)

            if finding["sensitive_paths"]:
                finding["impact"] = "Important"
                finding["exploitability"] = "Facile"
                finding["status"] = (
                    f"⚠️  Présent — révèle {len(finding['sensitive_paths'])} "
                    f"chemin(s) sensible(s) : {', '.join(finding['sensitive_paths'])}"
                )
            else:
                finding["status"] = "✅ Présent — aucun chemin sensible détecté"
        else:
            finding["status"] = "ℹ️  Absent (404)"

    except requests.exceptions.RequestException as e:
        finding["status"] = f"❌ Erreur : {e}"

    return finding


def _check_sitemap(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/sitemap.xml"
    status_code = _check_url(url)
    present = status_code == 200

    return {
        "file": "sitemap.xml",
        "url": url,
        "present": present,
        "impact": None,
        "exploitability": None,
        "status": "ℹ️  Présent (liste toutes les pages du site)"
                  if present else "ℹ️  Absent",
    }


def _check_sensitive_files(base_url: str) -> list:
    findings = []
    base = base_url.rstrip("/")

    for file_info in SENSITIVE_FILES:
        url = base + file_info["path"]
        status_code = _check_url(url)
        exposed = status_code == 200

        findings.append({
            "file": file_info["path"],
            "url": url,
            "present": exposed,
            "impact": file_info["impact"] if exposed else None,
            "exploitability": file_info["exploitability"] if exposed else None,
            "description": file_info["description"],
            "status": f"🔴 EXPOSÉ (HTTP {status_code})" if exposed
                      else f"✅ Non accessible (HTTP {status_code})",
        })

    return findings


def run(target: str) -> dict:
    results = {
        "module": "Fichiers Publics",
        "target": target,
        "findings": []
    }

    results["findings"].append(_check_robots(target))
    results["findings"].append(_check_sitemap(target))
    results["findings"].extend(_check_sensitive_files(target))

    return results


if __name__ == "__main__":
    import json
    output = run("https://example.com")
    print(json.dumps(output, indent=2, ensure_ascii=False))
