import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_PATHS = {
    "admin":          {"impact": "Important", "exploitability": "Facile",
                       "description": "Interface d'administration accessible"},
    "phpmyadmin":     {"impact": "Critique",  "exploitability": "Facile",
                       "description": "phpMyAdmin exposé — accès direct à la base de données"},
    "wp-admin":       {"impact": "Important", "exploitability": "Facile",
                       "description": "Interface d'administration WordPress accessible"},
    "wp-login":       {"impact": "Important", "exploitability": "Facile",
                       "description": "Page de connexion WordPress exposée"},
    "wp-login.php":   {"impact": "Important", "exploitability": "Facile",
                       "description": "Page de connexion WordPress exposée"},
    "backup":         {"impact": "Critique",  "exploitability": "Facile",
                       "description": "Dossier de sauvegarde accessible publiquement"},
    "config":         {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Dossier de configuration accessible"},
    ".git":           {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Dépôt Git exposé — code source accessible"},
    ".gitignore":     {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Fichier .gitignore exposé — révèle la structure du projet"},
    ".env":           {"impact": "Critique",  "exploitability": "Facile",
                       "description": "Fichier d'environnement exposé — mots de passe visibles"},
    "logs":           {"impact": "Important", "exploitability": "Facile",
                       "description": "Dossier de logs accessible — infos système exposées"},
    "install":        {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Script d'installation accessible — risque de réinstallation"},
    "install.php":    {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Script d'installation PHP accessible"},
    "setup":          {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Script de configuration accessible"},
    "setup.php":      {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Script de configuration PHP accessible"},
    "debug":          {"impact": "Important", "exploitability": "Facile",
                       "description": "Page de debug exposée — informations système visibles"},
    "phpinfo":        {"impact": "Important", "exploitability": "Facile",
                       "description": "phpinfo() exposé — configuration PHP visible"},
    "phpinfo.php":    {"impact": "Important", "exploitability": "Facile",
                       "description": "phpinfo() exposé — configuration PHP visible"},
    "php.ini":        {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Fichier php.ini exposé — configuration PHP visible"},
    "upload":         {"impact": "Important", "exploitability": "Facile",
                       "description": "Dossier d'upload accessible"},
    "uploads":        {"impact": "Important", "exploitability": "Facile",
                       "description": "Dossier d'uploads accessible"},
    "shell":          {"impact": "Critique",  "exploitability": "Facile",
                       "description": "Shell web potentiellement accessible"},
    "console":        {"impact": "Majeur",    "exploitability": "Facile",
                       "description": "Console d'administration exposée"},
    "server-status":  {"impact": "Important", "exploitability": "Facile",
                       "description": "Status Apache exposé — infos serveur visibles"},
    "changelog":      {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Changelog exposé — révèle la version exacte du logiciel"},
    "CHANGELOG":      {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Changelog exposé — révèle la version exacte du logiciel"},
    "readme":         {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "README exposé — révèle des informations sur le logiciel"},
    "README":         {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "README exposé — révèle des informations sur le logiciel"},
    "login":          {"impact": "Important", "exploitability": "Facile",
                       "description": "Page de connexion trouvée"},
    "login.php":      {"impact": "Important", "exploitability": "Facile",
                       "description": "Page de connexion PHP trouvée"},
    "docs":           {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Documentation accessible publiquement"},
    "dvwa":           {"impact": "Critique",  "exploitability": "Facile",
                       "description": "Application DVWA accessible — volontairement vulnérable"},
    "test":           {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Page de test accessible publiquement"},
    "tmp":            {"impact": "Important", "exploitability": "Facile",
                       "description": "Dossier temporaire accessible"},
    "temp":           {"impact": "Important", "exploitability": "Facile",
                       "description": "Dossier temporaire accessible"},
    "old":            {"impact": "Mineur",    "exploitability": "Facile",
                       "description": "Ancien fichier/dossier accessible"},
    "sql":            {"impact": "Critique",  "exploitability": "Facile",
                       "description": "Fichier SQL accessible — données de base de données exposées"},
}

# Liste des chemins à tester
WORDLIST = [
    # Admin & connexion
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-admin/",
    "/wp-login.php", "/login", "/login.php", "/signin", "/console",
    # Config & setup
    "/.env", "/.git", "/.git/config", "/.gitignore",
    "/config", "/config/", "/config.php", "/configuration.php",
    "/setup.php", "/install.php", "/install", "/install/",
    "/php.ini", "/phpinfo.php", "/info.php",
    # Backup & données
    "/backup", "/backup/", "/backup.zip", "/backup.sql", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql",
    "/wp-config.php.bak", "/config.php.bak",
    # Logs & debug
    "/logs", "/logs/", "/log", "/error_log", "/debug",
    "/server-status", "/server-info",
    # Docs & infos
    "/README.md", "/CHANGELOG.md", "/docs", "/docs/",
    # CMS spécifiques
    "/dvwa", "/dvwa/", "/phpmyadmin", "/phpmyadmin/",
    "/wp-content", "/wp-content/", "/wp-includes",
    "/sites/default", "/administrator/",
    # Upload
    "/upload", "/upload/", "/uploads", "/uploads/",
    # Divers
    "/tmp", "/temp", "/old", "/test", "/test.php",
    "/api", "/api/", "/v1", "/v2",
    "/shell.php", "/cmd.php", "/c99.php",
]

ACCESSIBLE_CODES = {200, 201, 301}
HEADERS = {"User-Agent": "Mozilla/5.0 (Security Audit)"}


def _extract_base_url(target: str) -> str:
    if not target.startswith("http"):
        target = "http://" + target
    # Supprime le chemin pour garder uniquement base
    parts = target.split("/")
    return "/".join(parts[:3])


def _get_risk(path: str) -> dict:
    path_lower = path.lower().strip("/")
    for keyword, risk in SENSITIVE_PATHS.items():
        if keyword.lower() in path_lower:
            return risk
    return {
        "impact": "Mineur",
        "exploitability": "Facile",
        "description": f"Chemin accessible non référencé : {path}"
    }


def _check_path(base_url: str, path: str) -> dict | None:
    """Vérifie un chemin et retourne un finding si accessible."""
    url = base_url.rstrip("/") + path
    try:
        r = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            verify=False,
            headers=HEADERS,
        )
        if r.status_code in ACCESSIBLE_CODES:
            return {"path": path, "code": r.status_code, "url": url}
    except requests.exceptions.RequestException:
        pass
    return None


def run(target: str) -> dict:
    base_url = _extract_base_url(target)

    results = {
        "module": "Dirsearch — Répertoires Cachés",
        "target": base_url,
        "findings": []
    }

    print(f"   🔎 Scan répertoires sur {base_url} ({len(WORDLIST)} chemins)...")

    findings = []
    seen = set()

    # Scan parallèle avec 10 threads (éthique)
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {
            executor.submit(_check_path, base_url, path): path
            for path in WORDLIST
        }
        for future in as_completed(future_to_path):
            result = future.result()
            if result and result["path"] not in seen:
                seen.add(result["path"])
                risk = _get_risk(result["path"])
                code_label = {
                    200: "✅ Accessible",
                    201: "✅ Accessible",
                    301: "↪️  Redirige",
                    302: "↪️  Redirige",
                }.get(result["code"], f"HTTP {result['code']}")

                findings.append({
                    "label": result["path"],
                    "description": risk["description"],
                    "http_code": result["code"],
                    "impact": risk["impact"],
                    "exploitability": risk["exploitability"],
                    "status": f"{code_label} (HTTP {result['code']})",
                })

    # Tri par code HTTP puis par chemin
    findings.sort(key=lambda x: (x["http_code"], x["label"]))
    results["findings"] = findings

    if not findings:
        results["findings"].append({
            "label": "Aucun répertoire sensible trouvé",
            "description": "Le scan n'a pas trouvé de chemins accessibles",
            "impact": None,
            "exploitability": None,
            "status": "✅ Aucun répertoire caché détecté",
        })

    return results


if __name__ == "__main__":
    import json
    output = run("http://localhost:8081")
    print(json.dumps(output, indent=2, ensure_ascii=False))
