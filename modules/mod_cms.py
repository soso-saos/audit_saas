import sys
import os
sys.path = [p for p in sys.path if not p.endswith('/modules') and not p.endswith('\\modules')]

import requests
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CMS_SIGNATURES = {
    "WordPress": {
        "icon": "🟦",
        "color": "#21759B",
        "paths_check": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "html_patterns": [
            r"/wp-content/",
            r"/wp-includes/",
            r'name="generator".*wordpress',
            r"wp-emoji",
        ],
        "header_patterns": ["x-redirect-by: wordpress"],
        "sensitive_paths": [
            "/wp-admin/", "/wp-login.php", "/wp-config.php.bak",
            "/wp-content/debug.log", "/wp-json/wp/v2/users",
            "/wp-includes/", "/?author=1",
        ],
        "description": "WordPress — CMS le plus populaire au monde (~40% du web)",
    },
    "Joomla": {
        "icon": "🟧",
        "color": "#F0811A",
        "paths_check": ["/administrator/", "/administrator", "/components/"],
        "html_patterns": [
            r"/components/com_",
            r"/media/jui/",
            r'name="generator".*joomla',
            r"joomla",
            r"/media/system/js/",
        ],
        "header_patterns": [],
        "sensitive_paths": [
            "/administrator/", "/configuration.php.bak",
            "/htaccess.txt", "/README.txt",
            "/CHANGELOG.php", "/administrator/manifests/",
            "/administrator/index.php",
        ],
        "description": "Joomla — CMS open source pour sites institutionnels",
    },
    "Drupal": {
        "icon": "🟦",
        "color": "#0077C0",
        "paths_check": ["/user/login", "/sites/default/", "/core/"],
        "html_patterns": [
            r'name="generator".*drupal',
            r"/sites/default/files/",
            r"drupal\.settings",
            r"/core/misc/drupal",
            r"drupal",
        ],
        "header_patterns": ["x-generator: drupal"],
        "sensitive_paths": [
            "/user/login", "/CHANGELOG.txt", "/core/CHANGELOG.txt",
            "/sites/default/settings.php", "/README.txt",
            "/install.php", "/?q=admin",
        ],
        "description": "Drupal — CMS robuste pour sites complexes",
    },
    "PrestaShop": {
        "icon": "🟪",
        "color": "#DF0067",
        "paths_check": ["/admin/", "/modules/", "/themes/"],
        "html_patterns": [
            r"prestashop",
            r"/modules/",
            r"var prestashop",
            r"PrestaShop",
        ],
        "header_patterns": [],
        "sensitive_paths": [
            "/admin/", "/app/config/parameters.php",
            "/config/settings.inc.php", "/install/",
            "/modules/", "/override/",
        ],
        "description": "PrestaShop — Solution e-commerce open source",
    },
    "Liferay": {
        "icon": "🟩",
        "color": "#0095DE",
        "paths_check": ["/c/portal/login", "/web/guest/home", "/o/frontend-js-web/"],
        "html_patterns": [
            r"liferay",
            r"Liferay",
            r"/o/frontend-js-web/",
            r"Liferay\.ThemeDisplay",
        ],
        "header_patterns": ["liferay-portal"],
        "sensitive_paths": [
            "/c/portal/login", "/c/portal/json_service",
            "/api/jsonws", "/web/guest/home",
            "/c/portal/upgrade_redirect",
        ],
        "description": "Liferay — Portail d'entreprise Java",
    },
    "DVWA": {
        "icon": "⚠️",
        "color": "#E74C3C",
        "paths_check": ["/dvwa/", "/login.php"],
        "html_patterns": [
            r"damn vulnerable",
            r"dvwa",
        ],
        "header_patterns": [],
        "sensitive_paths": [
            "/dvwa/", "/setup.php", "/config/",
            "/php.ini", "/login.php",
        ],
        "description": "DVWA — Application volontairement vulnérable (test uniquement)",
    },
}

HEADERS = {"User-Agent": "Mozilla/5.0 (Security Audit — ShieldScan)"}


def _fetch_page(url: str) -> tuple:
    try:
        r = requests.get(
            url, timeout=10, verify=False,
            allow_redirects=True, headers=HEADERS
        )
        return r.text.lower(), {k.lower(): v.lower() for k, v in r.headers.items()}
    except Exception:
        return "", {}


def _check_path_exists(base_url: str, path: str) -> bool:
    try:
        r = requests.get(
            base_url.rstrip("/") + path,
            timeout=5, verify=False,
            allow_redirects=False, headers=HEADERS
        )
        return r.status_code in {200, 301, 302, 403}
    except Exception:
        return False


def detect_cms(target: str) -> dict | None:
    html, headers = _fetch_page(target)
    base_url = target.rstrip("/")
    scores = {}

    for cms_name, sig in CMS_SIGNATURES.items():
        score = 0

        for pattern in sig["html_patterns"]:
            if re.search(pattern, html, re.IGNORECASE):
                score += 3

        for header_pattern in sig["header_patterns"]:
            key, _, value = header_pattern.partition(":")
            if key.strip() in headers:
                if not value or value.strip() in headers.get(key.strip(), ""):
                    score += 5

        for path in sig["paths_check"]:
            if _check_path_exists(base_url, path):
                score += 4

        if score > 0:
            scores[cms_name] = score

    if not scores:
        return None

    best_cms = max(scores, key=scores.get)
    if scores[best_cms] < 2:
        return None

    sig = CMS_SIGNATURES[best_cms]
    return {
        "cms_name":        best_cms,
        "icon":            sig["icon"],
        "color":           sig["color"],
        "description":     sig["description"],
        "confidence":      min(100, scores[best_cms] * 10),
        "sensitive_paths": sig["sensitive_paths"],
        "score":           scores[best_cms],
    }


def run(target: str) -> dict:
    results = {
        "module":       "Détection CMS",
        "target":       target,
        "cms_detected": None,
        "findings":     []
    }

    cms = detect_cms(target)

    if cms:
        results["cms_detected"] = cms
        results["findings"].append({
            "label":          f"{cms['icon']}  CMS détecté : {cms['cms_name']}",
            "description":    cms["description"],
            "impact":         None,
            "exploitability": None,
            "status":         f"ℹ️  {cms['cms_name']} — Confiance : {cms['confidence']}%",
            "cms_name":       cms["cms_name"],
            "risk_level":     None,
        })
    else:
        results["findings"].append({
            "label":          "CMS non identifié",
            "description":    "Technologie web non reconnue — application custom ou CMS rare",
            "impact":         None,
            "exploitability": None,
            "status":         "ℹ️  CMS inconnu ou application custom",
            "risk_level":     None,
        })

    return results


if __name__ == "__main__":
    targets = [
        (8080, "WordPress"),
        (8081, "DVWA"),
        (8083, "Joomla"),
        (8084, "Drupal"),
        (8085, "PrestaShop"),
        (8086, "Liferay"),
    ]
    for port, name in targets:
        print(f"\n--- Test {name} (port {port}) ---")
        result = run(f"http://localhost:{port}")
        cms = result.get("cms_detected")
        if cms:
            print(f"✅ CMS : {cms['icon']} {cms['cms_name']} (confiance : {cms['confidence']}%)")
        else:
            print("❌ Aucun CMS détecté")
