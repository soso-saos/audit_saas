import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from modules import mod_headers, mod_pubfiles, mod_whois, mod_nmap, mod_nikto, mod_dirsearch, mod_wpscan
from scoring.anssi_scorer import score_findings
from datetime import datetime
import uuid

DELAY_BETWEEN_MODULES = 1


def _tag_findings(findings: list, module_name: str) -> list:
    for f in findings:
        f["module_name"] = module_name
    return findings


def _detect_cms_from_findings(findings: list) -> dict | None:
    """
    Détecte le CMS depuis les findings POSITIFS uniquement.
    Ignore les checks négatifs (fichiers non trouvés, etc.)
    """
    positive_findings = []
    for f in findings:
        status = str(f.get("status", "")).lower()
        http_code = f.get("http_code")
        source = f.get("source", "")

        if http_code is not None:
            positive_findings.append(f)
        elif source == "nikto":
            positive_findings.append(f)
        elif "ouvert" in status or "détecté" in status:
            positive_findings.append(f)
        elif f.get("present") is True:
            positive_findings.append(f)

    all_text = " ".join([
        str(f.get("label", "")) + " " +
        str(f.get("description", "")) + " " +
        str(f.get("status", ""))
        for f in positive_findings
    ]).lower()

    cms_signals = {
        "WordPress": {
            "icon": "🟦", "color": "#21759B",
            "description": "WordPress — CMS le plus populaire au monde (~40% du web)",
            "keywords": [
                "wp-login", "wp-admin", "wp-content", "wp-includes",
                "wordpress", "wp-json", "wp-links-opml"
            ],
            "sensitive_paths": [
                "/wp-admin/", "/wp-login.php", "/wp-config.php.bak",
                "/wp-content/debug.log", "/wp-json/wp/v2/users",
                "/wp-includes/", "/?author=1",
            ]
        },
        "Joomla": {
            "icon": "🟧", "color": "#F0811A",
            "description": "Joomla — CMS open source pour sites institutionnels",
            "keywords": [
                "/administrator", "joomla", "/components/com_",
                "com_content", "/media/jui/"
            ],
            "sensitive_paths": [
                "/administrator/", "/administrator/index.php",
                "/configuration.php.bak", "/htaccess.txt",
                "/CHANGELOG.php", "/administrator/manifests/",
            ]
        },
        "Drupal": {
            "icon": "🟦", "color": "#0077C0",
            "description": "Drupal — CMS robuste pour sites complexes",
            "keywords": [
                "drupal", "/sites/default", "drupal.settings",
                "/core/misc/drupal", "x-generator: drupal"
            ],
            "sensitive_paths": [
                "/user/login", "/CHANGELOG.txt", "/core/CHANGELOG.txt",
                "/sites/default/settings.php", "/install.php",
            ]
        },
        "PrestaShop": {
            "icon": "🟪", "color": "#DF0067",
            "description": "PrestaShop — Solution e-commerce open source",
            "keywords": [
                "prestashop", "var prestashop", "presta"
            ],
            "sensitive_paths": [
                "/admin/", "/app/config/parameters.php",
                "/config/settings.inc.php", "/install/", "/modules/",
            ]
        },
        "Liferay": {
            "icon": "🟩", "color": "#0095DE",
            "description": "Liferay — Portail d'entreprise Java",
            "keywords": [
                "liferay", "/o/frontend-js-web/",
                "liferay.themedisplay", "/c/portal/"
            ],
            "sensitive_paths": [
                "/c/portal/login", "/api/jsonws",
                "/web/guest/home", "/c/portal/json_service",
            ]
        },
        "DVWA": {
            "icon": "⚠️", "color": "#E74C3C",
            "description": "DVWA — Application volontairement vulnérable",
            "keywords": [
                "dvwa", "damn vulnerable", "setup.php"
            ],
            "sensitive_paths": [
                "/dvwa/", "/setup.php", "/config/", "/php.ini",
            ]
        },
    }

    scores = {}
    for cms_name, sig in cms_signals.items():
        score = sum(1 for kw in sig["keywords"] if kw in all_text)
        if score > 0:
            scores[cms_name] = score

    if not scores:
        return None

    best = max(scores, key=scores.get)
    sig = cms_signals[best]

    return {
        "cms_name":        best,
        "icon":            sig["icon"],
        "color":           sig["color"],
        "description":     sig["description"],
        "confidence":      min(100, scores[best] * 25),
        "sensitive_paths": sig["sensitive_paths"],
    }


def _scan_cms_specific_paths(target: str, cms_info: dict) -> list:
    """Scan des chemins sensibles spécifiques au CMS détecté."""
    findings = []
    base = target.rstrip("/")
    cms_name = cms_info["cms_name"]

    path_risk = {
        "admin":     {"impact": "Important", "exploitability": "Facile"},
        "login":     {"impact": "Important", "exploitability": "Facile"},
        "config":    {"impact": "Critique",  "exploitability": "Facile"},
        "install":   {"impact": "Majeur",    "exploitability": "Facile"},
        "setup":     {"impact": "Majeur",    "exploitability": "Facile"},
        "log":       {"impact": "Important", "exploitability": "Facile"},
        "json":      {"impact": "Important", "exploitability": "Facile"},
        "api":       {"impact": "Important", "exploitability": "Facile"},
        "author":    {"impact": "Mineur",    "exploitability": "Facile"},
        "changelog": {"impact": "Mineur",    "exploitability": "Facile"},
        "readme":    {"impact": "Mineur",    "exploitability": "Facile"},
        "manifests": {"impact": "Mineur",    "exploitability": "Facile"},
    }

    for path in cms_info.get("sensitive_paths", []):
        try:
            r = requests.get(
                base + path, timeout=5, verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (Security Audit — ShieldScan)"}
            )
            if r.status_code not in {200, 301, 302, 403}:
                continue

            risk = {"impact": "Mineur", "exploitability": "Facile"}
            for keyword, r_info in path_risk.items():
                if keyword in path.lower():
                    risk = r_info
                    break

            code_label = {
                200: "✅ Accessible",
                301: "↪️  Redirige",
                302: "↪️  Redirige",
                403: "🔒 Interdit mais existant",
            }.get(r.status_code, f"HTTP {r.status_code}")

            findings.append({
                "label":          path,
                "description":    f"Chemin {cms_name} sensible détecté",
                "http_code":      r.status_code,
                "impact":         risk["impact"],
                "exploitability": risk["exploitability"],
                "status":         f"{code_label} (HTTP {r.status_code})",
            })

        except Exception:
            continue

    return findings


def run_audit(target: str, mode: str = "simple") -> dict:
    print(f"\n🔍 Démarrage de l'audit [{mode.upper()}] sur : {target}")
    print("=" * 60)

    all_findings = []
    modules_run = []
    cms_info = None

    # ── MODULE 1 — En-têtes HTTP ───────────────────────────────────
    print("▶ [1] Analyse des en-têtes de sécurité HTTP...")
    result = mod_headers.run(target)
    all_findings.extend(_tag_findings(result.get("findings", []), "🔒 En-têtes de Sécurité HTTP"))
    modules_run.append("HTTP Security Headers")
    time.sleep(DELAY_BETWEEN_MODULES)

    # ── MODULE 2 — Fichiers publics ────────────────────────────────
    print("▶ [2] Analyse des fichiers publics...")
    result = mod_pubfiles.run(target)
    all_findings.extend(_tag_findings(result.get("findings", []), "📂 Fichiers Publics"))
    modules_run.append("Fichiers Publics")
    time.sleep(DELAY_BETWEEN_MODULES)

    # ── MODULE 3 — WHOIS ──────────────────────────────────────────
    print("▶ [3] Analyse WHOIS du domaine...")
    result = mod_whois.run(target)
    all_findings.extend(_tag_findings(result.get("findings", []), "🌐 WHOIS / Domaine"))
    modules_run.append("WHOIS / Domaine")
    time.sleep(DELAY_BETWEEN_MODULES)

    # ── MODE AVANCÉ ────────────────────────────────────────────────
    if mode == "advanced":

        # MODULE 4 — Nmap
        print("▶ [4] Scan des ports ouverts (nmap)...")
        result = mod_nmap.run(target)
        all_findings.extend(_tag_findings(result.get("findings", []), "🔌 Scan de Ports (Nmap)"))
        modules_run.append("Scan de Ports (Nmap)")
        time.sleep(DELAY_BETWEEN_MODULES)

        # MODULE 5 — Nikto
        print("▶ [5] Scan des vulnérabilités web (nikto)...")
        result = mod_nikto.run(target)
        all_findings.extend(_tag_findings(result.get("findings", []), "🕷️ Nikto — Vulnérabilités Web"))
        modules_run.append("Nikto — Vulnérabilités Web")
        time.sleep(DELAY_BETWEEN_MODULES)

        # MODULE 6 — Dirsearch
        print("▶ [6] Découverte des répertoires cachés...")
        result = mod_dirsearch.run(target)
        all_findings.extend(_tag_findings(result.get("findings", []), "📁 Répertoires Cachés"))
        modules_run.append("Dirsearch — Répertoires Cachés")
        time.sleep(DELAY_BETWEEN_MODULES)

        # MODULE 7 — Détection CMS depuis les findings positifs
        print("▶ [7] Détection du CMS depuis les findings...")
        cms_info = _detect_cms_from_findings(all_findings)

        if cms_info:
            cms_name = cms_info["cms_name"]
            print(f"   🎯 CMS détecté : {cms_info['icon']} {cms_name} (confiance : {cms_info['confidence']}%)")

            # Finding informatif
            all_findings.append({
                "label":          f"{cms_info['icon']}  CMS détecté : {cms_name}",
                "description":    cms_info["description"],
                "impact":         None,
                "exploitability": None,
                "status":         f"ℹ️  {cms_name} — Confiance : {cms_info['confidence']}%",
                "risk_level":     None,
                "module_name":    "🖥️ Détection CMS",
            })
            modules_run.append("Détection CMS")

            # MODULE 8 — Scan adaptatif selon le CMS
            if cms_name == "WordPress":
                print("▶ [8] 🎯 WordPress → Lancement de WPScan...")
                result = mod_wpscan.run(target)
                all_findings.extend(_tag_findings(result.get("findings", []), "🔐 WPScan — Audit WordPress"))
                modules_run.append("WPScan — Audit WordPress")

            else:
                print(f"▶ [8] 🎯 {cms_name} → Scan chemins sensibles {cms_info['icon']}...")
                cms_findings = _scan_cms_specific_paths(target, cms_info)
                if cms_findings:
                    label = f"{cms_info['icon']} Chemins Sensibles {cms_name}"
                    all_findings.extend(_tag_findings(cms_findings, label))
                    modules_run.append(f"Scan {cms_name}")
                    print(f"   → {len(cms_findings)} chemin(s) sensible(s) trouvé(s)")
                else:
                    print(f"   → Aucun chemin sensible {cms_name} trouvé")

            time.sleep(DELAY_BETWEEN_MODULES)

        else:
            print("   ℹ️  Aucun CMS reconnu")
            all_findings.append({
                "label":          "CMS non identifié",
                "description":    "Technologie web non reconnue — application custom ou CMS rare",
                "impact":         None,
                "exploitability": None,
                "status":         "ℹ️  CMS inconnu ou application custom",
                "risk_level":     None,
                "module_name":    "🖥️ Détection CMS",
            })
            modules_run.append("Détection CMS")

    # ── SCORING ────────────────────────────────────────────────────
    print("\n📊 Calcul du score ANSSI...")
    scored = score_findings(all_findings)

    # Groupement par module
    modules_grouped = {}
    for f in scored["findings"]:
        module = f.get("module_name", "Autres")
        if module not in modules_grouped:
            modules_grouped[module] = []
        modules_grouped[module].append(f)

    report = {
        "id":              str(uuid.uuid4())[:8].upper(),
        "date":            datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "target":          target,
        "mode":            mode,
        "modules_run":     modules_run,
        "score":           scored["score"],
        "grade":           scored["grade"],
        "stats":           scored["stats"],
        "total_findings":  scored["total_findings"],
        "findings":        scored["findings"],
        "modules_grouped": modules_grouped,
        "cms_detected":    cms_info,
    }

    print(f"\n{'=' * 60}")
    print(f"  🎯 Cible    : {target}")
    print(f"  📅 Date     : {report['date']}")
    print(f"  🆔 ID       : {report['id']}")
    if cms_info:
        print(f"  🖥️  CMS      : {cms_info['icon']} {cms_info['cms_name']}")
    print(f"  📊 Score    : {report['score']}/100  →  Grade {report['grade']}")
    print(f"  🔴 Critique : {report['stats']['Critique']}")
    print(f"  🟠 Majeur   : {report['stats']['Majeur']}")
    print(f"  🟡 Important: {report['stats']['Important']}")
    print(f"  🔵 Mineur   : {report['stats']['Mineur']}")
    print(f"{'=' * 60}\n")

    return report


if __name__ == "__main__":
    import json
    report = run_audit("http://localhost:8081", mode="advanced")
    print(json.dumps(report, indent=2, ensure_ascii=False))
