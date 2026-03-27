import time
from modules import mod_headers, mod_pubfiles, mod_whois, mod_nmap, mod_nikto, mod_dirsearch, mod_wpscan
from scoring.anssi_scorer import score_findings
from datetime import datetime
import uuid

DELAY_BETWEEN_MODULES = 1


def _tag_findings(findings: list, module_name: str) -> list:
    """Ajoute le nom du module à chaque finding."""
    for f in findings:
        f["module_name"] = module_name
    return findings


def run_audit(target: str, mode: str = "simple") -> dict:
    print(f"\n🔍 Démarrage de l'audit [{mode.upper()}] sur : {target}")
    print("=" * 60)

    all_findings = []
    modules_run = []

    # MODULE 1 — En-têtes HTTP
    print("▶ [1] Analyse des en-têtes de sécurité HTTP...")
    result_headers = mod_headers.run(target)
    findings = result_headers.get("findings", [])
    all_findings.extend(_tag_findings(findings, "🔒 En-têtes de Sécurité HTTP"))
    modules_run.append("HTTP Security Headers")
    time.sleep(DELAY_BETWEEN_MODULES)

    # MODULE 2 — Fichiers publics
    print("▶ [2] Analyse des fichiers publics...")
    result_pubfiles = mod_pubfiles.run(target)
    findings = result_pubfiles.get("findings", [])
    all_findings.extend(_tag_findings(findings, "📂 Fichiers Publics"))
    modules_run.append("Fichiers Publics")
    time.sleep(DELAY_BETWEEN_MODULES)

    # MODULE 3 — WHOIS
    print("▶ [3] Analyse WHOIS du domaine...")
    result_whois = mod_whois.run(target)
    findings = result_whois.get("findings", [])
    all_findings.extend(_tag_findings(findings, "🌐 WHOIS / Domaine"))
    modules_run.append("WHOIS / Domaine")
    time.sleep(DELAY_BETWEEN_MODULES)

    # MODE AVANCÉ
    if mode == "advanced":

        print("▶ [4] Scan des ports ouverts (nmap)...")
        result_nmap = mod_nmap.run(target)
        findings = result_nmap.get("findings", [])
        all_findings.extend(_tag_findings(findings, "🔌 Scan de Ports (Nmap)"))
        modules_run.append("Scan de Ports (Nmap)")
        time.sleep(DELAY_BETWEEN_MODULES)

        print("▶ [5] Scan des vulnérabilités web (nikto)...")
        result_nikto = mod_nikto.run(target)
        findings = result_nikto.get("findings", [])
        all_findings.extend(_tag_findings(findings, "🕷️ Nikto — Vulnérabilités Web"))
        modules_run.append("Nikto — Vulnérabilités Web")
        time.sleep(DELAY_BETWEEN_MODULES)

        print("▶ [6] Découverte des répertoires cachés...")
        result_dirsearch = mod_dirsearch.run(target)
        findings = result_dirsearch.get("findings", [])
        all_findings.extend(_tag_findings(findings, "📁 Répertoires Cachés"))
        modules_run.append("Dirsearch — Répertoires Cachés")
        time.sleep(DELAY_BETWEEN_MODULES)

        # MODULE ADAPTATIF — WPScan
        if mod_wpscan.is_wordpress(all_findings):
            print("▶ [7] 🎯 WordPress détecté ! Lancement de WPScan...")
            result_wpscan = mod_wpscan.run(target)
            findings = result_wpscan.get("findings", [])
            all_findings.extend(_tag_findings(findings, "🔐 WPScan — Audit WordPress"))
            modules_run.append("WPScan — Audit WordPress")
            time.sleep(DELAY_BETWEEN_MODULES)
        else:
            print("   ℹ️  WordPress non détecté — WPScan ignoré")

    # SCORING
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
        "id": str(uuid.uuid4())[:8].upper(),
        "date": datetime.now().strftime("%d/%m/%Y à %H:%M"),
        "target": target,
        "mode": mode,
        "modules_run": modules_run,
        "score": scored["score"],
        "grade": scored["grade"],
        "stats": scored["stats"],
        "total_findings": scored["total_findings"],
        "findings": scored["findings"],
        "modules_grouped": modules_grouped,
    }

    print(f"\n{'=' * 60}")
    print(f"  🎯 Cible    : {target}")
    print(f"  📅 Date     : {report['date']}")
    print(f"  🆔 ID       : {report['id']}")
    print(f"  📊 Score    : {report['score']}/100  →  Grade {report['grade']}")
    print(f"  🔴 Critique : {report['stats']['Critique']}")
    print(f"  🟠 Majeur   : {report['stats']['Majeur']}")
    print(f"  🟡 Important: {report['stats']['Important']}")
    print(f"  🔵 Mineur   : {report['stats']['Mineur']}")
    print(f"{'=' * 60}\n")

    return report


if __name__ == "__main__":
    import json
    report = run_audit("http://localhost:8080", mode="advanced")
    print(json.dumps(report, indent=2, ensure_ascii=False))
