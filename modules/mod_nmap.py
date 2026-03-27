import subprocess
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DANGEROUS_PORTS = {
    21:   {"service": "FTP",        "impact": "Important", "exploitability": "Facile",
           "description": "Transfert de fichiers non chiffré — credentials interceptables"},
    22:   {"service": "SSH",        "impact": "Mineur",    "exploitability": "Difficile",
           "description": "Accès SSH exposé — vérifier si l'accès est restreint"},
    23:   {"service": "Telnet",     "impact": "Critique",  "exploitability": "Facile",
           "description": "Telnet non chiffré — tout le trafic est lisible en clair"},
    25:   {"service": "SMTP",       "impact": "Important", "exploitability": "Modérée",
           "description": "Serveur mail exposé — risque de spam relay"},
    80:   {"service": "HTTP",       "impact": None,        "exploitability": None,
           "description": "Serveur web HTTP — normal mais trafic non chiffré"},
    443:  {"service": "HTTPS",      "impact": None,        "exploitability": None,
           "description": "Serveur web HTTPS — normal et sécurisé"},
    445:  {"service": "SMB",        "impact": "Critique",  "exploitability": "Facile",
           "description": "Partage Windows exposé — cible privilégiée des ransomwares"},
    1433: {"service": "MSSQL",      "impact": "Critique",  "exploitability": "Facile",
           "description": "Base de données SQL Server exposée sur Internet"},
    3000: {"service": "App Web",    "impact": "Mineur",    "exploitability": "Facile",
           "description": "Application web sur port non standard — souvent sans protection"},
    3306: {"service": "MySQL",      "impact": "Critique",  "exploitability": "Facile",
           "description": "Base de données MySQL exposée — accès direct possible"},
    3389: {"service": "RDP",        "impact": "Majeur",    "exploitability": "Modérée",
           "description": "Bureau à distance Windows exposé — cible des attaques bruteforce"},
    5432: {"service": "PostgreSQL", "impact": "Critique",  "exploitability": "Facile",
           "description": "Base de données PostgreSQL exposée sur Internet"},
    6379: {"service": "Redis",      "impact": "Critique",  "exploitability": "Facile",
           "description": "Redis exposé sans authentification — lecture/écriture libre"},
    8080: {"service": "HTTP-Alt",   "impact": "Mineur",    "exploitability": "Facile",
           "description": "Port HTTP alternatif — souvent un panneau d'administration"},
    8443: {"service": "HTTPS-Alt",  "impact": "Mineur",    "exploitability": "Facile",
           "description": "Port HTTPS alternatif exposé"},
    27017:{"service": "MongoDB",    "impact": "Critique",  "exploitability": "Facile",
           "description": "Base de données MongoDB exposée — souvent sans mot de passe"},
}

# Versions connues comme vulnérables
VULNERABLE_VERSIONS = {
    "apache httpd 2.4.25": "CVE-2017-7679 — Vulnérabilité critique connue (très ancienne version)",
    "apache httpd 2.4.49": "CVE-2021-41773 — Path Traversal critique (exploit public disponible)",
    "apache httpd 2.4.50": "CVE-2021-42013 — Path Traversal critique (variante)",
}


def _extract_host(target: str) -> str:
    host = target.replace("https://", "").replace("http://", "")
    host = host.split("/")[0].split(":")[0]
    return host


def _check_version_cve(version: str) -> str | None:
    """Vérifie si une version est connue comme vulnérable."""
    version_lower = version.lower()
    for vuln_version, cve_info in VULNERABLE_VERSIONS.items():
        if vuln_version in version_lower:
            return cve_info
    return None


def run(target: str) -> dict:
    host = _extract_host(target)

    results = {
        "module": "Scan de Ports (Nmap)",
        "target": host,
        "findings": []
    }

    try:
        print(f"   🔎 Scan nmap sur {host} (top 1000 ports)...")

        cmd = [
            "nmap", "-sV", "-T3", "--open",
            "--top-ports", "1000",
            "-oG", "-",
            host
        ]

        output = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        raw = output.stdout

        findings = _parse_nmap_output(raw, host)
        results["findings"] = findings

        if not findings:
            results["findings"].append({
                "label": "Aucun port ouvert détecté",
                "description": "Tous les ports scannés sont fermés ou filtrés",
                "impact": None,
                "exploitability": None,
                "status": "✅ Aucun port dangereux exposé",
            })

    except subprocess.TimeoutExpired:
        results["error"] = "Timeout nmap — scan trop long (>120s)"
    except FileNotFoundError:
        results["error"] = "nmap non installé (apt install nmap)"
    except Exception as e:
        results["error"] = str(e)

    return results


def _parse_nmap_output(raw: str, host: str) -> list:
    findings = []
    open_ports = []

    port_pattern = r"(\d+)/open/(\w+)//([^/]*)//([^/]*)/"
    for line in raw.split("\n"):
        if "Ports:" in line:
            matches = re.findall(port_pattern, line)
            for match in matches:
                port_num  = int(match[0])
                protocol  = match[1]
                service   = match[2].strip() or "inconnu"
                version   = match[3].strip() or ""
                open_ports.append((port_num, protocol, service, version))

    for port_num, protocol, service, version in open_ports:
        port_info = DANGEROUS_PORTS.get(port_num, {
            "service": service,
            "impact": "Mineur",
            "exploitability": "Modérée",
            "description": f"Port {port_num} ouvert — service {service} exposé"
        })

        # Vérification CVE sur la version détectée
        cve_info = _check_version_cve(version)
        if cve_info:
            # Une CVE connue → on monte le niveau de risque
            port_info = {**port_info, "impact": "Critique",
                         "exploitability": "Facile",
                         "description": cve_info}

        service_label = port_info["service"]
        label = f"Port {port_num} — {service_label}"
        if version:
            label += f" ({version})"

        is_dangerous = port_info.get("impact") is not None

        finding = {
            "label": label,
            "port": port_num,
            "protocol": protocol,
            "service": service,
            "version": version,
            "description": port_info["description"],
            "impact": port_info["impact"],
            "exploitability": port_info["exploitability"],
            "status": "🔴 Ouvert — DANGEREUX" if is_dangerous else "✅ Ouvert — Normal",
        }
        findings.append(finding)

    return findings


if __name__ == "__main__":
    import json
    output = run("http://localhost:8080")
    print(json.dumps(output, indent=2, ensure_ascii=False))
