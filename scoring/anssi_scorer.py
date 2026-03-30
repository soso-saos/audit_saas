# =============================================================
# Moteur de scoring basé sur la matrice de risque ANSSI
# =============================================================

ANSSI_MATRIX = {
    "Mineur": {
        "Très difficile": "Mineur",
        "Difficile":      "Mineur",
        "Modérée":        "Important",
        "Facile":         "Majeur",
    },
    "Important": {
        "Très difficile": "Mineur",
        "Difficile":      "Important",
        "Modérée":        "Important",
        "Facile":         "Majeur",
    },
    "Majeur": {
        "Très difficile": "Important",
        "Difficile":      "Majeur",
        "Modérée":        "Majeur",
        "Facile":         "Critique",
    },
    "Critique": {
        "Très difficile": "Important",
        "Difficile":      "Majeur",
        "Modérée":        "Critique",
        "Facile":         "Critique",
    },
}

# Poids recalibrés — plus justes et proportionnés
RISK_WEIGHTS = {
    "Mineur":    1,
    "Important": 3,
    "Majeur":    6,
    "Critique":  15,
}

RISK_DISPLAY = {
    "Mineur":    {"color": "#3498db", "emoji": "🔵", "label": "Faible"},
    "Important": {"color": "#f39c12", "emoji": "🟠", "label": "Moyen"},
    "Majeur":    {"color": "#e67e22", "emoji": "🟠", "label": "Élevé"},
    "Critique":  {"color": "#e74c3c", "emoji": "🔴", "label": "Critique"},
}

GRADE_THRESHOLDS = [
    (90, "A"),
    (75, "B"),
    (40, "C"),
    (20, "D"),
    (0,  "F"),
]

# Mots-clés Nikto qui dupliquent ce que mod_headers détecte déjà
# On les filtre pour éviter le double comptage
NIKTO_HEADER_DUPLICATES = [
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
]


def get_risk_level(impact: str, exploitability: str) -> str:
    try:
        return ANSSI_MATRIX[impact][exploitability]
    except KeyError:
        return "Mineur"


def _is_nikto_header_duplicate(finding: dict) -> bool:
    """
    Retourne True si ce finding Nikto signale un header
    déjà détecté par mod_headers — on évite le double comptage.
    """
    if finding.get("source") != "nikto":
        return False
    label_lower = finding.get("label", "").lower()
    return any(keyword in label_lower for keyword in NIKTO_HEADER_DUPLICATES)


def score_findings(findings: list) -> dict:
    score = 100
    stats = {"Mineur": 0, "Important": 0, "Majeur": 0, "Critique": 0}
    scored_findings = []

    for finding in findings:
        # Filtre les doublons Nikto/Headers
        if _is_nikto_header_duplicate(finding):
            scored_findings.append({
                **finding,
                "risk_level": None,
                "deduplicated": True,
            })
            continue

        if not finding.get("impact") or not finding.get("exploitability"):
            scored_findings.append({**finding, "risk_level": None})
            continue

        risk_level = get_risk_level(finding["impact"], finding["exploitability"])
        penalty = RISK_WEIGHTS[risk_level]
        score -= penalty
        stats[risk_level] += 1

        scored_findings.append({
            **finding,
            "risk_level": risk_level,
            "penalty": penalty,
            "display": RISK_DISPLAY[risk_level],
        })

    score = max(0, score)

    return {
        "score": score,
        "grade": _get_grade(score),
        "stats": stats,
        "total_findings": sum(stats.values()),
        "findings": scored_findings,
    }


def _get_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


if __name__ == "__main__":
    import json
    test_findings = [
        {"header": "HSTS",  "impact": "Important", "exploitability": "Facile"},
        {"header": "CSP",   "impact": "Majeur",    "exploitability": "Facile"},
        {"header": "X-Frame-Options", "impact": "Important", "exploitability": "Facile"},
        {"header": "X-Content-Type-Options", "impact": "Mineur", "exploitability": "Facile"},
    ]
    result = score_findings(test_findings)
    print(json.dumps(result, indent=2, ensure_ascii=False))
