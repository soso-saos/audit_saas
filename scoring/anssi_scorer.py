# =============================================================
# Moteur de scoring basé sur la matrice de risque ANSSI
# Croise l'Impact d'une faille avec sa Difficulté d'exploitation
# =============================================================

# --- Matrice ANSSI : [Impact][Exploitabilité] → Niveau de risque ---
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

# --- Poids de chaque niveau : points retirés au score global ---
RISK_WEIGHTS = {
    "Mineur":    2,
    "Important": 5,
    "Majeur":    10,
    "Critique":  25,
}

# --- Couleurs et emojis pour le rapport visuel ---
RISK_DISPLAY = {
    "Mineur":    {"color": "#3498db", "emoji": "🔵", "label": "Faible"},
    "Important": {"color": "#f39c12", "emoji": "🟠", "label": "Moyen"},
    "Majeur":    {"color": "#e67e22", "emoji": "🟠", "label": "Élevé"},
    "Critique":  {"color": "#e74c3c", "emoji": "🔴", "label": "Critique"},
}

# --- Grille de grades (comme SSL Labs) ---
GRADE_THRESHOLDS = [
    (90, "A"),   # Excellent  : quasi aucune faille
    (75, "B"),   # Bien       : quelques points mineurs
    (40, "C"),   # Passable   : headers manquants, rien de critique
    (20, "D"),   # Mauvais    : failles importantes présentes
    (0,  "F"),   # Critique   : site très vulnérable
]


def get_risk_level(impact: str, exploitability: str) -> str:
    """Retourne le niveau de risque ANSSI pour une faille donnée."""
    try:
        return ANSSI_MATRIX[impact][exploitability]
    except KeyError:
        return "Mineur"  # Valeur par défaut si données manquantes


def score_findings(findings: list) -> dict:
    """
    Prend une liste de findings (depuis n'importe quel module)
    et calcule le score global, le grade et les statistiques.

    Chaque finding doit avoir : impact, exploitability (ou None si pas de faille)
    """
    score = 100
    stats = {"Mineur": 0, "Important": 0, "Majeur": 0, "Critique": 0}
    scored_findings = []

    for finding in findings:
        # On ne score que les failles réelles (impact non nul)
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

    # Score plancher à 0
    score = max(0, score)

    return {
        "score": score,
        "grade": _get_grade(score),
        "stats": stats,
        "total_findings": sum(stats.values()),
        "findings": scored_findings,
    }


def _get_grade(score: int) -> str:
    """Convertit un score numérique en grade lettre (A → F)."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


# --- Test rapide ---
if __name__ == "__main__":
    import json
    # On simule les findings de mod_headers.py
    test_findings = [
        {"header": "HSTS",  "impact": "Important", "exploitability": "Facile"},
        {"header": "CSP",   "impact": "Majeur",    "exploitability": "Facile"},
        {"header": "X-Frame-Options", "impact": "Important", "exploitability": "Facile"},
        {"header": "X-Content-Type-Options", "impact": "Mineur", "exploitability": "Facile"},
    ]
    result = score_findings(test_findings)
    print(json.dumps(result, indent=2, ensure_ascii=False))
