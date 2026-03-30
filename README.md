# 🛡️ ShieldScan — Plateforme d'audit de sécurité Web

> *Votre sécurité web, en un scan.*

Projet SAÉ 41 — BUT Informatique Cybersécurité 2025/2026

---

## 📋 Description
Plateforme SaaS d'audit de sécurité "Boîte Noire" pour sites Web.
Transforme un audit technique complexe en rapport visuel lisible,
à l'image des audits SEO comme WooRank.

---

## 🚀 Installation complète

### 1. Cloner le repo
```bash
git clone https://github.com/soso-saos/audit_saas.git
cd audit_saas
```

### 2. Créer et activer le venv Python
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installer les dépendances Python
```bash
pip install flask requests weasyprint
```

### 4. Installer les outils système
```bash
apt install nmap nikto wpscan whois -y
```

### 5. Lancer les environnements Docker (cibles vulnérables)
```bash
docker compose up -d
```

Cela lance automatiquement :

| Service | URL | Description |
|---------|-----|-------------|
| WordPress | http://localhost:8080 | CMS vulnérable |
| DVWA | http://localhost:8081 | App volontairement vulnérable |
| Nginx | http://localhost:8082 | Serveur web basique |
| Juice Shop | http://localhost:3000 | OWASP vulnérable |
| Joomla | http://localhost:8083 | CMS vulnérable |
| Drupal | http://localhost:8084 | CMS vulnérable |
| PrestaShop | http://localhost:8085 | E-commerce vulnérable |
| Liferay | http://localhost:8086 | Portail vulnérable |

### 6. Lancer ShieldScan
```bash
source venv/bin/activate
python web/app.py
```

### 7. Ouvrir dans le navigateur
```
http://127.0.0.1:5000
```

---

## 🎯 Utilisation

1. Entre l'URL cible (ex: `http://localhost:8081`)
2. Choisis le mode :
   - **🔍 Simple** : Audit passif rapide (headers, fichiers publics, WHOIS)
   - **⚡ Avancé** : Scan complet actif (nmap, nikto, dirsearch, wpscan)
3. Clique **Lancer l'audit**
4. Consulte le rapport ou **télécharge-le en PDF**

---

## 🔧 Modules disponibles

| Module | Description | Mode |
|--------|-------------|------|
| mod_headers.py | En-têtes de sécurité HTTP | Simple |
| mod_pubfiles.py | Fichiers publics exposés | Simple |
| mod_whois.py | Informations WHOIS domaine | Simple |
| mod_nmap.py | Scan de ports + détection CVE | Avancé |
| mod_nikto.py | Vulnérabilités web | Avancé |
| mod_dirsearch.py | Répertoires cachés | Avancé |
| mod_wpscan.py | Audit WordPress (adaptatif) | Avancé |

---

## 📊 Scoring ANSSI

Basé sur la matrice **Impact × Exploitabilité** de l'ANSSI.

| Grade | Score | Signification |
|-------|-------|---------------|
| A | 90-100 | Excellent |
| B | 75-89 | Bon |
| C | 40-74 | Passable |
| D | 20-39 | Insuffisant |
| F | 0-19 | Critique |

---

## ⚖️ Usage éthique
White Hat uniquement — n'auditez que les sites dont vous avez l'autorisation.
