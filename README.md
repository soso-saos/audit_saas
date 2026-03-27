# 🛡️ AuditSaaS — Plateforme d'audit de sécurité Web

Projet SAÉ 41 — BUT Informatique Cybersécurité 2025/2026

## 📋 Description
Plateforme SaaS d'audit de sécurité "Boîte Noire" pour sites Web.
Transforme un audit technique complexe en rapport visuel lisible.

## 🚀 Installation

### 1. Cloner le repo
git clone https://github.com/soso-saos/audit_saas.git
cd audit_saas

### 2. Créer et activer le venv
python3 -m venv venv
source venv/bin/activate

### 3. Installer les dépendances Python
pip install flask requests

### 4. Installer les outils système
apt install nmap nikto wpscan whois -y

### 5. Lancer les conteneurs Docker
cd ~/SAE41 && docker compose up -d
cd ~/audit_saas

### 6. Lancer l'application
source venv/bin/activate
python web/app.py

### 7. Ouvrir dans le navigateur
http://127.0.0.1:5000

## 🔧 Modules disponibles
| Module | Description | Mode |
|--------|-------------|------|
| mod_headers.py | En-têtes de sécurité HTTP | Simple |
| mod_pubfiles.py | Fichiers publics exposés | Simple |
| mod_whois.py | Informations WHOIS domaine | Simple |
| mod_nmap.py | Scan de ports + CVE | Avancé |
| mod_nikto.py | Vulnérabilités web | Avancé |
| mod_dirsearch.py | Répertoires cachés | Avancé |
| mod_wpscan.py | Audit WordPress (adaptatif) | Avancé |

## 📊 Scoring ANSSI
Basé sur la matrice Impact × Exploitabilité de l'ANSSI.
Score de 0 à 100, grades de A (excellent) à F (critique).

## ⚖️ Usage éthique
White Hat uniquement — n'auditez que les sites dont vous avez l'autorisation.
