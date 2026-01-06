# Guide d'installation détaillé

> Installation complète avec configuration avancée

## Table des matières

- [Prérequis système](#prérequis-système)
- [Installation Python](#installation-python)
- [Configuration des clés API](#configuration-des-clés-api)
- [Configuration des machines](#configuration-des-machines)
- [Configuration optionnelle](#configuration-optionnelle)
- [Vérification de l'installation](#vérification-de-linstallation)

## Prérequis système

### Python
- **Python 3.10+** (vérifier: `python3 --version`)
- pip (généralement inclus avec Python)

### Connexion SSH
- SSH configuré sur les machines cibles
- Accès SSH aux serveurs Linux à scanner
- Clés SSH ou mots de passe configurés

### Optionnel (pour visualisation réseau)
- Nmap
- Graphviz
- nmap-formatter

## Installation Python

### 1. Cloner le dépôt

```bash
git clone https://github.com/Y0plait/BaseSecu-VulnScanner.git
cd BaseSecu-VulnScanner
```

### 2. Créer un environnement virtuel

```bash
# Créer l'environnement
python3 -m venv .env

# Activer l'environnement
source .env/bin/activate          # macOS/Linux
# ou
.env\Scripts\activate.bat         # Windows CMD
# ou
.env\Scripts\Activate.ps1         # Windows PowerShell
```

**Vérifier l'activation:**
```bash
which python  # Doit afficher le chemin vers .env/bin/python
# ou sur Windows:
where python
```

### 3. Installer les dépendances

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Vérifier l'installation:**
```bash
python -c "import paramiko, requests, google, nvdlib, jinja2; print('✓ All packages installed')"
```

## Configuration des clés API

Les clés API sont requises pour les deux services principaux:

### 1. Google GenAI API (pour génération CPE)

**Obtenir la clé:**
1. Visiter https://aistudio.google.com
2. Cliquer sur "Get API Key" ou "Create API Key"
3. Copier la clé générée

**Configuration sécurisée (recommandée):**

✓ **Méthode 1: Variables d'environnement (.env)**

```bash
# Créer un fichier .env à la racine du projet
cat > .env << 'EOF'
GENAI_API_KEY=votre_clé_genai_ici
NVD_NIST_CPE_API_KEY=votre_clé_nvd_ici
EOF

# Vérifier que .env est dans .gitignore
grep ".env" .gitignore  # Doit retourner .env
```

✗ **Méthode 2: Hardcoder dans le code (NON RECOMMANDÉE)**

```python
# ❌ NE PAS FAIRE CELA - Risque de leak si push en git
GENAI_API_KEY = "AIzaSyBN8cc0t59xwaqAsBjzoiZzXThhCZ2ju1w"
```

**Limites:**
- Gratuit: 60 requêtes par minute
- Recommandation: Limiter à < 50 machines

### 2. NVD NIST API (pour requête vulnérabilités)

**Obtenir la clé:**
1. Visiter https://nvd.nist.gov/developers/request-an-api-key
2. Remplir le formulaire (nom, organisation, email)
3. La clé est envoyée par email (activée immédiatement)

**Configuration sécurisée (recommandée):**

✓ **Méthode 1: Variables d'environnement (.env)**

```bash
# Fichier .env (créé à l'étape précédente)
GENAI_API_KEY=votre_clé_genai_ici
NVD_NIST_CPE_API_KEY=votre_clé_nvd_ici
```

✗ **Méthode 2: Hardcoder dans le code (NON RECOMMANDÉE)**

```python
# ❌ NE PAS FAIRE CELA - Risque de leak si push en git
NVD_NIST_CPE_API_KEY = "5926d612-9e5a-4988-9a32-47f898a2a71c"
```

## Configuration des machines

### Format du fichier inventory.ini

```ini
[machine_name]
host = 192.168.1.10
user = ubuntu
password = secret123
type = linux

[another_machine]
host = prod.example.com
user = admin
password = 
type = linux
```

### Paramètres

| Paramètre | Obligatoire | Valeurs | Exemple |
|-----------|-------------|---------|---------|
| `host` | ✓ | IP ou hostname | `192.168.1.10` ou `server.com` |
| `user` | ✓ | Utilisateur SSH | `ubuntu`, `admin`, `root` |
| `password` | ✗ | Mot de passe SSH | Laisser vide pour clés SSH |
| `type` | ✗ | `linux` ou `windows` | `linux` (Windows non supporté) |

### Exemples de configuration

#### Via mot de passe

```ini
[debian-server]
host = 192.168.1.50
user = admin
password = MySecurePassword123
type = linux
```

#### Via clé SSH

```ini
[ubuntu-server]
host = ubuntu.example.com
user = ubuntu
password = 
type = linux
```

La clé SSH doit être configurée dans `~/.ssh/config` ou SSH doit pouvoir trouver la clé par défaut.

#### Multiples machines

```ini
[web-server]
host = 10.0.1.100
user = app
password = app_password
type = linux

[db-server]
host = 10.0.1.200
user = postgres
password = db_password
type = linux

[monitoring]
host = monitor.internal
user = monitor
password = 
type = linux
```

## Configuration optionnelle

### Visualisation réseau

Pour générer les diagrammes de topologie réseau dans les rapports HTML:

#### macOS

```bash
brew install nmap graphviz
go install github.com/vdjagilev/nmap-formatter/v3@latest
# Le binaire est installé dans ~/go/bin/nmap-formatter
cp ~/go/bin/nmap-formatter ./
```

#### Debian/Ubuntu

```bash
sudo apt-get install nmap graphviz graphviz-dev

# Option 1: Avec Go
go install github.com/vdjagilev/nmap-formatter/v3@latest
cp ~/go/bin/nmap-formatter ./

# Option 2: Télécharger le binaire pré-compilé
wget https://github.com/vdjagilev/nmap-formatter/releases/download/v3.0.0/nmap-formatter-linux-amd64.tar.gz
tar -xzvf nmap-formatter-linux-amd64.tar.gz
mv nmap-formatter ./
chmod +x nmap-formatter
```

#### Fedora/RHEL

```bash
sudo dnf install nmap graphviz graphviz-devel
go install github.com/vdjagilev/nmap-formatter/v3@latest
cp ~/go/bin/nmap-formatter ./
```

**Vérifier l'installation:**
```bash
nmap --version
dot -V
./nmap-formatter --version
```

### Paramètres personnalisés

Éditer `src/caching/constants.py`:

```python
# Délai entre requêtes NVD (en secondes)
API_REQUEST_DELAY = 0.6  # Dépend de votre clé API

# Répertoire de cache
CACHE_DIR = "cache"

# Fichier inventory par défaut
DEFAULT_INVENTORY = "inventory.ini"
```

## Vérification de l'installation

### Test complet

```bash
# 1. Vérifier Python
python --version  # Doit être 3.10+

# 2. Vérifier les packages
pip list | grep -E "paramiko|requests|google-genai|nvdlib|jinja2"

# 3. Vérifier les clés API
python -c "from src.caching.constants import GENAI_API_KEY, NVD_NIST_CPE_API_KEY; print(f'GenAI Key: {GENAI_API_KEY[:20]}...'); print(f'NVD Key: {NVD_NIST_CPE_API_KEY[:20]}...')"

# 4. Vérifier l'inventory
cat inventory.ini

# 5. Test de connexion SSH
ssh -v ubuntu@192.168.1.10 "echo 'SSH OK'" 2>&1 | grep -E "Authentications|OK|refused"
```

### Test de scan

```bash
# Test sur une seule machine
python main.py --inventory inventory.ini
```

## Dépannage

### Erreur: `ModuleNotFoundError: No module named 'paramiko'`

```bash
# Vérifier l'activation de l'environnement
source .env/bin/activate  # macOS/Linux

# Réinstaller
pip install -r requirements.txt
```

### Erreur: `Connection refused` (SSH)

```bash
# Vérifier les paramètres
ping <host>
ssh -v <user>@<host>  # Tester la connexion

# Vérifier le port SSH (par défaut 22)
# Vérifier le pare-feu
```

### Erreur: `401 Unauthorized` (API)

```bash
# Vérifier les clés API dans .env
cat .env

# Vérifier que les clés ne contiennent pas d'espaces
# Essayer de se reconnecter au service (downtime possible)
```

### Erreur: `GENAI_API_KEY environment variable not set`

```bash
# Créer le fichier .env
cat > .env << 'EOF'
GENAI_API_KEY=votre_clé_ici
NVD_NIST_CPE_API_KEY=votre_clé_ici
EOF

# Recharger l'environnement
source .env/bin/activate
```

### Pas de vulnérabilités détectées

```bash
# Les packages récents n'ont peut-être pas de CVE connus
# Utiliser --force-check pour re-vérifier
python main.py --force-check

# Ou --flush-cache pour recommencer
python main.py --flush-cache
```

## Sécurité - Prévention des fuites de clés API

### ⚠️ Important: Protéger vos clés API

**Les clés API NE DOIVENT JAMAIS être committées en git!**

### Bonnes pratiques

1. **Toujours utiliser des variables d'environnement**
```bash
# ✓ BON: Charger depuis .env
GENAI_API_KEY = os.getenv("GENAI_API_KEY")

# ✗ MAUVAIS: Hardcoder la clé
GENAI_API_KEY = "AIzaSyBN8cc0t59xwaqAsBjzoiZzXThhCZ2ju1w"
```

2. **Ajouter `.env` à `.gitignore`**
```bash
echo ".env" >> .gitignore
git rm --cached .env  # Si déjà commité
```

3. **Utiliser un pré-commit hook pour détecter les secrets**
```bash
# Installe Detect Secrets
pip install detect-secrets

# Initialise le baseline
detect-secrets scan > .secrets.baseline

# Crée le hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
detect-secrets-hook --baseline .secrets.baseline
EOF

chmod +x .git/hooks/pre-commit
```

4. **Si vous avez déjà leaked une clé API**

```bash
# ÉTAPE 1: Révoquer immédiatement la clé compromise
# - Google AI Studio: https://aistudio.google.com/app/apikey
# - NVD: Générer une nouvelle clé sur leur site

# ÉTAPE 2: Nettoyer l'historique git

# Option A: git filter-branch (recommandé)
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch src/caching/constants.py' \
  --prune-empty --tag-name-filter cat -- --all

# Forcer le push des changements
git push origin --force --all
git push origin --force --tags

# Option B: git-filter-repo (plus simple)
pip install git-filter-repo
git filter-repo --path src/caching/constants.py --invert-paths
```

5. **Audit: Vérifier qu'aucune clé n'a été committée**
```bash
# Chercher les patterns de clés dans l'historique git
git log -p -S "AIzaSy" -- src/

# Ou avec grep
git log --all -p | grep -E "GENAI_API_KEY|NVD_NIST_CPE_API_KEY|AIzaSy"
```

### Fichier `.env` obligatoire

```bash
# Créer à la racine du projet
cat > .env << 'EOF'
# Google GenAI API Key (https://aistudio.google.com)
GENAI_API_KEY=votre_clé_google_genai

# NVD NIST API Key (https://nvd.nist.gov/developers/request-an-api-key)
NVD_NIST_CPE_API_KEY=votre_clé_nvd
EOF

# ❌ IMPORTANT: NE JAMAIS commiter ce fichier
echo ".env" >> .gitignore
```

## Prochaines étapes

- [Guide de démarrage rapide](QUICK_START.md)
- [Architecture du code](STRUCTURE.md)
- [Documentation technique](DOCUMENTATION.md)
