# Guide de démarrage rapide

> Mise en place et premier scan en **5 minutes**

## Installation rapide

```bash
# 1. Cloner et entrer dans le répertoire
git clone https://github.com/Y0plait/BaseSecu-VulnScanner.git
cd BaseSecu-VulnScanner

# 2. Créer un environnement virtuel
python3 -m venv .env
source .env/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
```

## Configuration minimale

### 1. Configurer les clés API

Éditer `src/caching/constants.py`:

```python
GENAI_API_KEY = "votre_clé_google_genai"
NVD_NIST_CPE_API_KEY = "votre_clé_nvd"
```

**Obtenir les clés:**
- Google GenAI: https://aistudio.google.com
- NVD NIST: https://nvd.nist.gov/developers/request-an-api-key

### 2. Configurer les machines

Éditer `inventory.ini`:

```ini
[test-server]
host = 192.168.1.100
user = ubuntu
password = 
type = linux
```

## Lancer le scanner

```bash
# Scan complet avec rapport HTML
python main.py

# Options utiles
python main.py --help                 # Voir toutes les options
python main.py --inventory custom.ini # Utiliser un autre fichier
python main.py --force-check          # Vérifier tous les paquets
python main.py --report-only          # Régénérer rapports (pas de scan)
```

## Consulter les résultats

Après l'exécution:

```
✓ Rapport HTML: cache/vulnerability_report.html
✓ Données JSON: cache/machines/{machine_name}/vulnerability_report.json
✓ Logs: logs/vulnerability_scan_*.log
```

Ouvrir le rapport HTML dans un navigateur:
```bash
open cache/vulnerability_report.html  # macOS
# ou
firefox cache/vulnerability_report.html  # Linux/Windows
```

## Troubleshooting rapide

| Problème | Solution |
|----------|----------|
| `ModuleNotFoundError: No module named 'paramiko'` | Exécuter `pip install -r requirements.txt` |
| Erreur de connexion SSH | Vérifier les paramètres `host`, `user` et `password` dans `inventory.ini` |
| Clé API invalide | Vérifier les clés dans `src/caching/constants.py` |
| Pas de vulnérabilités détectées | Machine récente sans packages vulnérables, ou utiliser `--force-check` |

## Documentation détaillée

Pour plus d'informations:
- **Installation avancée**: [INSTALLATION.md](INSTALLATION.md)
- **Architecture du code**: [STRUCTURE.md](STRUCTURE.md)
- **Scanning matériel**: [HARDWARE_SCANNING.md](HARDWARE_SCANNING.md)
- **Visualisation réseau**: [NETWORK_VISUALIZATION.md](NETWORK_VISUALIZATION.md)
- **Référence technique**: [DOCUMENTATION.md](DOCUMENTATION.md)
