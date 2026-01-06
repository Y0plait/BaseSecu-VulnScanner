# Architecture du projet

## Structure des fichiers

```
.
├── main.py                          # Point d'entrée racine (dispatch vers src/core/main.py)
├── requirements.txt                 # Dépendances Python avec versions fixes
├── inventory.ini                    # Configuration des machines à scanner
├── visualnet-scanner.sh             # Script Bash pour génération SVG réseau
├── Doxyfile                         # Configuration Doxygen (génération documentation code)
├── README.md                        # Présentation générale (français)
│
├── cache/                           # Répertoire de cache généré à l'exécution
│   ├── vulnerability_cache.db       # Cache SQLite des CVE/CPE
│   ├── cpe_cache.json               # Cache global des CPE générés
│   ├── vulnerability_report.html    # Rapport HTML final
│   └── machines/                    # Répertoire par machine
│       ├── srv01/
│       │   ├── installed_packages.json    # Paquets détectés
│       │   ├── cpe_list_srv01.txt        # CPE générés (paquets)
│       │   ├── cpe_list_srv01_hw.txt     # CPE générés (matériel)
│       │   └── vulnerability_report.json # Rapport JSON
│       ├── srv02/
│       └── srv03/
│
├── logs/                            # Journaux d'exécution
│   └── vulnerability_scan_*.log     # Log détaillé de chaque scan
│
├── docs/                            # Documentation du projet
│   ├── QUICK_START.md               # Guide démarrage rapide (5 min)
│   ├── INSTALLATION.md              # Installation détaillée
│   ├── STRUCTURE.md                 # Ce fichier - Architecture
│   ├── SCAN.md                      # Configuration scanning réseau
│   ├── HARDWARE_SCANNING.md         # Scanning matériel CPU
│   ├── NETWORK_VISUALIZATION.md     # Visualisation réseau
│   ├── DOCUMENTATION.md             # Référence technique complète (EN)
│   └── doxygen/                     # Documentation générée par Doxygen
│       └── html/
│           └── index.html
│
├── templates/                       # Templates Jinja2
│   └── vulnerability_report.html    # Template rapport HTML
│
├── src/                             # Code source (organisé par responsabilité)
│   ├── __init__.py
│   │
│   ├── core/                        # 🎯 Orchestration principale
│   │   ├── __init__.py
│   │   └── main.py                  # Point d'entrée CLI + orchestration
│   │
│   ├── acquisition/                 # 📊 Collecte de données depuis machines
│   │   ├── __init__.py
│   │   ├── pkg_finder.py            # Découverte paquets via SSH
│   │   └── machine_processor.py     # Traitement par machine
│   │
│   ├── caching/                     # 💾 Couche persistance et configuration
│   │   ├── __init__.py
│   │   ├── cache_db.py              # Cache SQLite CVE/CPE
│   │   └── constants.py             # Configuration globale + clés API
│   │
│   ├── matching/                    # 🔗 Génération CPE via IA
│   │   ├── __init__.py
│   │   └── cpe_matcher.py           # Génération CPE (Google Gemini)
│   │
│   └── reporting/                   # 📋 Génération rapports et sortie
│       ├── __init__.py
│       ├── vulnerability_checker.py # Requêtes NVD API + matching
│       ├── report_generator.py      # Génération rapports JSON
│       ├── output_formatter.py      # Formatage terminal colorisé
│       ├── html_report_generator.py # Génération rapport HTML
│       └── network_visualizer.py    # Génération SVG topologie
│
└── .env/                            # Environnement virtuel Python
    ├── bin/
    ├── lib/
    └── ...
```

## Organisation des modules

### 🎯 **src/core** - Orchestration principale

**Responsabilité:** Coordonner l'ensemble du pipeline de scan

**Fichiers:**
- **main.py** (391 lignes)
  - Point d'entrée CLI avec argparse
  - Gestion des arguments: `--inventory`, `--flush-cache`, `--force-check`, `--report-only`
  - Orchestration du flux de scan complet
  - Gestion des logs
  - Génération des rapports finaux

**Flux principal:**
```
1. Parser arguments CLI
2. Charger configuration inventory.ini
3. (Optionnel) Vider les caches
4. Initialiser API Google GenAI
5. Tester connexion NVD
6. Pour chaque machine:
   - Acquérir paquets installés
   - Générer CPE (paquets + matériel)
   - Requêter vulnérabilités NVD
   - Générer rapports JSON
7. Fusionner et générer rapport HTML
```

---

### 📊 **src/acquisition** - Collecte de données

**Responsabilité:** Découvrir et récupérer les informations des machines cibles

**Fichiers:**

#### pkg_finder.py (180 lignes)
- **Connexion SSH:** Paramiko pour accès distant
- **Découverte Linux:**
  - Lister paquets: `apt list`, `rpm -qa`, `pacman -Q`
  - Récupérer versions
  - Parser sortie shell
- **Découverte matériel:**
  - Information CPU via `lscpu`
  - Vendor, model, stepping, flags
  - Pas besoin de droits root
- **Gestion des erreurs SSH**

#### machine_processor.py (250 lignes)
- **Orchestration par machine**
- **Caching des paquets** (détection des nouveaux)
- **Appel vers cpe_matcher** pour génération CPE
- **Logging et formatting**
- **Fusion paquets + matériel**

**Fonctions principales:**
```python
def process_machine_packages(config, machine)
  → (all_packages, new_packages)

def generate_cpes_for_packages(packages, machine, cpe_matcher)
  → {package: [cpe_strings]}

def process_machine_hardware(config, machine)
  → {vendor_id, model_name, family, ...}

def generate_cpes_for_hardware(hardware_info, machine, cpe_matcher)
  → {hardware_component: [cpe_strings]}
```

---

### 💾 **src/caching** - Persistance et configuration

**Responsabilité:** Gérer le cache et la configuration globale

**Fichiers:**

#### cache_db.py (200 lignes)
- **Base de données SQLite**
- **Schéma:**
  - `cpe_index`: Tracking des CPE requêtés
  - `vulnerabilities`: Cache CVE/CWE
- **Fonctions:**
  - `get_db()`: Initialisation et migration
  - `get_vulnerabilities()`: Lookup cache-first
  - `sync_modified_cves()`: Refresh optionnel
- **Rate limiting** automatique

#### constants.py (25 lignes)
- **Clés API:**
  - `GENAI_API_KEY`: Google GenAI
  - `NVD_NIST_CPE_API_KEY`: NVD NIST
- **Configuration:**
  - `CACHE_DIR`: Répertoire cache
  - `DEFAULT_INVENTORY`: Fichier par défaut
  - `API_REQUEST_DELAY`: Délai entre requêtes NVD

---

### 🔗 **src/matching** - Génération CPE via IA

**Responsabilité:** Convertir noms paquets/matériel en CPE standardisés

**Fichiers:**

#### cpe_matcher.py (350 lignes)
- **Client Google GenAI:**
  - Modèle: Gemini Flash 2.5
  - Temperature=0 (déterministe)
- **Prompts spécialisés:**
  - `PACKAGE_CPE_PROMPT`: Pour paquets logiciels
  - `HARDWARE_CPE_PROMPT`: Pour CPU/matériel
- **Cache CPE local:** `cpe_cache.json`
- **Validation format** CPE 2.3
- **Gestion des erreurs** API

**Format CPE 2.3:**
```
cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

Exemples:
cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
cpe:2.3:h:intel:xeon_platinum_8280:*:*:*:*:*:*:*:*
cpe:2.3:a:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*
```

---

### 📋 **src/reporting** - Génération rapports

**Responsabilité:** Requêter NVD, agréger résultats, générer rapports

**Fichiers:**

#### vulnerability_checker.py (200 lignes)
- **Requêtes NVD API**
- **Rate limiting:** 50 requêtes/30s avec clé
- **Gestion erreurs:**
  - 404: CPE invalide
  - 429: Rate limit atteint (exponential backoff)
  - 503: Service indisponible
- **Structuration CVE:**
  - CPE → CVE mapping
  - Descriptions détaillées
  - URLs CVE.org

#### report_generator.py (150 lignes)
- **Génération rapports JSON**
- **Structure par CPE**
- **Timestamps ISO 8601**
- **URLs CVE standardisées**
- **Sauvegarde fichier:**
  - `cache/machines/{machine}/vulnerability_report.json`

#### output_formatter.py (250 lignes)
- **Formatage terminal**
- **Couleurs ANSI:**
  - Rouge: Erreurs
  - Vert: Succès
  - Jaune: Avertissements
  - Cyan: Infos
- **Formatage sections**
- **Affichage vulnérabilités**
- **Statistiques finales**
- **Support hyperlinks OSC 8**

#### html_report_generator.py (400 lignes)
- **Template Jinja2**
- **Agrégation données JSON**
- **Formatage HTML/CSS**
- **Tables vulnérabilités**
- **Intégration SVG réseau**
- **Responsive design**

#### network_visualizer.py (200 lignes)
- **Exécution visualnet-scanner.sh**
- **Conversion SVG → base64**
- **Embedding dans HTML**
- **Gestion erreurs timeouts**
- **Support multi-machines**

---

## Flux de données

```
┌─────────────────────────────────────────────────────────────────┐
│                        Démarrage                                │
│              python main.py --inventory inv.ini                 │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │  src/core/main.py          │
        │  - Parse arguments         │
        │  - Charge inventory.ini    │
        └────────┬───────────────────┘
                 │
                 ▼
    ┌────────────────────────────────────┐
    │  Pour chaque machine:              │
    └────────┬────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────┐
│ src/acquisition/machine_processor.py                       │
│  ├─ Récupérer paquets                                      │
│  │   └─ src/acquisition/pkg_finder.py (SSH)               │
│  │       └─ src/caching/cache_db.py (cache)               │
│  │                                                         │
│  ├─ Générer CPE paquets                                    │
│  │   └─ src/matching/cpe_matcher.py (GenAI)               │
│  │       └─ src/caching/constants.py (clés)               │
│  │                                                         │
│  ├─ Récupérer matériel                                     │
│  │   └─ src/acquisition/pkg_finder.py (SSH lscpu)         │
│  │                                                         │
│  └─ Générer CPE matériel                                   │
│      └─ src/matching/cpe_matcher.py (GenAI)               │
└────────┬─────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│ src/reporting/vulnerability_checker.py                     │
│  ├─ Requête NVD API                                        │
│  │   └─ nvdlib.searchCPE()                                │
│  │       └─ src/caching/cache_db.py (cache)              │
│  │                                                        │
│  ├─ Récupère CVE/descriptions                             │
│  │   └─ Rate limit: 0.6s entre requêtes                  │
│  │                                                        │
│  └─ Fusion avec cache existant                            │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│ src/reporting/report_generator.py                          │
│  ├─ Génère rapport JSON                                    │
│  │   └─ cache/machines/{machine}/vulnerability_report.json │
│  │                                                        │
│  └─ src/reporting/output_formatter.py                     │
│      └─ Affiche terminal colorisé                         │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│ src/reporting/html_report_generator.py                     │
│  ├─ Agrège tous les rapports JSON                          │
│  ├─ Applique template Jinja2                               │
│  │   └─ templates/vulnerability_report.html               │
│  │                                                        │
│  ├─ Intègre visualisations réseau                          │
│  │   └─ src/reporting/network_visualizer.py               │
│  │       └─ visualnet-scanner.sh (Nmap)                   │
│  │                                                        │
│  └─ Génère rapport final HTML                             │
│      └─ cache/vulnerability_report.html                   │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
   ┌──────────────────┐
   │  Rapport généré! │
   │  Ouvert au HTML  │
   └──────────────────┘
```

## Avantages de cette structure

| Avantage | Bénéfice |
|----------|----------|
| **Séparation des responsabilités** | Chaque module = une responsabilité unique |
| **Testabilité** | Modules testables indépendamment |
| **Maintenabilité** | Modification d'un module n'affecte pas les autres |
| **Extensibilité** | Ajouter features dans les modules appropriés |
| **Clarté des imports** | Chemins complets montrent les dépendances |
| **Scaling horizontal** | Ajouter machines sans refactoriser |

## Commandes utiles

```bash
# Voir la structure
tree src/ --dirsfirst

# Générer doc Doxygen
doxygen Doxyfile

# Voir les imports Python
grep -r "^import\|^from" src/ | cut -d: -f2 | sort -u

# Compter les lignes de code
find src/ -name "*.py" -exec wc -l {} + | tail -1

# Chercher une fonction
grep -rn "def function_name" src/
```

## Prochaines étapes

- [Documentation technique complète](DOCUMENTATION.md)
- [Guide d'installation](INSTALLATION.md)
- [Scanning matériel](HARDWARE_SCANNING.md)
- [Visualisation réseau](NETWORK_VISUALIZATION.md)
