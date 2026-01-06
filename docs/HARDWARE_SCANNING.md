# Scanning des vulnérabilités matériel

> Détection automatique des vulnérabilités CPU (Spectre, Meltdown, etc.)

## Vue d'ensemble

Le scanner inclut une détection complète des vulnérabilités matériel **en plus** du scanning logiciel. Cette fonction détecte les vulnérabilités de microarchitecture CPU comme Spectre, Meltdown, et d'autres problèmes de sécurité spécifiques aux processeurs.

## Fonctionnalités

### 1. Collecte d'informations matériel

- **Méthode**: Commande `lscpu` via SSH (pas d'accès root requis)
- **Données collectées**:
  - Identifiant fabricant (Intel, AMD, ARM, etc.)
  - Nom du modèle CPU
  - Numéros famille/modèle CPU
  - Information stepping (version microcode)
  - Drapeaux CPU (capacités microarchitecture)
  - Nombre de cœurs et threads

### 2. Génération CPE matériel

- Conversion de descriptions CPU en identifiants CPE 2.3
- Prompt IA spécialisé pour:
  - Identification fabricant CPU
  - Extraction nom modèle
  - Patterns vulnérabilités matériel
- Format CPE: `cpe:2.3:h:vendor:product:version:*:*:*:*:*:*:*`

### 3. Détection vulnérabilités CPU

Détecte les vulnérabilités microarchitecture CPU connues:

| Vulnérabilité | CVE | Description |
|---------------|-----|-------------|
| **Spectre V1** | CVE-2017-5753 | Induction cible branche |
| **Spectre V2** | CVE-2017-5715 | Induction branche indirecte |
| **Meltdown** | CVE-2017-5754 | Charge cache données rogue |
| **RIDL/Zombieload** | CVE-2019-11091 | Échantillonnage données microarchitecture |
| **MDS** | CVE-2018-12126/27/30 | Attaques échantillonnage données |
| **Bus Locking** | CVE-2021-21224 | Problèmes verrouillage bus Intel |
| **Microcode** | Divers | Errata CPU et patches |

## Implémentation

### Nouveaux modules

#### `pkg_finder.get_hardware_info(config, machine)` 
Récupère informations matériel via SSH:

```python
{
    'vendor_id': 'GenuineIntel',
    'model_name': 'Intel(R) Xeon(R) Platinum 8280 CPU @ 2.70GHz',
    'family': '6',
    'model': '85',
    'stepping': '11',
    'flags': 'fpu vme de pse tsc msr ...',
    'cores': '56',
    'threads': '2'
}
```

#### `machine_processor.process_machine_hardware(config, machine)`
Fonction wrapper qui:
- Vérifie type machine (Linux seulement)
- Récupère informations matériel
- Log et affiche résultats
- Retourne informations parsées

#### `machine_processor.generate_cpes_for_hardware(hardware_info, machine, cpe_matcher)`
Génère CPE matériel:
- Extrait vendor et model
- Appelle modèle IA pour CPE matériel
- Valide format CPE
- Retourne: `{composant: [cpe_strings]}`

### Prompts IA

#### `HARDWARE_CPE_PROMPT`
Prompt spécialisé pour CPE matériel:
- Identification fabricant CPU
- Extraction nom modèle
- Exemples Intel, AMD, ARM
- Cible vulnérabilités microarchitecture

## Flux d'intégration

### Workflow scanner

```
1. Traitement machine
   ├─ Récupérer paquets
   ├─ Récupérer matériel (NEW)
   └─ Afficher configuration système

2. Scanning vulnérabilités logicielles
   ├─ Générer CPE paquets
   ├─ Requête NVD CVE
   └─ Afficher vulnérabilités software

3. Scanning vulnérabilités matériel (NEW)
   ├─ Générer CPE matériel
   ├─ Requête NVD CVE
   └─ Afficher vulnérabilités CPU

4. Génération rapport
   ├─ Fusionner paquets + matériel
   ├─ Générer rapport JSON unifié
   └─ Afficher nombre total vulnérabilités
```

## Structure cache

Informations matériel cachées aux côtés des paquets:

```
cache/
├── machines/
│   ├── srv01/
│   │   ├── installed_packages.json      # Paquets
│   │   ├── cpe_list_srv01.txt           # CPE paquets
│   │   ├── cpe_list_srv01_hw.txt        # CPE matériel (NEW)
│   │   └── vulnerability_report.json    # Rapport unifié
│   └── ...
```

## Exemples

### CPE matériel générés

```
Input:  Intel(R) Xeon(R) Platinum 8280 CPU @ 2.70GHz
Output: cpe:2.3:h:intel:xeon_platinum_8280:*:*:*:*:*:*:*:*

Input:  AMD EPYC 7002 Series Processor
Output: cpe:2.3:h:amd:epyc_7002:*:*:*:*:*:*:*:*

Input:  ARM Cortex-A72 Processor
Output: cpe:2.3:h:arm:cortex_a72:*:*:*:*:*:*:*:*
```

### CVE détectés par scanning matériel

```json
{
  "cpe:2.3:h:intel:xeon_platinum_8280:*:*:*:*:*:*:*:*": [
    {
      "cve_id": "CVE-2017-5753",
      "description": "Spectre Variant 1: Branch Target Injection",
      "severity": "High"
    },
    {
      "cve_id": "CVE-2017-5715",
      "description": "Spectre Variant 2: Indirect Branch Prediction",
      "severity": "High"
    },
    {
      "cve_id": "CVE-2017-5754",
      "description": "Meltdown: Rogue Data Cache Load",
      "severity": "Critical"
    }
  ]
}
```

## Limitations

- **Linux seulement**: Windows n'expose pas `lscpu`
- **Pas de vrification Mitigations**: Scanne les CPU potentiellement vulnérables, ne vérifie pas les patches microcode
- **CPE Approximatifs**: Génération IA basée sur description modèle (pas parfait)

## Options d'exécution

```bash
# Scan normal (inclut scanning matériel)
python main.py

# Forcer re-scanning matériel
python main.py --force-check

# Vider cache et re-scanner
python main.py --flush-cache

# Générer rapport sans re-scanner
python main.py --report-only
```

## Prochaines étapes

- [Architecture du code](STRUCTURE.md)
- [Configuration scanning réseau](SCAN.md)
- [Visualisation réseau](NETWORK_VISUALIZATION.md)
- [Installation complète](INSTALLATION.md)
