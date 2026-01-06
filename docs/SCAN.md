# Configuration du scanning réseau

> Guide de configuration du script `visualnet-scanner.sh` pour générer des diagrammes de topologie réseau

## Vue d'ensemble

Le script `visualnet-scanner.sh` utilise **Nmap** pour scanner le réseau et **nmap-formatter** pour générer des diagrammes SVG visuels de la topologie. Ces diagrammes sont intégrés automatiquement dans les rapports HTML générés par le scanner de vulnérabilités.

## Prérequis

### Dépendances système

- **Nmap**: Utilitaire de scan réseau et cartographie de ports
- **Graphviz**: Logiciel de visualisation de graphes (commande `dot`)
- **nmap-formatter**: Convertisseur Nmap → SVG

## Installation

### 1. Installer Nmap

**macOS:**
```bash
brew install nmap
```

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Fedora/RHEL:**
```bash
sudo dnf install nmap
```

### 2. Installer Graphviz

**macOS:**
```bash
brew install graphviz
```

**Debian/Ubuntu:**
```bash
sudo apt-get install graphviz graphviz-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install graphviz graphviz-devel
```

### 3. Installer nmap-formatter

#### Option A: Avec Go (recommandé)

Nécessite Go 1.18+ installé.

```bash
go install github.com/vdjagilev/nmap-formatter/v3@latest
cp ~/go/bin/nmap-formatter ./
```

#### Option B: Binaire pré-compilé

Télécharger depuis [Releases GitHub](https://github.com/vdjagilev/nmap-formatter/releases):

```bash
# macOS
VERSION=v3.0.0
curl -L https://github.com/vdjagilev/nmap-formatter/releases/download/$VERSION/nmap-formatter-darwin-amd64.tar.gz | tar xz
mv nmap-formatter ./

# Linux
VERSION=v3.0.0
curl -L https://github.com/vdjagilev/nmap-formatter/releases/download/$VERSION/nmap-formatter-linux-amd64.tar.gz | tar xz
mv nmap-formatter ./

# Rendre exécutable
chmod +x nmap-formatter
```

#### Option C: Compiler depuis la source

```bash
git clone https://github.com/vdjagilev/nmap-formatter.git
cd nmap-formatter
go build
cp nmap-formatter /chemin/vers/le/projet/
cd /chemin/vers/le/projet
```

### Vérifier l'installation

```bash
nmap --version
dot -V
./nmap-formatter --version
```

## Utilisation

### Syntaxe de base

```bash
./visualnet-scanner.sh [RÉSEAU_CIBLE]
```

### Paramètres

- `RÉSEAU_CIBLE` (optionnel): Adresse réseau à scanner
  - Format: `192.168.1.0/24`, `10.0.0.1`, `example.com`, etc.
  - Si omis, un prompt interactive demande l'adresse

### Exemples

```bash
# Mode interactif
./visualnet-scanner.sh

# Scanner un réseau entier
./visualnet-scanner.sh 192.168.1.0/24

# Scanner un hôte unique
./visualnet-scanner.sh 192.168.1.100

# Scanner avec droits root (détection OS, versions services)
sudo ./visualnet-scanner.sh 192.168.1.0/24
```

## Fonctionnement

Le script effectue les étapes suivantes:

1. **Vérification dépendances**: Contrôle que `nmap`, `dot` et `nmap-formatter` sont disponibles
2. **Saisie cible**: Demande l'adresse réseau si non fournie
3. **Scan Nmap**: Lance un scan Nmap rapide (`-T4 -F`) sur le réseau cible
4. **Formatage**: Convertit la sortie Nmap en format DOT, puis génère SVG via Graphviz
5. **Génération fichier**: Produit `test.svg` avec la topologie visuelle

### Fichiers générés

| Fichier | Description |
|---------|-------------|
| `output.xml` | Résultat Nmap brut en XML |
| `test.svg` | Diagramme SVG de la topologie |
| `nmap_errors.log` | Erreurs Nmap (si présentes) |

## Intégration avec le scanner de vulnérabilités

Les diagrammes SVG sont **automatiquement intégrés** dans le rapport HTML si:

1. Le binaire `nmap-formatter` est présent
2. L'hôte est accessible via Nmap
3. La génération SVG réussit

Si la visualisation échoue, le rapport HTML s'affiche quand même sans les diagrammes.

### Flux automatique

```bash
# Scan du scanner de vulnérabilités
python main.py --inventory inventory.ini

# 1. Scan paquets + vulnérabilités
# 2. Génère rapport JSON

# 3. Génération HTML:
#    - Agrège rapports JSON
#    - Pour chaque machine: exécute visualnet-scanner.sh
#    - Convertit SVG en base64
#    - Intègre dans rapport HTML
#    - Sauvegarde cache/vulnerability_report.html
```

## Options avancées

### Scan plus détaillé

Pour détection OS et versions services (plus lent):

```bash
sudo ./visualnet-scanner.sh 192.168.1.0/24 -sV -sC -A
```

Éditer le script pour modifier les paramètres Nmap.

### Scan sans visualisation

Si Nmap est disponible mais pas `nmap-formatter`:

```bash
nmap 192.168.1.0/24 -oX output.xml
```

## Dépannage

| Erreur | Solution |
|--------|----------|
| "nmap' not installed" | Installer Nmap via package manager |
| "'dot' not found" | Installer Graphviz |
| "'nmap-formatter' not found" | Placer le binaire à la racine du projet |
| "'nmap-formatter' not executable" | `chmod +x nmap-formatter` |
| Erreur Nmap | Vérifier `nmap_errors.log` |
| Pas de droits d'accès réseau | Essayer avec `sudo` |

## Considérations de sécurité

- **Permission légale**: Ne scanner que les réseaux que vous possédez ou avez explicitement le droit de scanner
- **Restrictions réseau**: Les scans rapides (`-T4 -F`) minimisent l'impact réseau
- **Gestion binaire**: Vérifier l'intégrité du binaire `nmap-formatter` avant utilisation

## Références

- [Nmap Official](https://nmap.org)
- [nmap-formatter GitHub](https://github.com/vdjagilev/nmap-formatter)
- [Graphviz](https://graphviz.org)

## Prochaines étapes

- [Guide d'installation complet](INSTALLATION.md)
- [Scanning matériel](HARDWARE_SCANNING.md)
- [Visualisation réseau](NETWORK_VISUALIZATION.md)
