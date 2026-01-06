# Visualisation du réseau

> Intégration de diagrammes SVG de topologie réseau dans les rapports HTML

## Vue d'ensemble

Le scanner génère des **diagrammes SVG visuels** de la topologie réseau et les **intègre automatiquement** dans les rapports HTML. Cela permet de visualiser rapidement les hôtes, ports et services découverts lors des scans.

## Fonctionnalités

### 1. Génération SVG automatique

- **Source**: Script `visualnet-scanner.sh` basé sur Nmap
- **Outils**: Nmap (discovery) + nmap-formatter (conversion) + Graphviz (SVG)
- **Déclenchement**: Automatique lors de génération rapport HTML
- **Fallback**: Rapport généré même si SVG échoue

### 2. Intégration dans rapports HTML

- **Embedding direct**: SVG intégré en base64 (pas de dépendances externes)
- **Par machine**: Un diagramme par hôte scanné
- **Responsive**: Scrollbar horizontal pour diagrammes larges
- **Style cohérent**: Intégration avec CSS du rapport

### 3. Contenu du diagramme

Le SVG affiche:
- Hôtes découverts (nœuds)
- Ports ouverts par hôte
- Services identifiés
- Versions de service
- Connexions entre hôtes (le cas échéant)

## Architecture

### Module network_visualizer.py

**Responsabilité:** Générer SVG et les préparer pour intégration HTML

**Fonctions:**

#### `generate_network_svg_for_host(host_address, machine_name)`
- Exécute `visualnet-scanner.sh` pour un hôte
- Récupère SVG généré
- Gère timeouts (5 minutes max)
- Retourne contenu SVG ou None si erreur

#### `svg_to_base64(svg_file_path)`
- Convertit fichier SVG en base64
- Permet embedding direct dans HTML
- Élimine dépendances de fichiers

#### `read_svg_content(svg_file_path)`
- Lit SVG comme texte brut
- Prépare pour injection dans HTML
- Valide fichier existe et accessible

#### `generate_network_visualizations(machines_config)`
- Appelle pour chaque machine
- Agrège tous SVG
- Retourne dict: `{machine_name: {svg_content, ...}}`
- Gère les erreurs sans bloquer

### Template HTML

**Template:** `templates/vulnerability_report.html`

**Section réseau:**
```html
<!-- Network Topology Visualization -->
{% if network_visualizations.get(machine_name, {}).get('svg_content') %}
    <div class="border-t border-gray-200 p-6 bg-gray-50">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">
            <span class="material-icons">share</span>
            Network Topology
        </h4>
        <div class="bg-white border border-gray-200 rounded-lg p-4 overflow-x-auto">
            {{ network_visualizations[machine_name].svg_content|safe }}
        </div>
    </div>
{% endif %}
```

**Caractéristiques:**
- Rendu SVG uniquement si contenu disponible
- Filtre `|safe` pour rendu markup SVG
- Scrollbar horizontale pour grands diagrammes
- Design responsive

## Flux de génération

```
Scan vulnérabilités
├─ Collecte paquets + versions
├─ Requête NVD CVE
└─ Génère cache/machines/{machine}/vulnerability_report.json

Génération rapport HTML
├─ Agrège rapports JSON
├─ Pour chaque machine:
│  ├─ Exécute: visualnet-scanner.sh <host>
│  ├─ Récupère: test.svg généré
│  ├─ Convertit: SVG → base64 (ou texte brut)
│  └─ Stocke: {machine_name: {svg_content: ...}}
├─ Applique template Jinja2
├─ Insère SVG dans sections machines
└─ Génère: cache/vulnerability_report.html
```

## Gestion des erreurs

### Fallback gracieux

Si SVG échoue:
- ✓ Rapport HTML toujours généré
- ✓ Seules les sections SVG sont omises
- ✓ Données vulnérabilités affichées complètement
- ✓ Log d'erreur enregistré

### Causes communes d'échec

| Cause | Impact |
|-------|--------|
| Nmap pas installé | SVG non généré, rapport HTML OK |
| Host non joignable | SVG non généré, rapport HTML OK |
| Timeout réseau | SVG non généré, rapport HTML OK |
| nmap-formatter absent | SVG non généré, rapport HTML OK |

## Options de configuration

### Activation/désactivation

La génération SVG est:
- **Automatique** si `nmap-formatter` est présent
- **Silencieuse** si dépendances manquantes
- **Sans blocage** même en cas d'erreur

### Personnalisation

Éditer `src/reporting/network_visualizer.py`:

```python
# Timeout pour scan (secondes)
SCAN_TIMEOUT = 300

# Commande Nmap personnalisée
# (modifier dans visualnet-scanner.sh)
```

## Fichiers générés

### Temporaires (pendant génération)

```
output.xml          # Résultat Nmap brut
test.svg           # Diagramme SVG (avant base64)
nmap_errors.log    # Erreurs Nmap
```

### Finaux

```
cache/vulnerability_report.html  # Rapport avec SVG intégré
```

Les SVG **n'existant pas en tant que fichier séparé** dans le rapport final - ils sont intégrés directement en base64.

## Limitations

- **Par hôte**: Un SVG par adresse IP/hostname
- **Pas de hiérarchie**: Diagrammes plats, pas de groupement par sous-réseau
- **Services simples**: Basé sur résultats Nmap (pas d'analyse profonde)
- **Pas de temps réel**: Snapshot statique du moment du scan

## Dépannage

### "SVG not generated"

```bash
# Vérifier Nmap
nmap --version

# Vérifier Graphviz
dot -V

# Vérifier nmap-formatter
./nmap-formatter --version

# Tester directement
./visualnet-scanner.sh 192.168.1.100
ls -la test.svg
```

### Diagramme vide ou incorrect

- Vérifier que l'hôte est joignable
- Essayer scan avec `sudo` pour droits élevés
- Vérifier logs: `cat nmap_errors.log`

### Rapport HTML sans SVG

- Vérifier les logs du scanner
- Confirmer que Nmap/Graphviz/nmap-formatter sont installés
- Données de vulnérabilités devraient quand même être présentes

## Prochaines étapes

- [Configuration scanning réseau](SCAN.md)
- [Scanning matériel](HARDWARE_SCANNING.md)
- [Architecture du code](STRUCTURE.md)
- [Installation complète](INSTALLATION.md)
