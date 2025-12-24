# BaseSecu-VulnScanner
> Projet de base de la sécu, A3 S1 CPE.

## Sommaire

- [Contexte](#contexte)
- [Consignes & description du projet](#consignes--description-du-projet)
  - [Objectifs](#objectifs)
  - [Travail attendu](#travail-attendu)
  - [Livrables](#livrables)
- [Présentation de la solution](#présentation-de-la-solution)
- [Utilisation](#utilisation)
  - [Prérequis](#prérequis)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Exécution](#exécution)

## Contexte

Dans un contexte de multiplication des cybermenaces, les entreprises doivent être capables
d’identifier rapidement les vulnérabilités présentes dans leur système d’information. Cependant, la
détection et la corrélation manuelle entre les actifs d’un réseau (matériels, logiciels, services) et les
bases de connaissance de menaces (CTI : Cyber Threat Intelligence) constituent une tâche complexe
et chronophage.
Ce projet vise à développer un outil capable de scanner automatiquement une infrastructure réseau
afin d’identifier les matériels, logiciels et services présents, puis de faire correspondre ces éléments
avec les bases de données CTI (telles que CVE, CWE, et CPE) pour détecter les vulnérabilités connues
affectant les composants identifiés.

## Consignes & description du projet

### Objectifs

1. Cartographier automatiquement une infrastructure réseau (machines, ports, services,
versions logicielles).
2. Collecter des informations CTI (OpenCTI, CVE, CWE, CPE, NVD, etc.).
3. Faire le matching entre les composants détectés et les vulnérabilités connues.
4. (Optionnel) Générer un rapport de vulnérabilité présentant les éléments à risque, leur criticité
et les correctifs recommandés.
5. (Optionnel) Proposer une visualisation graphique du réseau et des vulnérabilités associées.

### Travail attendu

• Utilisation d’un outil de scan réseau
• Extraction des données CTI depuis les bases publiques
• Conception d’un algorithme ou d’un pipeline pour faire la correspondance entre le scan et les
vulnérabilités.
• (Bonus) Intégration d’un modèle de scoring de risque ou d’une priorisation des vulnérabilités
selon leur criticité (CVSS).
• (Bonus) Développement d’une interface web simple pour visualiser les résultats.

### Livrables
• Code source de l’outil ou du prototype développé
• Rapport technique détaillant la démarche, les choix techniques et les résultats
• Démonstration ou présentation du fonctionnement de la solution

## Présentation de la solution

La solution développée est un scanner de vulnérabilités automatisé qui collecte des informations CTI et fait le matching entre les composants détectés et les vulnérabilités connues à l'aide du LLM `gemini-flash-2.5` de Google. L'outil se base sur le matching entre CPE (common platform enumeration) et CVE (common vulnerabilities and exposures) pour identifier les vulnérabilités associées paquets présents sur les actifs (Linux & Windows pour le moment) d'un réseau.

**Note**: la majorité des commentaires et documentations dans le code sont en anglais pour respecter les standards internationaux de développement logiciel et ont été rédigés à l'aide d'un modèle IA. Cependant, cette présentation et le README principal sont en français pour une meilleure compréhension dans le contexte académique.

Les principales fonctionnalités de l'outil incluent :

- Scan automatique du réseau pour identifier les actifs (à implémenter)
- Extraction et traitement des données CTI (hardware à implémenter).
- Matching des composants avec les vulnérabilités connues.
- Génération de rapports de vulnérabilité détaillés.
- Visualisation graphique des vulnérabilités (dashboard) (à implémenter).

Toute la codebase à été organisée de manière modulaire pour faciliter la maintenance et l'extensibilité. La structure détaillée du projet est disponible dans le fichier [STRUCTURE.md](STRUCTURE.md).

Une documentation détaillé des modules et de leur fonctionnement est également fournie pour aider à la compréhension et à l'utilisation de l'outil, voir [DOCUMENTATION.md](DOCUMENTATION.md).

## Utilisation

### Prérequis

- Python 3.10 ou supérieur
- Bibliothèques Python listées dans `requirements.txt`

### Installation

1. Cloner le dépôt :
   
   ```bash
   git clone https://github.com/Y0plait/BaseSecu-VulnScanner.git
   cd BaseSecu-VulnScanner
   ```

2. Installer les dépendances :

    ```bash
    pip install -r requirements.txt
    ```

### Configuration

1. Modifier le fichier `inventory.ini` pour ajouter les machines à scanner. Exemple:

    ```ini
    [<nom_de_la_machine>]
    host = <adresse_ip_ou_hostname>
    user = <nom_utilisateur_ssh>
    password = <mot_de_passe_ssh> / vide si utilisation de clés SSH
    type = <type_de_machine>  # ex: linux, windows
    ```

2. Configurer les clés API dans `src/caching/constants.py`. Pour obtenir une clé API NVD, inscrivez-vous sur le [site officiel NVD](https://nvd.nist.gov/developers/request-an-api-key).

### Exécution

Lancer le scanner avec la commande suivante :

```bash
python main.py --inventory inventory.ini
```

Des options supplémentaires sont disponibles, utilisez `--help` pour les voir :

```bash
python main.py --help
```
