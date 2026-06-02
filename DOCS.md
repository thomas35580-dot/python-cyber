# Documentation technique — ssh-brute-hunter

Analyse automatisée de logs SSH pour la détection de tentatives de brute-force.

---

## Table des matières

1. [Imports](#1-imports)
2. [Constantes globales](#2-constantes-globales)
3. [Initialisation SIGINT](#3-initialisation-sigint)
4. [Fonctions](#4-fonctions)
   - [parser_arguments](#41-parser_arguments)
   - [extraire_ip](#42-extraire_ip)
   - [extraire_utilisateur](#43-extraire_utilisateur)
   - [analyser_logs](#44-analyser_logs)
   - [afficher_resultats](#45-afficher_resultats)
   - [generer_rapport](#46-generer_rapport)
   - [main](#47-main)
5. [Analyse vs corrigé formateur](#5-analyse-vs-corrigé-formateur)
6. [Fonctions supplémentaires hors TP](#6-fonctions-supplémentaires-hors-tp)
7. [Utilisation](#7-utilisation)

---

## 1. Imports

```python
import re
```
**Module `re` — expressions régulières.**
Fournit les fonctions de recherche de motifs dans des chaînes de caractères.
Utilisé ici pour extraire une adresse IPv4 et un nom d'utilisateur depuis une ligne de log brute.
Fonction clé : `re.search(motif, chaine)` — retourne la première occurrence du motif ou `None`.

---

```python
import sys
```
**Module `sys` — interface avec l'interpréteur Python.**
Utilisé pour deux raisons :
- `sys.exit(1)` : arrêt immédiat du programme avec un code d'erreur (1 = erreur) si le fichier de logs est introuvable.
- `sys.exit(0)` : arrêt propre sans erreur lors d'une interruption Ctrl+C.

---

```python
import signal
```
**Module `signal` — gestion des signaux système.**
Permet d'intercepter les signaux envoyés au processus par le système d'exploitation.
`signal.SIGINT` est le signal envoyé par Ctrl+C. Sans interception, Python affiche un `KeyboardInterrupt` et une stacktrace. Avec le handler défini ici, le programme se termine silencieusement avec `sys.exit(0)`.

---

```python
import argparse
```
**Module `argparse` — analyse des arguments en ligne de commande.**
Permet de passer des options au script sans modifier le code source.
Génère automatiquement un message d'aide (`--help`), valide les types, et fournit les valeurs par défaut.
Utilisé pour rendre `--fichier`, `--seuil` et `--rapport` configurables à l'exécution.

---

```python
from collections import defaultdict
```
**`defaultdict` du module `collections`.**
Variante de `dict` qui initialise automatiquement une valeur par défaut à la première utilisation d'une clé inconnue.
- `defaultdict(int)` : initialise à `0`, ce qui évite un `KeyError` lors du premier `compteur[ip] += 1`.
- `defaultdict(set)` : initialise à un ensemble vide `set()`, ce qui évite un `KeyError` lors du premier `.add()`.
Sans `defaultdict`, il faudrait tester `if ip not in compteur` avant chaque incrément.

---

```python
from pathlib import Path
```
**`Path` du module `pathlib`.**
Représentation orientée objet des chemins de fichiers, compatible Windows et Linux.
Utilisé pour :
- `Path(chemin).exists()` : vérifier l'existence du fichier avant ouverture.
- `Path(chemin).stat().st_size` : lire la taille du fichier en octets sans l'ouvrir.
Alternative plus lisible et portable que `os.path.exists()` + `os.path.getsize()`.

---

## 2. Constantes globales

```python
LOG_FILE = "auth.log"
```
Nom du fichier de logs par défaut. Valeur utilisée comme défaut dans `argparse` et modifiable via `--fichier`.

```python
RAPPORT_FILE = "rapport_bruteforce.txt"
```
Nom du fichier de rapport généré par défaut. Modifiable via `--rapport`.

```python
SEUIL_ALERTE = 3
```
Nombre minimal d'échecs de connexion pour qu'une IP soit marquée comme suspecte. Modifiable via `--seuil`.

```python
TAILLE_MAX_MO = 100
```
Seuil d'avertissement en mégaoctets. Si le fichier de logs dépasse cette taille, un message d'avertissement est affiché avant le traitement. Le traitement continue — c'est une information, pas un blocage.

---

## 3. Initialisation SIGINT

```python
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
```

Enregistre un handler pour le signal `SIGINT` (Ctrl+C).
- `signal.signal(signal, handler)` : associe une fonction au signal.
- `lambda *_: sys.exit(0)` : fonction anonyme qui ignore tous ses arguments (`*_`) et appelle `sys.exit(0)`.

Sans cette ligne, appuyer sur Ctrl+C pendant une analyse affiche :
```
^CTraceback (most recent call last):
  ...
KeyboardInterrupt
```
Avec cette ligne, le programme se termine proprement sans sortie d'erreur.

---

## 4. Fonctions

### 4.1 `parser_arguments`

```python
def parser_arguments() -> argparse.Namespace:
```

**Rôle :** Déclare et analyse les arguments passés en ligne de commande.

**Retourne :** Un objet `argparse.Namespace` dont les attributs correspondent aux arguments (`args.fichier`, `args.seuil`, `args.rapport`).

**Arguments déclarés :**

| Argument | Type | Défaut | Description |
|---|---|---|---|
| `--fichier` | str | `auth.log` | Fichier de logs SSH à analyser |
| `--seuil` | int | `3` | Nombre d'échecs déclenchant une alerte |
| `--rapport` | str | `rapport_bruteforce.txt` | Fichier de sortie du rapport |

**Exemple d'appel :**
```bash
python analyse_ssh.py --fichier /var/log/auth.log --seuil 5 --rapport rapport.txt
```

---

### 4.2 `extraire_ip`

```python
def extraire_ip(ligne: str) -> str | None:
```

**Rôle :** Extraire l'adresse IPv4 source depuis une ligne de log SSH.

**Paramètre :** `ligne` — une ligne brute du fichier `auth.log`.

**Retourne :** L'adresse IP sous forme de chaîne (`"192.168.1.10"`) ou `None` si aucune IP n'est trouvée.

**Expression régulière :**
```
from\s+(\d{1,3}(?:\.\d{1,3}){3})
```

Décomposition :
- `from` : mot-clé littéral présent dans tous les logs SSH d'échec.
- `\s+` : un ou plusieurs espaces/tabulations (plus robuste qu'un espace fixe).
- `(` `)` : groupe capturant — seule la partie entre parenthèses est retournée par `.group(1)`.
- `\d{1,3}` : entre 1 et 3 chiffres (1er octet de l'IP).
- `(?:\.\d{1,3}){3}` : groupe non-capturant répété 3 fois pour les 3 octets restants.

**Exemple :**
```
"Jun 2 10:12:01 server sshd[1234]: Failed password for root from 192.168.1.10 port 51423 ssh2"
→ "192.168.1.10"
```

---

### 4.3 `extraire_utilisateur`

```python
def extraire_utilisateur(ligne: str) -> str | None:
```

**Rôle :** Extraire le nom du compte utilisateur ciblé par la tentative de connexion.

**Paramètre :** `ligne` — une ligne brute du fichier `auth.log`.

**Retourne :** Le nom du compte (`"root"`, `"admin"`) ou `None`.

**Expression régulière :**
```
Failed password for (?:invalid user )?(\S+) from
```

Décomposition :
- `Failed password for` : préfixe commun à tous les échecs SSH.
- `(?:invalid user )?` : groupe non-capturant optionnel (`?`) — présent pour les comptes inexistants.
- `(\S+)` : groupe capturant — un ou plusieurs caractères non-blancs = le nom d'utilisateur.
- ` from` : délimiteur de fin.

**Gère les deux formats sshd :**
```
Failed password for root from ...           → "root"
Failed password for invalid user test from → "test"
```

> **Fonction supplémentaire** — absente du TP de base et du corrigé formateur. Voir [section 7](#7-fonctions-supplémentaires-hors-tp).

---

### 4.4 `analyser_logs`

```python
def analyser_logs(chemin: str) -> tuple[dict, dict]:
```

**Rôle :** Lire le fichier de logs ligne par ligne, filtrer les échecs, compter les tentatives par IP et collecter les comptes ciblés.

**Paramètre :** `chemin` — chemin vers le fichier de logs.

**Retourne :** Un tuple de deux dictionnaires :
- `echecs_par_ip` : `{"192.168.1.10": 3, "45.83.12.9": 4}`
- `cibles_par_ip` : `{"192.168.1.10": {"root", "admin"}, "45.83.12.9": {"test", "oracle", ...}}`

**Déroulement interne :**

```
1. Path(chemin).exists()        → arrêt si fichier absent
2. stat().st_size               → avertissement si > 100 Mo
3. open() + for ligne in f      → lecture ligne par ligne (pas readlines)
4. "Failed password" not in ligne → skip immédiat (early continue)
5. extraire_ip(ligne)           → skip si pas d'IP trouvée
6. echecs_par_ip[ip] += 1       → comptage automatique via defaultdict
7. extraire_utilisateur(ligne)  → ajout au set des comptes ciblés
```

**Point clé — gestion mémoire :**
```python
for ligne in f:   # itérateur natif de fichier
```
Python lit une ligne à la fois et la libère immédiatement. La RAM consommée reste constante quelle que soit la taille du fichier, contrairement à `f.readlines()` qui charge tout en mémoire.

---

### 4.5 `afficher_resultats`

```python
def afficher_resultats(echecs_par_ip: dict, cibles_par_ip: dict, seuil: int) -> None:
```

**Rôle :** Afficher le résumé de l'analyse dans le terminal, trié par nombre d'échecs décroissant.

**Paramètres :**
- `echecs_par_ip` : dictionnaire IP → nombre d'échecs.
- `cibles_par_ip` : dictionnaire IP → ensemble de comptes ciblés.
- `seuil` : valeur de comparaison pour le statut SUSPECTE / OK.

**Format de sortie :**
```
Analyse terminée.
-----------------
45.83.12.9 : 4 échec(s) - SUSPECTE | comptes ciblés : admin, oracle, postgres, test
192.168.1.10 : 3 échec(s) - SUSPECTE | comptes ciblés : admin, root
```

**Différence vs corrigé formateur :** Le corrigé affiche uniquement `SUSPECTE` ou `OK` sans les comptes ciblés. Notre version enrichit chaque ligne avec les comptes tentés.

---

### 4.6 `generer_rapport`

```python
def generer_rapport(echecs_par_ip: dict, cibles_par_ip: dict, seuil: int, fichier_rapport: str) -> None:
```

**Rôle :** Écrire le rapport d'analyse dans un fichier texte.

**Paramètres :**
- `echecs_par_ip` : dictionnaire IP → nombre d'échecs.
- `cibles_par_ip` : dictionnaire IP → ensemble de comptes ciblés.
- `seuil` : seuil d'alerte utilisé pour l'analyse.
- `fichier_rapport` : chemin du fichier de sortie.

**Structure du rapport généré :**
```
Rapport d'analyse SSH
======================

Seuil d'alerte : 3 échecs

Résumé des échecs par IP :
- 45.83.12.9 : 4 échec(s) | comptes ciblés : admin, oracle, postgres, test
- 192.168.1.10 : 3 échec(s) | comptes ciblés : admin, root

IP suspectes :
- ALERTE : 45.83.12.9 avec 4 échecs
- ALERTE : 192.168.1.10 avec 3 échecs
```

**Cas limite géré :** Si aucune IP n'atteint le seuil, la section "IP suspectes" affiche `Aucune IP suspecte détectée.` — absent du corrigé formateur original.

---

### 4.7 `main`

```python
def main() -> None:
```

**Rôle :** Point d'entrée du programme. Orchestre l'enchaînement des étapes.

**Flux d'exécution :**
```
parser_arguments()      → récupère les options CLI
analyser_logs()         → lit et analyse le fichier
afficher_resultats()    → affiche dans le terminal
generer_rapport()       → écrit le fichier .txt
print(rapport généré)   → confirmation finale
```

Le `print` de confirmation est volontairement placé **après** `generer_rapport()` pour ne s'afficher que si le rapport a bien été créé.

---

## 5. Analyse vs corrigé formateur

### Points identiques

| Élément | Notre code | Corrigé |
|---|---|---|
| Logique générale | Identique | Identique |
| `defaultdict(int)` | Oui | Oui |
| `FileNotFoundError` | Oui | Oui |
| Encodage `utf-8` | Oui | Oui |
| `if __name__ == "__main__"` | Oui | Oui |
| Tri décroissant par nb d'échecs | Oui | Oui |

### Différences

| Critère | Notre code | Corrigé formateur |
|---|---|---|
| Lecture fichier | Ligne par ligne (`for ligne in f`) | Ligne par ligne |
| Type hints | Oui, sur toutes les fonctions | Oui |
| Seuil en paramètre | Oui | Oui |
| Cas "aucune IP suspecte" | Géré | Géré |
| Statut OK affiché | Oui | Oui |
| `print` rapport dans `main` | Oui (correct) | Oui |
| Argparse CLI | **Oui** | **Non** |
| Comptes utilisateurs ciblés | **Oui** | **Non** |
| Avertissement taille fichier | **Oui** | **Non** |
| Handler SIGINT | **Oui** | **Non** |
| Regex `\s+` (robuste) | **Oui** (`\s+`) | Espace fixe |
| `sys.exit` sur fichier absent | `sys.exit(1)` | Retourne dict vide |

**Note sur `sys.exit(1)` :** Le corrigé retourne un dict vide et laisse le programme continuer sans logs. Notre choix d'arrêter le programme est plus strict mais cohérent : un fichier de logs absent est une erreur fatale pour un outil d'analyse. Les deux approches sont valides selon le contexte.

---

## 6. Fonctions supplémentaires hors TP

Ces fonctions vont au-delà des exigences du TP de base et répondent aux **améliorations possibles** listées en section 8 du sujet formateur.

### `parser_arguments` — CLI configurable

Répond à :
> *Ajouter une option en ligne de commande pour choisir le fichier de logs.*
> *Ajouter une option en ligne de commande pour modifier le seuil.*

```bash
python analyse_ssh.py --fichier /var/log/auth.log --seuil 10 --rapport output.txt
```

### `extraire_utilisateur` — comptes les plus ciblés

Répond à :
> *Détecter les comptes utilisateurs les plus ciblés.*

Collecte tous les comptes tentés par IP via un `defaultdict(set)`.
Affiché dans le terminal et dans le rapport :
```
45.83.12.9 : 4 échec(s) - SUSPECTE | comptes ciblés : admin, oracle, postgres, test
```

### Avertissement taille fichier

Répond à l'exigence implicite d'un outil utilisable en production sur des logs réels (souvent plusieurs centaines de Mo).

### Handler `SIGINT`

Protection contre la saturation de ressources en cas d'interruption manuelle pendant l'analyse d'un fichier volumineux.

---

## 7. Utilisation

### Lancement standard

```bash
python analyse_ssh.py
```

Analyse `auth.log` dans le dossier courant avec le seuil par défaut de 3.

### Options disponibles

```bash
python analyse_ssh.py --help
```

```
usage: analyse_ssh.py [-h] [--fichier FICHIER] [--seuil SEUIL] [--rapport RAPPORT]

Détection de brute-force SSH par analyse de logs.

options:
  --fichier FICHIER   Fichier de logs à analyser (défaut : auth.log)
  --seuil SEUIL       Nombre d'échecs avant alerte (défaut : 3)
  --rapport RAPPORT   Fichier de sortie du rapport (défaut : rapport_bruteforce.txt)
```

### Exemples

```bash
# Seuil personnalisé
python analyse_ssh.py --seuil 5

# Fichier et rapport personnalisés
python analyse_ssh.py --fichier /var/log/auth.log --rapport /tmp/rapport.txt

# Analyse avec seuil élevé pour réduire les faux positifs
python analyse_ssh.py --seuil 10 --rapport rapport_strict.txt
```
