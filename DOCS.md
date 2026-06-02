# Documentation technique — ssh-brute-hunter

Analyse automatisée de logs SSH pour la détection de tentatives de brute-force.

---

## Table des matières

1. [Imports](#1-imports)
2. [Constantes globales](#2-constantes-globales)
3. [Patterns compilés](#3-patterns-compilés)
4. [Dataclass `ResultatAnalyse`](#4-dataclass-resultatanalyse)
5. [Fonctions internes](#5-fonctions-internes)
   - [_severite](#51-_severite)
   - [_valider_ip](#52-_valider_ip)
   - [_parse_timestamp](#53-_parse_timestamp)
   - [_taux_max_fenetre](#54-_taux_max_fenetre)
   - [_sanitiser](#55-_sanitiser)
   - [_seuil_positif](#56-_seuil_positif)
6. [Fonctions publiques](#6-fonctions-publiques)
   - [parser_arguments](#61-parser_arguments)
   - [analyser_logs](#62-analyser_logs)
   - [afficher_resultats](#63-afficher_resultats)
   - [generer_rapport](#64-generer_rapport)
   - [main](#65-main)
7. [Analyse vs corrigé formateur](#7-analyse-vs-corrigé-formateur)
8. [Apports hors TP de base](#8-apports-hors-tp-de-base)
9. [Utilisation](#9-utilisation)

---

## 1. Imports

```python
import re
```
**Module `re` — expressions régulières.**
Compilées une seule fois au niveau du module via `re.compile()` pour éviter de recompiler à chaque ligne de log.

---

```python
import sys
```
**Module `sys` — interface avec l'interpréteur Python.**
- `sys.exit(1)` : arrêt avec code d'erreur sur fichier introuvable.
- `sys.exit(0)` : arrêt propre sur Ctrl+C.
- `sys.stdout.reconfigure(encoding="utf-8")` : forçage de l'encodage UTF-8 dans `main()` pour éviter les `UnicodeEncodeError` sur les consoles Windows (cp1252).

---

```python
import signal
```
**Module `signal` — gestion des signaux système.**
`signal.SIGINT` intercepte Ctrl+C. Le handler est installé dans `main()` — pas au niveau du module — pour ne pas interférer si le code est importé par un autre programme (ex. : GUI).

---

```python
import argparse
```
**Module `argparse` — arguments en ligne de commande.**
Génère le message `--help`, valide les types, fournit les valeurs par défaut. Rend `--fichier`, `--seuil`, `--rapport` et `--fenetre` configurables sans modifier le code.

---

```python
import operator
```
**Module `operator` — fonctions d'opérateurs.**
`operator.itemgetter(1)` est utilisé comme clé de tri sur les tuples `(ip, nb)`. Plus rapide qu'une `lambda` car implémenté en C.

---

```python
import ipaddress
```
**Module `ipaddress` — validation d'adresses IP.**
`ipaddress.ip_address(ip)` valide silencieusement une adresse IPv4 ou IPv6 extraite par regex. Lève `ValueError` si l'adresse est malformée — évite de compter des faux positifs.

---

```python
import os
import tempfile
```
**Modules `os` / `tempfile` — écriture atomique du rapport.**
Combinés pour écrire dans un fichier temporaire puis le déplacer via `os.replace()`. Garantit que le rapport n'est jamais dans un état partiellement écrit.

---

```python
from collections import defaultdict
```
**`defaultdict` — dictionnaires avec valeur par défaut.**
- `defaultdict(int)` : compteur d'échecs, initialisé à `0` sans `KeyError`.
- `defaultdict(set)` : ensemble de comptes ciblés par IP, initialisé à `set()` sans `KeyError`.
- `defaultdict(list)` : liste d'horodatages par IP, initialisée à `[]`.

---

```python
from dataclasses import dataclass, field
```
**`dataclass` — structure de résultat typée.**
`ResultatAnalyse` regroupe toutes les données produites par `analyser_logs()` dans un objet structuré, passé tel quel aux fonctions d'affichage et de rapport.

---

```python
from datetime import datetime
```
**`datetime` — horodatages et calculs de fenêtre.**
Parsé depuis les lignes de log pour alimenter l'algorithme de fenêtre glissante.

---

```python
from pathlib import Path
```
**`Path` — chemins de fichiers portables (Windows/Linux).**
Utilisé pour `.exists()`, `.stat().st_size` et `.resolve().parent` (chemin du répertoire cible pour le fichier temporaire).

---

## 2. Constantes globales

```python
LOG_FILE              = "auth.log"
RAPPORT_FILE          = "rapport_bruteforce.txt"
SEUIL_ALERTE          = 3
FENETRE_GLISSANTE_S   = 60
SEUIL_AVERT_TAILLE_MO = 100
```

| Constante | Rôle |
|---|---|
| `LOG_FILE` | Fichier de logs par défaut (overridé par `--fichier`) |
| `RAPPORT_FILE` | Rapport de sortie par défaut (overridé par `--rapport`) |
| `SEUIL_ALERTE` | Seuil minimum d'échecs pour alerte (overridé par `--seuil`) |
| `FENETRE_GLISSANTE_S` | Durée de la fenêtre glissante en secondes (overridé par `--fenetre`) |
| `SEUIL_AVERT_TAILLE_MO` | Avertissement si fichier > 100 Mo — non bloquant |

```python
_ANNEE_COURANTE = datetime.now().year
```
Extrait une seule fois au chargement du module. Évite d'appeler `datetime.now()` pour chaque ligne de log (potentiellement des millions). Corrigé automatiquement si le log date de l'année précédente (passage d'année).

---

## 3. Patterns compilés

Tous les patterns sont compilés une fois au niveau du module :

```python
_IP_V4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IP_V6 = r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
_IP    = rf"({_IP_V4}|{_IP_V6})"
```
Pattern IP unifié : capture IPv4 **et** IPv6 dans le groupe 1.

```python
_RE_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
```
Horodatage syslog : `"Jun  2 10:12:01"` en début de ligne.

```python
_RE_IP_FROM = re.compile(rf"from\s+{_IP}")
```
Extrait l'IP source après `from `. `\s+` est plus robuste qu'un espace fixe.

```python
_RE_USER = re.compile(r"(?:Failed password for (?:invalid user )?|Invalid user )(\S+) from")
```
Extrait le compte ciblé dans les deux formats sshd :
- `Failed password for root from ...`
- `Failed password for invalid user test from ...`
- `Invalid user oracle from ...`

```python
_RE_LIGNE_ECHEC = re.compile(
    r"Failed password|Invalid user"
    r"|Too many authentication failures"
    r"|maximum authentication attempts exceeded"
    r"|Disconnecting.*preauth"
)
```
Filtre toutes les lignes représentant un échec d'authentification, quel que soit le format sshd.

```python
_RE_REPEATED = re.compile(rf"message repeated (\d+) times:.*?from\s+{_IP}")
```
Traite les logs compressés : `"message repeated 5 times: [ Failed password ... from IP ]"`. Le compteur N est appliqué en une seule opération pour éviter le double comptage.

```python
_RE_ACCEPTED = re.compile(rf"Accepted (?:password|publickey) for \S+ from\s+{_IP}")
```
Détecte une connexion acceptée. Si une IP a des échecs **et** une acceptation, elle est marquée COMPROMIS.

---

## 4. Dataclass `ResultatAnalyse`

```python
@dataclass
class ResultatAnalyse:
    tries:      list[tuple[str, int]]  = field(default_factory=list)
    cibles:     dict[str, set[str]]    = field(default_factory=dict)
    taux_max:   dict[str, float]       = field(default_factory=dict)
    compromises: set[str]              = field(default_factory=set)
    nb_lignes:  int                    = 0
```

| Champ | Contenu |
|---|---|
| `tries` | Liste `[(ip, nb_echecs), ...]` triée par nb décroissant |
| `cibles` | `{ip: {"root", "admin", ...}}` — comptes tentés par IP |
| `taux_max` | `{ip: float}` — max d'échecs dans n'importe quelle fenêtre de N secondes |
| `compromises` | IPs ayant des échecs **et** une connexion acceptée |
| `nb_lignes` | Nombre total de lignes lues (affiché dans le rapport) |

---

## 5. Fonctions internes

### 5.1 `_severite`

```python
def _severite(nb: int, seuil: int, taux: float = 0.0) -> str:
```

Calcule le niveau de sévérité en combinant le comptage cumulatif (`nb`) et le taux maximal sur fenêtre (`taux`) via un **OR logique** : `score = max(nb, taux)`.

| Score | Niveau |
|---|---|
| `< seuil` | `"ok"` |
| `< seuil × 2` | `"suspect"` |
| `< seuil × 3` | `"eleve"` |
| `>= seuil × 3` | `"critique"` |

Ce choix permet de détecter à la fois :
- les attaques **rapides** (taux élevé, nb faible)
- les campagnes **lentes** (nb élevé, taux faible)

---

### 5.2 `_valider_ip`

```python
def _valider_ip(ip: str) -> bool:
```

Délègue à `ipaddress.ip_address()`. Retourne `False` sur `ValueError` sans propager d'exception. Protège contre les faux positifs dans les cas où la regex capturerait une chaîne non-IP.

---

### 5.3 `_parse_timestamp`

```python
def _parse_timestamp(ligne: str) -> datetime | None:
```

Parse l'horodatage syslog (`"Jun  2 10:12:01"`) en `datetime` en utilisant `_ANNEE_COURANTE`. Applique une correction automatique de passage d'année : si le timestamp résultant est dans le futur, l'année est décrémentée de 1 (cas d'un log de décembre relu en janvier).

---

### 5.4 `_taux_max_fenetre`

```python
def _taux_max_fenetre(horodatages: list[datetime], fenetre_s: int) -> float:
```

**Algorithme two-pointer (fenêtre glissante), O(n log n).**

Trie les horodatages une fois, puis parcourt avec deux pointeurs `gauche` / `droite`. Pour chaque position de `droite`, avance `gauche` jusqu'à ce que la fenêtre `ts[droite] - ts[gauche]` tienne dans `fenetre_s` secondes. Retourne le maximum de `droite - gauche + 1` observé.

Retourne le nombre maximal d'échecs observés dans n'importe quelle fenêtre de `fenetre_s` secondes — indépendamment du moment où cette fenêtre se situe dans le log.

---

### 5.5 `_sanitiser`

```python
def _sanitiser(texte: str) -> str:
```

Filtre les caractères non imprimables des noms d'utilisateurs extraits du log. Protège contre les injections de caractères de contrôle dans le rapport.

---

### 5.6 `_seuil_positif`

```python
def _seuil_positif(valeur: str) -> int:
```

Validateur `argparse` pour `--seuil`. Lève `argparse.ArgumentTypeError` si la valeur est inférieure à 1, ce qui génère un message d'erreur propre sans stacktrace.

---

## 6. Fonctions publiques

### 6.1 `parser_arguments`

```python
def parser_arguments() -> argparse.Namespace:
```

**Retourne** un `argparse.Namespace` avec les attributs `fichier`, `seuil`, `rapport`, `fenetre`.

| Argument | Type | Défaut | Description |
|---|---|---|---|
| `--fichier` | str | `auth.log` | Fichier de logs SSH |
| `--seuil` | int (>= 1) | `3` | Échecs avant alerte |
| `--rapport` | str | `rapport_bruteforce.txt` | Fichier de sortie |
| `--fenetre` | int | `60` | Fenêtre glissante (secondes) |

---

### 6.2 `analyser_logs`

```python
def analyser_logs(chemin: str, fenetre_s: int = FENETRE_GLISSANTE_S) -> ResultatAnalyse:
```

**Déroulement interne :**

```
1. Path(chemin).exists()          → sys.exit(1) si fichier absent
2. stat().st_size > 100 Mo        → avertissement non bloquant
3. open(encoding="utf-8", errors="replace")
4. for ligne in f                 → lecture ligne par ligne (mémoire constante)
5. _RE_REPEATED.search(ligne)     → compressé N fois → traité en priorité (pas de double comptage)
6. _RE_LIGNE_ECHEC.search(ligne)  → toute ligne d'échec
7. _RE_IP_FROM + _valider_ip      → extraction et validation IP
8. echecs[ip] += 1                → comptage via defaultdict
9. horodatages[ip].append(ts)     → pour la fenêtre glissante
10. _RE_USER.search(ligne)        → extraction du compte ciblé
11. _RE_ACCEPTED.search(ligne)    → détection connexion acceptée
```

**Après la boucle :**
```python
taux_max    = {ip: _taux_max_fenetre(horodatages[ip], fenetre_s) for ip in echecs ...}
compromises = ips_echec & ips_acceptees   # intersection des deux ensembles
```

**Exceptions gérées :** `IsADirectoryError`, `PermissionError`, `OSError`.

---

### 6.3 `afficher_resultats`

```python
def afficher_resultats(res: ResultatAnalyse, seuil: int,
                       fenetre_s: int = FENETRE_GLISSANTE_S) -> None:
```

Affiche le résumé trié dans le terminal. Le libellé de la colonne taux inclut la valeur réelle de `fenetre_s` : `"14 échecs/60s"`.

**Format de sortie :**
```
Analyse terminée.
-----------------
185.220.101.5 : 22 échec(s) - CRITIQUE | 14 échecs/60s | comptes : admin, root, test...
192.168.1.10  : 12 échec(s) - COMPROMIS | 2 échecs/60s | comptes : admin, root
91.121.44.6   : 7 échec(s)  - ÉLEVÉ    | 3 échecs/60s | comptes : admin, root, test
2001:db8::cafe : 4 échec(s) - SUSPECT  | 4 échecs/60s | comptes : admin, ubuntu
192.168.1.100 : 2 échec(s)  - OK       | 2 échecs/60s | comptes : jean.dupont

⚠  COMPROMISSION PROBABLE : 192.168.1.10
```

---

### 6.4 `generer_rapport`

```python
def generer_rapport(res: ResultatAnalyse, seuil: int, fichier_rapport: str,
                    fenetre_s: int = FENETRE_GLISSANTE_S) -> None:
```

**Écriture atomique :** `tempfile.mkstemp()` crée un fichier temporaire dans le même répertoire que la cible, le contenu y est écrit, puis `os.replace()` remplace atomiquement la cible. Si une erreur survient, le fichier temporaire est supprimé et la cible précédente est préservée.

La fonction interne `_ecrire_rapport()` produit :

```
Rapport d'analyse SSH
======================

Seuil d'alerte       : 3 échecs
Fenêtre glissante    : 60 secondes
Lignes analysées     : 120
IP compromises       : 1

Résumé des échecs par IP :
- 185.220.101.5 : 22 échec(s) | taux max : 14 échecs/60s | comptes : admin, root...
- 192.168.1.10  : 12 échec(s) | taux max : 2 échecs/60s [COMPROMIS] | comptes : admin, root

IP suspectes :
- ALERTE : 185.220.101.5 avec 22 échecs | taux max : 14 échecs/60s
- ALERTE : 192.168.1.10 avec 12 échecs | taux max : 2 échecs/60s ← COMPROMIS

  [si alerte déclenchée par taux seul :]
- ALERTE : x.x.x.x avec 2 échecs (nb cumulé : 2, alerte sur taux : 4 échecs/60s)

COMPROMISSIONS DÉTECTÉES :
- 192.168.1.10 : 12 échec(s) suivis d'une connexion acceptée
```

---

### 6.5 `main`

```python
def main() -> None:
```

**Flux d'exécution :**
```
sys.stdout.reconfigure(encoding="utf-8")   → UTF-8 pour consoles Windows
signal.signal(SIGINT, ...)                 → Ctrl+C propre
parser_arguments()                         → options CLI
analyser_logs()                            → lecture + analyse
afficher_resultats()                       → terminal
generer_rapport()                          → fichier .txt (atomique)
print("Rapport généré : ...")              → confirmation (après écriture réussie)
```

Le handler SIGINT est installé dans `main()` et non au niveau du module, pour ne pas interférer quand `analyse_ssh` est importé par `gui_ssh.py`.

---

## 7. Analyse vs corrigé formateur

### Points identiques

| Élément | Notre code | Corrigé |
|---|---|---|
| Logique générale | Identique | Identique |
| `defaultdict(int)` | Oui | Oui |
| Gestion fichier absent | Oui | Oui |
| Encodage `utf-8` | Oui | Oui |
| `if __name__ == "__main__"` | Oui | Oui |
| Tri décroissant par nb d'échecs | Oui | Oui |

### Apports par rapport au corrigé

| Critère | Notre code | Corrigé formateur |
|---|---|---|
| CLI configurable | `--fichier` `--seuil` `--rapport` `--fenetre` | Aucun argparse |
| Niveaux de sévérité | OK / SUSPECT / ÉLEVÉ / CRITIQUE / COMPROMIS | SUSPECTE / OK |
| Support IPv6 | Oui | Non |
| Formats détectés | 5 patterns | `Failed password` uniquement |
| `message repeated N times` | Oui (anti double-comptage) | Non |
| Fenêtre glissante (taux) | Two-pointer O(n log n) | Non |
| Détection compromission | `ips_echec & ips_acceptees` | Non |
| Comptes utilisateurs ciblés | Oui (`defaultdict(set)`) | Non |
| Validation IP | `ipaddress.ip_address()` | Aucune |
| Horodatage + correction année | Oui | Non |
| Écriture atomique rapport | `tempfile.mkstemp` + `os.replace` | `open()` direct |
| Handler SIGINT | Dans `main()` | Non |
| `IsADirectoryError` | Capturée | Non |
| Encodage Windows | `sys.stdout.reconfigure(utf-8)` | Non |
| Interface graphique | `gui_ssh.py` (customtkinter) | Non |

---

## 8. Apports hors TP de base

Ces éléments vont au-delà des exigences du TP et répondent aux **améliorations possibles** listées dans le sujet formateur.

### Fenêtre glissante — détection d'attaques rapides

Un scan de 14 connexions en 44 secondes peut ne représenter qu'un faible nb cumulatif si les logs analysés couvrent des mois. Sans fenêtre glissante, l'attaque passerait sous le radar. `_taux_max_fenetre()` calcule le maximum d'échecs dans n'importe quelle fenêtre de N secondes via un algorithme two-pointer.

### OR logique dans `_severite`

`score = max(nb, taux)` — un brute-force rapide (taux élevé) et une campagne lente (nb élevé) utilisent le même seuil. Le "pire" des deux indicateurs l'emporte.

### Détection de compromission

L'intersection `ips_echec & ips_acceptees` identifie les IPs qui ont d'abord échoué puis réussi à se connecter. Ces IPs sont affichées COMPROMIS indépendamment de leur niveau de sévérité.

### Écriture atomique

`tempfile.mkstemp` + `os.replace` garantit qu'en cas d'erreur disque ou d'interruption, le rapport précédent est conservé intact — jamais de fichier vide ou tronqué.

### Interface graphique (`gui_ssh.py`)

- Thèmes : Cyber (rouge), Matrix (vert), Midnight (violet)
- Analyse en thread séparé (UI non bloquée)
- Animations : pulsation du point de statut, compteurs animés, apparition en cascade des lignes
- Fenêtre glissante configurable depuis l'interface
- Mode démo intégré

---

## 9. Utilisation

### Lancement CLI

```bash
python analyse_ssh.py
```

### Lancement GUI

```bash
python gui_ssh.py
```

### Options CLI complètes

```bash
python analyse_ssh.py --help
```

```
usage: analyse_ssh.py [-h] [--fichier FICHIER] [--seuil SEUIL]
                      [--rapport RAPPORT] [--fenetre FENETRE]

Détection de brute-force SSH par analyse de logs.

options:
  --fichier FICHIER  Fichier de logs (défaut : auth.log)
  --seuil SEUIL      Échecs minimum avant alerte, >= 1 (défaut : 3)
  --rapport RAPPORT  Fichier de sortie (défaut : rapport_bruteforce.txt)
  --fenetre FENETRE  Fenêtre glissante en secondes (défaut : 60)
```

### Exemples

```bash
# Seuil personnalisé
python analyse_ssh.py --seuil 5

# Fichier et rapport personnalisés
python analyse_ssh.py --fichier /var/log/auth.log --rapport /tmp/rapport.txt

# Fenêtre de 2 minutes pour réduire les faux positifs sur scans lents
python analyse_ssh.py --fenetre 120 --seuil 10

# Analyse stricte avec toutes les options
python analyse_ssh.py --fichier /var/log/auth.log --seuil 3 --rapport rapport.txt --fenetre 60
```