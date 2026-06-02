# ssh-brute-hunter

Outil d'analyse de logs SSH en Python pour détecter automatiquement les tentatives de brute-force, les scans lents et les compromissions.

## Fonctionnalités

- Détection multi-format : `Failed password`, `Invalid user`, `Too many authentication failures`, `Disconnecting preauth`, `message repeated N times`
- Support IPv4 et IPv6
- Fenêtre glissante configurable pour détecter les attaques rapides
- 5 niveaux de sévérité : **OK / SUSPECT / ÉLEVÉ / CRITIQUE / COMPROMIS**
- Détection de compromission (échecs suivis d'une connexion acceptée)
- Rapport texte généré atomiquement (pas de fichier corrompu en cas d'interruption)
- Interface graphique avec thèmes et animations (`gui_ssh.py`)

## Utilisation

### CLI

```bash
python analyse_ssh.py
```

```bash
python analyse_ssh.py --fichier /var/log/auth.log --seuil 5 --rapport rapport.txt --fenetre 120
```

**Options disponibles :**

| Option | Défaut | Description |
|---|---|---|
| `--fichier` | `auth.log` | Fichier de logs SSH à analyser |
| `--seuil` | `3` | Échecs minimum avant alerte (>= 1) |
| `--rapport` | `rapport_bruteforce.txt` | Fichier de sortie |
| `--fenetre` | `60` | Fenêtre glissante en secondes |

### GUI

```bash
pip install -r requirements.txt
python gui_ssh.py
```

## Exemple de sortie

```
Analyse terminée.
-----------------
185.220.101.5 : 22 échec(s) - CRITIQUE | 14 échecs/60s | comptes : admin, root, test...
192.168.1.10  : 12 échec(s) - COMPROMIS | 2 échecs/60s | comptes : admin, root
91.121.44.6   : 7 échec(s)  - ÉLEVÉ    | 3 échecs/60s | comptes : admin, root, test
103.99.0.43   : 5 échec(s)  - SUSPECT  | 5 échecs/60s | comptes : mysql, postgres...
192.168.1.100 : 2 échec(s)  - OK       | 2 échecs/60s | comptes : jean.dupont

⚠  COMPROMISSION PROBABLE : 192.168.1.10

Rapport généré : rapport_bruteforce.txt
```

## Structure

```
ssh-brute-hunter/
├── analyse_ssh.py           # Moteur d'analyse (CLI)
├── gui_ssh.py               # Interface graphique (customtkinter)
├── auth.log                 # Fichier de logs SSH à analyser
├── rapport_bruteforce.txt   # Rapport généré automatiquement
├── requirements.txt         # customtkinter>=5.2.0
└── DOCS.md                  # Documentation technique
```