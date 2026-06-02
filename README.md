# ssh-brute-hunter

Outil d'analyse de logs SSH en Python pour détecter automatiquement les tentatives de brute-force.

## Fonctionnement

Le script lit un fichier `auth.log`, isole les lignes `Failed password`, extrait les adresses IP via regex et compte les échecs par IP. Toute IP atteignant le seuil d'alerte est marquée comme suspecte et consignée dans un rapport.

```
Analyse terminée.
-----------------
45.83.12.9 : 4 échec(s) - SUSPECTE
192.168.1.10 : 3 échec(s) - SUSPECTE
Rapport généré : rapport_bruteforce.txt
```

## Utilisation

```bash
python analyse_ssh.py
```

Le fichier `auth.log` doit être dans le même répertoire. Le rapport est généré dans `rapport_bruteforce.txt`.

## Seuil d'alerte

Configurable dans le script via la constante `SEUIL` (défaut : 3 échecs).

## Structure

```
ssh-brute-hunter/
├── auth.log                 # Fichier de logs SSH à analyser
├── analyse_ssh.py           # Script principal
└── rapport_bruteforce.txt   # Rapport généré automatiquement
```
