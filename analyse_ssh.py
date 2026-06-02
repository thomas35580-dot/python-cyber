import re
import sys
from collections import defaultdict

LOG_FILE = "auth.log"
RAPPORT_FILE = "rapport_bruteforce.txt"
SEUIL = 3


def lire_logs(chemin):
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"Erreur : le fichier '{chemin}' est introuvable.")
        sys.exit(1)


def filtrer_echecs(lignes):
    return [ligne for ligne in lignes if "Failed password" in ligne]


def extraire_ip(ligne):
    # L'IP se trouve après le mot "from" dans les logs sshd
    match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", ligne)
    return match.group(1) if match else None


def compter_echecs(lignes_echec):
    compteur = defaultdict(int)
    for ligne in lignes_echec:
        ip = extraire_ip(ligne)
        if ip:
            compteur[ip] += 1
    return dict(sorted(compteur.items(), key=lambda x: x[1], reverse=True))


def afficher_resultats(compteur):
    print("Analyse terminée.")
    print("-----------------")
    for ip, nb in compteur.items():
        statut = " - SUSPECTE" if nb >= SEUIL else ""
        print(f"{ip} : {nb} échec(s){statut}")
    print(f"Rapport généré : {RAPPORT_FILE}")


def generer_rapport(compteur):
    suspectes = {ip: nb for ip, nb in compteur.items() if nb >= SEUIL}

    with open(RAPPORT_FILE, "w", encoding="utf-8") as f:
        f.write("Rapport d'analyse SSH\n")
        f.write("======================\n\n")
        f.write(f"Seuil d'alerte : {SEUIL} échecs\n\n")
        f.write("Résumé des échecs par IP :\n")
        for ip, nb in compteur.items():
            f.write(f"- {ip} : {nb} échec(s)\n")
        f.write("\nIP suspectes :\n")
        for ip, nb in suspectes.items():
            f.write(f"- ALERTE : {ip} avec {nb} échecs\n")


def main():
    lignes = lire_logs(LOG_FILE)
    lignes_echec = filtrer_echecs(lignes)
    compteur = compter_echecs(lignes_echec)
    afficher_resultats(compteur)
    generer_rapport(compteur)


if __name__ == "__main__":
    main()
