import re
import sys
import signal
import argparse
from collections import defaultdict
from pathlib import Path

LOG_FILE = "auth.log"
RAPPORT_FILE = "rapport_bruteforce.txt"
SEUIL_ALERTE = 3
TAILLE_MAX_MO = 100

# Sortie propre sur Ctrl+C — évite un traceback sur interruption manuelle
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))


def parser_arguments() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Détection de brute-force SSH par analyse de logs.")
    p.add_argument("--fichier", default=LOG_FILE,
                   help=f"Fichier de logs à analyser (défaut : {LOG_FILE})")
    p.add_argument("--seuil", type=int, default=SEUIL_ALERTE,
                   help=f"Nombre d'échecs avant alerte (défaut : {SEUIL_ALERTE})")
    p.add_argument("--rapport", default=RAPPORT_FILE,
                   help=f"Fichier de sortie du rapport (défaut : {RAPPORT_FILE})")
    return p.parse_args()


def extraire_ip(ligne: str) -> str | None:
    match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", ligne)
    return match.group(1) if match else None


def extraire_utilisateur(ligne: str) -> str | None:
    # Gère "for root" et "for invalid user oracle"
    match = re.search(r"Failed password for (?:invalid user )?(\S+) from", ligne)
    return match.group(1) if match else None


def analyser_logs(chemin: str) -> tuple[dict, dict]:
    """Lit le fichier ligne par ligne sans charger tout en RAM."""
    chemin_path = Path(chemin)

    if not chemin_path.exists():
        print(f"Erreur : le fichier '{chemin}' est introuvable.")
        sys.exit(1)

    taille_mo = chemin_path.stat().st_size / (1024 * 1024)
    if taille_mo > TAILLE_MAX_MO:
        print(f"Avertissement : fichier volumineux ({taille_mo:.1f} Mo), traitement en cours...")

    echecs_par_ip: defaultdict = defaultdict(int)
    cibles_par_ip: defaultdict = defaultdict(set)

    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            if "Failed password" not in ligne:
                continue
            ip = extraire_ip(ligne)
            if not ip:
                continue
            echecs_par_ip[ip] += 1
            utilisateur = extraire_utilisateur(ligne)
            if utilisateur:
                cibles_par_ip[ip].add(utilisateur)

    return dict(echecs_par_ip), dict(cibles_par_ip)


def afficher_resultats(echecs_par_ip: dict, cibles_par_ip: dict, seuil: int) -> None:
    print("Analyse terminée.")
    print("-----------------")
    for ip, nb in sorted(echecs_par_ip.items(), key=lambda x: x[1], reverse=True):
        statut = "SUSPECTE" if nb >= seuil else "OK"
        comptes = ", ".join(sorted(cibles_par_ip.get(ip, set())))
        print(f"{ip} : {nb} échec(s) - {statut} | comptes ciblés : {comptes}")


def generer_rapport(echecs_par_ip: dict, cibles_par_ip: dict, seuil: int, fichier_rapport: str) -> None:
    suspectes = {ip: nb for ip, nb in echecs_par_ip.items() if nb >= seuil}

    with open(fichier_rapport, "w", encoding="utf-8") as f:
        f.write("Rapport d'analyse SSH\n")
        f.write("======================\n\n")
        f.write(f"Seuil d'alerte : {seuil} échecs\n\n")
        f.write("Résumé des échecs par IP :\n")
        for ip, nb in sorted(echecs_par_ip.items(), key=lambda x: x[1], reverse=True):
            comptes = ", ".join(sorted(cibles_par_ip.get(ip, set())))
            f.write(f"- {ip} : {nb} échec(s) | comptes ciblés : {comptes}\n")
        f.write("\nIP suspectes :\n")
        if not suspectes:
            f.write("Aucune IP suspecte détectée.\n")
        else:
            for ip, nb in sorted(suspectes.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- ALERTE : {ip} avec {nb} échecs\n")


def main() -> None:
    args = parser_arguments()
    echecs_par_ip, cibles_par_ip = analyser_logs(args.fichier)
    afficher_resultats(echecs_par_ip, cibles_par_ip, args.seuil)
    generer_rapport(echecs_par_ip, cibles_par_ip, args.seuil, args.rapport)
    print(f"\nRapport généré : {args.rapport}")


if __name__ == "__main__":
    main()
