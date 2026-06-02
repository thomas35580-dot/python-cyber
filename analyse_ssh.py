import re
import sys
import signal
import argparse
import operator
from collections import defaultdict
from pathlib import Path

LOG_FILE = "auth.log"
RAPPORT_FILE = "rapport_bruteforce.txt"
SEUIL_ALERTE = 3
TAILLE_MAX_MO = 100

# Regex compilées une seule fois au chargement du module
_RE_IP = re.compile(r"from\s+((?:\d{1,3}\.){3}\d{1,3})")
_RE_USER = re.compile(r"Failed password for (?:invalid user )?(\S+) from")

# Clé de tri réutilisée — operator.itemgetter est plus rapide qu'une lambda
_PAR_NB_DESC = operator.itemgetter(1)

signal.signal(signal.SIGINT, lambda *_: sys.exit(0))


def _seuil_positif(valeur: str) -> int:
    n = int(valeur)
    if n < 1:
        raise argparse.ArgumentTypeError("Le seuil doit être un entier >= 1.")
    return n


def parser_arguments() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Détection de brute-force SSH par analyse de logs.")
    p.add_argument("--fichier", default=LOG_FILE,
                   help=f"Fichier de logs à analyser (défaut : {LOG_FILE})")
    p.add_argument("--seuil", type=_seuil_positif, default=SEUIL_ALERTE,
                   help=f"Nombre d'échecs avant alerte, >= 1 (défaut : {SEUIL_ALERTE})")
    p.add_argument("--rapport", default=RAPPORT_FILE,
                   help=f"Fichier de sortie du rapport (défaut : {RAPPORT_FILE})")
    return p.parse_args()


def _valider_ip(ip: str) -> bool:
    """Vérifie que chaque octet est dans [0, 255]."""
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))


def extraire_ip(ligne: str) -> str | None:
    match = _RE_IP.search(ligne)
    if not match:
        return None
    ip = match.group(1)
    return ip if _valider_ip(ip) else None


def extraire_utilisateur(ligne: str) -> str | None:
    match = _RE_USER.search(ligne)
    if not match:
        return None
    # Supprime les caractères non imprimables — prévient l'injection dans le rapport
    propre = "".join(c for c in match.group(1) if c.isprintable())
    return propre if propre else None


def analyser_logs(chemin: str) -> tuple[dict[str, int], dict[str, set[str]]]:
    """Lit le fichier ligne par ligne sans charger tout en RAM."""
    chemin_path = Path(chemin)

    if not chemin_path.exists():
        print(f"Erreur : le fichier '{chemin}' est introuvable.")
        sys.exit(1)

    taille_mo = chemin_path.stat().st_size / (1024 * 1024)
    if taille_mo > TAILLE_MAX_MO:
        print(f"Avertissement : fichier volumineux ({taille_mo:.1f} Mo), traitement en cours...")

    echecs_par_ip: defaultdict[str, int] = defaultdict(int)
    cibles_par_ip: defaultdict[str, set[str]] = defaultdict(set)

    try:
        # errors='replace' : un caractère invalide devient '?' sans lever d'exception
        with open(chemin, "r", encoding="utf-8", errors="replace") as f:
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
    except PermissionError:
        print(f"Erreur : permission refusée pour lire '{chemin}'.")
        sys.exit(1)

    return dict(echecs_par_ip), dict(cibles_par_ip)


def _trier(echecs_par_ip: dict[str, int]) -> list[tuple[str, int]]:
    """Calcule le tri une seule fois, partagé entre affichage et rapport."""
    return sorted(echecs_par_ip.items(), key=_PAR_NB_DESC, reverse=True)


def afficher_resultats(
    echecs_par_ip: dict[str, int],
    cibles_par_ip: dict[str, set[str]],
    seuil: int,
) -> None:
    print("Analyse terminée.")
    print("-----------------")
    for ip, nb in _trier(echecs_par_ip):
        statut = "SUSPECTE" if nb >= seuil else "OK"
        comptes = ", ".join(sorted(cibles_par_ip.get(ip, set())))
        print(f"{ip} : {nb} échec(s) - {statut} | comptes ciblés : {comptes}")


def generer_rapport(
    echecs_par_ip: dict[str, int],
    cibles_par_ip: dict[str, set[str]],
    seuil: int,
    fichier_rapport: str,
) -> None:
    tries = _trier(echecs_par_ip)
    suspectes = [(ip, nb) for ip, nb in tries if nb >= seuil]

    try:
        with open(fichier_rapport, "w", encoding="utf-8") as f:
            f.write("Rapport d'analyse SSH\n")
            f.write("======================\n\n")
            f.write(f"Seuil d'alerte : {seuil} échecs\n\n")
            f.write("Résumé des échecs par IP :\n")
            for ip, nb in tries:
                comptes = ", ".join(sorted(cibles_par_ip.get(ip, set())))
                f.write(f"- {ip} : {nb} échec(s) | comptes ciblés : {comptes}\n")
            f.write("\nIP suspectes :\n")
            if not suspectes:
                f.write("Aucune IP suspecte détectée.\n")
            else:
                for ip, nb in suspectes:
                    f.write(f"- ALERTE : {ip} avec {nb} échecs\n")
    except PermissionError:
        print(f"Erreur : permission refusée pour écrire '{fichier_rapport}'.")
        sys.exit(1)
    except OSError as e:
        print(f"Erreur lors de l'écriture du rapport : {e}")
        sys.exit(1)


def main() -> None:
    args = parser_arguments()
    echecs_par_ip, cibles_par_ip = analyser_logs(args.fichier)
    afficher_resultats(echecs_par_ip, cibles_par_ip, args.seuil)
    generer_rapport(echecs_par_ip, cibles_par_ip, args.seuil, args.rapport)
    print(f"\nRapport généré : {args.rapport}")


if __name__ == "__main__":
    main()
