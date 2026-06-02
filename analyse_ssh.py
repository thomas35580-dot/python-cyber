import re
import sys
import signal
import argparse
import operator
import ipaddress
import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LOG_FILE               = "auth.log"
RAPPORT_FILE           = "rapport_bruteforce.txt"
SEUIL_ALERTE           = 3
FENETRE_GLISSANTE_S    = 60
SEUIL_AVERT_TAILLE_MO  = 100   # avertissement (non bloquant)

# ── Patterns compilés ─────────────────────────────────────────────────────────
_IP_V4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IP_V6 = r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
_IP    = rf"({_IP_V4}|{_IP_V6})"

# Horodatage syslog : "Jun  2 10:12:01"
_RE_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# IP après "from "
_RE_IP_FROM = re.compile(rf"from\s+{_IP}")

# Nom d'utilisateur ciblé (Failed password / Invalid user)
_RE_USER = re.compile(r"(?:Failed password for (?:invalid user )?|Invalid user )(\S+) from")

# Toutes les lignes qui représentent un échec d'authentification
_RE_LIGNE_ECHEC = re.compile(
    r"Failed password|Invalid user"
    r"|Too many authentication failures"
    r"|maximum authentication attempts exceeded"
    r"|Disconnecting.*preauth"
)

# "message repeated 5 times: [ Failed password ... from IP ]"
_RE_REPEATED = re.compile(rf"message repeated (\d+) times:.*?from\s+{_IP}")

# Connexion acceptée (pour détecter une compromission)
_RE_ACCEPTED = re.compile(
    rf"Accepted (?:password|publickey) for \S+ from\s+{_IP}"
)

_PAR_NB_DESC    = operator.itemgetter(1)
_ANNEE_COURANTE = datetime.now().year   # extrait une fois — évite l'appel par ligne


# ── Dataclass résultat ────────────────────────────────────────────────────────

@dataclass
class ResultatAnalyse:
    tries: list[tuple[str, int]]      = field(default_factory=list)
    cibles: dict[str, set[str]]       = field(default_factory=dict)
    taux_max: dict[str, float]        = field(default_factory=dict)
    compromises: set[str]             = field(default_factory=set)
    nb_lignes: int                    = 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severite(nb: int, seuil: int, taux: float = 0.0) -> str:
    """Combine comptage cumulatif et taux max (OR logique, retient le pire niveau).

    Un brute-force rapide (taux élevé, nb faible) et une campagne lente
    (nb élevé, taux faible) sont tous les deux détectés correctement.
    """
    score = max(nb, taux)
    if score < seuil:          return "ok"
    elif score < seuil * 2:    return "suspect"
    elif score < seuil * 3:    return "eleve"
    else:                      return "critique"


def _valider_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _parse_timestamp(ligne: str) -> datetime | None:
    m = _RE_TS.match(ligne)
    if not m:
        return None
    try:
        ts = datetime.strptime(
            f"{_ANNEE_COURANTE} {m.group(1).strip()}", "%Y %b %d %H:%M:%S"
        )
        # Passage d'année : log de déc. relu en janv. → timestamp dans le futur
        if ts > datetime.now():
            ts = ts.replace(year=_ANNEE_COURANTE - 1)
        return ts
    except ValueError:
        return None


def _taux_max_fenetre(horodatages: list[datetime], fenetre_s: int) -> float:
    """Nombre max d'échecs dans n'importe quelle fenêtre de fenetre_s secondes (O(n log n))."""
    if not horodatages:
        return 0.0
    ts = sorted(horodatages)
    max_nb, gauche = 1, 0
    for droite in range(len(ts)):
        while (ts[droite] - ts[gauche]).total_seconds() > fenetre_s:
            gauche += 1
        max_nb = max(max_nb, droite - gauche + 1)
    return float(max_nb)


def _sanitiser(texte: str) -> str:
    return "".join(c for c in texte if c.isprintable())


def _seuil_positif(valeur: str) -> int:
    n = int(valeur)
    if n < 1:
        raise argparse.ArgumentTypeError("Le seuil doit être >= 1.")
    return n


# ── CLI ───────────────────────────────────────────────────────────────────────

def parser_arguments() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Détection de brute-force SSH par analyse de logs.")
    p.add_argument("--fichier",  default=LOG_FILE,
                   help=f"Fichier de logs (défaut : {LOG_FILE})")
    p.add_argument("--seuil",    type=_seuil_positif, default=SEUIL_ALERTE,
                   help=f"Échecs minimum avant alerte, >= 1 (défaut : {SEUIL_ALERTE})")
    p.add_argument("--rapport",  default=RAPPORT_FILE,
                   help=f"Fichier de sortie (défaut : {RAPPORT_FILE})")
    p.add_argument("--fenetre",  type=int, default=FENETRE_GLISSANTE_S,
                   help=f"Fenêtre glissante en secondes (défaut : {FENETRE_GLISSANTE_S})")
    return p.parse_args()


# ── Analyse ───────────────────────────────────────────────────────────────────

def analyser_logs(chemin: str, fenetre_s: int = FENETRE_GLISSANTE_S) -> ResultatAnalyse:
    """Lit le fichier ligne par ligne, détecte brute-force et compromissions."""
    chemin_path = Path(chemin)
    if not chemin_path.exists():
        print(f"Erreur : le fichier '{chemin}' est introuvable.")
        sys.exit(1)

    taille_mo = chemin_path.stat().st_size / (1024 * 1024)
    if taille_mo > SEUIL_AVERT_TAILLE_MO:
        print(f"Avertissement : fichier volumineux ({taille_mo:.1f} Mo)…")

    echecs:        defaultdict[str, int]           = defaultdict(int)
    cibles:        defaultdict[str, set[str]]      = defaultdict(set)
    horodatages:   defaultdict[str, list[datetime]]= defaultdict(list)
    ips_echec:     set[str]                        = set()
    ips_acceptees: set[str]                        = set()
    nb_lignes = 0

    try:
        with open(chemin, "r", encoding="utf-8", errors="replace") as f:
            for ligne in f:
                nb_lignes += 1
                ts = _parse_timestamp(ligne)

                # "message repeated N times: [...]" — compresse N lignes identiques
                m_rep = _RE_REPEATED.search(ligne)
                if m_rep:
                    count = int(m_rep.group(1))
                    ip    = m_rep.group(2)
                    if _valider_ip(ip):
                        echecs[ip]  += count
                        ips_echec.add(ip)
                        if ts:
                            horodatages[ip].extend([ts] * min(count, 500))
                    continue

                # Lignes d'échec
                if _RE_LIGNE_ECHEC.search(ligne):
                    m_ip = _RE_IP_FROM.search(ligne)
                    if m_ip:
                        ip = m_ip.group(1)
                        if _valider_ip(ip):
                            echecs[ip] += 1
                            ips_echec.add(ip)
                            if ts:
                                horodatages[ip].append(ts)
                            m_user = _RE_USER.search(ligne)
                            if m_user:
                                user = _sanitiser(m_user.group(1))
                                if user:
                                    cibles[ip].add(user)
                    continue

                # Connexion acceptée
                m_acc = _RE_ACCEPTED.search(ligne)
                if m_acc:
                    ip = m_acc.group(1)
                    if _valider_ip(ip):
                        ips_acceptees.add(ip)

    except IsADirectoryError:
        print(f"Erreur : '{chemin}' est un répertoire, pas un fichier.")
        sys.exit(1)
    except PermissionError:
        print(f"Erreur : permission refusée pour lire '{chemin}'.")
        sys.exit(1)
    except OSError as e:
        print(f"Erreur lors de la lecture de '{chemin}' : {e}")
        sys.exit(1)

    taux_max = {
        ip: _taux_max_fenetre(horodatages[ip], fenetre_s)
        for ip in echecs
        if len(horodatages[ip]) >= 2
    }

    return ResultatAnalyse(
        tries       = sorted(echecs.items(), key=_PAR_NB_DESC, reverse=True),
        cibles      = dict(cibles),
        taux_max    = taux_max,
        compromises = ips_echec & ips_acceptees,
        nb_lignes   = nb_lignes,
    )


# ── Affichage terminal ────────────────────────────────────────────────────────

def afficher_resultats(res: ResultatAnalyse, seuil: int,
                       fenetre_s: int = FENETRE_GLISSANTE_S) -> None:
    LABELS = {
        "ok": "OK", "suspect": "SUSPECT",
        "eleve": "ÉLEVÉ", "critique": "CRITIQUE",
    }
    print("Analyse terminée.")
    print("-----------------")
    for ip, nb in res.tries:
        taux   = res.taux_max.get(ip, 0)
        sev    = "compromis" if ip in res.compromises else _severite(nb, seuil, taux)
        label  = "COMPROMIS" if sev == "compromis" else LABELS[sev]
        taux_s = f" | {taux:.0f} échecs/{fenetre_s}s" if taux else ""
        comptes = ", ".join(sorted(res.cibles.get(ip, set())))
        print(f"{ip} : {nb} échec(s) - {label}{taux_s} | comptes : {comptes}")
    if res.compromises:
        print(f"\n⚠  COMPROMISSION PROBABLE : {', '.join(sorted(res.compromises))}")


# ── Rapport ───────────────────────────────────────────────────────────────────

def _ecrire_rapport(f, res: ResultatAnalyse, seuil: int,
                    fenetre_s: int = FENETRE_GLISSANTE_S) -> None:
    f.write("Rapport d'analyse SSH\n")
    f.write("======================\n\n")
    f.write(f"Seuil d'alerte       : {seuil} échecs\n")
    f.write(f"Fenêtre glissante    : {fenetre_s} secondes\n")
    f.write(f"Lignes analysées     : {res.nb_lignes}\n")
    f.write(f"IP compromises       : {len(res.compromises)}\n\n")

    f.write("Résumé des échecs par IP :\n")
    for ip, nb in res.tries:
        comptes = ", ".join(sorted(res.cibles.get(ip, set())))
        taux    = res.taux_max.get(ip, 0)
        taux_s  = f" | taux max : {taux:.0f} échecs/{fenetre_s}s" if taux else ""
        flag    = " [COMPROMIS]" if ip in res.compromises else ""
        f.write(f"- {ip} : {nb} échec(s){taux_s}{flag} | comptes : {comptes}\n")

    f.write("\nIP suspectes :\n")
    suspectes = [(ip, nb) for ip, nb in res.tries
                 if _severite(nb, seuil, res.taux_max.get(ip, 0)) != "ok"]
    if not suspectes:
        f.write("Aucune IP suspecte détectée.\n")
    else:
        for ip, nb in suspectes:
            taux = res.taux_max.get(ip, 0)
            flag = " ← COMPROMIS" if ip in res.compromises else ""
            if taux and nb < seuil:
                # Alerte déclenchée par le taux seul — le nb brut serait trompeur sans explication
                raison = f" (nb cumulé : {nb}, alerte sur taux : {taux:.0f} échecs/{fenetre_s}s)"
            elif taux:
                raison = f" | taux max : {taux:.0f} échecs/{fenetre_s}s"
            else:
                raison = ""
            f.write(f"- ALERTE : {ip} avec {nb} échecs{raison}{flag}\n")

    if res.compromises:
        f.write("\nCOMPROMISSIONS DÉTECTÉES :\n")
        for ip in sorted(res.compromises):
            nb = dict(res.tries).get(ip, 0)
            f.write(f"- {ip} : {nb} échec(s) suivis d'une connexion acceptée\n")


def generer_rapport(res: ResultatAnalyse, seuil: int, fichier_rapport: str,
                    fenetre_s: int = FENETRE_GLISSANTE_S) -> None:
    parent = Path(fichier_rapport).resolve().parent
    try:
        fd, tmp = tempfile.mkstemp(dir=parent, suffix=".tmp", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                _ecrire_rapport(f, res, seuil, fenetre_s)
            os.replace(tmp, fichier_rapport)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except PermissionError:
        print(f"Erreur : permission refusée pour écrire '{fichier_rapport}'.")
        sys.exit(1)
    except OSError as e:
        print(f"Erreur lors de l'écriture du rapport : {e}")
        sys.exit(1)


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main() -> None:
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    args = parser_arguments()
    res  = analyser_logs(args.fichier, fenetre_s=args.fenetre)
    afficher_resultats(res, args.seuil, fenetre_s=args.fenetre)
    generer_rapport(res, args.seuil, args.rapport, fenetre_s=args.fenetre)
    print(f"\nRapport généré : {args.rapport}")


if __name__ == "__main__":
    main()
