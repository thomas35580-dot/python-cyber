import operator
import signal
import sys
import threading
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk

from analyse_ssh import (
    LOG_FILE, RAPPORT_FILE, SEUIL_ALERTE,
    ResultatAnalyse, _severite,
    analyser_logs, generer_rapport,
)

signal.signal(signal.SIGINT, signal.SIG_DFL)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette de base (fond fixe, accents par thème) ───────────────────────────
C_BG      = "#0d1117"
C_SURFACE = "#161b22"
C_BORDER  = "#21262d"
C_MUTED   = "#2d3748"
C_MUTED2  = "#4a5568"
C_TEXT    = "#e2e8f0"
C_TEXT2   = "#8b949e"
C_TEXT3   = "#484f58"

# Sévérité — fixes
C_OK       = "#51cf66"
C_SUSPECT  = "#f6c90e"
C_ELEVE    = "#ff8c42"
C_CRITIQUE = "#ff4444"
C_COMPROM  = "#e040fb"
C_DANGER   = "#ff6b6b"
C_WARNING  = "#f6c90e"

# ── Thèmes (accent color + sfx) ───────────────────────────────────────────────
PALETTES: dict[str, dict] = {
    "Cyber": {
        "accent":  "#e94560",
        "accent2": "#c53030",
        "dot_ok":  "#51cf66",
        "label":   "Cyber",
    },
    "Matrix": {
        "accent":  "#00e676",
        "accent2": "#00c853",
        "dot_ok":  "#00e676",
        "label":   "Matrix",
    },
    "Midnight": {
        "accent":  "#7c3aed",
        "accent2": "#6d28d9",
        "dot_ok":  "#4ade80",
        "label":   "Midnight",
    },
}
_THEME_ACTIF = "Cyber"

LABELS_STATUT = {
    "ok":       "✓  OK",
    "suspect":  "⚠  SUSPECT",
    "eleve":    "●  ÉLEVÉ",
    "critique": "⚡  CRITIQUE",
    "compromis":"💀  COMPROMIS",
}

# ── Données de démo ───────────────────────────────────────────────────────────
_DEMO_ECHECS: dict[str, int] = {
    "185.220.101.5":  14,
    "10.0.0.55":       7,
    "45.83.12.9":      4,
    "192.168.1.10":    3,
    "203.0.113.42":    2,
    "fe80::1%eth0":    5,
    "2001:db8::cafe":  1,
    "192.168.1.20":    1,
}
_DEMO_CIBLES: dict[str, set[str]] = {
    "185.220.101.5": {"root","admin","mysql","postgres","oracle",
                      "test","deploy","ubuntu","pi","git","www","ftp"},
    "10.0.0.55":     {"root","ubuntu","pi","admin","user","git","deploy"},
    "45.83.12.9":    {"admin","oracle","postgres","test"},
    "192.168.1.10":  {"admin","root"},
    "203.0.113.42":  {"guest","backup"},
    "fe80::1%eth0":  {"root","admin"},
    "2001:db8::cafe":{"john"},
    "192.168.1.20":  {"john"},
}
_DEMO_TAUX: dict[str, float] = {
    "185.220.101.5": 12.0, "10.0.0.55": 6.0,
    "45.83.12.9": 4.0, "192.168.1.10": 2.0,
    "fe80::1%eth0": 5.0,
}
_DEMO_COMPROMISES = {"192.168.1.10"}


def _demo_resultats() -> ResultatAnalyse:
    tries = sorted(_DEMO_ECHECS.items(), key=operator.itemgetter(1), reverse=True)
    return ResultatAnalyse(
        tries=tries,
        cibles=_DEMO_CIBLES,
        taux_max=_DEMO_TAUX,
        compromises=_DEMO_COMPROMISES,
        nb_lignes=248,
    )


# ── Application ───────────────────────────────────────────────────────────────

class SSHBruteHunter(ctk.CTk):

    def __init__(self) -> None:
        super().__init__()
        self.title("SSH Brute-Hunter")
        self.geometry("1220x740")
        self.minsize(980, 640)
        self.configure(fg_color=C_BG)

        self._var_fichier = ctk.StringVar(value=LOG_FILE)
        self._var_seuil   = ctk.IntVar(value=SEUIL_ALERTE)
        self._var_rapport = ctk.StringVar(value=RAPPORT_FILE)
        self._resultats: ResultatAnalyse | None = None
        self._theme       = _THEME_ACTIF
        self._pulse_job: str | None = None
        self._anime_job:  str | None = None

        self._build_ui()
        self._log("Interface initialisée — choisissez un fichier ou lancez le mode démo.")

    # ── Construction ──────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

    def _build_sidebar(self) -> None:
        sb = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=C_SURFACE)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(99, weight=1)

        pal = PALETTES[self._theme]
        r = 0

        # Logo
        ctk.CTkLabel(sb, text="SSH", font=ctk.CTkFont(size=36, weight="bold"),
                     text_color=pal["accent"]).grid(row=r, column=0, padx=24, pady=(30,0), sticky="w")
        r += 1
        ctk.CTkLabel(sb, text="Brute-Hunter",
                     font=ctk.CTkFont(size=14), text_color=C_TEXT2).grid(
                     row=r, column=0, padx=24, pady=(0,2), sticky="w"); r += 1
        ctk.CTkLabel(sb, text="v2.0  ·  Blue Team Analysis Tool",
                     font=ctk.CTkFont(size=9), text_color=C_TEXT3).grid(
                     row=r, column=0, padx=24, pady=(0,20), sticky="w"); r += 1

        self._sep(sb, r); r += 1
        self._section(sb, r, "THÈME"); r += 1

        self._theme_btn = ctk.CTkSegmentedButton(
            sb, values=list(PALETTES.keys()),
            command=self._changer_theme,
            font=ctk.CTkFont(size=11),
            fg_color=C_MUTED,
            selected_color=pal["accent"],
            selected_hover_color=pal["accent2"],
            unselected_color=C_MUTED,
            unselected_hover_color=C_MUTED2,
        )
        self._theme_btn.set(self._theme)
        self._theme_btn.grid(row=r, column=0, padx=20, pady=(0,20), sticky="ew"); r += 1

        self._sep(sb, r); r += 1
        self._section(sb, r, "CONFIGURATION"); r += 1

        # Fichier
        self._label(sb, r, "Fichier de logs"); r += 1
        row_f = ctk.CTkFrame(sb, fg_color="transparent")
        row_f.grid(row=r, column=0, padx=20, pady=(0,14), sticky="ew")
        row_f.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(row_f, textvariable=self._var_fichier,
                     height=32, font=ctk.CTkFont(size=11),
                     fg_color=C_MUTED, border_color=C_BORDER).grid(
                     row=0, column=0, sticky="ew", padx=(0,6))
        ctk.CTkButton(row_f, text="…", width=32, height=32,
                      fg_color=C_MUTED, hover_color=C_MUTED2,
                      command=self._choisir_fichier).grid(row=0, column=1)
        r += 1

        # Seuil
        self._label(sb, r, "Seuil d'alerte"); r += 1
        row_s = ctk.CTkFrame(sb, fg_color="transparent")
        row_s.grid(row=r, column=0, padx=20, pady=(0,2), sticky="ew")
        row_s.grid_columnconfigure(0, weight=1)
        self._lbl_seuil = ctk.CTkLabel(row_s, text=str(SEUIL_ALERTE),
                                        font=ctk.CTkFont(size=26, weight="bold"),
                                        text_color=pal["accent"], width=44)
        self._lbl_seuil.grid(row=0, column=1, padx=(10,0))
        self._slider = ctk.CTkSlider(row_s, from_=1, to=20, number_of_steps=19,
                                      variable=self._var_seuil,
                                      command=self._on_seuil,
                                      button_color=pal["accent"],
                                      button_hover_color=pal["accent2"],
                                      progress_color=pal["accent"])
        self._slider.grid(row=0, column=0, sticky="ew")
        r += 1
        ctk.CTkLabel(sb, text="échecs minimum par IP",
                     font=ctk.CTkFont(size=10), text_color=C_TEXT3).grid(
                     row=r, column=0, padx=20, pady=(0,14), sticky="w"); r += 1

        # Rapport
        self._label(sb, r, "Fichier rapport"); r += 1
        ctk.CTkEntry(sb, textvariable=self._var_rapport,
                     height=32, font=ctk.CTkFont(size=11),
                     fg_color=C_MUTED, border_color=C_BORDER).grid(
                     row=r, column=0, padx=20, pady=(0,20), sticky="ew"); r += 1

        self._sep(sb, r); r += 1
        self._section(sb, r, "ACTIONS"); r += 1

        self._btn_analyser = ctk.CTkButton(
            sb, text="⚡  Analyser", height=44,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=pal["accent"], hover_color=pal["accent2"],
            command=self._lancer_analyse)
        self._btn_analyser.grid(row=r, column=0, padx=20, pady=(0,8), sticky="ew"); r += 1

        ctk.CTkButton(sb, text="◎  Mode démo", height=36,
                      font=ctk.CTkFont(size=12),
                      fg_color=C_MUTED, hover_color=C_MUTED2,
                      command=self._mode_demo).grid(
                      row=r, column=0, padx=20, pady=(0,8), sticky="ew"); r += 1

        self._btn_export = ctk.CTkButton(
            sb, text="↓  Exporter rapport", height=36,
            font=ctk.CTkFont(size=12),
            fg_color=C_MUTED, hover_color=C_MUTED2,
            state="disabled", command=self._exporter_rapport)
        self._btn_export.grid(row=r, column=0, padx=20, pady=(0,8), sticky="ew"); r += 1

        ctk.CTkButton(sb, text="✕  Effacer", height=32,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", hover_color=C_MUTED,
                      border_width=1, border_color=C_BORDER,
                      command=self._effacer).grid(
                      row=r, column=0, padx=20, pady=(0,20), sticky="ew")

        self._sb = sb

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, corner_radius=0, fg_color=C_BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=3)
        main.grid_rowconfigure(4, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(main, height=56, fg_color=C_SURFACE, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hdr, text="Résultats d'analyse",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=C_TEXT).grid(row=0, column=0, padx=20, pady=16, sticky="w")
        self._lbl_stats = ctk.CTkLabel(hdr, text="",
                                        font=ctk.CTkFont(size=12),
                                        text_color=C_TEXT2)
        self._lbl_stats.grid(row=0, column=2, padx=20, pady=16, sticky="e")

        # Barre de progression
        self._progress = ctk.CTkProgressBar(
            main, mode="indeterminate", height=3, corner_radius=0,
            fg_color=C_BORDER, progress_color=PALETTES[self._theme]["accent"])
        self._progress.grid(row=1, column=0, sticky="ew")
        self._progress.set(0)

        # Tableau
        frame_tree = ctk.CTkFrame(main, fg_color=C_BG, corner_radius=0)
        frame_tree.grid(row=2, column=0, sticky="nsew", padx=16, pady=(16,8))
        frame_tree.grid_rowconfigure(0, weight=1)
        frame_tree.grid_columnconfigure(0, weight=1)

        self._appliquer_style_tree()

        cols = ("ip", "echecs", "taux", "statut", "comptes")
        self._tree = ttk.Treeview(frame_tree, columns=cols,
                                   show="headings", style="SSH.Treeview",
                                   selectmode="browse")
        self._tree.heading("ip",      text="Adresse IP",      anchor="w")
        self._tree.heading("echecs",  text="Échecs",           anchor="center")
        self._tree.heading("taux",    text="Max / 60s",        anchor="center")
        self._tree.heading("statut",  text="Statut",           anchor="center")
        self._tree.heading("comptes", text="Comptes ciblés",   anchor="w")
        self._tree.column("ip",      width=165, minwidth=130, anchor="w")
        self._tree.column("echecs",  width=70,  minwidth=55,  anchor="center")
        self._tree.column("taux",    width=90,  minwidth=75,  anchor="center")
        self._tree.column("statut",  width=145, minwidth=110, anchor="center")
        self._tree.column("comptes", width=380, minwidth=180, anchor="w")

        self._tree.tag_configure("ok",        foreground=C_OK)
        self._tree.tag_configure("suspect",   foreground=C_SUSPECT)
        self._tree.tag_configure("eleve",     foreground=C_ELEVE)
        self._tree.tag_configure("critique",  foreground=C_CRITIQUE)
        self._tree.tag_configure("compromis", foreground=C_COMPROM)
        self._tree.tag_configure("nouveau",   background="#1f3a5f")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        scroll = ctk.CTkScrollbar(frame_tree, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # Séparateur
        ctk.CTkFrame(main, height=1, fg_color=C_BORDER).grid(
            row=3, column=0, sticky="ew")

        # Journal
        frame_j = ctk.CTkFrame(main, fg_color=C_BG, corner_radius=0)
        frame_j.grid(row=4, column=0, sticky="nsew", padx=16, pady=(10,14))
        frame_j.grid_rowconfigure(1, weight=1)
        frame_j.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame_j, text="Journal",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=C_TEXT2).grid(row=0, column=0, sticky="w", pady=(0,4))
        self._journal = ctk.CTkTextbox(
            frame_j, height=120, fg_color=C_SURFACE,
            text_color=C_TEXT2, font=("Consolas", 11),
            corner_radius=6, border_width=1, border_color=C_BORDER)
        self._journal.grid(row=1, column=0, sticky="nsew")
        self._journal.configure(state="disabled")

        self._main = main

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=C_BORDER)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        self._dot = ctk.CTkLabel(bar, text="●", text_color=C_OK,
                                  font=ctk.CTkFont(size=9))
        self._dot.grid(row=0, column=0, padx=(12,4))

        self._lbl_status = ctk.CTkLabel(bar, text="Prêt",
                                         font=ctk.CTkFont(size=11), text_color=C_TEXT2)
        self._lbl_status.grid(row=0, column=1, sticky="w")

        self._lbl_detail = ctk.CTkLabel(bar, text="",
                                         font=ctk.CTkFont(size=11), text_color=C_TEXT3)
        self._lbl_detail.grid(row=0, column=2, padx=12, sticky="e")

        ctk.CTkLabel(bar, text="ssh-brute-hunter v2.0",
                     font=ctk.CTkFont(size=10), text_color=C_TEXT3).grid(
                     row=0, column=3, padx=12)

    # ── Helpers UI ────────────────────────────────────────────────────────────

    def _sep(self, p, row: int) -> None:
        ctk.CTkFrame(p, height=1, fg_color=C_BORDER).grid(
            row=row, column=0, sticky="ew", padx=0)

    def _section(self, p, row: int, txt: str) -> None:
        ctk.CTkLabel(p, text=txt, font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=C_TEXT3).grid(row=row, column=0, padx=20, pady=(16,6), sticky="w")

    def _label(self, p, row: int, txt: str) -> None:
        ctk.CTkLabel(p, text=txt, font=ctk.CTkFont(size=12),
                     text_color=C_TEXT).grid(row=row, column=0, padx=20, pady=(0,4), sticky="w")

    def _appliquer_style_tree(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("SSH.Treeview",
                    background=C_SURFACE, foreground=C_TEXT,
                    fieldbackground=C_SURFACE, borderwidth=0,
                    rowheight=38, font=("Consolas", 11))
        s.configure("SSH.Treeview.Heading",
                    background=C_BORDER, foreground=C_TEXT2,
                    borderwidth=0, font=("Consolas", 11, "bold"), relief="flat")
        s.map("SSH.Treeview",
              background=[("selected", "#1f6feb")],
              foreground=[("selected", "#ffffff")])
        s.map("SSH.Treeview.Heading",
              background=[("active", C_MUTED)])

    # ── Thème ─────────────────────────────────────────────────────────────────

    def _changer_theme(self, nom: str) -> None:
        self._theme = nom
        pal = PALETTES[nom]
        self._btn_analyser.configure(fg_color=pal["accent"], hover_color=pal["accent2"])
        self._slider.configure(button_color=pal["accent"],
                               button_hover_color=pal["accent2"],
                               progress_color=pal["accent"])
        self._lbl_seuil.configure(text_color=pal["accent"])
        self._progress.configure(progress_color=pal["accent"])
        self._theme_btn.configure(selected_color=pal["accent"],
                                  selected_hover_color=pal["accent2"])
        # Mise à jour du logo SSH dans la sidebar
        for widget in self._sb.winfo_children():
            if isinstance(widget, ctk.CTkLabel) and widget.cget("text") == "SSH":
                widget.configure(text_color=pal["accent"])
                break
        self._log(f"Thème changé : {nom}")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _on_seuil(self, val: float) -> None:
        self._lbl_seuil.configure(text=str(int(val)))

    def _choisir_fichier(self) -> None:
        chemin = filedialog.askopenfilename(
            title="Choisir un fichier de logs SSH",
            filetypes=[("Fichiers log", "*.log"), ("Tous les fichiers", "*.*")])
        if chemin:
            self._var_fichier.set(chemin)
            self._log(f"Fichier : {chemin}")

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._journal.configure(state="normal")
        self._journal.insert("end", f"[{ts}]  {msg}\n")
        self._journal.see("end")
        self._journal.configure(state="disabled")

    def _set_status(self, texte: str, couleur: str = C_OK, detail: str = "") -> None:
        self._lbl_status.configure(text=texte)
        self._dot.configure(text_color=couleur)
        self._lbl_detail.configure(text=detail)

    def _on_select(self, _event) -> None:
        sel = self._tree.selection()
        if sel:
            v = self._tree.item(sel[0], "values")
            if v:
                self._set_status(f"Sélection : {v[0]}", C_TEXT2,
                                 f"{v[1]} échecs  ·  taux {v[2]}  ·  {v[3]}")

    # ── Animations ────────────────────────────────────────────────────────────

    def _pulse_dot(self, couleur_finale: str, n: int = 6) -> None:
        if self._pulse_job:
            self.after_cancel(self._pulse_job)
        def _step(i: int) -> None:
            if i <= 0:
                self._dot.configure(text_color=couleur_finale)
                return
            c = "#ffffff" if i % 2 == 0 else couleur_finale
            self._dot.configure(text_color=c)
            self._pulse_job = self.after(130, _step, i - 1)
        _step(n)

    def _animer_stats(self, nb_total: int, nb_suspects: int,
                      step: int = 0) -> None:
        if step > nb_total:
            suspects_str = f"  ·  {nb_suspects} suspecte(s)" if nb_suspects else ""
            self._lbl_stats.configure(
                text=f"{nb_total} IP analysées{suspects_str}")
            return
        s = min(step, nb_suspects) if nb_total > 0 else 0
        self._lbl_stats.configure(text=f"{step} IP analysées  ·  {s} suspecte(s)")
        inc = max(1, nb_total // 18)
        self._after_anime = self.after(28, self._animer_stats, nb_total,
                                       nb_suspects, step + inc)

    def _inserer_ligne_anime(self, rows: list, idx: int) -> None:
        if idx >= len(rows):
            self._log(f"Affichage terminé — {len(rows)} IP.")
            return
        ip, nb, statut, taux_s, comptes, tag_final = rows[idx]
        iid = self._tree.insert("", "end",
                                values=(ip, nb, taux_s, statut, comptes),
                                tags=("nouveau",))
        # Flash → couleur finale après 350 ms
        self.after(350, lambda i=iid, t=tag_final: self._tree.item(i, tags=(t,)))
        delay = 55 if len(rows) <= 20 else 20
        self._anime_job = self.after(delay, self._inserer_ligne_anime, rows, idx + 1)

    # ── Analyse ───────────────────────────────────────────────────────────────

    def _lancer_analyse(self) -> None:
        if self._anime_job:
            self.after_cancel(self._anime_job)
        self._btn_analyser.configure(state="disabled", text="Analyse en cours…")
        self._progress.configure(mode="indeterminate")
        self._progress.start()
        self._set_status("Analyse en cours…", C_WARNING)
        self._log(f"Lancement  ·  {self._var_fichier.get()}  ·  seuil {self._var_seuil.get()}")
        threading.Thread(target=self._thread_analyse, daemon=True).start()

    def _thread_analyse(self) -> None:
        try:
            res = analyser_logs(self._var_fichier.get())
            seuil = self._var_seuil.get()
            self.after(0, self._afficher, res, seuil)
        except SystemExit:
            self.after(0, self._log, "Erreur : fichier introuvable ou illisible.")
            self.after(0, self._set_status, "Erreur", C_DANGER)
        finally:
            self.after(0, self._progress.stop)
            self.after(0, self._progress.set, 0)
            self.after(0, lambda: self._btn_analyser.configure(
                state="normal", text="⚡  Analyser"))

    def _afficher(self, res: ResultatAnalyse, seuil: int) -> None:
        for row in self._tree.get_children():
            self._tree.delete(row)

        nb_suspects = sum(1 for ip, nb in res.tries
                          if nb >= seuil or ip in res.compromises)

        rows = []
        for ip, nb in res.tries:
            sev     = "compromis" if ip in res.compromises else _severite(nb, seuil)
            statut  = LABELS_STATUT[sev]
            taux    = res.taux_max.get(ip, 0)
            taux_s  = f"{taux:.0f}/min" if taux else "—"
            comptes = ", ".join(sorted(res.cibles.get(ip, set())))
            rows.append((ip, nb, statut, taux_s, comptes, sev))

        self._inserer_ligne_anime(rows, 0)
        self._animer_stats(len(res.tries), nb_suspects)

        couleur = C_DANGER if nb_suspects > 0 else C_OK
        msg = f"{nb_suspects} IP suspecte(s)"
        if res.compromises:
            msg += f"  ·  {len(res.compromises)} COMPROMIS"
            couleur = C_COMPROM
        self._set_status(msg, couleur, f"{res.nb_lignes} lignes analysées")
        self._pulse_dot(couleur)
        self._resultats = res
        self._btn_export.configure(state="normal")

        if res.compromises:
            self._log(f"COMPROMISSION : {', '.join(sorted(res.compromises))}")

    # ── Mode démo ─────────────────────────────────────────────────────────────

    def _mode_demo(self) -> None:
        self._log("Mode démo — données simulées (8 IP, 1 compromise, IPv6 inclus).")
        res = _demo_resultats()
        self._afficher(res, self._var_seuil.get())

    # ── Export ────────────────────────────────────────────────────────────────

    def _exporter_rapport(self) -> None:
        if not self._resultats:
            return
        chemin = filedialog.asksaveasfilename(
            title="Enregistrer le rapport",
            defaultextension=".txt",
            initialfile=self._var_rapport.get(),
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")])
        if not chemin:
            return
        generer_rapport(self._resultats, self._var_seuil.get(), chemin)
        self._log(f"Rapport → {chemin}")
        self._set_status("Rapport exporté", C_OK, chemin)
        self._pulse_dot(C_OK)

    # ── Effacer ───────────────────────────────────────────────────────────────

    def _effacer(self) -> None:
        if self._anime_job:
            self.after_cancel(self._anime_job)
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._journal.configure(state="normal")
        self._journal.delete("1.0", "end")
        self._journal.configure(state="disabled")
        self._lbl_stats.configure(text="")
        self._btn_export.configure(state="disabled")
        self._resultats = None
        self._set_status("Prêt", PALETTES[self._theme]["dot_ok"])
        self._log("Interface réinitialisée.")


if __name__ == "__main__":
    app = SSHBruteHunter()
    app.mainloop()
