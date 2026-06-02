import signal
import sys
import threading
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk

from analyse_ssh import (
    LOG_FILE,
    RAPPORT_FILE,
    SEUIL_ALERTE,
    _trier,
    analyser_logs,
    generer_rapport,
)

# Restaure le handler par défaut — analyse_ssh l'écrase à l'import
signal.signal(signal.SIGINT, signal.SIG_DFL)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ───────────────────────────────────────────────────────────────────
C_BG        = "#0d1117"
C_SURFACE   = "#161b22"
C_BORDER    = "#21262d"
C_ACCENT    = "#e94560"
C_ACCENT2   = "#c53030"
C_MUTED     = "#2d3748"
C_MUTED2    = "#4a5568"
C_TEXT      = "#e2e8f0"
C_TEXT2     = "#8b949e"
C_TEXT3     = "#484f58"
C_DANGER    = "#ff6b6b"
C_SUCCESS   = "#51cf66"
C_WARNING   = "#f6c90e"

DEMO_ECHECS = {
    "185.220.101.5":  12,
    "10.0.0.55":       7,
    "45.83.12.9":      4,
    "192.168.1.10":    3,
    "203.0.113.42":    2,
    "192.168.1.20":    1,
}
DEMO_CIBLES = {
    "185.220.101.5": {"root","admin","mysql","postgres","oracle","test",
                      "deploy","ubuntu","pi","git","www","ftp"},
    "10.0.0.55":     {"root","ubuntu","pi","admin","user","git","deploy"},
    "45.83.12.9":    {"admin","oracle","postgres","test"},
    "192.168.1.10":  {"admin","root"},
    "203.0.113.42":  {"guest","backup"},
    "192.168.1.20":  {"john"},
}


class SSHBruteHunter(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("SSH Brute-Hunter")
        self.geometry("1180x720")
        self.minsize(960, 620)
        self.configure(fg_color=C_BG)

        self._var_fichier  = ctk.StringVar(value=LOG_FILE)
        self._var_seuil    = ctk.IntVar(value=SEUIL_ALERTE)
        self._var_rapport  = ctk.StringVar(value=RAPPORT_FILE)
        self._resultats: tuple | None = None

        self._build_ui()
        self._log("Interface initialisée — choisissez un fichier ou lancez le mode démo.")

    # ── Construction UI ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

    def _build_sidebar(self) -> None:
        sb = ctk.CTkFrame(self, width=272, corner_radius=0, fg_color=C_SURFACE)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(99, weight=1)

        r = 0

        # Logo
        ctk.CTkLabel(sb, text="SSH", font=ctk.CTkFont(size=34, weight="bold"),
                     text_color=C_ACCENT).grid(row=r, column=0, padx=24, pady=(32, 0), sticky="w")
        r += 1
        ctk.CTkLabel(sb, text="Brute-Hunter", font=ctk.CTkFont(size=13),
                     text_color=C_TEXT2).grid(row=r, column=0, padx=24, pady=(0, 4), sticky="w")
        r += 1
        ctk.CTkLabel(sb, text="v2.0  ·  Blue Team Tool",
                     font=ctk.CTkFont(size=10), text_color=C_TEXT3).grid(
                     row=r, column=0, padx=24, pady=(0, 20), sticky="w")
        r += 1

        self._sep(sb, r); r += 1

        # Section configuration
        self._section(sb, r, "CONFIGURATION"); r += 1

        # Fichier log
        self._label(sb, r, "Fichier de logs"); r += 1
        row_f = ctk.CTkFrame(sb, fg_color="transparent")
        row_f.grid(row=r, column=0, padx=20, pady=(0, 14), sticky="ew")
        row_f.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(row_f, textvariable=self._var_fichier,
                     height=32, font=ctk.CTkFont(size=11),
                     fg_color=C_MUTED, border_color=C_BORDER,
                     placeholder_text="auth.log").grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(row_f, text="…", width=32, height=32,
                      fg_color=C_MUTED, hover_color=C_MUTED2,
                      command=self._choisir_fichier).grid(row=0, column=1)
        r += 1

        # Seuil
        self._label(sb, r, "Seuil d'alerte"); r += 1
        row_s = ctk.CTkFrame(sb, fg_color="transparent")
        row_s.grid(row=r, column=0, padx=20, pady=(0, 2), sticky="ew")
        row_s.grid_columnconfigure(0, weight=1)
        self._lbl_seuil_val = ctk.CTkLabel(row_s, text=str(SEUIL_ALERTE),
                                            font=ctk.CTkFont(size=24, weight="bold"),
                                            text_color=C_ACCENT, width=40)
        self._lbl_seuil_val.grid(row=0, column=1, padx=(10, 0))
        ctk.CTkSlider(row_s, from_=1, to=20, number_of_steps=19,
                      variable=self._var_seuil,
                      command=self._on_seuil,
                      button_color=C_ACCENT,
                      button_hover_color=C_ACCENT2,
                      progress_color=C_ACCENT).grid(row=0, column=0, sticky="ew")
        r += 1
        ctk.CTkLabel(sb, text="échecs minimum par IP",
                     font=ctk.CTkFont(size=10), text_color=C_TEXT3).grid(
                     row=r, column=0, padx=20, pady=(0, 14), sticky="w")
        r += 1

        # Fichier rapport
        self._label(sb, r, "Fichier rapport"); r += 1
        ctk.CTkEntry(sb, textvariable=self._var_rapport,
                     height=32, font=ctk.CTkFont(size=11),
                     fg_color=C_MUTED, border_color=C_BORDER,
                     placeholder_text="rapport_bruteforce.txt").grid(
                     row=r, column=0, padx=20, pady=(0, 20), sticky="ew")
        r += 1

        self._sep(sb, r); r += 1
        self._section(sb, r, "ACTIONS"); r += 1

        # Bouton principal
        self._btn_analyser = ctk.CTkButton(
            sb, text="⚡  Analyser", height=44,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C_ACCENT, hover_color=C_ACCENT2,
            command=self._lancer_analyse)
        self._btn_analyser.grid(row=r, column=0, padx=20, pady=(0, 8), sticky="ew")
        r += 1

        ctk.CTkButton(sb, text="◎  Mode démo", height=36,
                      font=ctk.CTkFont(size=12),
                      fg_color=C_MUTED, hover_color=C_MUTED2,
                      command=self._mode_demo).grid(
                      row=r, column=0, padx=20, pady=(0, 8), sticky="ew")
        r += 1

        self._btn_export = ctk.CTkButton(
            sb, text="↓  Exporter rapport", height=36,
            font=ctk.CTkFont(size=12),
            fg_color=C_MUTED, hover_color=C_MUTED2,
            state="disabled", command=self._exporter_rapport)
        self._btn_export.grid(row=r, column=0, padx=20, pady=(0, 8), sticky="ew")
        r += 1

        ctk.CTkButton(sb, text="✕  Effacer", height=32,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", hover_color=C_MUTED,
                      border_width=1, border_color=C_BORDER,
                      command=self._effacer).grid(
                      row=r, column=0, padx=20, pady=(0, 20), sticky="ew")

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, corner_radius=0, fg_color=C_BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=3)
        main.grid_rowconfigure(4, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Header barre résultats
        hdr = ctk.CTkFrame(main, height=56, fg_color=C_SURFACE, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hdr, text="Résultats d'analyse",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=C_TEXT).grid(row=0, column=0, padx=20, pady=16, sticky="w")
        self._lbl_stats = ctk.CTkLabel(hdr, text="",
                                        font=ctk.CTkFont(size=11),
                                        text_color=C_TEXT2)
        self._lbl_stats.grid(row=0, column=2, padx=20, pady=16, sticky="e")

        # Barre de progression (masquée par défaut)
        self._progress = ctk.CTkProgressBar(main, mode="indeterminate",
                                             height=3, corner_radius=0,
                                             fg_color=C_BORDER,
                                             progress_color=C_ACCENT)
        self._progress.grid(row=1, column=0, sticky="ew")
        self._progress.set(0)

        # Tableau
        frame_tree = ctk.CTkFrame(main, fg_color=C_BG, corner_radius=0)
        frame_tree.grid(row=2, column=0, sticky="nsew", padx=16, pady=(16, 8))
        frame_tree.grid_rowconfigure(0, weight=1)
        frame_tree.grid_columnconfigure(0, weight=1)

        self._appliquer_style_tree()

        cols = ("ip", "echecs", "statut", "comptes")
        self._tree = ttk.Treeview(frame_tree, columns=cols,
                                   show="headings", style="SSH.Treeview",
                                   selectmode="browse")
        self._tree.heading("ip",      text="Adresse IP",     anchor="w")
        self._tree.heading("echecs",  text="Échecs",          anchor="center")
        self._tree.heading("statut",  text="Statut",          anchor="center")
        self._tree.heading("comptes", text="Comptes ciblés",  anchor="w")
        self._tree.column("ip",      width=160, minwidth=130, anchor="w")
        self._tree.column("echecs",  width=80,  minwidth=60,  anchor="center")
        self._tree.column("statut",  width=120, minwidth=100, anchor="center")
        self._tree.column("comptes", width=400, minwidth=200, anchor="w")
        self._tree.tag_configure("suspecte", foreground=C_DANGER)
        self._tree.tag_configure("ok",       foreground=C_SUCCESS)
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
        frame_j.grid(row=4, column=0, sticky="nsew", padx=16, pady=(10, 14))
        frame_j.grid_rowconfigure(1, weight=1)
        frame_j.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame_j, text="Journal",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=C_TEXT2).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self._journal = ctk.CTkTextbox(
            frame_j, height=120, fg_color=C_SURFACE,
            text_color=C_TEXT2, font=("Consolas", 11),
            corner_radius=6, border_width=1, border_color=C_BORDER)
        self._journal.grid(row=1, column=0, sticky="nsew")
        self._journal.configure(state="disabled")

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=C_BORDER)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        self._dot = ctk.CTkLabel(bar, text="●", text_color=C_SUCCESS,
                                  font=ctk.CTkFont(size=9))
        self._dot.grid(row=0, column=0, padx=(12, 4), pady=0)

        self._lbl_status = ctk.CTkLabel(bar, text="Prêt",
                                         font=ctk.CTkFont(size=11),
                                         text_color=C_TEXT2)
        self._lbl_status.grid(row=0, column=1, sticky="w")

        self._lbl_detail = ctk.CTkLabel(bar, text="",
                                         font=ctk.CTkFont(size=11),
                                         text_color=C_TEXT3)
        self._lbl_detail.grid(row=0, column=2, padx=12, sticky="e")

        ctk.CTkLabel(bar, text="ssh-brute-hunter v2.0",
                     font=ctk.CTkFont(size=10),
                     text_color=C_TEXT3).grid(row=0, column=3, padx=12)

    # ── Helpers UI ─────────────────────────────────────────────────────────

    def _sep(self, parent, row: int) -> None:
        ctk.CTkFrame(parent, height=1, fg_color=C_BORDER).grid(
            row=row, column=0, sticky="ew", padx=0, pady=0)

    def _section(self, parent, row: int, texte: str) -> None:
        ctk.CTkLabel(parent, text=texte,
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=C_TEXT3).grid(
                     row=row, column=0, padx=20, pady=(16, 6), sticky="w")

    def _label(self, parent, row: int, texte: str) -> None:
        ctk.CTkLabel(parent, text=texte,
                     font=ctk.CTkFont(size=12), text_color=C_TEXT).grid(
                     row=row, column=0, padx=20, pady=(0, 4), sticky="w")

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

    # ── Callbacks ──────────────────────────────────────────────────────────

    def _on_seuil(self, val: float) -> None:
        self._lbl_seuil_val.configure(text=str(int(val)))

    def _choisir_fichier(self) -> None:
        chemin = filedialog.askopenfilename(
            title="Choisir un fichier de logs SSH",
            filetypes=[("Fichiers log", "*.log"), ("Tous les fichiers", "*.*")])
        if chemin:
            self._var_fichier.set(chemin)
            self._log(f"Fichier sélectionné : {chemin}")

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._journal.configure(state="normal")
        self._journal.insert("end", f"[{ts}]  {msg}\n")
        self._journal.see("end")
        self._journal.configure(state="disabled")

    def _set_status(self, texte: str, couleur: str = C_SUCCESS,
                    detail: str = "") -> None:
        self._lbl_status.configure(text=texte)
        self._dot.configure(text_color=couleur)
        self._lbl_detail.configure(text=detail)

    def _on_select(self, _event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if vals:
            self._set_status(f"Sélection : {vals[0]}", C_TEXT2,
                             f"{vals[1]} échec(s)  ·  {vals[2]}")

    # ── Analyse ────────────────────────────────────────────────────────────

    def _lancer_analyse(self) -> None:
        self._btn_analyser.configure(state="disabled", text="Analyse en cours…")
        self._progress.configure(mode="indeterminate")
        self._progress.start()
        self._set_status("Analyse en cours…", C_WARNING)
        self._log(f"Lancement analyse  ·  fichier : {self._var_fichier.get()}  ·  seuil : {self._var_seuil.get()}")
        threading.Thread(target=self._thread_analyse, daemon=True).start()

    def _thread_analyse(self) -> None:
        try:
            echecs, cibles = analyser_logs(self._var_fichier.get())
            seuil = self._var_seuil.get()
            self.after(0, self._afficher, echecs, cibles, seuil)
        except SystemExit:
            self.after(0, self._log, "Erreur : fichier introuvable ou illisible.")
            self.after(0, self._set_status, "Erreur", C_DANGER)
        finally:
            self.after(0, self._progress.stop)
            self.after(0, self._progress.set, 0)
            self.after(0, lambda: self._btn_analyser.configure(
                state="normal", text="⚡  Analyser"))

    def _afficher(self, echecs: dict[str, int],
                  cibles: dict[str, set[str]], seuil: int) -> None:
        for row in self._tree.get_children():
            self._tree.delete(row)

        tries = _trier(echecs)
        nb_suspects = sum(1 for _, nb in tries if nb >= seuil)

        for ip, nb in tries:
            statut = "⚠  SUSPECTE" if nb >= seuil else "✓  OK"
            tag    = "suspecte"    if nb >= seuil else "ok"
            comptes = ", ".join(sorted(cibles.get(ip, set())))
            self._tree.insert("", "end",
                              values=(ip, nb, statut, comptes), tags=(tag,))

        total = len(tries)
        self._lbl_stats.configure(
            text=f"{total} IP  ·  {nb_suspects} suspecte(s)  ·  seuil : {seuil}")
        self._log(f"Terminé — {total} IP analysées, {nb_suspects} suspecte(s).")
        couleur = C_DANGER if nb_suspects > 0 else C_SUCCESS
        self._set_status(f"{nb_suspects} IP suspecte(s) détectée(s)", couleur,
                         f"{total} IP analysées")
        self._resultats = (echecs, cibles, seuil)
        self._btn_export.configure(state="normal")

    # ── Mode démo ──────────────────────────────────────────────────────────

    def _mode_demo(self) -> None:
        self._log("Mode démo activé — données simulées (6 IP, dont 3 suspectes).")
        self._afficher(DEMO_ECHECS, DEMO_CIBLES, self._var_seuil.get())

    # ── Export ─────────────────────────────────────────────────────────────

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
        echecs, cibles, seuil = self._resultats
        generer_rapport(echecs, cibles, seuil, chemin)
        self._log(f"Rapport exporté → {chemin}")
        self._set_status("Rapport exporté", C_SUCCESS, chemin)

    # ── Effacer ────────────────────────────────────────────────────────────

    def _effacer(self) -> None:
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._journal.configure(state="normal")
        self._journal.delete("1.0", "end")
        self._journal.configure(state="disabled")
        self._lbl_stats.configure(text="")
        self._btn_export.configure(state="disabled")
        self._resultats = None
        self._set_status("Prêt", C_SUCCESS)
        self._log("Interface réinitialisée.")


if __name__ == "__main__":
    app = SSHBruteHunter()
    app.mainloop()
