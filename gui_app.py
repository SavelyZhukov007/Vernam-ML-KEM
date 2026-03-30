import sys
import os
import base64
import threading
import time
import struct
import secrets
import json

sys.path.insert(0, os.path.dirname(__file__))
from core.crypto_engine import (
    encrypt,
    decrypt,
    pack_binary,
    unpack_binary,
    make_reversible_pair,
    EncryptionLevel,
    detect_encoding,
)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


COLORS = {
    "bg": "#050a0e",
    "bg2": "#0a1118",
    "bg3": "#0f1923",
    "alice": "#00ff88",
    "alice_dim": "#006633",
    "border": "#1a2d20",
    "text": "#c8e8d0",
    "text_dim": "#4a7a5a",
    "warn": "#ffaa00",
    "error": "#ff4466",
    "bob": "#4488ff",
}


def hex_color(c):
    return c


class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ML-KEM Crypto System — Zhukov Savely 2ИСИП-724")
        self.geometry("1400x900")
        self.configure(bg=COLORS["bg"])
        self.resizable(True, True)

        self.current_level = tk.IntVar(value=4)
        self.input_mode = tk.StringVar(value="text")
        self.hkdf_info = tk.StringVar(value="hybrid-otp-derivation-2026")
        self.n_tamper = tk.IntVar(value=5)
        self.file_data = None
        self.file_name = None
        self.encrypt_result = None
        self.packed_bytes = None
        self.correct_bytes = None
        self.tampered_bytes = None
        self.per_byte_log = []

        self._build_ui()
        self._setup_styles()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=COLORS["bg2"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=COLORS["bg2"],
            foreground=COLORS["text_dim"],
            padding=[12, 6],
            font=("Courier", 9),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["bg3"])],
            foreground=[("selected", COLORS["alice"])],
        )
        style.configure("TFrame", background=COLORS["bg"])
        style.configure(
            "TLabelframe",
            background=COLORS["bg2"],
            foreground=COLORS["alice"],
            bordercolor=COLORS["border"],
        )
        style.configure(
            "TLabelframe.Label",
            background=COLORS["bg2"],
            foreground=COLORS["alice"],
            font=("Courier", 9, "bold"),
        )
        style.configure(
            "Vertical.TScrollbar",
            background=COLORS["bg2"],
            troughcolor=COLORS["bg3"],
            borderwidth=0,
        )

    def _build_ui(self):
        self._build_header()
        paned = tk.PanedWindow(
            self, orient=tk.HORIZONTAL, bg=COLORS["bg"], sashwidth=4, sashrelief=tk.FLAT
        )
        paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        left = self._build_left_panel(paned)
        center = self._build_center_panel(paned)
        right = self._build_right_panel(paned)

        paned.add(left, minsize=340)
        paned.add(center, minsize=500)
        paned.add(right, minsize=320)
        paned.paneconfig(left, width=360)
        paned.paneconfig(right, width=340)

    def _build_header(self):
        hdr = tk.Frame(self, bg=COLORS["bg2"], height=50)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        tk.Label(
            hdr,
            text="  ML-KEM CRYPTO SYSTEM",
            font=("Courier", 14, "bold"),
            bg=COLORS["bg2"],
            fg=COLORS["alice"],
        ).pack(side=tk.LEFT, padx=16, pady=10)

        tk.Label(
            hdr,
            text="Zhukov Savely · 2ИСИП-724",
            font=("Courier", 9),
            bg=COLORS["bg2"],
            fg=COLORS["text_dim"],
        ).pack(side=tk.RIGHT, padx=16)

        self.status_label = tk.Label(
            hdr,
            text="● READY",
            font=("Courier", 9),
            bg=COLORS["bg2"],
            fg=COLORS["alice"],
        )
        self.status_label.pack(side=tk.RIGHT, padx=8)

    def _lf(self, parent, text, **kw):
        f = ttk.LabelFrame(parent, text=text, **kw)
        f.configure(style="TLabelframe")
        return f

    def _label(self, parent, text, color=None, font=None):
        return tk.Label(
            parent,
            text=text,
            bg=COLORS["bg2"],
            fg=color or COLORS["text_dim"],
            font=font or ("Courier", 9),
        )

    def _entry(self, parent, textvariable=None, **kw):
        e = tk.Entry(
            parent,
            bg=COLORS["bg3"],
            fg=COLORS["alice"],
            insertbackground=COLORS["alice"],
            relief=tk.FLAT,
            font=("Courier", 10),
            textvariable=textvariable,
            **kw,
        )
        e.configure(
            highlightthickness=1,
            highlightcolor=COLORS["alice_dim"],
            highlightbackground=COLORS["border"],
        )
        return e

    def _btn(self, parent, text, cmd, color=None, **kw):
        c = color or COLORS["alice"]
        b = tk.Button(
            parent,
            text=text,
            command=cmd,
            bg=COLORS["bg3"],
            fg=c,
            activebackground=COLORS["bg2"],
            activeforeground=c,
            relief=tk.FLAT,
            font=("Courier", 9, "bold"),
            cursor="hand2",
            **kw,
        )
        b.configure(
            highlightthickness=1, highlightcolor=c, highlightbackground=COLORS["border"]
        )
        return b

    def _text_area(self, parent, height=8, **kw):
        t = scrolledtext.ScrolledText(
            parent,
            bg=COLORS["bg3"],
            fg=COLORS["alice"],
            insertbackground=COLORS["alice"],
            font=("Courier", 9),
            relief=tk.FLAT,
            height=height,
            **kw,
        )
        t.configure(
            highlightthickness=1,
            highlightcolor=COLORS["alice_dim"],
            highlightbackground=COLORS["border"],
        )
        return t

    def _build_left_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg2"])

        # Input section
        inp_lf = self._lf(frame, " ВВОД ДАННЫХ ")
        inp_lf.pack(fill=tk.X, padx=6, pady=6)

        # Mode
        mode_frame = tk.Frame(inp_lf, bg=COLORS["bg2"])
        mode_frame.pack(fill=tk.X, padx=6, pady=4)
        tk.Radiobutton(
            mode_frame,
            text="ТЕКСТ",
            variable=self.input_mode,
            value="text",
            bg=COLORS["bg2"],
            fg=COLORS["text_dim"],
            selectcolor=COLORS["bg3"],
            activebackground=COLORS["bg2"],
            activeforeground=COLORS["alice"],
            font=("Courier", 9),
            command=self._toggle_input_mode,
        ).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(
            mode_frame,
            text="ФАЙЛ",
            variable=self.input_mode,
            value="file",
            bg=COLORS["bg2"],
            fg=COLORS["text_dim"],
            selectcolor=COLORS["bg3"],
            activebackground=COLORS["bg2"],
            activeforeground=COLORS["alice"],
            font=("Courier", 9),
            command=self._toggle_input_mode,
        ).pack(side=tk.LEFT, padx=4)

        self.text_input = self._text_area(inp_lf, height=7)
        self.text_input.pack(fill=tk.X, padx=6, pady=4)
        self.text_input.insert(tk.END, "Введите сообщение для шифрования...")

        self.file_frame = tk.Frame(inp_lf, bg=COLORS["bg2"])
        self.file_info_label = self._label(
            self.file_frame, "Файл не выбран", color=COLORS["text_dim"]
        )
        self.file_info_label.pack(fill=tk.X, padx=6, pady=2)
        self._btn(self.file_frame, "📁 ВЫБРАТЬ ФАЙЛ", self._choose_file).pack(
            fill=tk.X, padx=6, pady=2
        )

        # Level selector
        lvl_lf = self._lf(frame, " УРОВЕНЬ ШИФРОВАНИЯ ")
        lvl_lf.pack(fill=tk.X, padx=6, pady=4)

        levels = [
            (1, "L1 · Предпросмотр (100 символов)", False),
            (2, "L2 · Verbose (все переменные, пошагово)", False),
            (3, "L3 · Reversible (2 файла + N байт)", False),
            (4, "L4 · ML-KEM FULL (постквантовый) ★", True),
        ]
        for lvl, txt, ideal in levels:
            f = tk.Frame(lvl_lf, bg=COLORS["bg2"])
            f.pack(fill=tk.X, padx=6, pady=1)
            rb = tk.Radiobutton(
                f,
                text=txt,
                variable=self.current_level,
                value=lvl,
                bg=COLORS["bg2"],
                fg=COLORS["alice"] if ideal else COLORS["text"],
                selectcolor=COLORS["bg3"],
                activebackground=COLORS["bg2"],
                activeforeground=COLORS["alice"],
                font=("Courier", 9, "bold" if ideal else "normal"),
                command=self._on_level_change,
            )
            rb.pack(side=tk.LEFT)
            if ideal:
                tk.Label(
                    f,
                    text=" [IDEAL]",
                    bg=COLORS["bg2"],
                    fg=COLORS["alice"],
                    font=("Courier", 8, "bold"),
                ).pack(side=tk.LEFT)

        # Settings
        cfg_lf = self._lf(frame, " НАСТРОЙКИ ")
        cfg_lf.pack(fill=tk.X, padx=6, pady=4)

        self._label(cfg_lf, "HKDF INFO:").pack(anchor=tk.W, padx=6, pady=(4, 0))
        self._entry(cfg_lf, textvariable=self.hkdf_info).pack(fill=tk.X, padx=6, pady=2)

        self.tamper_frame = tk.Frame(cfg_lf, bg=COLORS["bg2"])
        self._label(self.tamper_frame, "N изменённых байт (L3):").pack(
            anchor=tk.W, padx=6, pady=(4, 0)
        )
        self._entry(self.tamper_frame, textvariable=self.n_tamper, width=10).pack(
            anchor=tk.W, padx=6, pady=2
        )

        # Buttons
        btn_lf = tk.Frame(frame, bg=COLORS["bg2"])
        btn_lf.pack(fill=tk.X, padx=6, pady=6)

        self._btn(
            btn_lf, "⚡ ЗАШИФРОВАТЬ", self._do_encrypt, color=COLORS["alice"]
        ).pack(fill=tk.X, padx=4, pady=2)

        self.decrypt_btn = self._btn(
            btn_lf,
            "🔓 РАСШИФРОВАТЬ ИЗ ФАЙЛА",
            self._do_decrypt_file,
            color=COLORS["bob"],
        )
        self.decrypt_btn.pack(fill=tk.X, padx=4, pady=2)

        self.download_btn = self._btn(
            btn_lf,
            "⬇ СКАЧАТЬ ЗАШИФРОВАННЫЙ .BIN",
            self._save_encrypted,
            color=COLORS["warn"],
        )
        self.download_btn.pack(fill=tk.X, padx=4, pady=2)
        self.download_btn.configure(state=tk.DISABLED)

        self.download_rev_btn = self._btn(
            btn_lf,
            "⬇ СКАЧАТЬ REVERSIBLE ПАРУ",
            self._save_reversible,
            color=COLORS["warn"],
        )
        self.download_rev_btn.pack(fill=tk.X, padx=4, pady=2)
        self.download_rev_btn.configure(state=tk.DISABLED)

        return frame

    def _build_center_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg"])
        nb = ttk.Notebook(frame)
        nb.pack(fill=tk.BOTH, expand=True)
        self.nb = nb

        # Tab 1: Steps
        self.steps_tab = tk.Frame(nb, bg=COLORS["bg2"])
        nb.add(self.steps_tab, text=" ШАГИ АЛГОРИТМА ")
        self.steps_text = self._text_area(self.steps_tab, height=40)
        self.steps_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.steps_text.configure(state=tk.DISABLED)

        # Tab 2: Byte log
        self.bytelog_tab = tk.Frame(nb, bg=COLORS["bg2"])
        nb.add(self.bytelog_tab, text=" ПОБАЙТОВЫЙ XOR ")
        self._build_bytelog_tab()

        # Tab 3: Result
        self.result_tab = tk.Frame(nb, bg=COLORS["bg2"])
        nb.add(self.result_tab, text=" РЕЗУЛЬТАТ ")
        self.result_text = self._text_area(self.result_tab, height=40)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.result_text.configure(state=tk.DISABLED)

        # Tab 4: Decrypt
        self.decrypt_tab = tk.Frame(nb, bg=COLORS["bg2"])
        nb.add(self.decrypt_tab, text=" РАСШИФРОВКА ")
        self.decrypt_text = self._text_area(self.decrypt_tab, height=40)
        self.decrypt_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.decrypt_text.configure(state=tk.DISABLED)

        return frame

    def _build_bytelog_tab(self):
        columns = (
            "idx",
            "p_dec",
            "p_bin",
            "p_char",
            "k_dec",
            "c_dec",
            "c_bin",
            "c_char",
        )
        headers = (
            "#",
            "P(дек)",
            "P(bin)",
            "P(chr)",
            "K(дек)",
            "C(дек)",
            "C(bin)",
            "C(chr)",
        )

        frame = tk.Frame(self.bytelog_tab, bg=COLORS["bg2"])
        frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self._label(
            frame,
            "Побайтовое шифрование: P XOR K = C   (первые 500 байт)",
            color=COLORS["alice"],
        ).pack(anchor=tk.W, pady=4)

        tree_frame = tk.Frame(frame, bg=COLORS["bg2"])
        tree_frame.pack(fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, style="Vertical.TScrollbar")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.byte_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        self.byte_tree.pack(fill=tk.BOTH, expand=True)
        vsb.config(command=self.byte_tree.yview)
        hsb.config(command=self.byte_tree.xview)

        widths = [45, 60, 90, 50, 60, 60, 90, 50]
        for col, hdr, w in zip(columns, headers, widths):
            self.byte_tree.heading(col, text=hdr)
            self.byte_tree.column(col, width=w, anchor=tk.CENTER)

        style = ttk.Style()
        style.configure(
            "Treeview",
            background=COLORS["bg3"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["bg3"],
            font=("Courier", 9),
            rowheight=20,
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["bg2"],
            foreground=COLORS["alice"],
            font=("Courier", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", COLORS["bg2"])])

    def _build_right_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg2"])

        # ML-KEM info
        info_lf = self._lf(frame, " ML-KEM ДАННЫЕ ")
        info_lf.pack(fill=tk.X, padx=6, pady=6)

        self.mlkem_info = self._text_area(info_lf, height=10)
        self.mlkem_info.pack(fill=tk.X, padx=4, pady=4)
        self.mlkem_info.configure(state=tk.DISABLED)
        self._write_ta(
            self.mlkem_info,
            "Зашифруйте данные для просмотра\ncриптографических параметров...\n",
        )

        # Preview
        prev_lf = self._lf(frame, " ПРЕДПРОСМОТР (100 символов) ")
        prev_lf.pack(fill=tk.X, padx=6, pady=4)
        self.preview_text = self._text_area(prev_lf, height=4)
        self.preview_text.pack(fill=tk.X, padx=4, pady=4)
        self.preview_text.configure(state=tk.DISABLED)

        # Reversible info
        self.rev_lf = self._lf(frame, " REVERSIBLE (L3) ")
        self.rev_lf.pack(fill=tk.X, padx=6, pady=4)
        self.rev_info = self._text_area(self.rev_lf, height=5)
        self.rev_info.pack(fill=tk.X, padx=4, pady=4)
        self.rev_info.configure(state=tk.DISABLED)
        self._write_ta(
            self.rev_info,
            "Выберите уровень L3 и зашифруйте\nдля создания reversible пары файлов.",
        )

        # Algorithm explanation
        algo_lf = self._lf(frame, " АЛГОРИТМ ")
        algo_lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        algo_text = self._text_area(algo_lf, height=8)
        algo_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        algo_text.configure(state=tk.NORMAL)
        algo_text.insert(
            tk.END,
            """ML-KEM (Kyber-768):
━━━━━━━━━━━━━━━━━━━
Постквантовый KEM на
основе Module-LWE.

NIST PQC стандарт 2024.
Стойкость: 128-bit PQ.

keygen() → (pk, sk)
encaps(pk) → (ct, ss)
decaps(sk, ct) → ss

HKDF (RFC 5869):
━━━━━━━━━━━━━━━
Extract(salt, IKM) → PRK
Expand(PRK, L, info) → OKM

OTP (Шифр Вернама):
━━━━━━━━━━━━━━━━━━
C[i] = P[i] XOR K[i]
Абсолютная стойкость при
однократном ключе.

HMAC-SHA256:
━━━━━━━━━━━
MAC = H(K || H(K || M))
Аутентификация данных.
""",
        )
        algo_text.configure(state=tk.DISABLED)

        return frame

    def _toggle_input_mode(self):
        mode = self.input_mode.get()
        if mode == "text":
            self.file_frame.pack_forget()
            self.text_input.pack(fill=tk.X, padx=6, pady=4)
        else:
            self.text_input.pack_forget()
            self.file_frame.pack(fill=tk.X, padx=6, pady=4)

    def _on_level_change(self):
        lvl = self.current_level.get()
        if lvl == 3:
            self.tamper_frame.pack(fill=tk.X, padx=6, pady=2)
        else:
            self.tamper_frame.pack_forget()

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Выберите файл для шифрования")
        if not path:
            return
        with open(path, "rb") as f:
            self.file_data = f.read()
        self.file_name = os.path.basename(path)
        self.file_info_label.configure(
            text=f"📎 {self.file_name} ({len(self.file_data)/1024:.1f} KB)",
            fg=COLORS["alice"],
        )

    def _write_ta(self, widget, text, clear=True):
        widget.configure(state=tk.NORMAL)
        if clear:
            widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)

    def _set_status(self, text, color=None):
        self.status_label.configure(text=text, fg=color or COLORS["alice"])
        self.update_idletasks()

    def _do_encrypt(self):
        threading.Thread(target=self._encrypt_thread, daemon=True).start()

    def _encrypt_thread(self):
        try:
            self._set_status("● ШИФРОВАНИЕ...", COLORS["warn"])
            self.download_btn.configure(state=tk.DISABLED)
            self.download_rev_btn.configure(state=tk.DISABLED)

            level = EncryptionLevel(self.current_level.get())

            if self.input_mode.get() == "text":
                text = self.text_input.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showerror("Ошибка", "Введите текст")
                    return
                data = text.encode("utf-8")
                fname = None
            else:
                if not self.file_data:
                    messagebox.showerror("Ошибка", "Выберите файл")
                    return
                data = self.file_data
                fname = self.file_name

            info_bytes = self.hkdf_info.get().encode()
            result = encrypt(data, level, file_name=fname, custom_info=info_bytes)
            self.encrypt_result = result

            import secrets as sec

            salt_bytes = sec.token_bytes(32)
            nonce_bytes = bytes.fromhex(result.nonce)
            self.packed_bytes = pack_binary(result, salt_bytes, nonce_bytes)

            self._render_steps(result)
            self._render_result(result)
            self._render_mlkem_info(result)
            self._render_bytelog(result)
            self._render_preview(result)

            if level == EncryptionLevel.REVERSIBLE:
                n = self.n_tamper.get()
                pair = make_reversible_pair(result, n)
                self.correct_bytes = pair.correct_file
                self.tampered_bytes = pair.tampered_file
                self._render_reversible(pair)
                self.download_rev_btn.configure(state=tk.NORMAL)

            self.download_btn.configure(state=tk.NORMAL)
            self._set_status("● ГОТОВО", COLORS["alice"])

        except Exception as e:
            import traceback

            self._set_status("● ОШИБКА", COLORS["error"])
            messagebox.showerror(
                "Ошибка шифрования", f"{e}\n\n{traceback.format_exc()}"
            )

    def _render_steps(self, result):
        out = []
        out.append("=" * 72)
        out.append(f"  ML-KEM + OTP ГИБРИДНОЕ ШИФРОВАНИЕ  |  Уровень: L{result.level}")
        out.append("=" * 72)
        out.append("")

        for step in result.steps:
            out.append(f"┌─ ШАГ {step.step_num:02d}: {step.title}")
            out.append(f"│  {step.description}")
            if step.explanation:
                for line in step.explanation.split("\n"):
                    out.append(f"│  {line}")
            if step.variables:
                out.append("│")
                out.append("│  ПЕРЕМЕННЫЕ:")
                for k, v in step.variables.items():
                    val = str(v)
                    if len(val) > 80:
                        val = val[:80] + "..."
                    out.append(f"│  {k:<30} = {val}")
            if step.hex_data:
                out.append("│")
                out.append("│  HEX ДАННЫЕ:")
                hex_str = step.hex_data[:160]
                for i in range(0, len(hex_str), 64):
                    out.append(f"│  {hex_str[i:i+64]}")
            out.append("└" + "─" * 71)
            out.append("")

        self._write_ta(self.steps_text, "\n".join(out))
        self.nb.select(0)

    def _render_bytelog(self, result):
        for item in self.byte_tree.get_children():
            self.byte_tree.delete(item)

        logs = result.per_byte_log[:500]
        if not logs:
            if result.level < 2:
                self.byte_tree.insert(
                    "",
                    tk.END,
                    values=(
                        "—",
                        "—",
                        "—",
                        "—",
                        "—",
                        "—",
                        "—",
                        "L2+ для побайтового лога",
                    ),
                )
            return

        for b in logs:
            self.byte_tree.insert(
                "",
                tk.END,
                values=(
                    b["idx"],
                    b["p_dec"],
                    b["p_bin"],
                    b["p_char"],
                    b["k_dec"],
                    b["c_dec"],
                    b["c_bin"],
                    b["c_char"],
                ),
            )

    def _render_result(self, result):
        out = []
        out.append("╔" + "═" * 70 + "╗")
        out.append("║  РЕЗУЛЬТАТ ШИФРОВАНИЯ" + " " * 48 + "║")
        out.append("╚" + "═" * 70 + "╝")
        out.append("")
        out.append(f"Уровень:         L{result.level}")
        out.append(f"Входных байт:    {len(result.plaintext)}")
        out.append(f"Шифртекст байт:  {len(result.ciphertext)}")
        out.append(f'Кодировка:       {result.encoding or "binary"}')
        out.append(
            f'Время:           {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.timestamp))}'
        )
        out.append("")
        out.append("ПРЕДПРОСМОТР (100 символов):")
        out.append("─" * 72)
        out.append(
            result.preview_100 or "(нет — бинарный файл или неподдерживаемая кодировка)"
        )
        out.append("")
        out.append("ШИФРТЕКСТ (HEX, первые 128 байт):")
        out.append("─" * 72)
        hex_str = result.ciphertext_hex[:256]
        for i in range(0, len(hex_str), 64):
            out.append(hex_str[i : i + 64])
        out.append("")
        out.append("ШИФРТЕКСТ (BASE64, первые 80 символов):")
        out.append("─" * 72)
        out.append(result.ciphertext_b64[:80] + "...")
        out.append("")
        out.append("MAC (HMAC-SHA256):")
        out.append("─" * 72)
        out.append(result.mac or "—")
        out.append("")
        out.append("NONCE:")
        out.append(result.nonce or "—")
        self._write_ta(self.result_text, "\n".join(out))

    def _render_mlkem_info(self, result):
        out = []
        out.append("ML-KEM КРИПТОГРАФИЧЕСКИЕ ДАННЫЕ")
        out.append("─" * 40)
        out.append(f"Shared Secret:")
        out.append(result.shared_secret.hex()[:64] + "...")
        out.append("")
        out.append(f"OTP Ключ (первые 32 байта):")
        out.append(result.otp_key_hex[:64] + "...")
        out.append("")
        out.append(f"Public Key (первые 32 байта):")
        out.append(result.mlkem_public_key.hex()[:64] + "...")
        out.append("")
        out.append(f"KEM Шифртекст (первые 32 байта):")
        out.append(result.mlkem_encapsulated.hex()[:64] + "...")
        out.append("")
        out.append(f"PK длина:  {len(result.mlkem_public_key)} байт")
        out.append(f"SK длина:  {len(result.mlkem_secret_key)} байт")
        out.append(f"CT длина:  {len(result.mlkem_encapsulated)} байт")
        out.append(f"SS длина:  {len(result.shared_secret)} байт")
        self._write_ta(self.mlkem_info, "\n".join(out))

    def _render_preview(self, result):
        preview = result.preview_100 or "(нет текстового превью)"
        self._write_ta(self.preview_text, preview)

    def _render_reversible(self, pair):
        out = []
        out.append(f"N изменённых байт: {pair.n_tampered}")
        out.append(f"Позиции: {pair.tampered_positions[:15]}...")
        out.append("")
        out.append("correct_encrypted.bin  — оригинал")
        out.append("tampered_encrypted.bin — с изменениями")
        out.append("")
        out.append("При расшифровке tampered-файла MAC")
        out.append("не совпадёт → обнаружена атака.")
        self._write_ta(self.rev_info, "\n".join(out))

    def _do_decrypt_file(self):
        path = filedialog.askopenfilename(
            title="Выберите зашифрованный .bin файл",
            filetypes=[("Binary", "*.bin"), ("All", "*.*")],
        )
        if not path:
            return
        threading.Thread(target=self._decrypt_thread, args=(path,), daemon=True).start()

    def _decrypt_thread(self, path):
        try:
            self._set_status("● РАСШИФРОВКА...", COLORS["warn"])
            with open(path, "rb") as f:
                data = f.read()

            result = unpack_binary(data)

            out = []
            out.append("╔" + "═" * 70 + "╗")
            out.append("║  РЕЗУЛЬТАТ РАСШИФРОВКИ" + " " * 47 + "║")
            out.append("╚" + "═" * 70 + "╝")
            out.append("")
            out.append(f"Файл:            {os.path.basename(path)}")
            out.append(f'Уровень:         L{result["level"]}')
            out.append(
                f'Timestamp:       {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result["timestamp"]))}'
            )
            out.append("")
            out.append("РАСШИФРОВАННЫЕ ДАННЫЕ:")
            out.append("─" * 72)

            plaintext = result["plaintext"]
            enc = detect_encoding(plaintext)
            if enc:
                try:
                    text = plaintext.decode(enc)
                    out.append(f"Кодировка: {enc}")
                    out.append("")
                    out.append(text[:2000])
                    if len(text) > 2000:
                        out.append(f"\n... (ещё {len(text)-2000} символов)")
                except Exception:
                    pass
            else:
                out.append("(Бинарный файл — HEX дамп)")
                hex_dump = result["plaintext_hex"][:512]
                for i in range(0, len(hex_dump), 64):
                    out.append(hex_dump[i : i + 64])

            out.append("")
            out.append("КРИПТОГРАФИЧЕСКИЕ ДАННЫЕ:")
            out.append("─" * 72)
            out.append(f'Shared Secret:   {result["shared_secret"][:64]}...')
            out.append(f'OTP Key:         {result["otp_key"][:64]}...')
            out.append(f'Salt:            {result["salt"][:64]}...')
            out.append(f'Nonce:           {result["nonce"]}')
            out.append(f'MAC:             {result["mac"]}')

            self._write_ta(self.decrypt_text, "\n".join(out))
            self.nb.select(3)
            self._set_status("● РАСШИФРОВАНО", COLORS["alice"])

            # Offer save
            save = messagebox.askyesno("Сохранить?", "Сохранить расшифрованные данные?")
            if save:
                ext = "txt" if enc else "bin"
                out_path = filedialog.asksaveasfilename(
                    defaultextension=f".{ext}", initialfile=f"decrypted.{ext}"
                )
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(plaintext)
                    messagebox.showinfo("Сохранено", f"Файл сохранён: {out_path}")

        except Exception as e:
            import traceback

            self._set_status("● ОШИБКА", COLORS["error"])
            messagebox.showerror(
                "Ошибка расшифровки", f"{e}\n\n{traceback.format_exc()[:800]}"
            )

    def _save_encrypted(self):
        if not self.packed_bytes:
            messagebox.showerror("Ошибка", "Сначала зашифруйте данные")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            initialfile="encrypted.bin",
            filetypes=[("Binary", "*.bin"), ("All", "*.*")],
        )
        if path:
            with open(path, "wb") as f:
                f.write(self.packed_bytes)
            messagebox.showinfo("Сохранено", f"Зашифрованный файл сохранён:\n{path}")

    def _save_reversible(self):
        if not self.correct_bytes or not self.tampered_bytes:
            messagebox.showerror("Ошибка", "Сначала зашифруйте на уровне L3")
            return
        folder = filedialog.askdirectory(title="Выберите папку для сохранения")
        if not folder:
            return
        cp = os.path.join(folder, "correct_encrypted.bin")
        tp = os.path.join(folder, "tampered_encrypted.bin")
        with open(cp, "wb") as f:
            f.write(self.correct_bytes)
        with open(tp, "wb") as f:
            f.write(self.tampered_bytes)
        messagebox.showinfo("Сохранено", f"Сохранены два файла:\n{cp}\n{tp}")


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
