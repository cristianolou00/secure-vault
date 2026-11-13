"""
Aplicação Gráfica Completa - SecureVault (app.py)

Gestor Profissional de Credenciais e Ficheiros Criptografados
Funcionalidades Comerciais:
1. Gestão de Credenciais (Logins, Chaves, Cartões, Notas)
2. Ficheiros Seguros (Encriptação e armazenamento de ficheiros/PDFs/imagens)
3. Auditoria de Segurança:
   - Detetor de senhas fracas e repetidas
   - Verificação de senhas vazadas na internet com k-Anonymity (HaveIBeenPwned)
   - Health Score dinâmico (0 a 100%)
4. Bloqueio Automático por Inatividade (Auto-Lock configurável)
5. Gerador Criptográfico com cálculo de entropia
6. Definições: Mudança de Senha Mestre, Exportação/Importação CSV e Backups
"""

import os
import sys
import time
import threading
import webbrowser
from typing import Optional, Dict, Any, List, Tuple

import customtkinter as ctk
from tkinter import messagebox, filedialog

from vault.storage import VaultStorage
from vault.crypto import DecryptionError, SecurityError
from vault.models import VaultEntry
from vault.generator import generate_password, calculate_entropy
from vault.audit import audit_vault, AuditReport
from vault.file_crypto import VaultFileAttachment, format_file_size
from vault.backup import export_entries_to_csv, import_entries_from_csv, change_master_password
from vault.pwned import check_password_leak

# Configuração visual do CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

DEFAULT_FILEPATH = "meu_cofre.vault"
ICON_PATH = "assets/icon.ico"


class EntryDialog(ctk.CTkToplevel):
    """Janela modal para Adicionar ou Editar uma Credencial."""

    def __init__(self, parent, entry: Optional[VaultEntry] = None, on_save=None):
        super().__init__(parent)
        self.entry = entry
        self.on_save = on_save

        title_text = "Editar Credencial" if entry else "Nova Credencial"
        self.title(title_text)
        self.geometry("520x620")
        self.resizable(False, False)
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except Exception:
                pass
        self.grab_set()

        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(frame, text=title_text, font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(15, 10))

        # Título
        ctk.CTkLabel(frame, text="Título / Serviço *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.title_entry = ctk.CTkEntry(frame, placeholder_text="Ex: GitHub, Gmail, Banco", height=35)
        self.title_entry.pack(fill="x", padx=25, pady=(2, 10))

        # Utilizador / Email
        ctk.CTkLabel(frame, text="Utilizador / Email *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.user_entry = ctk.CTkEntry(frame, placeholder_text="Ex: utilizador@email.com", height=35)
        self.user_entry.pack(fill="x", padx=25, pady=(2, 10))

        # Palavra-passe com botão Gerar
        ctk.CTkLabel(frame, text="Palavra-passe *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        pwd_row = ctk.CTkFrame(frame, fg_color="transparent")
        pwd_row.pack(fill="x", padx=25, pady=(2, 10))

        self.pwd_entry = ctk.CTkEntry(pwd_row, placeholder_text="Senha segura", height=35)
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        gen_btn = ctk.CTkButton(pwd_row, text="⚡ Gerar", width=80, height=35, command=self._quick_generate)
        gen_btn.pack(side="right")

        # Categoria
        ctk.CTkLabel(frame, text="Categoria", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.cat_menu = ctk.CTkOptionMenu(
            frame,
            values=["Geral", "Pessoal", "Trabalho", "Finanças", "Redes Sociais", "Servidores / API"],
            height=35
        )
        self.cat_menu.pack(fill="x", padx=25, pady=(2, 10))

        # URL
        ctk.CTkLabel(frame, text="URL / Website", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.url_entry = ctk.CTkEntry(frame, placeholder_text="Ex: https://github.com", height=35)
        self.url_entry.pack(fill="x", padx=25, pady=(2, 10))

        # Notas
        ctk.CTkLabel(frame, text="Notas Confidenciais", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.notes_box = ctk.CTkTextbox(frame, height=75)
        self.notes_box.pack(fill="x", padx=25, pady=(2, 15))

        # Botões
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=25, pady=(10, 0))

        cancel_btn = ctk.CTkButton(btn_row, text="Cancelar", fg_color="transparent", border_width=1, command=self.destroy)
        cancel_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        save_btn = ctk.CTkButton(btn_row, text="Guardar no Cofre", command=self._save)
        save_btn.pack(side="right", fill="x", expand=True, padx=(10, 0))

        if entry:
            self.title_entry.insert(0, entry.title)
            self.user_entry.insert(0, entry.username)
            self.pwd_entry.insert(0, entry.password)
            self.url_entry.insert(0, entry.url)
            self.cat_menu.set(entry.category)
            self.notes_box.insert("1.0", entry.notes)

    def _quick_generate(self):
        new_pwd = generate_password(length=18)
        self.pwd_entry.delete(0, "end")
        self.pwd_entry.insert(0, new_pwd)

    def _save(self):
        title = self.title_entry.get().strip()
        user = self.user_entry.get().strip()
        pwd = self.pwd_entry.get()
        url = self.url_entry.get().strip()
        category = self.cat_menu.get()
        notes = self.notes_box.get("1.0", "end-1c").strip()

        if not title:
            messagebox.showwarning("Campo Obrigatório", "O título não pode estar vazio.", parent=self)
            return
        if not pwd:
            messagebox.showwarning("Campo Obrigatório", "A palavra-passe não pode estar vazia.", parent=self)
            return

        entry_id = self.entry.id if self.entry else None
        created_at = self.entry.created_at if self.entry else None

        updated_entry = VaultEntry(
            title=title,
            username=user,
            password=pwd,
            url=url,
            notes=notes,
            category=category,
            entry_id=entry_id,
            created_at=created_at,
        )

        if self.on_save:
            self.on_save(updated_entry)
        self.destroy()


class ChangePasswordDialog(ctk.CTkToplevel):
    """Janela modal para alterar a Palavra-passe Mestre com re-cifragem atómica."""

    def __init__(self, parent, on_change=None):
        super().__init__(parent)
        self.on_change = on_change
        self.title("Alterar Palavra-passe Mestre")
        self.geometry("450x380")
        self.resizable(False, False)
        self.grab_set()

        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(frame, text="Alterar Senha Mestre", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(15, 10))
        ctk.CTkLabel(
            frame,
            text="Isto irá re-derivar uma nova chave Argon2id e re-cifrar\ntodo o ficheiro .vault com um novo Salt e Nonce.",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=(0, 15))

        ctk.CTkLabel(frame, text="Nova Palavra-passe Mestre *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.new_pwd1 = ctk.CTkEntry(frame, show="•", height=35)
        self.new_pwd1.pack(fill="x", padx=25, pady=(2, 10))

        ctk.CTkLabel(frame, text="Confirmar Nova Palavra-passe *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=25)
        self.new_pwd2 = ctk.CTkEntry(frame, show="•", height=35)
        self.new_pwd2.pack(fill="x", padx=25, pady=(2, 15))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=25, pady=(10, 0))

        ctk.CTkButton(btn_row, text="Cancelar", fg_color="transparent", border_width=1, command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(btn_row, text="Re-cifrar Cofre", fg_color="#059669", hover_color="#047857", command=self._confirm).pack(side="right", fill="x", expand=True, padx=(10, 0))

    def _confirm(self):
        p1 = self.new_pwd1.get()
        p2 = self.new_pwd2.get()
        if len(p1) < 6:
            messagebox.showwarning("Senha Fraca", "A nova senha deve ter pelo menos 6 caracteres.", parent=self)
            return
        if p1 != p2:
            messagebox.showwarning("Não coincide", "As palavras-passe não coincidem.", parent=self)
            return
        if self.on_change:
            self.on_change(p1)
        self.destroy()


class SecureVaultApp(ctk.CTk):
    """Janela Principal e Controladora da Aplicação SecureVault."""

    def __init__(self):
        super().__init__()

        self.title("SecureVault - Gestor Criptografado Profissional")
        self.geometry("1060x700")
        self.minsize(920, 600)

        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except Exception:
                pass

        # Estado da Aplicação
        self.vault_path = DEFAULT_FILEPATH
        self.master_password: Optional[str] = None
        self.vault_data: Optional[Dict[str, Any]] = None
        self.entries: List[VaultEntry] = []
        self.files: List[VaultFileAttachment] = []
        self.selected_entry: Optional[VaultEntry] = None
        self.clipboard_clear_timer: Optional[threading.Timer] = None
        self.current_nav = "credentials"

        # Sistema de Bloqueio Automático por Inatividade (Auto-Lock)
        self.auto_lock_minutes = 5  # 5 minutos padrão (0 = desativado)
        self.last_activity_time = time.time()
        self._setup_activity_listeners()

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        self._show_unlock_screen()
        # Iniciar ciclo de verificação de inatividade
        self._check_idle_timeout()

    # -------------------------------------------------------------
    # SISTEMA DE AUTO-LOCK POR INATIVIDADE
    # -------------------------------------------------------------
    def _setup_activity_listeners(self):
        """Monitoriza eventos de rato e teclado em toda a aplicação para reiniciar o cronómetro."""
        self.bind_all("<Key>", self._on_user_interaction, add="+")
        self.bind_all("<Button>", self._on_user_interaction, add="+")
        self.bind_all("<Motion>", self._on_user_interaction, add="+")

    def _on_user_interaction(self, event=None):
        """Atualiza o timestamp da última atividade do utilizador."""
        self.last_activity_time = time.time()

    def _check_idle_timeout(self):
        """Verifica periodicamente se o tempo limite de inatividade foi ultrapassado."""
        if self.master_password is not None and self.auto_lock_minutes > 0:
            idle_seconds = time.time() - self.last_activity_time
            if idle_seconds >= (self.auto_lock_minutes * 60):
                self._lock_vault(reason="Cofre bloqueado automaticamente por inatividade.")
                return

        # Verifica novamente a cada 5 segundos
        self.after(5000, self._check_idle_timeout)

    # -------------------------------------------------------------
    # ECRÃ 1: AUTENTICAÇÃO / DESBLOQUEIO
    # -------------------------------------------------------------
    def _show_unlock_screen(self, notice_msg: str = ""):
        for widget in self.container.winfo_children():
            widget.destroy()

        center_card = ctk.CTkFrame(self.container, corner_radius=18, width=460, height=530)
        center_card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center_card, text="🛡️", font=ctk.CTkFont(size=52)).pack(pady=(30, 5))
        ctk.CTkLabel(center_card, text="SecureVault", font=ctk.CTkFont(size=28, weight="bold")).pack()
        ctk.CTkLabel(
            center_card,
            text="Padrão Militar AES-256-GCM + KDF Argon2id (64MB RAM)\n100% Offline e Privado no teu Computador",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(pady=(4, 20))

        if notice_msg:
            ctk.CTkLabel(center_card, text=f"ℹ️ {notice_msg}", font=ctk.CTkFont(size=11, weight="bold"), text_color="#F59E0B").pack(pady=(0, 10))

        file_exists = os.path.exists(self.vault_path)
        status_text = f"Ficheiro: {self.vault_path}" if file_exists else f"Novo Cofre a Criar: {self.vault_path}"
        status_color = "#22C55E" if file_exists else "#F59E0B"
        ctk.CTkLabel(center_card, text=status_text, font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color).pack(pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(
            center_card,
            placeholder_text="Palavra-passe Mestre",
            show="•",
            width=340,
            height=42,
            font=ctk.CTkFont(size=14)
        )
        self.pwd_entry.pack(pady=10)
        self.pwd_entry.bind("<Return>", lambda _: self._handle_unlock_or_create())
        self.pwd_entry.focus()

        self.show_pwd_var = ctk.BooleanVar(value=False)
        show_cb = ctk.CTkCheckBox(
            center_card,
            text="Mostrar palavra-passe",
            variable=self.show_pwd_var,
            command=self._toggle_pwd_visibility,
            font=ctk.CTkFont(size=12)
        )
        show_cb.pack(pady=(0, 15))

        self.feedback_label = ctk.CTkLabel(center_card, text="", font=ctk.CTkFont(size=12))
        self.feedback_label.pack(pady=(0, 10))

        action_text = "Desbloquear Cofre" if file_exists else "Criar Novo Cofre"
        self.action_btn = ctk.CTkButton(
            center_card,
            text=action_text,
            width=340,
            height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._handle_unlock_or_create
        )
        self.action_btn.pack(pady=(0, 25))

    def _toggle_pwd_visibility(self):
        self.pwd_entry.configure(show="" if self.show_pwd_var.get() else "•")

    def _handle_unlock_or_create(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            self.feedback_label.configure(text="Introduz a palavra-passe mestre.", text_color="#EF4444")
            return

        self.action_btn.configure(state="disabled")
        self.feedback_label.configure(text="A derivar chave criptográfica com Argon2id...", text_color="#38BDF8")

        threading.Thread(target=self._async_auth, args=(pwd,), daemon=True).start()

    def _async_auth(self, password: str):
        try:
            if os.path.exists(self.vault_path):
                data = VaultStorage.load_vault(self.vault_path, password)
            else:
                data = {
                    "vault_name": "Cofre Pessoal",
                    "version": 1,
                    "entries": {},
                    "files": {},
                }
                VaultStorage.create_new_vault(self.vault_path, password, data)

            self.master_password = password
            self.vault_data = data
            self.entries = [VaultEntry.from_dict(v) for v in data.get("entries", {}).values()]
            self.files = [VaultFileAttachment.from_dict(f) for f in data.get("files", {}).values()]
            self.last_activity_time = time.time()

            self.after(0, self._show_main_interface)
        except DecryptionError:
            self.after(0, lambda: self._on_auth_fail("Palavra-passe incorreta ou cofre corrompido."))
        except Exception as exc:
            self.after(0, lambda: self._on_auth_fail(f"Erro: {str(exc)}"))

    def _on_auth_fail(self, msg: str):
        self.action_btn.configure(state="normal")
        self.feedback_label.configure(text=msg, text_color="#EF4444")

    # -------------------------------------------------------------
    # ECRÃ 2: INTERFACE PRINCIPAL MULTI-SECÇÕES
    # -------------------------------------------------------------
    def _show_main_interface(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        self.sidebar = ctk.CTkFrame(self.container, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=20)
        ctk.CTkLabel(logo_frame, text="🛡️ SecureVault", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(logo_frame, text="● Encriptado (256-bit)", font=ctk.CTkFont(size=11), text_color="#22C55E").pack(anchor="w")

        self.nav_btns = {}
        nav_items = [
            ("credentials", "🔑 Credenciais"),
            ("files", "📁 Ficheiros Seguros"),
            ("audit", "🛡️ Auditoria & Fugas"),
            ("generator", "⚡ Gerador"),
            ("settings", "⚙️ Definições"),
        ]

        for nav_id, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor="w",
                height=40,
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                command=lambda nid=nav_id: self._navigate_to(nid),
            )
            btn.pack(fill="x", padx=10, pady=4)
            self.nav_btns[nav_id] = btn

        lock_btn = ctk.CTkButton(
            self.sidebar,
            text="🔒 Bloquear Cofre",
            height=38,
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._lock_vault,
        )
        lock_btn.pack(side="bottom", fill="x", padx=15, pady=20)

        self.main_content = ctk.CTkFrame(self.container, corner_radius=0, fg_color="transparent")
        self.main_content.pack(side="right", fill="both", expand=True)

        self._navigate_to("credentials")

    def _navigate_to(self, nav_id: str):
        self.current_nav = nav_id
        for nid, btn in self.nav_btns.items():
            if nid == nav_id:
                btn.configure(fg_color=("#3B82F6", "#1D4ED8"), text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=("gray10", "gray90"))

        for w in self.main_content.winfo_children():
            w.destroy()

        if nav_id == "credentials":
            self._render_credentials_view()
        elif nav_id == "files":
            self._render_files_view()
        elif nav_id == "audit":
            self._render_audit_view()
        elif nav_id == "generator":
            self._render_generator_view()
        elif nav_id == "settings":
            self._render_settings_view()

    # -------------------------------------------------------------
    # SECÇÃO 1: CREDENCIAIS
    # -------------------------------------------------------------
    def _render_credentials_view(self):
        top_row = ctk.CTkFrame(self.main_content, fg_color="transparent", height=50)
        top_row.pack(fill="x", padx=20, pady=(15, 10))

        self.search_entry = ctk.CTkEntry(top_row, placeholder_text="🔍 Pesquisar serviço, utilizador ou categoria...", height=38)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 15))
        self.search_entry.bind("<KeyRelease>", lambda _: self._refresh_entries_list())

        add_btn = ctk.CTkButton(top_row, text="+ Nova Credencial", height=38, width=150, command=self._open_add_dialog)
        add_btn.pack(side="right")

        body = ctk.CTkFrame(self.main_content, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        left_col = ctk.CTkFrame(body, width=320, corner_radius=12)
        left_col.pack(side="left", fill="both", expand=False, padx=(0, 10))

        self.entries_scroll = ctk.CTkScrollableFrame(left_col, fg_color="transparent")
        self.entries_scroll.pack(fill="both", expand=True, padx=5, pady=5)

        self.details_pane = ctk.CTkFrame(body, corner_radius=12)
        self.details_pane.pack(side="right", fill="both", expand=True)

        self._refresh_entries_list()
        if self.selected_entry and any(e.id == self.selected_entry.id for e in self.entries):
            self._show_entry_details(self.selected_entry)
        else:
            self._show_empty_details()

    def _refresh_entries_list(self):
        for widget in self.entries_scroll.winfo_children():
            widget.destroy()

        query = self.search_entry.get().strip().lower() if hasattr(self, "search_entry") else ""
        filtered = [
            e for e in self.entries
            if query in e.title.lower() or query in e.username.lower() or query in e.category.lower()
        ]

        if not filtered:
            msg = "Nenhum resultado." if query else "Cofre vazio.\nClica em '+ Nova Credencial'."
            ctk.CTkLabel(self.entries_scroll, text=msg, text_color="gray", font=ctk.CTkFont(size=13)).pack(pady=40)
            return

        for entry in filtered:
            card = ctk.CTkFrame(self.entries_scroll, corner_radius=8, cursor="hand2")
            card.pack(fill="x", pady=4, padx=5)
            card.bind("<Button-1>", lambda _, e=entry: self._show_entry_details(e))

            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", padx=10, pady=(8, 2))
            top_row.bind("<Button-1>", lambda _, e=entry: self._show_entry_details(e))

            title_lbl = ctk.CTkLabel(top_row, text=entry.title, font=ctk.CTkFont(size=14, weight="bold"))
            title_lbl.pack(side="left")
            title_lbl.bind("<Button-1>", lambda _, e=entry: self._show_entry_details(e))

            cat_badge = ctk.CTkLabel(top_row, text=entry.category, font=ctk.CTkFont(size=10), text_color="#38BDF8")
            cat_badge.pack(side="right")
            cat_badge.bind("<Button-1>", lambda _, e=entry: self._show_entry_details(e))

            user_lbl = ctk.CTkLabel(card, text=entry.username or "(sem utilizador)", font=ctk.CTkFont(size=12), text_color="gray")
            user_lbl.pack(anchor="w", padx=10, pady=(0, 8))
            user_lbl.bind("<Button-1>", lambda _, e=entry: self._show_entry_details(e))

    def _show_empty_details(self):
        for w in self.details_pane.winfo_children():
            w.destroy()
        placeholder = ctk.CTkFrame(self.details_pane, fg_color="transparent")
        placeholder.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(placeholder, text="🔑", font=ctk.CTkFont(size=48)).pack(pady=10)
        ctk.CTkLabel(placeholder, text="Seleciona uma credencial", font=ctk.CTkFont(size=16, weight="bold")).pack()
        ctk.CTkLabel(placeholder, text="ou adiciona uma nova com o botão '+ Nova Credencial'", text_color="gray", font=ctk.CTkFont(size=12)).pack()

    def _show_entry_details(self, entry: VaultEntry):
        self.selected_entry = entry
        for w in self.details_pane.winfo_children():
            w.destroy()

        content = ctk.CTkScrollableFrame(self.details_pane, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=25, pady=25)

        # Cabeçalho
        h_row = ctk.CTkFrame(content, fg_color="transparent")
        h_row.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(h_row, text=entry.title, font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        ctk.CTkLabel(h_row, text=f"Categoria: {entry.category}", font=ctk.CTkFont(size=12), text_color="#38BDF8").pack(side="right")

        # Utilizador
        ctk.CTkLabel(content, text="UTILIZADOR / EMAIL", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", pady=(10, 2))
        u_frame = ctk.CTkFrame(content)
        u_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(u_frame, text=entry.username or "-", font=ctk.CTkFont(size=14)).pack(side="left", padx=12, pady=8)
        if entry.username:
            ctk.CTkButton(u_frame, text="Copiar", width=70, height=28, command=lambda: self._copy_to_clipboard(entry.username, "Utilizador")).pack(side="right", padx=8)

        # Senha
        ctk.CTkLabel(content, text="PALAVRA-PASSE", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", pady=(10, 2))
        p_frame = ctk.CTkFrame(content)
        p_frame.pack(fill="x", pady=(0, 10))

        pwd_var = ctk.StringVar(value="••••••••••••••••")
        ctk.CTkLabel(p_frame, textvariable=pwd_var, font=ctk.CTkFont(size=14, family="Consolas")).pack(side="left", padx=12, pady=8)

        def toggle_mask():
            if pwd_var.get().startswith("•"):
                pwd_var.set(entry.password)
                rev_btn.configure(text="Ocultar")
            else:
                pwd_var.set("••••••••••••••••")
                rev_btn.configure(text="Mostrar")

        ctk.CTkButton(p_frame, text="Copiar Segura", width=105, height=28, fg_color="#059669", hover_color="#047857", command=lambda: self._copy_secure_password(entry.password)).pack(side="right", padx=(4, 8))
        rev_btn = ctk.CTkButton(p_frame, text="Mostrar", width=75, height=28, command=toggle_mask)
        rev_btn.pack(side="right", padx=4)

        # Entropia da Senha
        entropy, rating, color = calculate_entropy(entry.password)
        ctk.CTkLabel(content, text=f"Força da Senha: {rating} ({entropy:.1f} bits de entropia)", font=ctk.CTkFont(size=11, weight="bold"), text_color=color).pack(anchor="w", pady=(0, 6))

        # -------------------------------------------------------------
        # VERIFICAÇÃO DE FUGAS (k-Anonymity / HaveIBeenPwned)
        # -------------------------------------------------------------
        leak_box = ctk.CTkFrame(content, corner_radius=8)
        leak_box.pack(fill="x", pady=(0, 15))

        leak_status_lbl = ctk.CTkLabel(leak_box, text="Verificação de Fugas Públicas (k-Anonymity): Não testada", font=ctk.CTkFont(size=11), text_color="gray")
        leak_status_lbl.pack(side="left", padx=12, pady=8)

        def run_single_leak_check():
            leak_check_btn.configure(state="disabled")
            leak_status_lbl.configure(text="A consultar HaveIBeenPwned via k-Anonymity...", text_color="#38BDF8")

            def bg_check():
                leaked, count = check_password_leak(entry.password)
                def update_ui():
                    leak_check_btn.configure(state="normal")
                    if count == -1:
                        leak_status_lbl.configure(text="⚠️ Sem ligação à internet para verificação de fugas.", text_color="#F59E0B")
                    elif leaked:
                        leak_status_lbl.configure(text=f"🚨 FUGA DETETADA: Esta senha apareceu em {count:,} fugas públicas!", text_color="#EF4444")
                    else:
                        leak_status_lbl.configure(text="✅ Segura: Nenhuma fuga pública conhecida para esta senha.", text_color="#10B981")
                self.after(0, update_ui)

            threading.Thread(target=bg_check, daemon=True).start()

        leak_check_btn = ctk.CTkButton(leak_box, text="🔍 Testar Fuga", width=110, height=26, font=ctk.CTkFont(size=11), command=run_single_leak_check)
        leak_check_btn.pack(side="right", padx=8, pady=6)

        # URL
        if entry.url:
            ctk.CTkLabel(content, text="URL / WEBSITE", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", pady=(10, 2))
            url_frame = ctk.CTkFrame(content)
            url_frame.pack(fill="x", pady=(0, 10))
            ctk.CTkLabel(url_frame, text=entry.url, font=ctk.CTkFont(size=13), text_color="#60A5FA").pack(side="left", padx=12, pady=8)
            ctk.CTkButton(url_frame, text="Abrir Link", width=80, height=28, command=lambda: webbrowser.open(entry.url)).pack(side="right", padx=8)

        # Notas
        if entry.notes:
            ctk.CTkLabel(content, text="NOTAS CONFIDENCIAIS", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray").pack(anchor="w", pady=(10, 2))
            notes_box = ctk.CTkTextbox(content, height=90)
            notes_box.pack(fill="x", pady=(0, 15))
            notes_box.insert("1.0", entry.notes)
            notes_box.configure(state="disabled")

        self.copy_feedback = ctk.CTkLabel(content, text="", font=ctk.CTkFont(size=12))
        self.copy_feedback.pack(pady=5)

        # Ações
        a_row = ctk.CTkFrame(content, fg_color="transparent")
        a_row.pack(fill="x", pady=(15, 0))
        ctk.CTkButton(a_row, text="✏️ Editar Credencial", width=150, command=lambda: self._open_edit_dialog(entry)).pack(side="left")
        ctk.CTkButton(a_row, text="🗑️ Eliminar", width=110, fg_color="#DC2626", hover_color="#B91C1C", command=lambda: self._delete_entry(entry)).pack(side="right")

    # -------------------------------------------------------------
    # SECÇÃO 2: FICHEIROS SEGUROS
    # -------------------------------------------------------------
    def _render_files_view(self):
        top_row = ctk.CTkFrame(self.main_content, fg_color="transparent", height=50)
        top_row.pack(fill="x", padx=25, pady=(20, 10))

        ctk.CTkLabel(top_row, text="📁 Ficheiros e Documentos Encriptados", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(top_row, text="➕ Adicionar Ficheiro ao Cofre", height=38, command=self._add_file_to_vault).pack(side="right")

        ctk.CTkLabel(
            self.main_content,
            text="Os ficheiros adicionados são cifrados com AES-256-GCM e armazenados diretamente dentro do teu cofre binário.",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(anchor="w", padx=25, pady=(0, 15))

        files_scroll = ctk.CTkScrollableFrame(self.main_content, corner_radius=12)
        files_scroll.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        if not self.files:
            empty_frame = ctk.CTkFrame(files_scroll, fg_color="transparent")
            empty_frame.pack(pady=60)
            ctk.CTkLabel(empty_frame, text="📄", font=ctk.CTkFont(size=44)).pack(pady=10)
            ctk.CTkLabel(empty_frame, text="Nenhum ficheiro encriptado ainda", font=ctk.CTkFont(size=16, weight="bold")).pack()
            ctk.CTkLabel(empty_frame, text="Podes guardar PDFs, imagens, chaves privadas SSH ou documentos.", text_color="gray").pack()
            return

        for f_att in self.files:
            card = ctk.CTkFrame(files_scroll, corner_radius=8)
            card.pack(fill="x", pady=5, padx=5)

            ctk.CTkLabel(card, text="📄", font=ctk.CTkFont(size=22)).pack(side="left", padx=(15, 10), pady=12)

            info_col = ctk.CTkFrame(card, fg_color="transparent")
            info_col.pack(side="left", fill="x", expand=True)

            ctk.CTkLabel(info_col, text=f_att.filename, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(info_col, text=f"Tamanho: {format_file_size(f_att.file_size)} | Guardado a: {f_att.created_at[:10]}", font=ctk.CTkFont(size=11), text_color="gray").pack(anchor="w")

            ctk.CTkButton(card, text="🗑️", width=40, fg_color="#DC2626", hover_color="#B91C1C", command=lambda f=f_att: self._delete_file(f)).pack(side="right", padx=(5, 15))
            ctk.CTkButton(card, text="📥 Extrair / Desencriptar", width=160, command=lambda f=f_att: self._export_file(f)).pack(side="right", padx=5)

    def _add_file_to_vault(self):
        file_path = filedialog.askopenfilename(
            title="Seleciona o ficheiro para guardar de forma segura",
            filetypes=[("Todos os Ficheiros", "*.*")]
        )
        if not file_path:
            return

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            data_bytes = f.read()

        attachment = VaultFileAttachment(filename=filename, data_bytes=data_bytes)
        self.files.append(attachment)
        self._persist_vault()
        messagebox.showinfo("Sucesso", f"O ficheiro '{filename}' foi encriptado e guardado no cofre!")
        self._navigate_to("files")

    def _export_file(self, attachment: VaultFileAttachment):
        save_path = filedialog.asksaveasfilename(
            title="Onde desejas guardar o ficheiro desencriptado?",
            initialfile=attachment.filename
        )
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(attachment.data_bytes)
        messagebox.showinfo("Extraído", f"Ficheiro desencriptado com sucesso para:\n{save_path}")

    def _delete_file(self, attachment: VaultFileAttachment):
        confirm = messagebox.askyesno("Confirmar", f"Desejas eliminar permanentemente o ficheiro '{attachment.filename}' do cofre?")
        if not confirm:
            return
        self.files = [f for f in self.files if f.id != attachment.id]
        self._persist_vault()
        self._navigate_to("files")

    # -------------------------------------------------------------
    # SECÇÃO 3: AUDITORIA DE SEGURANÇA E FUGAS ONLINE
    # -------------------------------------------------------------
    def _render_audit_view(self):
        report: AuditReport = audit_vault(self.entries)

        scroll = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=25, pady=20)

        ctk.CTkLabel(scroll, text="🛡️ Auditoria de Segurança & Fugas Online", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(scroll, text="Análise local de vulnerabilidades + Verificação anónima HaveIBeenPwned (k-Anonymity).", font=ctk.CTkFont(size=12), text_color="gray").pack(anchor="w", pady=(0, 20))

        # Cartão de Pontuação de Saúde
        score_card = ctk.CTkFrame(scroll, corner_radius=12)
        score_card.pack(fill="x", pady=(0, 20))

        score_color = "#10B981" if report.health_score >= 80 else "#F59E0B" if report.health_score >= 50 else "#EF4444"
        ctk.CTkLabel(score_card, text=f"{report.health_score}%", font=ctk.CTkFont(size=44, weight="bold"), text_color=score_color).pack(side="left", padx=30, pady=20)

        score_info = ctk.CTkFrame(score_card, fg_color="transparent")
        score_info.pack(side="left", fill="x", expand=True, pady=15)
        status_title = "Excelente Proteção!" if report.health_score >= 80 else "Atenção: Riscos de Segurança Detetados" if report.health_score >= 50 else "Cofre Vulnerável!"
        ctk.CTkLabel(score_info, text=status_title, font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(score_info, text=f"Total: {report.total_entries} | Fracas: {report.total_weak} | Repetidas: {report.total_reused}", text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        # -------------------------------------------------------------
        # AUDITORIA GLOBAL DE FUGAS (k-Anonymity)
        # -------------------------------------------------------------
        leak_audit_card = ctk.CTkFrame(scroll, corner_radius=12, border_width=1, border_color="#3B82F6")
        leak_audit_card.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(leak_audit_card, text="🌐 Varredura Global de Fugas (HaveIBeenPwned)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=15, pady=(12, 2))
        ctk.CTkLabel(
            leak_audit_card,
            text="Verifica todas as senhas contra mais de 800 milhões de credenciais vazadas na Dark Web usando k-Anonymity.\nNenhuma senha ou hash completo sai do teu computador.",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(anchor="w", padx=15, pady=(0, 10))

        leak_results_frame = ctk.CTkFrame(leak_audit_card, fg_color="transparent")
        leak_results_frame.pack(fill="x", padx=15, pady=(0, 10))

        def run_full_leak_scan():
            full_scan_btn.configure(state="disabled", text="A verificar...")
            for w in leak_results_frame.winfo_children():
                w.destroy()

            status_lbl = ctk.CTkLabel(leak_results_frame, text="A verificar credenciais (1 a 1)...", text_color="#38BDF8")
            status_lbl.pack(anchor="w", pady=5)

            def bg_scan():
                breached = []
                net_error = False
                for idx, entry in enumerate(self.entries):
                    is_leaked, count = check_password_leak(entry.password)
                    if count == -1:
                        net_error = True
                        break
                    elif is_leaked:
                        breached.append((entry, count))
                    time.sleep(0.15)  # Respeita o rate limit da API

                def update_results():
                    full_scan_btn.configure(state="normal", text="🔍 Iniciar Varredura de Fugas")
                    status_lbl.destroy()

                    if net_error:
                        ctk.CTkLabel(leak_results_frame, text="⚠️ Erro de rede: Não foi possível contactar o servidor HaveIBeenPwned.", text_color="#F59E0B").pack(anchor="w")
                        return

                    if not breached:
                        ctk.CTkLabel(leak_results_frame, text="🎉 Excelente! Nenhuma das tuas credenciais foi encontrada em fugas públicas conhecidas.", font=ctk.CTkFont(size=12, weight="bold"), text_color="#10B981").pack(anchor="w", pady=5)
                    else:
                        ctk.CTkLabel(leak_results_frame, text=f"🚨 ATENÇÃO: {len(breached)} credenciais constam em fugas de dados públicas conhecidas:", font=ctk.CTkFont(size=13, weight="bold"), text_color="#EF4444").pack(anchor="w", pady=(5, 8))
                        for b_entry, b_count in breached:
                            row = ctk.CTkFrame(leak_results_frame, corner_radius=6)
                            row.pack(fill="x", pady=2)
                            ctk.CTkLabel(row, text=f"{b_entry.title} ({b_entry.username})", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=10, pady=4)
                            ctk.CTkLabel(row, text=f"{b_count:,} vazamentos", font=ctk.CTkFont(size=11, weight="bold"), text_color="#EF4444").pack(side="right", padx=10)

                self.after(0, update_results)

            threading.Thread(target=bg_scan, daemon=True).start()

        full_scan_btn = ctk.CTkButton(leak_audit_card, text="🔍 Iniciar Varredura de Fugas", width=220, command=run_full_leak_scan)
        full_scan_btn.pack(anchor="w", padx=15, pady=(0, 15))

        # Alertas de Senhas Reutilizadas
        if report.reused_groups:
            ctk.CTkLabel(scroll, text="⚠️ Senhas Reutilizadas (Risco Crítico de Invasão em Cadeia)", font=ctk.CTkFont(size=15, weight="bold"), text_color="#EF4444").pack(anchor="w", pady=(15, 8))
            for pwd, elist in report.reused_groups.items():
                group_box = ctk.CTkFrame(scroll, corner_radius=8, border_width=1, border_color="#EF4444")
                group_box.pack(fill="x", pady=4)
                services = ", ".join(e.title for e in elist)
                ctk.CTkLabel(group_box, text=f"A mesma senha é usada em {len(elist)} serviços:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=12, pady=(8, 2))
                ctk.CTkLabel(group_box, text=services, text_color="#38BDF8", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=12, pady=(0, 8))

        # Alertas de Senhas Fracas
        if report.weak_entries:
            ctk.CTkLabel(scroll, text="⚠️ Senhas Fracas (Baixa Entropia)", font=ctk.CTkFont(size=15, weight="bold"), text_color="#F59E0B").pack(anchor="w", pady=(20, 8))
            for entry in report.weak_entries:
                w_box = ctk.CTkFrame(scroll, corner_radius=8)
                w_box.pack(fill="x", pady=3)
                ctk.CTkLabel(w_box, text=entry.title, font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=12, pady=8)
                entropy, rating, color = calculate_entropy(entry.password)
                ctk.CTkLabel(w_box, text=f"{rating} ({entropy:.1f} bits)", font=ctk.CTkFont(size=12, weight="bold"), text_color=color).pack(side="right", padx=12)

    # -------------------------------------------------------------
    # SECÇÃO 4: GERADOR DE SENHAS
    # -------------------------------------------------------------
    def _render_generator_view(self):
        gen_frame = ctk.CTkFrame(self.main_content, fg_color="transparent")
        gen_frame.pack(fill="both", expand=True, padx=50, pady=30)

        ctk.CTkLabel(gen_frame, text="⚡ Gerador Criptográfico de Palavras-passe", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(gen_frame, text="Entropia gerada por gerador seguro do SO (secrets / CryptGenRandom).", font=ctk.CTkFont(size=12), text_color="gray").pack(anchor="w", pady=(0, 25))

        self.gen_pwd_var = ctk.StringVar(value=generate_password(18))
        display_box = ctk.CTkFrame(gen_frame, height=55)
        display_box.pack(fill="x", pady=(0, 15))

        pwd_lbl = ctk.CTkLabel(display_box, textvariable=self.gen_pwd_var, font=ctk.CTkFont(size=18, family="Consolas", weight="bold"))
        pwd_lbl.pack(side="left", padx=15, pady=12)

        copy_btn = ctk.CTkButton(display_box, text="Copiar Segura", width=110, fg_color="#059669", hover_color="#047857", command=lambda: self._copy_secure_password(self.gen_pwd_var.get()))
        copy_btn.pack(side="right", padx=10)

        ctk.CTkLabel(gen_frame, text="Comprimento da Palavra-passe:", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
        slider_row = ctk.CTkFrame(gen_frame, fg_color="transparent")
        slider_row.pack(fill="x", pady=(5, 15))

        self.length_val_lbl = ctk.CTkLabel(slider_row, text="18 caracteres", width=95, font=ctk.CTkFont(size=13, weight="bold"))
        self.length_val_lbl.pack(side="right")

        self.length_slider = ctk.CTkSlider(slider_row, from_=8, to=48, number_of_steps=40, command=self._on_slider_change)
        self.length_slider.set(18)
        self.length_slider.pack(side="left", fill="x", expand=True)

        self.use_upper = ctk.BooleanVar(value=True)
        self.use_lower = ctk.BooleanVar(value=True)
        self.use_digits = ctk.BooleanVar(value=True)
        self.use_symbols = ctk.BooleanVar(value=True)

        cb_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
        cb_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkCheckBox(cb_frame, text="Maiúsculas (A-Z)", variable=self.use_upper, command=self._regenerate_password).grid(row=0, column=0, sticky="w", pady=5)
        ctk.CTkCheckBox(cb_frame, text="Minúsculas (a-z)", variable=self.use_lower, command=self._regenerate_password).grid(row=0, column=1, sticky="w", padx=25, pady=5)
        ctk.CTkCheckBox(cb_frame, text="Números (0-9)", variable=self.use_digits, command=self._regenerate_password).grid(row=1, column=0, sticky="w", pady=5)
        ctk.CTkCheckBox(cb_frame, text="Símbolos (!@#$...)", variable=self.use_symbols, command=self._regenerate_password).grid(row=1, column=1, sticky="w", padx=25, pady=5)

        gen_now_btn = ctk.CTkButton(gen_frame, text="⚡ Gerar Nova Palavra-passe", height=42, font=ctk.CTkFont(size=14, weight="bold"), command=self._regenerate_password)
        gen_now_btn.pack(fill="x", pady=(10, 0))

    def _on_slider_change(self, val):
        self.length_val_lbl.configure(text=f"{int(val)} caracteres")
        self._regenerate_password()

    def _regenerate_password(self):
        new_pwd = generate_password(
            length=int(self.length_slider.get()),
            use_upper=self.use_upper.get(),
            use_lower=self.use_lower.get(),
            use_digits=self.use_digits.get(),
            use_symbols=self.use_symbols.get(),
        )
        self.gen_pwd_var.set(new_pwd)

    # -------------------------------------------------------------
    # SECÇÃO 5: DEFINIÇÕES & FERRAMENTAS
    # -------------------------------------------------------------
    def _render_settings_view(self):
        scroll = ctk.CTkScrollableFrame(self.main_content, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=40, pady=25)

        ctk.CTkLabel(scroll, text="⚙️ Definições e Gestão do Cofre", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", pady=(0, 20))

        # Bloco: Auto-Lock
        s0 = ctk.CTkFrame(scroll, corner_radius=12)
        s0.pack(fill="x", pady=(0, 15), padx=5)
        ctk.CTkLabel(s0, text="🔒 Bloqueio Automático por Inatividade (Auto-Lock)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 2))
        ctk.CTkLabel(s0, text="Bloqueia o cofre e limpa as credenciais da memória RAM quando não utilizas a app.", text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 10))

        lock_options_map = {
            "1 minuto": 1,
            "5 minutos": 5,
            "15 minutos": 15,
            "30 minutos": 30,
            "Desativado": 0,
        }
        current_opt_text = "5 minutos"
        for text_label, mins in lock_options_map.items():
            if mins == self.auto_lock_minutes:
                current_opt_text = text_label
                break

        def on_change_autolock(choice):
            self.auto_lock_minutes = lock_options_map.get(choice, 5)
            self.last_activity_time = time.time()

        lock_menu = ctk.CTkOptionMenu(s0, values=list(lock_options_map.keys()), command=on_change_autolock, width=160)
        lock_menu.set(current_opt_text)
        lock_menu.pack(anchor="w", padx=20, pady=(0, 15))

        # Bloco: Segurança da Palavra-passe Mestre
        s1 = ctk.CTkFrame(scroll, corner_radius=12)
        s1.pack(fill="x", pady=(0, 15), padx=5)
        ctk.CTkLabel(s1, text="Palavra-passe Mestre", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 2))
        ctk.CTkLabel(s1, text="Altera a palavra-passe do cofre e força a geração de um novo Salt e chave Argon2id.", text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 10))
        ctk.CTkButton(s1, text="🔑 Alterar Palavra-passe Mestre", width=220, command=self._open_change_pwd_dialog).pack(anchor="w", padx=20, pady=(0, 15))

        # Bloco: Importação e Exportação
        s2 = ctk.CTkFrame(scroll, corner_radius=12)
        s2.pack(fill="x", pady=(0, 15), padx=5)
        ctk.CTkLabel(s2, text="Importação e Exportação (CSV)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 2))
        ctk.CTkLabel(s2, text="Compatível com ficheiros CSV do Google Chrome, Bitwarden e KeePass.", text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 10))

        btn_row = ctk.CTkFrame(s2, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 15))
        ctk.CTkButton(btn_row, text="📥 Importar de CSV", width=160, command=self._import_csv).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="📤 Exportar para CSV", width=160, fg_color="transparent", border_width=1, command=self._export_csv).pack(side="left")

        # Bloco: Cópia de Segurança Integral
        s3 = ctk.CTkFrame(scroll, corner_radius=12)
        s3.pack(fill="x", pady=(0, 15), padx=5)
        ctk.CTkLabel(s3, text="Cópia de Segurança Integral", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 2))
        ctk.CTkLabel(s3, text=f"Localização atual do teu ficheiro encriptado: {os.path.abspath(self.vault_path)}", text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 10))
        ctk.CTkButton(s3, text="💾 Criar Cópia de Segurança (.vaultbackup)", width=260, command=self._backup_vault_file).pack(anchor="w", padx=20, pady=(0, 15))

    def _open_change_pwd_dialog(self):
        ChangePasswordDialog(self, on_change=self._execute_change_password)

    def _execute_change_password(self, new_password: str):
        try:
            change_master_password(self.vault_path, self.master_password, new_password)
            self.master_password = new_password
            messagebox.showinfo("Sucesso", "Palavra-passe mestre alterada com sucesso!\nO cofre foi re-cifrado com um novo Salt e Nonce.")
        except Exception as exc:
            messagebox.showerror("Erro", f"Falha ao alterar senha mestre: {exc}")

    def _import_csv(self):
        file_path = filedialog.askopenfilename(title="Seleciona o ficheiro CSV para importar", filetypes=[("Ficheiros CSV", "*.csv")])
        if not file_path:
            return
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        new_entries, count = import_entries_from_csv(content)
        if count == 0:
            messagebox.showwarning("Aviso", "Nenhuma credencial válida encontrada no ficheiro CSV.")
            return

        self.entries.extend(new_entries)
        self._persist_vault()
        messagebox.showinfo("Sucesso", f"{count} credenciais importadas com sucesso!")
        self._navigate_to("credentials")

    def _export_csv(self):
        confirm = messagebox.askyesno(
            "Aviso de Segurança",
            "Exportar para CSV irá guardar as tuas credenciais em TEXTO LIMPO (sem encriptação) na pasta que escolheres.\n\nDesejas continuar?"
        )
        if not confirm:
            return

        save_path = filedialog.asksaveasfilename(title="Guardar CSV", defaultextension=".csv", filetypes=[("Ficheiros CSV", "*.csv")])
        if not save_path:
            return

        csv_text = export_entries_to_csv(self.entries)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(csv_text)
        messagebox.showinfo("Sucesso", f"Credenciais exportadas para:\n{save_path}")

    def _backup_vault_file(self):
        save_path = filedialog.asksaveasfilename(title="Guardar Cópia de Segurança", defaultextension=".vaultbackup", filetypes=[("Backup Seguro", "*.vaultbackup"), ("Cofre", "*.vault")])
        if not save_path:
            return
        with open(self.vault_path, "rb") as src, open(save_path, "wb") as dst:
            dst.write(src.read())
        messagebox.showinfo("Sucesso", f"Cópia de segurança cifrada guardada com sucesso em:\n{save_path}")

    # -------------------------------------------------------------
    # OPERAÇÕES DE DADOS E COFRE
    # -------------------------------------------------------------
    def _open_add_dialog(self):
        EntryDialog(self, entry=None, on_save=self._save_entry)

    def _open_edit_dialog(self, entry: VaultEntry):
        EntryDialog(self, entry=entry, on_save=self._save_entry)

    def _save_entry(self, entry: VaultEntry):
        existing_index = next((i for i, e in enumerate(self.entries) if e.id == entry.id), None)
        if existing_index is not None:
            self.entries[existing_index] = entry
        else:
            self.entries.insert(0, entry)

        self._persist_vault()
        self._refresh_entries_list()
        self._show_entry_details(entry)

    def _delete_entry(self, entry: VaultEntry):
        confirm = messagebox.askyesno("Confirmar Eliminação", f"Desejas eliminar permanentemente a credencial '{entry.title}'?", parent=self)
        if not confirm:
            return

        self.entries = [e for e in self.entries if e.id != entry.id]
        self._persist_vault()
        self.selected_entry = None
        self._refresh_entries_list()
        self._show_empty_details()

    def _persist_vault(self):
        if not self.master_password:
            return

        payload = {
            "vault_name": self.vault_data.get("vault_name", "Cofre Pessoal"),
            "version": 1,
            "entries": {e.id: e.to_dict() for e in self.entries},
            "files": {f.id: f.to_dict() for f in self.files},
        }
        VaultStorage.save_vault(self.vault_path, self.master_password, payload)

    def _copy_to_clipboard(self, text: str, label: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        if hasattr(self, "copy_feedback"):
            self.copy_feedback.configure(text=f"[✓] {label} copiado para a área de transferência!", text_color="#10B981")

    def _copy_secure_password(self, password: str):
        self._copy_to_clipboard(password, "Palavra-passe")
        if hasattr(self, "copy_feedback"):
            self.copy_feedback.configure(text="[✓] Palavra-passe copiada! (Será apagada da memória em 30s)", text_color="#10B981")

        if self.clipboard_clear_timer:
            self.clipboard_clear_timer.cancel()

        def clear_clip():
            try:
                self.clipboard_clear()
            except Exception:
                pass

        self.clipboard_clear_timer = threading.Timer(30.0, clear_clip)
        self.clipboard_clear_timer.daemon = True
        self.clipboard_clear_timer.start()

    def _lock_vault(self, reason: str = ""):
        self.master_password = None
        self.vault_data = None
        self.entries = []
        self.files = []
        self.selected_entry = None
        self._show_unlock_screen(notice_msg=reason)


def main():
    app = SecureVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
