from logging import root
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib
import os
import sys
import base64
import customtkinter as ctk

from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ================= CONFIG =================
DB_NAME = "passwords.db"
MASTER_FILE = "master.dat"
ITERATIONS = 390_000

# ================= CRIPTO =================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_master(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode()).hexdigest()

# ================= DB =================
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL
            )
        """)

# ================= MASTER =================
def setup_master(root):
    if os.path.exists(MASTER_FILE):
        return

    pwd = simpledialog.askstring(
        "Criar senha master",
        "Crie sua senha master:",
        show="*",
        parent=root
    )
    if not pwd:
        sys.exit()

    salt = os.urandom(16)
    pwd_hash = hash_master(pwd, salt)

    with open(MASTER_FILE, "wb") as f:
        f.write(salt + pwd_hash.encode())

    messagebox.showinfo("OK", "Senha master criada!", parent=root)

def check_master(root):
    tentativas = 3

    with open(MASTER_FILE, "rb") as f:
        data = f.read()

    salt = data[:16]
    stored_hash = data[16:].decode()

    while tentativas > 0:
        pwd = simpledialog.askstring(
            "Senha master",
            f"Digite a senha master\nTentativas restantes: {tentativas}",
            show="*",
            parent=root
        )

        if not pwd:
            sys.exit()

        if hash_master(pwd, salt) == stored_hash:
            key = derive_key(pwd, salt)
            return Fernet(key)

        tentativas -= 1
        messagebox.showerror(
            "Erro",
            "Senha master incorreta!",
            parent=root
        )

    messagebox.showerror(
        "Bloqueado",
        "Número máximo de tentativas atingido.\nO programa será encerrado.",
        parent=root
    )
    sys.exit()

# ================= TELAS INTERNAS E FUNÇÕES =================

def clear_content(content):
    """Limpa a área principal antes de carregar outra tela"""
    for widget in content.winfo_children():
        widget.destroy()


def salvar_senha_tela(root, cipher, content):
    clear_content(content)

    frame = ctk.CTkFrame(content, corner_radius=20, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both", padx=60, pady=40)

    ctk.CTkLabel(frame, text="➕ Salvar Nova Senha", font=("Arial", 20, "bold")).pack(pady=15)

    e_serv = ctk.CTkEntry(frame, placeholder_text="Serviço", width=300)
    e_user = ctk.CTkEntry(frame, placeholder_text="Usuário", width=300)
    e_pwd = ctk.CTkEntry(frame, placeholder_text="Senha", show="*", width=300)

    e_serv.pack(pady=8)
    e_user.pack(pady=8)
    e_pwd.pack(pady=8)

    def salvar():
        service, user, pwd = e_serv.get(), e_user.get(), e_pwd.get()
        if not service or not user or not pwd:
            return messagebox.showerror("Erro", "Preencha todos os campos!", parent=root)

        encrypted = cipher.encrypt(pwd.encode())
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("INSERT INTO users (service, username, password) VALUES (?, ?, ?)",
                         (service, user, encrypted))
        messagebox.showinfo("OK", "Senha salva com sucesso!", parent=root)

    ctk.CTkButton(frame, text="💾 Salvar", width=200, corner_radius=15, command=salvar).pack(pady=20)


def buscar_servico_tela(root, cipher, content):
    clear_content(content)

    frame = ctk.CTkFrame(content, corner_radius=20, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both", padx=60, pady=40)

    ctk.CTkLabel(frame, text="🔍 Buscar Serviço", font=("Arial", 20, "bold")).pack(pady=15)

    e_busca = ctk.CTkEntry(frame, placeholder_text="Nome do serviço", width=300)
    e_busca.pack(pady=10)

    box = tk.Text(frame, width=70, height=10, bd=0, relief="flat")
    box.pack(pady=15)

    def buscar():
        termo = e_busca.get()
        with sqlite3.connect(DB_NAME) as conn:
            rows = conn.execute("SELECT service, username, password FROM users WHERE service LIKE ?",
                                (f"%{termo}%",)).fetchall()

        box.delete("1.0", tk.END)
        if not rows:
            return box.insert(tk.END, "Nenhum serviço encontrado.")

        for s, u, p in rows:
            try: dec = cipher.decrypt(p).decode()
            except: dec = "[ERRO]"
            box.insert(tk.END, f"Serviço: {s} | Usuário: {u} | Senha: {dec}\n")

    ctk.CTkButton(frame, text="🔎 Buscar", width=200, corner_radius=15, command=buscar).pack(pady=10)

def listar_senhas_tela(root, cipher, content):
    # 🔐 Pedir senha master novamente
    pwd_confirm = simpledialog.askstring(
        "Confirmação de Segurança",
        "Digite novamente a senha master para visualizar as senhas:",
        show="*",
        parent=root
    )

    if not pwd_confirm:
        messagebox.showwarning("Cancelado", "A ação foi cancelada.", parent=root)
        return

    # ⚠️ Verifica senha
    with open(MASTER_FILE, "rb") as f:
        data = f.read()
    salt = data[:16]
    stored_hash = data[16:].decode()

    # Se estiver incorreta -> bloqueia visualização
    if hash_master(pwd_confirm, salt) != stored_hash:
        messagebox.showerror("Acesso Negado", "Senha master incorreta! Não é possível exibir as senhas.", parent=root)
        return

    # ================= TELA APÓS CONFIRMAÇÃO =================
    clear_content(content)

    frame = ctk.CTkFrame(content, corner_radius=20, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both", padx=60, pady=40)

    ctk.CTkLabel(frame, text="📋 Todas as Senhas", font=("Arial", 20, "bold")).pack(pady=15)

    box = tk.Text(frame, width=70, height=12, bd=0, relief="flat", bg="#121212", fg="white")
    box.pack(pady=10)

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute("SELECT service, username, password FROM users").fetchall()

    if not rows:
        box.insert(tk.END, "Nenhuma senha cadastrada.\n")
        return

    for service, username, encrypted_pwd in rows:
        try:
            decrypted = cipher.decrypt(encrypted_pwd).decode()
        except:
            decrypted = "[ERRO AO DECIFRAR]"

        box.insert(tk.END, f"🔐 Serviço: {service}\n👤 Usuário: {username}\n🔑 Senha: {decrypted}\n")
        box.insert(tk.END, "──────────────────────────────────────\n")


def alterar_senha_tela(root, cipher, content):
    clear_content(content)

    frame = ctk.CTkFrame(content, corner_radius=20, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both", padx=60, pady=40)

    ctk.CTkLabel(frame, text="✏️ Alterar Senha", font=("Arial", 22, "bold")).pack(pady=10)

    # Campos
    e_serv = ctk.CTkEntry(frame, placeholder_text="Serviço (ex: Instagram)", width=300)
    e_nova = ctk.CTkEntry(frame, placeholder_text="Nova Senha", show="*", width=300)
    e_serv.pack(pady=10)
    e_nova.pack(pady=10)

    # Função interna para alterar
    def confirmar_alteracao():
        service = e_serv.get().strip()
        nova = e_nova.get().strip()

        if not service or not nova:
            messagebox.showwarning("Aviso", "Preencha todos os campos!", parent=root)
            return

        # Verifica se o serviço existe
        with sqlite3.connect(DB_NAME) as conn:
            rows = conn.execute(
                "SELECT id, service, username FROM users WHERE service LIKE ?",
                (f"%{service}%",)
            ).fetchall()

        if not rows:
            messagebox.showinfo("Erro", "Nenhuma senha encontrada com esse serviço.", parent=root)
            return

        # Se tiver mais de uma, escolher qual alterar
        if len(rows) > 1:
            selecao = tk.simpledialog.askinteger(
                "Várias encontradas",
                "Foram encontradas várias entradas.\nDigite o ID da senha que deseja alterar:\n\n" +
                "\n".join([f"ID {r[0]} - {r[1]} ({r[2]})" for r in rows]),
                parent=root
            )
            if not selecao:
                return
            target_id = selecao
        else:
            target_id = rows[0][0]

        # Atualiza no banco
        encrypted = cipher.encrypt(nova.encode())
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("UPDATE users SET password=? WHERE id=?", (encrypted, target_id))

        messagebox.showinfo("Sucesso", "Senha alterada com sucesso!", parent=root)
        e_serv.delete(0, "end")
        e_nova.delete(0, "end")

    # Botão de confirmar
    ctk.CTkButton(
        frame,
        text="Salvar Nova Senha",
        fg_color="#0057b7",
        hover_color="#003f8a",
        command=confirmar_alteracao,
        width=200
    ).pack(pady=25)



def deletar_senha_tela(root, cipher, content):
    clear_content(content)

    ctk.CTkLabel(content, text="🗑️ Deletar Senha", font=("Arial", 20, "bold")).pack(pady=10)

    entrada = ctk.CTkEntry(content, width=350, placeholder_text="Digite o serviço")
    entrada.pack(pady=10)

    def buscar_para_deletar():
        termo = entrada.get().strip()

        if not termo:
            messagebox.showerror("Erro", "Digite o nome do serviço para buscar!", parent=root)
            return

        with sqlite3.connect(DB_NAME) as conn:
            rows = conn.execute(
                "SELECT id, service, username, password FROM users WHERE LOWER(service) LIKE LOWER(?)",
                (f"%{termo}%",)
            ).fetchall()

        if not rows:
            messagebox.showinfo("Aviso", "Nenhuma senha encontrada com esse nome.", parent=root)
            return

        # --- Popup com lista para escolher ---
        popup = ctk.CTkToplevel(root)
        popup.title("Confirmação - Escolha a senha para deletar")
        popup.geometry("500x300")
        popup.grab_set()  # trava a tela até escolher

        ctk.CTkLabel(
            popup,
            text=f"Selecione a senha que deseja deletar:",
            font=("Arial", 16, "bold")
        ).pack(pady=10)

        frame_lista = ctk.CTkFrame(popup)
        frame_lista.pack(fill="both", expand=True, padx=10, pady=10)

        for user_id, serv, user, pwd in rows:
            try:
                senha_dec = cipher.decrypt(pwd).decode()
            except:
                senha_dec = "[ERRO]"

            item = ctk.CTkButton(
                frame_lista,
                text=f"{serv}  |  {user}  |  {senha_dec}",
                fg_color="#b30000",
                hover_color="#7a0000",
                command=lambda i=user_id, s=serv: confirmar_exclusao(i, s, popup)
            )
            item.pack(pady=5, fill="x")
        
        ctk.CTkButton(popup, text="Cancelar", command=popup.destroy).pack(pady=10)

    def confirmar_exclusao(user_id, nome_servico, janela):
        resposta = messagebox.askyesno(
            "Confirmar Exclusão",
            f"Tem certeza que deseja deletar a senha do serviço:\n\n  {nome_servico}\n\nIsso NÃO poderá ser desfeito!"
        )
        if not resposta:
            return

        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()

        janela.destroy()
        clear_content(content)
        messagebox.showinfo("OK", "Senha deletada com sucesso!", parent=root)

    ctk.CTkButton(content, text="Buscar", width=200, command=buscar_para_deletar).pack(pady=20)



# ================= MAIN =================

def main():
    # ===== Aparência =====
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.title("Gerenciador de Senhas - Profissional")
    app.geometry("950x540")

    init_db()
    setup_master(app)
    cipher = check_master(app)

    # ===== Grid principal =====
    app.grid_columnconfigure(1, weight=1)
    app.grid_rowconfigure(0, weight=1)

    # ===== SIDEBAR ESTILIZADO =====
    sidebar = ctk.CTkFrame(app, width=220, corner_radius=20)
    sidebar.grid(row=0, column=0, sticky="nsw", padx=15, pady=15)

    ctk.CTkLabel(
        sidebar, 
        text="🔐 Password Manager", 
        font=("Arial", 20, "bold")
    ).pack(pady=(20,10))

    # Botões estilizados
    button_style = {
        "width": 180,
        "height": 40,
        "corner_radius": 12,
        "font": ("Arial", 14)
    }

    ctk.CTkButton(sidebar, text="➕ Salvar Senha",
                  command=lambda: salvar_senha_tela(app, cipher, content),
                  **button_style).pack(pady=8)

    ctk.CTkButton(sidebar, text="🔍 Buscar Serviço",
                  command=lambda: buscar_servico_tela(app, cipher, content),
                  **button_style).pack(pady=8)

    ctk.CTkButton(sidebar, text="📋 Listar Senhas",
                  command=lambda: listar_senhas_tela(app, cipher, content),
                  **button_style).pack(pady=8)

    ctk.CTkButton(sidebar, text="✏️ Alterar Senha",
                  command=lambda: alterar_senha_tela(app, cipher, content),
                  **button_style).pack(pady=8)

    ctk.CTkButton(sidebar, text="🗑️ Deletar Senha",
                  command=lambda: deletar_senha_tela(app, cipher, content),
                  **button_style).pack(pady=8)

    # Botão Sair destacado
    ctk.CTkButton(
        sidebar,
        text="🚪 Sair",
        fg_color="#b30000",
        hover_color="#7a0000",
        **button_style,
        command=app.destroy
    ).pack(pady=(40,10))

    # ===== ÁREA PRINCIPAL =====
    global content
    content = ctk.CTkFrame(app, corner_radius=20)
    content.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)

    ctk.CTkLabel(
        content,
        text="Bem-vindo ao Gerenciador de Senhas 🔐\nEscolha uma opção no menu 👉",
        font=("Arial", 22, "bold"),
        justify="center"
    ).pack(expand=True)

    app.mainloop()



if __name__ == "__main__":
    main()
