import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib
import os
import sys
import base64

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

# ================= DATABASE =================
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

# ================= MASTER PASSWORD =================
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
    pwd = simpledialog.askstring(
        "Senha master",
        "Digite a senha master:",
        show="*",
        parent=root
    )
    if not pwd:
        sys.exit()

    with open(MASTER_FILE, "rb") as f:
        data = f.read()

    salt = data[:16]
    stored_hash = data[16:].decode()

    if hash_master(pwd, salt) != stored_hash:
        messagebox.showerror("Erro", "Senha master incorreta!", parent=root)
        sys.exit()

    key = derive_key(pwd, salt)
    return Fernet(key)

# ================= FUNÇÕES =================
def salvar_senha(root, cipher):
    service = simpledialog.askstring("Serviço", "Nome do serviço:", parent=root)
    user = simpledialog.askstring("Usuário", "Nome do usuário:", parent=root)
    pwd = simpledialog.askstring("Senha", "Senha:", show="*", parent=root)

    if not service or not user or not pwd:
        return

    encrypted = cipher.encrypt(pwd.encode())

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO users (service, username, password) VALUES (?, ?, ?)",
            (service, user, encrypted)
        )

    messagebox.showinfo("OK", "Senha salva com sucesso!", parent=root)

def listar_senhas(root, cipher):
    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            "SELECT service, username, password FROM users"
        ).fetchall()

    if not rows:
        messagebox.showinfo("Lista", "Nenhuma senha salva.", parent=root)
        return

    texto = ""
    for service, user, pwd in rows:
        decrypted = cipher.decrypt(pwd).decode()
        texto += (
            f"Serviço: {service}\n"
            f"Usuário: {user}\n"
            f"Senha: {decrypted}\n\n"
        )

    messagebox.showinfo("Senhas", texto, parent=root)

def buscar_servico(root, cipher):
    termo = simpledialog.askstring(
        "Buscar serviço",
        "Digite o nome do serviço:",
        parent=root
    )

    if not termo:
        return

    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute(
            """
            SELECT service, username, password
            FROM users
            WHERE service LIKE ?
            """,
            (f"%{termo}%",)
        ).fetchall()

    if not rows:
        messagebox.showinfo(
            "Resultado",
            "Nenhum serviço encontrado.",
            parent=root
        )
        return

    texto = ""
    for service, user, pwd in rows:
        decrypted = cipher.decrypt(pwd).decode()
        texto += (
            f"Serviço: {service}\n"
            f"Usuário: {user}\n"
            f"Senha: {decrypted}\n\n"
        )

    messagebox.showinfo("Resultados", texto, parent=root)

# ================= MAIN =================
def main():
    root = tk.Tk()
    root.withdraw()

    init_db()
    setup_master(root)
    cipher = check_master(root)

    root.deiconify()
    root.title("Gerenciador de Senhas Seguro")
    root.geometry("300x260")
    root.resizable(False, False)

    tk.Button(
        root, text="Salvar Senha",
        width=25,
        command=lambda: salvar_senha(root, cipher)
    ).pack(pady=8)

    tk.Button(
        root, text="Buscar por Serviço",
        width=25,
        command=lambda: buscar_servico(root, cipher)
    ).pack(pady=8)

    tk.Button(
        root, text="Listar Senhas",
        width=25,
        command=lambda: listar_senhas(root, cipher)
    ).pack(pady=8)

    tk.Button(
        root, text="Sair",
        width=25,
        command=root.destroy
    ).pack(pady=8)

    root.mainloop()

if __name__ == "__main__":
    main()
