# 🔐 Gerenciador de Senhas Seguro em Python

Um gerenciador de senhas moderno e seguro, criado em Python utilizando:
- `CustomTkinter` para interface profissional
- `SQLite` para armazenamento local
- `PBKDF2 + SHA256` para derivação de chave
- `Fernet (AES)` para criptografia das senhas
- Tela de Master Password com tentativas limitadas e verificação

---

## 📁 Estrutura do Projeto

- **Python 3**
- **Tkinter** (interface gráfica)
- **SQLite** (banco de dados local)
- **Cryptography / Fernet (AES)** para criptografia
- **PBKDF2-HMAC-SHA256 + salt** para derivar chaves seguras
- **Hash SHA-256** para autenticação da senha master

---

## 🚀 Funcionalidades

- 🔑 Autenticação com senha master
- 🪪 Criação de senha master com SALT e hash SHA-256
- 🧠 Derivação de chave com PBKDF2HMAC
- 🔐 Criptografia dos dados com Fernet (AES)
- 💾 Armazenamento local usando SQLite
- 🪟 Interface gráfica com botões e funções

---

## 🗺️ Interface - Botões e Funções

| Botão / Ação      | Função                                      |
| ----------------- | ------------------------------------------- |
| ➕ Adicionar Senha | Salva uma nova senha criptografada no banco |
| 🔍 Mostrar Senhas | Exibe senhas descriptografadas na tela      |
| 🗑️ Deletar Senha | Remove uma senha selecionada                |
| 🔐 Login / Logout | Gerencia autenticação com senha master      |

---

##📜 Licença

Este é um projeto livre para estudo e uso pessoal.
🚫 Não é permitido uso comercial sem autorização.

---

## 🛡️ Segurança Utilizada

### 🔑 Autenticação
- Senha master protegida com **SHA-256 + SALT**
- Arquivo de autenticação: `master.dat`

### 🔐 Criptografia dos dados
- Derivação de chave usando:
```python
PBKDF2HMAC(SHA256, 32 bytes, 390.000 iterações)

