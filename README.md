# 🔐 Gerenciador de Senhas Seguro em Python

Um gerenciador de senhas local com **criptografia avançada**, interface gráfica em Tkinter e armazenamento protegido em SQLite.  
Agora utilizando **PBKDF2 + Fernet**, limite de tentativas da senha master e busca otimizada por serviços.

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

## 🛡️ Segurança Utilizada

### 🔑 Autenticação
- Senha master protegida com **SHA-256 + SALT**
- Arquivo de autenticação: `master.dat`

### 🔐 Criptografia dos dados
- Derivação de chave usando:
```python
PBKDF2HMAC(SHA256, 32 bytes, 390.000 iterações)