# 🔐 Gerenciador de Senhas em Python

Um gerenciador de senhas simples e seguro desenvolvido em **Python**, utilizando **Tkinter** para interface gráfica, **SQLite** para armazenamento local e **criptografia forte** com **PBKDF2 + Fernet**.

Este projeto tem fins **educacionais** e demonstra boas práticas de segurança no armazenamento de senhas.

---

## 🚀 Funcionalidades

- 🔑 Senha master para acesso ao sistema
- 🔐 Criptografia segura das senhas salvas
- 💾 Armazenamento local com SQLite
- 🔎 Busca de senhas por serviço
- 🖥 Interface gráfica simples (Tkinter)
- ❌ Proteção contra vazamento de dados sensíveis

---

## 🛡️ Segurança

O sistema utiliza:

- **PBKDF2 (Password-Based Key Derivation Function 2)**  
  → Deriva uma chave forte a partir da senha master

- **Fernet (AES + HMAC)**  
  → Criptografa e descriptografa as senhas armazenadas

Arquivos sensíveis **não são versionados no GitHub**:
- `passwords.db`
- `master.dat`
- `secret.key`

Esses arquivos são ignorados via `.gitignore`.

---

## 📂 Estrutura do Projeto

