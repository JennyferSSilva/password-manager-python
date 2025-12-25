# 🔐 Gerenciador de Senhas Seguro em Python

Um gerenciador de senhas local com **criptografia avançada**, interface gráfica em Tkinter e armazenamento protegido em SQLite.  
Agora utilizando **PBKDF2 + Fernet**, limite de tentativas da senha master e busca otimizada por serviços.

---
## 📁 Estrutura do Projeto
```plaintext

projeto-gerenciador-senhas/
├── app.py                    # Arquivo principal da aplicação Flask
├── requirements.txt          # Dependências do projeto
├── README.md                 # Documentação do projeto
│
├── database/
│   └── senhas.db             # Banco de dados SQLite
│
├── static/
│   ├── css/
│   │   └── style.css         # Arquivo de estilos da interface
│   ├── img/
│   │   └── logo.png          # (Opcional) Imagens do sistema
│
├── templates/
│   ├── index.html            # Página inicial
│   ├── login.html            # Tela de login
│   ├── cadastro.html         # Tela de cadastro
│   └── painel.html           # Painel principal do usuário
│
└── utils/
    ├── security.py           # Funções de criptografia e hashing
    ├── database.py           # Funções auxiliares para o banco de dados
    └── interface.py          # Controle dos botões e funções da interface


---

## 🚀 Tecnologias Utilizadas
- **Python 3**
- **Tkinter** (interface gráfica)
- **SQLite** (banco de dados local)
- **Cryptography / Fernet (AES)** para criptografia
- **PBKDF2-HMAC-SHA256 + salt** para derivar chaves seguras
- **Hash SHA-256** para autenticação da senha master

---

## 🚀 Funcionalidades

| Função | Status |
|--------|--------|
| Criar senha master na primeira execução | ✔️ |
| Verificação da senha master ao iniciar | ✔️ |
| Criptografia de senhas com Fernet | ✔️ |
| Salvar novas senhas | ✔️ |
| Listar todas as senhas | ✔️ |
| Buscar senhas por serviço | ✔️ |
| **Alterar senha existente** | ✔️ *novo* |
| **Deletar senha existente** | ✔️ *novo* |
| Botão "Sair" reorganizado como último item | ✔️ |
---

## 🗺️ Interface - Botões e Funções

| Botão                | O que faz                                      |
|----------------------|-------------------------------------------------|
| **Salvar Senha**     | Adiciona um novo registro criptografado         |
| **Buscar por Serviço** | Pesquisa por nome do serviço no banco de dados |
| **Listar Senhas**    | Mostra todos os serviços e usuários cadastrados |
| **Alterar Senha**    | Atualiza a senha armazenada de um serviço       |
| **Deletar Senha**    | Remove definitivamente uma senha do banco       |
| **Sair**             | Encerra o programa e fecha a interface          |
---

## 🛡️ Segurança Utilizada

### 🔑 Autenticação
- Senha master protegida com **SHA-256 + SALT**
- Arquivo de autenticação: `master.dat`

### 🔐 Criptografia dos dados
- Derivação de chave usando:
```python
PBKDF2HMAC(SHA256, 32 bytes, 390.000 iterações)

---

## 🚀 Como Rodar o Projeto

### **1️⃣ Criar ambiente virtual (opcional, mas recomendado)**
```bash
python -m venv venv
source venv/bin/activate     # Linux/Mac
venv\Scripts\activate        # Windows

### **2️⃣ Instalar dependências**
```bash
pip install cryptography

### **3️⃣ Executar o programa**
```bash
python gui_password_manager.py

---

## ✏️ Edição e Manutenção

### **Alterar o código (opcional)**
```bash
git add .
git commit -m "Atualizações na interface e gerenciamento de senhas"
git push

---

## 📄 Licença
Projeto livre para **estudo e uso pessoal**.  
Não é permitido uso comercial sem autorização do autor.
