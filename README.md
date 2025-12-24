# 🔐 Gerenciador de Senhas Seguro em Python

Um gerenciador de senhas local com **criptografia avançada**, interface gráfica em Tkinter e armazenamento protegido em SQLite.  
Agora utilizando **PBKDF2 + Fernet**, limite de tentativas da senha master e busca otimizada por serviços.

---

## 🚀 Funcionalidades

| Função | Descrição |
|--------|------------|
| Senha Master | Protege o acesso ao sistema |
| PBKDF2 + Salt | Derivação da chave criptográfica com 390.000 iterações |
| Criptografia Fernet | AES + HMAC para proteger as senhas armazenadas |
| Armazenamento Local | Senhas dentro de um banco SQLite local |
| Busca por Serviço | Pesquisa senhas digitando o nome do serviço |
| Listagem com Opção Ocultar | Exibe senhas criptografadas ou descriptografadas conforme escolha |
| 3 Tentativas de Login | Bloqueia o acesso após erros consecutivos |

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

# 📌 COMO ATUALIZAR NO GITHUB (depois do novo README)

No PowerShell:

```powershell
git add README.md
git commit -m "Atualização do README com novas funcionalidades"
git push
