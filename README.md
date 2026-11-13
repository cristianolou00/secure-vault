# 🛡️ SecureVault — Gestor Criptografado Profissional (100% Offline)

O **SecureVault** é um cofre criptográfico desktop profissional, desenhado para proteção de credenciais, chaves confidenciais e documentos sensíveis, com padrão de segurança militar (**Argon2id + AES-256-GCM**), sem dependência de serviços em nuvem ou servidores externos.

---

## ⚡ Como Usar Imediatamente (Sem Instalar Nada)

Tens o executável nativo compilado diretamente na raiz do projeto:

👉 **Duplo clique em `SecureVault.exe`**  
*(Podes mover este ficheiro para qualquer computador Windows ou pen USB — funciona de forma 100% autónoma, sem necessidade de ter o Python instalado).*

---

## 🌟 Funcionalidades Comerciais

### 1. 🔑 Gestão Completa de Credenciais
* **CRUD Completo:** Adiciona, edita, categoriza e elimina credenciais (Logins, Chaves de API, Cartões, Servidores, Notas Confidenciais).
* **Pesquisa Instantânea:** Filtro em tempo real por título, utilizador ou categoria.
* **Cópia Segura com Autodestruição:** Ao clicares em "Copiar Segura", a senha é copiada para a área de transferência do Windows e **apagada automaticamente da memória após 30 segundos**, impedindo que fique no histórico do clipboard.
* **Medidor de Entropia em Tempo Real:** Calcula matematicamente os bits de entropia de cada palavra-passe e classifica-a (*Muito Fraca*, *Fraca*, *Média*, *Forte*, *Excelente*).

### 2. 🌐 Verificação de Senhas Vazadas na Internet ($k$-Anonymity)
* **Integração com HaveIBeenPwned:** Verifica se as tuas senhas constam em mais de 800 milhões de credenciais expostas na Dark Web.
* **Privacidade Absoluta com $k$-Anonymity:** A senha NUNCA sai do computador. Calcula-se o hash SHA-1 da senha e enviam-se apenas os primeiros 5 caracteres para a API. A comparação dos restantes 35 caracteres é realizada **100% localmente** no teu PC.

### 3. 🔒 Bloqueio Automático por Inatividade (Auto-Lock)
* **Proteção contra Acesso Físico:** Se o utilizador se afastar do computador, a app deteta a ausência de interação (rato/teclado) e bloqueia o cofre automaticamente.
* **Destruição Imediata de Memória:** Ao bloquear, as chaves de 256 bits são imediatamente sobrescritas com zeros binários (`ctypes.memset`) na RAM.
* **Tempo Configurável:** 1 minuto, 5 minutos, 15 minutos, 30 minutos ou Desativado.

### 4. 📁 Ficheiros e Documentos Encriptados (Armazenamento Seguro)
* Guarda **PDFs, imagens, contratos, chaves privadas SSH** diretamente dentro do teu cofre binário encriptado.
* Extrai e desencripta qualquer documento de volta para o disco com um clique.

### 5. 🛡️ Auditoria de Saúde de Segurança (Security Audit Engine)
* **Health Score do Cofre (0% a 100%):** Avaliação contínua da postura de segurança.
* **Varredura Global de Fugas:** Testa todas as credenciais do cofre em massa com um único clique.
* **Detetor de Senhas Reutilizadas:** Alerta sobre senhas idênticas partilhadas por vários serviços (eliminando o risco de invasões em cadeia).
* **Detetor de Senhas Fracas:** Lista de credenciais que precisam de ser fortalecidas.

### 6. ⚡ Gerador Criptográfico de Palavras-passe
* Baseado no módulo `secrets` do sistema operativo (entropia do kernel).
* Comprimento configurável (8 a 48 caracteres), filtros para maiúsculas, minúsculas, números e símbolos, com garantia de inclusão de todos os conjuntos selecionados.

### 7. ⚙️ Definições, Cópias de Segurança e Portabilidade
* **Alteração Segura da Palavra-passe Mestre:** Re-deriva uma nova chave com Argon2id, gera um novo Salt e Nonce e re-encripta todo o cofre de forma atómica.
* **Importação/Exportação CSV:** Compatível com ficheiros CSV do Google Chrome, Bitwarden e KeePass.
* **Cópia de Segurança Integral:** Gera cópias cifradas `.vaultbackup` para guardar em discos externos ou na nuvem sem risco.

---

## 🔬 Arquitetura de Cibersegurança

| Componente | Algoritmo / Mecanismo | Parâmetros / Detalhes |
|---|---|---|
| **Derivação de Chave (KDF)** | **Argon2id** (Vencedor do PHC) | 64 MiB de RAM, 2 iterações, 4 lanes, Salt de 16 bytes. Resistente a ataques de GPU/ASIC. |
| **Cifra Autenticada** | **AES-256-GCM** (NIST SP 800-38D) | Chave de 256 bits, Nonce único de 12 bytes por gravação, Tag de Autenticação de 16 bytes. |
| **Integridade de Cabeçalho** | **AAD (Associated Authenticated Data)** | Assinatura criptográfica dos Magic Bytes (`b"VAUL"`) e Versão (`0x0001`). Impede adulteração de formato. |
| **Privacidade em Rede** | **$k$-Anonymity (HaveIBeenPwned)** | Hash SHA-1 truncado a 5 caracteres de prefixo. A API nunca tem acesso à senha ou ao hash completo. |
| **Higiene de Memória RAM** | **`ctypes.memset` nativo em C** | Preenchimento forçado de buffers com zeros (`0x00`) para prevenir extração de senhas em *memory dumps*. |
| **Gravação no Disco** | **Escrita Atómica (ACID)** | Gravação temporária + `os.fsync()` no hardware + `os.replace()`. Impossível corromper o ficheiro em falhas de energia. |

---

## 🧪 Suite de Testes Automatizada
Para validar a integridade criptográfica e funcional:
```powershell
python -m unittest tests/test_vault.py
```
*(9 testes unitários cobrindo ciclo AES-GCM, KDF Argon2id, k-Anonymity SHA-1, rejeição de senhas erradas, deteção de adulteração de bits, serialização de ficheiros, exportação/importação CSV e alteração de chave mestre).*
