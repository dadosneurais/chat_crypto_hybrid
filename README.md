# SecureChat

SecureChat é um **chat seguro em linha de comando** que utiliza **criptografia híbrida**, combinando AES para criptografia simétrica das mensagens e RSA para criptografia da chave de sessão. Este projeto é ideal para aprendizado de criptografia aplicada a comunicação em rede.

---

## Funcionalidades

- Comunicação entre **cliente e servidor** via TCP.
- **Criptografia híbrida**:
  - AES-256 para criptografia das mensagens.
  - RSA-2048 para proteção da chave AES.
- **Armazenamento local da conversa** em texto puro (`chat.txt`).
- Interface mínima **CLI (linha de comando)**.
- Multiusuário limitado: o servidor pode aceitar múltiplas conexões (configurável via `s.listen(n)`).

---

## Requisitos

- Python 3.8 ou superior
- Biblioteca requerida:
  ```bash
  pip install pycryptodome
