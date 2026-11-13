"""
Módulo de Verificação de Fugas de Dados Públicas (pwned.py)

IMPLEMENTAÇÃO DO MODELO MATEMÁTICO DE k-ANONYMITY:
Para verificar se uma palavra-passe foi exposta em fugas conhecidas (como LinkedIn,
Adobe, Yahoo, etc.) SEM expor a palavra-passe à internet:

1. Calculamos o hash SHA-1 da senha:
   Ex: "password123" -> "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
2. Dividimos o hash:
   - Prefixo (5 caracteres): "CBFDA"
   - Sufixo (35 caracteres): "C6008F9CAB4083784CBD1874F76618D2A97"
3. Enviamos APENAS os 5 primeiros caracteres para a API do HaveIBeenPwned:
   GET https://api.pwnedpasswords.com/range/CBFDA
4. A API devolve centenas de sufixos de hashes que começam por "CBFDA" e a respetiva contagem.
5. O programa pesquisa LOCALMENTE na lista se o nosso sufixo está lá.

A API NUNCA sabe qual é a nossa senha, nem sequer sabe o hash completo!
"""

import hashlib
import urllib.request
import urllib.error
from typing import Tuple


def check_password_leak(password: str, timeout: float = 5.0) -> Tuple[bool, int]:
    """
    Verifica se a senha consta na base de dados de fugas do HaveIBeenPwned.
    
    Retorna:
      (foi_vazada: bool, contagem_de_fugas: int)
      Se ocorrer erro de rede ou timeout, devolve (False, -1) para não bloquear a app.
    """
    if not password:
        return False, 0

    # 1. Calcular o SHA-1 da senha em maiúsculas
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecureVault-Password-Auditor-Educational-Tool"}
    )

    try:
        # Usa apenas a biblioteca padrão (urllib) sem necessidade de bibliotecas externas (requests)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return False, -1
            data = response.read().decode("utf-8", errors="ignore")

        # 2. Pesquisa local na resposta da API
        for line in data.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            ret_suffix, ret_count = line.split(":", 1)
            if ret_suffix.strip().upper() == suffix:
                count = int(ret_count.strip())
                return True, count

        return False, 0

    except (urllib.error.URLError, TimeoutError, Exception):
        # Em caso de falha de ligação à internet, devolve -1 (indisponível) de forma graciosa
        return False, -1
