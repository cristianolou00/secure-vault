"""
Gerador Criptograficamente Seguro de Palavras-passe (generator.py)

SEGURANÇA:
Utiliza o módulo 'secrets' do Python (que consome entropia do sistema operativo
via /dev/urandom ou CryptGenRandom no Windows), garantindo que os números
não são previsíveis como no módulo 'random' padrão.
"""

import math
import secrets
import string
from typing import Tuple

UPPERCASE_CHARS = string.ascii_uppercase
LOWERCASE_CHARS = string.ascii_lowercase
DIGIT_CHARS = string.digits
SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Gera uma palavra-passe aleatória e criptograficamente segura.
    
    Garante que pelo menos um caractere de cada conjunto selecionado
    está presente na senha final.
    """
    if length < 6:
        length = 6

    char_pool = ""
    guaranteed = []

    if use_upper:
        char_pool += UPPERCASE_CHARS
        guaranteed.append(secrets.choice(UPPERCASE_CHARS))
    if use_lower:
        char_pool += LOWERCASE_CHARS
        guaranteed.append(secrets.choice(LOWERCASE_CHARS))
    if use_digits:
        char_pool += DIGIT_CHARS
        guaranteed.append(secrets.choice(DIGIT_CHARS))
    if use_symbols:
        char_pool += SYMBOL_CHARS
        guaranteed.append(secrets.choice(SYMBOL_CHARS))

    if not char_pool:
        # Se nada for selecionado, usa minúsculas e números por padrão
        char_pool = LOWERCASE_CHARS + DIGIT_CHARS
        guaranteed.append(secrets.choice(char_pool))

    remaining_length = length - len(guaranteed)
    remaining_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]

    # Combina e baralha de forma segura
    password_chars = guaranteed + remaining_chars
    # Fisher-Yates shuffle usando secrets.randbelow
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def calculate_entropy(password: str) -> Tuple[float, str, str]:
    """
    Calcula a entropia teórica da senha em bits:
      E = L * log2(R)
    onde L é o comprimento e R é o tamanho do conjunto de caracteres.
    
    Retorna:
      (bits_entropia, classificacao_texto, cor_hexadecimal)
    """
    if not password:
        return 0.0, "Vazia", "#888888"

    pool_size = 0
    if any(c in UPPERCASE_CHARS for c in password):
        pool_size += 26
    if any(c in LOWERCASE_CHARS for c in password):
        pool_size += 26
    if any(c in DIGIT_CHARS for c in password):
        pool_size += 10
    if any(c in SYMBOL_CHARS or (not c.isalnum() and c not in " \t\r\n") for c in password):
        pool_size += 32

    if pool_size == 0:
        pool_size = 1

    entropy = len(password) * math.log2(pool_size)

    if entropy < 36:
        return entropy, "Muito Fraca", "#EF4444"  # Vermelho
    elif entropy < 50:
        return entropy, "Fraca", "#F97316"        # Laranja
    elif entropy < 65:
        return entropy, "Média", "#FACC15"        # Amarelo
    elif entropy < 80:
        return entropy, "Forte", "#22C55E"        # Verde
    else:
        return entropy, "Excelente", "#10B981"    # Verde Esmeralda
