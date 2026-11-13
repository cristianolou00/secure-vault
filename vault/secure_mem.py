"""
Módulo de Higiene e Gestão Segura de Memória (secure_mem.py)

CONCEITO DE SEGURANÇA:
Em linguagens de alto nível com Garbage Collector (como Python), quando criamos
uma string ou variável com uma senha, o sistema não garante QUANDO ou SE esses
bytes serão removidos da memória RAM.
Se o computador entrar em hibernação (criando hiberfil.sys), fizer swap/paging
para o disco, ou se for inspecionado via dump de memória (ex: Mimikatz ou Process Explorer),
essas credenciais podem ser lidas em texto limpo.

SOLUÇÃO:
Usamos arrays de bytes mutáveis (bytearray) e forçamos o sistema operativo a
sobrescrever fisicamente os blocos de memória com zeros (b'\x00') usando a API nativa
do C ('ctypes.memset') assim que a operação termina.
"""

import ctypes
from typing import Union


def zero_memory(target: Union[bytearray, memoryview]) -> None:
    """
    Sobrescreve diretamente o bloco de memória de um bytearray com zeros binários.
    
    Utiliza ctypes.memset diretamente no endereço de memória física alocado pelo buffer,
    impedindo que otimizações do compilador/interpretador ignorem a limpeza.
    """
    if not isinstance(target, (bytearray, memoryview)):
        return

    length = len(target)
    if length == 0:
        return

    try:
        # Obtém o ponteiro de memória C subjacente ao bytearray
        buffer_type = ctypes.c_char * length
        address = buffer_type.from_buffer(target)
        # Escreve 0 em todos os bytes do bloco de memória
        ctypes.memset(address, 0, length)
    except Exception:
        # Fallback manual caso ctypes falhe em algum ambiente específico
        for i in range(length):
            target[i] = 0


class SecureBuffer:
    """
    Context Manager (bloco 'with') para dados ultrassensíveis (como a chave mestra em bytes).
    
    Garante que, mesmo que ocorra um erro ou exceção no código, os bytes da chave
    são imediatamente destruídos e sobrescritos com zeros na RAM antes de sair do bloco.
    
    Exemplo de uso:
        with SecureBuffer(raw_key_bytes) as secure_key:
            cipher = AESGCM(bytes(secure_key.data))
            # ... processamento ...
        # Aqui, secure_key já foi 100% preenchido com zeros!
    """

    def __init__(self, sensitive_data: Union[bytes, bytearray, str]):
        if isinstance(sensitive_data, str):
            sensitive_bytes = sensitive_data.encode("utf-8")
        elif isinstance(sensitive_data, (bytes, bytearray)):
            sensitive_bytes = sensitive_data
        else:
            raise TypeError("Os dados devem ser bytes, bytearray ou str.")

        # Armazenamos sempre em bytearray mutável para permitir a limpeza física
        self.data = bytearray(sensitive_bytes)

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()

    def get_bytes(self) -> bytes:
        """Retorna uma cópia transitória em bytes para APIs que exijam tipo 'bytes' imutável."""
        return bytes(self.data)

    def destroy(self) -> None:
        """Destrói os dados na memória RAM sobrescrevendo com zeros."""
        if hasattr(self, "data") and self.data is not None:
            zero_memory(self.data)
            # Desaloca a referência
            self.data = bytearray(0)
