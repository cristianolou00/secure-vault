@echo off
title SecureVault - Cofre Criptografado
echo A iniciar o SecureVault...
python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Ocorreu um erro ao iniciar a aplicacao.
    pause
)
