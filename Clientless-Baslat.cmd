@echo off
setlocal
cd /d "%~dp0"
title Clientless - Metin2 TR
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -u tools\start_clientless.py %*
) else (
    python -u tools\start_clientless.py %*
)
set "result=%errorlevel%"
echo.
echo Oturum sona erdi. Yukaridaki sonucu kontrol edebilirsiniz.
pause
exit /b %result%
