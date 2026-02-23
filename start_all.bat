@echo off
echo ============================================================
echo   Iniciando ambos entornos en paralelo...
echo   QA  -^> http://localhost:5000
echo   PRD -^> http://localhost:5001
echo ============================================================
cd /d "%~dp0"

rem ── Variables de entorno requeridas ──────────────────────────
set SECRET_KEY=1dcd419b3e3352f7a951916f9fd997ed293d42ad3212e9c0ac854e9613d22b11
set FLASK_DEBUG=0

start "VPN-QA" cmd /k "set SECRET_KEY=%SECRET_KEY% && set FLASK_DEBUG=%FLASK_DEBUG% && python webapp.py --env qa"
timeout /t 2 /nobreak >nul
start "VPN-PRD" cmd /k "set SECRET_KEY=%SECRET_KEY% && set FLASK_DEBUG=%FLASK_DEBUG% && python webapp.py --env prd"
echo.
echo Ambos entornos iniciados. Cierra las ventanas para detener.
pause
