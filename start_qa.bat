@echo off
echo ============================================================
echo   VPN GlobalProtect - Entorno QA (puerto 5000)
echo ============================================================
taskkill /F /IM python.exe /T >nul 2>&1
cd /d "%~dp0"
set ENV=qa
set SECRET_KEY=1dcd419b3e3352f7a951916f9fd997ed293d42ad3212e9c0ac854e9613d22b11
set SMTP_PASS=opqxrpaypoumndbp
python webapp.py --env %ENV%
pause
