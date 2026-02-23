@echo off
echo ============================================================
echo   VPN GlobalProtect - Entorno PRODUCCION (puerto 5001)
echo ============================================================
cd /d "%~dp0"

:: Verificar dependencias
python -c "import flask" 2>nul
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Faltan librerias. Intentando instalar dependencias...
    python -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] No se pudo instalar las dependencias automaticamente. 
        echo Ejecute: pip install -r requirements.txt
        pause
        exit /b
    )
)

set ENV=prd
set SECRET_KEY=1dcd419b3e3352f7a951916f9fd997ed293d42ad3212e9c0ac854e9613d22b11
set SMTP_PASS=opqxrpaypoumndbp
python webapp.py --env %ENV%
pause
