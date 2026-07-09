@echo off
title CAMSAFE AI - Lancement du serveur
echo ============================================================
echo   CAMSAFE AI - Installation et demarrage
echo ============================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo Telecharge Python sur https://www.python.org/downloads/
    echo IMPORTANT : coche "Add Python to PATH" pendant l'installation.
    pause
    exit /b
)

echo [1/3] Creation de l'environnement virtuel...
if not exist venv (
    python -m venv venv
)

echo [2/3] Installation des dependances...
call venv\Scripts\activate.bat
pip install -r requirements.txt --quiet

echo [3/3] Demarrage du serveur CAMSAFE AI...
echo.
echo Ouvre ton navigateur sur : http://127.0.0.1:5000
echo (Ferme cette fenetre pour arreter le serveur)
echo.
python app.py

pause
