#!/bin/bash
echo "============================================================"
echo "  CAMSAFE AI - Installation et démarrage"
echo "============================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERREUR] Python 3 n'est pas installé."
    echo "Installe-le depuis https://www.python.org/downloads/"
    exit 1
fi

cd "$(dirname "$0")"

echo "[1/3] Création de l'environnement virtuel..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

echo "[2/3] Installation des dépendances..."
source venv/bin/activate
pip install -r requirements.txt --quiet

echo "[3/3] Démarrage du serveur CAMSAFE AI..."
echo ""
echo "Ouvre ton navigateur sur : http://127.0.0.1:5000"
echo "(Ctrl+C pour arrêter le serveur)"
echo ""
python3 app.py
