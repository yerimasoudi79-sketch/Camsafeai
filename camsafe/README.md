# CAMSAFE AI

**L'IA au service de la cybersécurité et du patriotisme numérique au Cameroun.**

Plateforme web de détection de menaces numériques : liens de phishing, SMS/emails frauduleux et contenus médias suspects, avec tableau de bord statistique et signalement communautaire.

> Prototype fonctionnel réalisé dans le cadre d'un dossier de candidature, porté par **Yaya Zacharia**, étudiant en Génie Logiciel (BTS GL — ISSTMADD Ngaoundéré).

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Démarrage rapide](#démarrage-rapide)
- [Architecture du projet](#architecture-du-projet)
- [Configuration](#configuration)
- [Déploiement](#déploiement)
- [Limites connues et pistes d'évolution](#limites-connues-et-pistes-dévolution)

---

## Fonctionnalités

| Module | Description |
|---|---|
| 🔍 **Vérification de liens** | Détection heuristique de phishing : typosquatting, usurpation de marque, TLD à risque, raccourcisseurs, absence de HTTPS... |
| 📩 **Vérification de messages** | Analyse de SMS/emails pour repérer l'ingénierie sociale : urgence artificielle, promesses de gain, demandes de données sensibles |
| 🖼️ **Vérification de médias** | Premier niveau d'analyse de fichiers image/vidéo (métadonnées, indices de manipulation) |
| 📊 **Tableau de bord** | Statistiques globales, évolution des menaces dans le temps, répartition par type |
| 👥 **Signalement communautaire** | Les citoyens peuvent signaler une menace rencontrée pour alerter les autres utilisateurs |
| 🔐 **Comptes utilisateurs** | Inscription, connexion, historique personnel des analyses |
| 🔌 **API JSON** | Endpoints `/api/analyse/url` et `/api/stats`, prêts pour une future application mobile |

---

## Démarrage rapide

### Prérequis

- Python 3.10 ou supérieur

### Windows

1. Installer [Python 3.10+](https://www.python.org/downloads/) en cochant **"Add Python to PATH"**.
2. Double-cliquer sur `lancer_windows.bat`.
3. Ouvrir un navigateur sur l'adresse affichée (`http://127.0.0.1:5000`).

### macOS / Linux

```bash
./lancer_mac_linux.sh
```

### Installation manuelle

```bash
python -m venv venv
source venv/bin/activate       # Windows : venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

Puis ouvrir **http://127.0.0.1:5000**.

Au premier lancement, la base de données SQLite est créée automatiquement et pré-remplie avec des données de démonstration, afin que le tableau de bord ne soit pas vide.

---

## Architecture du projet

```
camsafe/
├── app.py                     # Application Flask : routes, auth, logique de vue
├── camsafe_core/
│   ├── database.py            # Connexion SQLite, schéma, données de démonstration
│   ├── detection.py           # Moteur de détection heuristique (règles + scoring)
│   └── stats.py                # Agrégations pour le tableau de bord
├── templates/                  # Vues Jinja2
│   ├── base.html
│   ├── index.html
│   ├── check_url.html / check_message.html / check_media.html
│   ├── dashboard.html / community.html / report.html
│   ├── login.html / register.html
│   └── about.html
├── static/
│   ├── css/style.css           # Design système (thème sombre, accents drapeau CM)
│   ├── js/main.js
│   └── img/                    # Favicon, fond mosaïque Cameroun (guilloché CNI)
├── instance/                   # Généré à l'exécution — non versionné
│   ├── camsafe.db
│   └── uploads/
├── requirements.txt
├── render.yaml                 # Configuration de déploiement Render
├── .env.example                # Modèle de variables d'environnement
├── lancer_windows.bat
└── lancer_mac_linux.sh
```

### Stack technique

`Python` · `Flask` · `SQLite` · `Jinja2` · `Chart.js` — architecture prête à accueillir de vrais modèles ML (TensorFlow/scikit-learn) et une application mobile Flutter consommant l'API JSON existante.

---

## Configuration

Le projet fonctionne sans configuration en local. Pour un déploiement, copier `.env.example` en `.env` et définir une vraie clé secrète :

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # à coller dans SECRET_KEY
```

| Variable | Description | Défaut |
|---|---|---|
| `SECRET_KEY` | Clé de signature des sessions Flask | valeur de développement (à changer en prod) |
| `PORT` | Port d'écoute du serveur | `5000` |

---

## Déploiement

Le projet inclut un `render.yaml` prêt à l'emploi pour [Render](https://render.com/) :

```bash
gunicorn app:app
```

Pour tout autre hébergeur compatible WSGI (Railway, Fly.io, PythonAnywhere...), le point d'entrée est `app:app` et la seule variable obligatoire à définir est `SECRET_KEY`.

---

## Limites connues et pistes d'évolution

Le moteur de détection actuel (`camsafe_core/detection.py`) repose sur des **règles et heuristiques explicites** (mots-clés, structure de domaine, métadonnées de fichiers) — pas encore sur un modèle de deep learning entraîné. Le score produit reste néanmoins cohérent, déterministe et explicable, et l'architecture est conçue pour qu'un vrai modèle (CNN pour la détection de deepfakes, NLP pour l'analyse de texte) puisse être branché plus tard sans changer la structure du projet.

Pistes pour la suite :

- Entraîner et intégrer de vrais modèles ML (TensorFlow) sur des jeux de données de phishing / deepfakes
- Migrer vers PostgreSQL pour un usage en production à plus grande échelle
- Construire l'application mobile Flutter en consommant l'API JSON déjà exposée
- Ajouter un rôle modérateur pour valider les signalements communautaires
- Ajouter l'authentification à deux facteurs pour les comptes entreprises/administrations

---

*Projet développé avec Claude (Anthropic) comme assistant de développement.*
