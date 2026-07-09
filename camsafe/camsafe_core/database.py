"""
Gestion de la base de données SQLite pour CAMSAFE AI.
"""
import sqlite3
from datetime import datetime, timedelta
import random

_connection_cache = {}


def get_db(db_path):
    if db_path not in _connection_cache:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        _connection_cache[db_path] = conn
    return _connection_cache[db_path]


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'citoyen',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    verdict TEXT,
    score INTEGER,
    severity TEXT,
    details TEXT,
    community_flag INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""


def init_db(db_path):
    conn = get_db(db_path)
    conn.executescript(SCHEMA)
    conn.commit()

    # Peupler avec des données de démonstration si la table est vide,
    # pour que le tableau de bord et la carte des menaces ne soient pas vides
    # à la première utilisation.
    count = conn.execute('SELECT COUNT(*) as c FROM reports').fetchone()['c']
    if count == 0:
        _seed_demo_data(conn)


def _seed_demo_data(conn):
    """Insère des signalements factices réalistes pour la démonstration."""
    demo_kinds = ['url', 'message', 'media']
    demo_targets = [
        'mtn-cameroon-bonus-gratuit.com',
        'Vous avez gagné 500 000 FCFA, cliquez ici',
        'orange-money-verification.net',
        'video_ministre_declaration.mp4',
        'camtel-facture-impayee.info',
        '+237 6XX XX XX XX - SMS suspect gains loterie',
        'campay-secure-login.support',
        'photo_profil_generee.jpg',
        'ecobank-alert-compte-bloque.com',
        'Message WhatsApp: investissement crypto garanti 300%',
    ]
    severities = ['high', 'medium', 'low']

    now = datetime.utcnow()
    for i in range(42):
        days_ago = random.randint(0, 29)
        created = now - timedelta(days=days_ago, hours=random.randint(0, 23))
        severity = random.choices(severities, weights=[0.35, 0.4, 0.25])[0]
        score = {'high': random.randint(75, 98), 'medium': random.randint(45, 74), 'low': random.randint(10, 44)}[severity]
        conn.execute(
            '''INSERT INTO reports (user_id, kind, target, verdict, score, severity, details, community_flag, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                None,
                random.choice(demo_kinds),
                random.choice(demo_targets),
                'contenu suspect détecté' if severity != 'low' else 'contenu probablement sûr',
                score,
                severity,
                'Donnée de démonstration générée automatiquement.',
                random.choice([0, 0, 1]),
                created.isoformat()
            )
        )
    conn.commit()
