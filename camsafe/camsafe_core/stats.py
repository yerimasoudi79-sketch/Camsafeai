"""
Calculs statistiques pour le tableau de bord CAMSAFE AI.
"""
from datetime import datetime, timedelta
from collections import defaultdict


def get_global_stats(db):
    total = db.execute('SELECT COUNT(*) as c FROM reports').fetchone()['c']
    high = db.execute("SELECT COUNT(*) as c FROM reports WHERE severity = 'high'").fetchone()['c']
    medium = db.execute("SELECT COUNT(*) as c FROM reports WHERE severity = 'medium'").fetchone()['c']
    low = db.execute("SELECT COUNT(*) as c FROM reports WHERE severity = 'low'").fetchone()['c']
    users = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    community = db.execute('SELECT COUNT(*) as c FROM reports WHERE community_flag = 1').fetchone()['c']

    return {
        'total_analyses': total,
        'high_risk': high,
        'medium_risk': medium,
        'low_risk': low,
        'registered_users': users,
        'community_reports': community,
        'protection_rate': round(((high + medium) / total * 100), 1) if total else 0,
    }


def get_threat_timeline(db, days=14):
    rows = db.execute('SELECT created_at, severity FROM reports').fetchall()
    buckets = defaultdict(lambda: {'high': 0, 'medium': 0, 'low': 0})

    today = datetime.utcnow().date()
    for i in range(days):
        day = today - timedelta(days=days - 1 - i)
        buckets[day.isoformat()]  # ensure key exists in order

    for row in rows:
        try:
            d = datetime.fromisoformat(row['created_at']).date()
        except (ValueError, TypeError):
            continue
        key = d.isoformat()
        if key in buckets:
            sev = row['severity'] or 'low'
            buckets[key][sev] = buckets[key].get(sev, 0) + 1

    labels = list(buckets.keys())
    return {
        'labels': labels,
        'high': [buckets[d]['high'] for d in labels],
        'medium': [buckets[d]['medium'] for d in labels],
        'low': [buckets[d]['low'] for d in labels],
    }


def get_threat_type_breakdown(db):
    rows = db.execute('SELECT kind, COUNT(*) as c FROM reports GROUP BY kind').fetchall()
    labels_map = {'url': 'Liens / URLs', 'message': 'SMS / Emails', 'media': 'Médias (images/vidéos)'}
    labels = [labels_map.get(row['kind'], row['kind']) for row in rows]
    counts = [row['c'] for row in rows]
    return {
        'labels': labels,
        'counts': counts,
    }
