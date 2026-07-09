"""
CAMSAFE AI - Plateforme de cybersécurité et de sensibilisation numérique
Point d'entrée principal de l'application Flask.
"""
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from camsafe_core.database import init_db, get_db
from camsafe_core.detection import analyze_url, analyze_sms_email, analyze_deepfake_metadata
from camsafe_core import stats as stats_module

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'camsafe-ai-dev-secret-change-in-production')
app.config['DATABASE'] = os.path.join(BASE_DIR, 'instance', 'camsafe.db')
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'instance', 'uploads')

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

with app.app_context():
    init_db(app.config['DATABASE'])


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def current_user():
    if 'user_id' not in session:
        return None
    db = get_db(app.config['DATABASE'])
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return user


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Connecte-toi pour accéder à cette page.", "warning")
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    return dict(current_user=current_user())


# ---------------------------------------------------------------
# Pages publiques
# ---------------------------------------------------------------

@app.route('/')
def index():
    db = get_db(app.config['DATABASE'])
    global_stats = stats_module.get_global_stats(db)
    recent_alerts = db.execute(
        'SELECT * FROM reports WHERE severity = "high" ORDER BY created_at DESC LIMIT 5'
    ).fetchall()
    return render_template('index.html', stats=global_stats, recent_alerts=recent_alerts)


@app.route('/a-propos')
def about():
    return render_template('about.html')


# ---------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------

@app.route('/inscription', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'citoyen')

        if not name or not email or not password:
            flash("Merci de remplir tous les champs.", "error")
            return render_template('register.html')

        db = get_db(app.config['DATABASE'])
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash("Un compte existe déjà avec cet email.", "error")
            return render_template('register.html')

        db.execute(
            'INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
            (name, email, generate_password_hash(password), role, datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Compte créé avec succès. Connecte-toi.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/connexion', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db(app.config['DATABASE'])
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user is None or not check_password_hash(user['password_hash'], password):
            flash("Email ou mot de passe incorrect.", "error")
            return render_template('login.html')

        session.clear()
        session['user_id'] = user['id']
        flash(f"Bienvenue, {user['name']} !", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/deconnexion')
def logout():
    session.clear()
    flash("Tu as été déconnecté.", "info")
    return redirect(url_for('index'))


# ---------------------------------------------------------------
# Tableau de bord
# ---------------------------------------------------------------

@app.route('/tableau-de-bord')
@login_required
def dashboard():
    db = get_db(app.config['DATABASE'])
    user = current_user()

    my_reports = db.execute(
        'SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
        (user['id'],)
    ).fetchall()

    global_stats = stats_module.get_global_stats(db)
    threat_timeline = stats_module.get_threat_timeline(db)
    threat_types = stats_module.get_threat_type_breakdown(db)

    return render_template(
        'dashboard.html',
        my_reports=my_reports,
        stats=global_stats,
        timeline=threat_timeline,
        threat_types=threat_types
    )


# ---------------------------------------------------------------
# Outils de détection
# ---------------------------------------------------------------

@app.route('/verifier-url', methods=['GET', 'POST'])
def check_url():
    result = None
    submitted_url = ''
    if request.method == 'POST':
        submitted_url = request.form.get('url', '').strip()
        if submitted_url:
            result = analyze_url(submitted_url)
            _log_analysis(kind='url', target=submitted_url, result=result)
    return render_template('check_url.html', result=result, submitted_url=submitted_url)


@app.route('/verifier-message', methods=['GET', 'POST'])
def check_message():
    result = None
    submitted_text = ''
    if request.method == 'POST':
        submitted_text = request.form.get('message', '').strip()
        if submitted_text:
            result = analyze_sms_email(submitted_text)
            _log_analysis(kind='message', target=submitted_text[:120], result=result)
    return render_template('check_message.html', result=result, submitted_text=submitted_text)


@app.route('/verifier-media', methods=['GET', 'POST'])
def check_media():
    result = None
    filename = None
    if request.method == 'POST':
        file = request.files.get('media_file')
        if file and file.filename:
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            result = analyze_deepfake_metadata(filepath, filename)
            _log_analysis(kind='media', target=filename, result=result)
    return render_template('check_media.html', result=result, filename=filename)


def _log_analysis(kind, target, result):
    db = get_db(app.config['DATABASE'])
    user = current_user()
    db.execute(
        '''INSERT INTO reports (user_id, kind, target, verdict, score, severity, details, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            user['id'] if user else None,
            kind,
            target,
            result['verdict'],
            result['score'],
            result['severity'],
            result.get('explanation_raw', ''),
            datetime.utcnow().isoformat()
        )
    )
    db.commit()


# ---------------------------------------------------------------
# Signalement communautaire
# ---------------------------------------------------------------

@app.route('/signaler', methods=['GET', 'POST'])
def report_threat():
    if request.method == 'POST':
        db = get_db(app.config['DATABASE'])
        user = current_user()
        kind = request.form.get('kind', 'autre')
        target = request.form.get('target', '').strip()
        description = request.form.get('description', '').strip()

        if not target:
            flash("Merci d'indiquer l'élément à signaler (lien, numéro, contenu...).", "error")
            return render_template('report.html')

        db.execute(
            '''INSERT INTO reports (user_id, kind, target, verdict, score, severity, details, created_at, community_flag)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)''',
            (
                user['id'] if user else None,
                kind,
                target,
                'signalé par la communauté',
                75,
                'medium',
                description,
                datetime.utcnow().isoformat()
            )
        )
        db.commit()
        flash("Merci ! Ton signalement a été enregistré et sera examiné.", "success")
        return redirect(url_for('community'))

    return render_template('report.html')


@app.route('/communaute')
def community():
    db = get_db(app.config['DATABASE'])
    reports = db.execute(
        'SELECT * FROM reports WHERE community_flag = 1 ORDER BY created_at DESC LIMIT 30'
    ).fetchall()
    return render_template('community.html', reports=reports)


# ---------------------------------------------------------------
# API JSON (pour extension mobile / future app Flutter)
# ---------------------------------------------------------------

@app.route('/api/analyse/url', methods=['POST'])
def api_check_url():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'url manquante'}), 400
    result = analyze_url(url)
    return jsonify(result)


@app.route('/api/stats')
def api_stats():
    db = get_db(app.config['DATABASE'])
    return jsonify(stats_module.get_global_stats(db))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('PORT') is None  # debug seulement en local
    print("=" * 60)
    print(" CAMSAFE AI - Démarrage du serveur")
    if debug_mode:
        print(" Ouvre ton navigateur sur : http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
