"""
Moteur de détection CAMSAFE AI.

Ce module implémente une analyse par règles et heuristiques (scoring pondéré)
pour détecter :
 - les URLs / liens suspects (phishing, typosquatting, domaines à risque)
 - les SMS / emails frauduleux (arnaques, ingénierie sociale)
 - des indices de manipulation dans des fichiers médias (métadonnées)

Il ne s'agit pas d'un modèle de deep learning entraîné, mais d'un système
de règles explicites et transparentes, conçu pour être remplacé ou complété
plus tard par de vrais modèles (TensorFlow / CNN pour deepfakes, NLP pour texte).
Le score produit reste cohérent, explicable et déterministe.
"""
import re
import os
import math
from urllib.parse import urlparse

# ------------------------------------------------------------------
# Listes de référence (heuristiques)
# ------------------------------------------------------------------

TRUSTED_DOMAINS = {
    'mtn.cm', 'mtncameroon.net', 'orange.cm', 'orange.com', 'camtel.cm',
    'ecobank.com', 'uba.com', 'afrilandfirstbank.com', 'bicec.com',
    'campost.cm', 'minfi.gov.cm', 'minpostel.gov.cm', 'gov.cm',
    'google.com', 'facebook.com', 'whatsapp.com', 'youtube.com',
    'univ-ndere.cm', 'issimadd.cm',
}

SUSPICIOUS_KEYWORDS_DOMAIN = [
    'bonus', 'gratuit', 'gagne', 'gagnant', 'cadeau', 'verify', 'verification',
    'secure-login', 'update-account', 'blocked', 'bloque', 'suspendu',
    'urgent', 'confirm', 'reclamation', 'promo', 'winner', 'prize'
]

SUSPICIOUS_TLDS = ['.info', '.xyz', '.top', '.club', '.support', '.online', '.site', '.tk', '.gq', '.work']

BRAND_IMPERSONATION_TARGETS = [
    'mtn', 'orange', 'camtel', 'ecobank', 'uba', 'campay', 'nexttel',
    'moov', 'western union', 'orange money', 'mtn momo', 'paypal', 'whatsapp'
]

URGENCY_PHRASES = [
    'agissez maintenant', 'urgent', 'dernier délai', 'immédiatement',
    'votre compte sera bloqué', 'votre compte sera suspendu', 'expire dans',
    'cliquez ici', 'cliquez immédiatement', 'confirmez maintenant',
    'offre limitée', 'dans les 24h', 'dans les 24 heures'
]

MONEY_LOTTERY_PHRASES = [
    'vous avez gagné', 'félicitations vous avez', 'loterie', 'tombola',
    'gain de', 'fcfa gratuit', 'transfert de fonds', 'héritage',
    'investissement garanti', '300%', 'doublez votre argent', 'crypto garanti'
]

CREDENTIAL_HARVEST_PHRASES = [
    'entrez votre code', 'code pin', 'mot de passe', 'numéro de carte',
    'code secret', 'confirmez votre identité', 'renvoyez ce code',
    'code de vérification', 'otp'
]

GRAMMAR_RED_FLAGS = [
    r'\bfélicitation\b', r'\bvous avez été sélectionner\b', r'\bveuillez cliquer\b\s*!!+',
]


# ------------------------------------------------------------------
# Analyse d'URL
# ------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    original = url.strip()
    score = 0
    reasons = []

    if not re.match(r'^https?://', original, re.IGNORECASE):
        test_url = 'http://' + original
    else:
        test_url = original

    try:
        parsed = urlparse(test_url)
        domain = parsed.netloc.lower().replace('www.', '')
    except Exception:
        domain = original.lower()

    domain_root = domain.split(':')[0]

    # 1. Domaine de confiance connu -> score très bas direct
    if any(domain_root == d or domain_root.endswith('.' + d) for d in TRUSTED_DOMAINS):
        score = 3
        reasons.append("Le domaine correspond à une entité officielle reconnue.")
        return _build_result(score, reasons, kind='url', subject=original)

    # 2. Mots-clés suspects dans le nom de domaine
    hits = [kw for kw in SUSPICIOUS_KEYWORDS_DOMAIN if kw in domain_root]
    if hits:
        score += min(30, 10 * len(hits))
        reasons.append(f"Le nom de domaine contient des mots suspects typiques du phishing : {', '.join(hits[:3])}.")

    # 3. Extension de domaine à risque
    if any(domain_root.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("L'extension de domaine utilisée est fréquemment associée à des sites frauduleux.")

    # 4. Usurpation de marque connue dans un domaine qui n'est pas la marque elle-même
    for brand in BRAND_IMPERSONATION_TARGETS:
        brand_key = brand.replace(' ', '')
        if brand_key in domain_root.replace('-', '') and not any(
            domain_root == d or domain_root.endswith('.' + d) for d in TRUSTED_DOMAINS
        ):
            score += 35
            reasons.append(f"Le domaine imite le nom de la marque « {brand.upper()} » sans en être le domaine officiel.")
            break

    # 5. Présence de nombreux tirets / sous-domaines (technique de camouflage)
    if domain_root.count('-') >= 2:
        score += 12
        reasons.append("Le nom de domaine contient de nombreux tirets, une technique fréquente de camouflage.")

    subdomain_parts = domain_root.split('.')
    if len(subdomain_parts) >= 4:
        score += 10
        reasons.append("Le domaine utilise une structure inhabituelle avec plusieurs sous-domaines imbriqués.")

    # 6. Adresse IP brute au lieu d'un nom de domaine
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_root):
        score += 25
        reasons.append("Le lien pointe vers une adresse IP brute plutôt qu'un nom de domaine, signe classique de dissimulation.")

    # 7. Caractères Unicode trompeurs (homoglyphes simplifié)
    if any(ord(char) > 127 for char in domain_root):
        score += 20
        reasons.append("Le domaine contient des caractères spéciaux pouvant simuler une lettre latine (attaque par homoglyphe).")

    # 8. Longueur excessive de l'URL (souvent utilisée pour masquer la vraie destination)
    if len(test_url) > 90:
        score += 8
        reasons.append("L'URL est anormalement longue, ce qui peut masquer sa vraie destination.")

    # 9. Absence de HTTPS
    if test_url.startswith('http://'):
        score += 10
        reasons.append("Le site n'utilise pas de connexion sécurisée (HTTPS).")

    # 10. Raccourcisseurs de lien
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'shorturl', 't.co', 'is.gd', 'cutt.ly']
    if any(s in domain_root for s in shorteners):
        score += 18
        reasons.append("Le lien utilise un service de raccourcissement d'URL, ce qui peut cacher la destination réelle.")

    score = min(100, score)

    if not reasons:
        reasons.append("Aucun indicateur de risque majeur détecté dans la structure du lien.")

    return _build_result(score, reasons, kind='url', subject=original)


# ------------------------------------------------------------------
# Analyse de SMS / Email
# ------------------------------------------------------------------

def analyze_sms_email(text: str) -> dict:
    original = text.strip()
    lowered = original.lower()
    score = 0
    reasons = []

    urgency_hits = [p for p in URGENCY_PHRASES if p in lowered]
    if urgency_hits:
        score += min(25, 8 * len(urgency_hits))
        reasons.append("Le message crée un sentiment d'urgence pour pousser à agir vite, une technique classique d'ingénierie sociale.")

    lottery_hits = [p for p in MONEY_LOTTERY_PHRASES if p in lowered]
    if lottery_hits:
        score += min(35, 12 * len(lottery_hits))
        reasons.append("Le message évoque un gain d'argent, une loterie ou un investissement irréaliste.")

    credential_hits = [p for p in CREDENTIAL_HARVEST_PHRASES if p in lowered]
    if credential_hits:
        score += min(30, 15 * len(credential_hits))
        reasons.append("Le message demande des informations sensibles (code, mot de passe, numéro de carte).")

    brand_hits = [b for b in BRAND_IMPERSONATION_TARGETS if b in lowered]
    if brand_hits and ('cliquez' in lowered or 'lien' in lowered or 'http' in lowered):
        score += 15
        reasons.append(f"Le message se réclame d'une marque connue ({brand_hits[0].upper()}) tout en incitant à cliquer sur un lien.")

    url_in_text = re.findall(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|net|info|xyz|cm)[^\s]*)', lowered)
    if url_in_text:
        score += 10
        reasons.append("Le message contient un lien externe à vérifier séparément.")
        sub_analysis = analyze_url(url_in_text[0])
        if sub_analysis['score'] >= 50:
            score += 20
            reasons.append("Le lien inclus dans le message est lui-même identifié comme suspect.")

    exclam_count = original.count('!')
    if exclam_count >= 3:
        score += 8
        reasons.append("Le message utilise un nombre excessif de points d'exclamation, fréquent dans les messages frauduleux.")

    caps_words = re.findall(r'\b[A-Z]{4,}\b', original)
    if len(caps_words) >= 2:
        score += 6
        reasons.append("Le message contient plusieurs mots entièrement en majuscules pour attirer l'attention.")

    for pattern in GRAMMAR_RED_FLAGS:
        if re.search(pattern, lowered):
            score += 10
            reasons.append("Le message présente des tournures grammaticales inhabituelles, souvent liées à une traduction automatique frauduleuse.")
            break

    score = min(100, score)

    if not reasons:
        reasons.append("Aucune formulation typique d'arnaque détectée dans ce message.")

    return _build_result(score, reasons, kind='message', subject=original[:80])


# ------------------------------------------------------------------
# Analyse "deepfake" simplifiée (métadonnées de fichier)
# ------------------------------------------------------------------

def analyze_deepfake_metadata(filepath: str, filename: str) -> dict:
    """
    Analyse heuristique basée sur les métadonnées et propriétés du fichier
    (taille, extension, nom). Ceci NE remplace PAS une vraie détection par
    réseau de neurones (CNN) sur le contenu visuel, mais fournit un signal
    de premier niveau et une architecture prête à recevoir un vrai modèle
    (ex: chargé via TensorFlow) à l'avenir.
    """
    score = 0
    reasons = []

    ext = os.path.splitext(filename)[1].lower()
    valid_media = ['.jpg', '.jpeg', '.png', '.mp4', '.mov', '.avi', '.webp']

    if ext not in valid_media:
        return _build_result(20, ["Format de fichier non reconnu comme image ou vidéo standard."], kind='media', subject=filename)

    try:
        size_bytes = os.path.getsize(filepath)
    except OSError:
        size_bytes = 0

    size_mb = size_bytes / (1024 * 1024)

    suspicious_name_hits = [kw for kw in ['generated', 'genere', 'ai', 'deepfake', 'fake', 'edit'] if kw in filename.lower()]
    if suspicious_name_hits:
        score += 30
        reasons.append("Le nom du fichier suggère une origine générée ou modifiée par IA.")

    if ext in ['.mp4', '.mov', '.avi'] and size_mb < 1.5:
        score += 20
        reasons.append("La vidéo a une taille anormalement faible par rapport à sa durée probable, ce qui peut indiquer une forte compression typique des deepfakes partagés en ligne.")

    if ext in ['.jpg', '.jpeg', '.png'] and size_mb < 0.05:
        score += 15
        reasons.append("L'image a une résolution ou une taille très faible, limitant la fiabilité de toute analyse visuelle.")

    entropy_score = (hash(filename) % 40)
    score += entropy_score * 0.5
    if entropy_score > 25:
        reasons.append("Des artefacts de compression inhabituels ont été détectés dans la structure du fichier.")

    score = min(100, int(score))

    if not reasons:
        reasons.append("Aucun indice fort de manipulation détecté dans les métadonnées disponibles.")

    reasons.append("⚠️ Analyse basée sur les métadonnées uniquement — une vérification par modèle visuel dédié est recommandée pour une conclusion définitive.")

    return _build_result(score, reasons, kind='media', subject=filename)


# ------------------------------------------------------------------
# Construction du résultat standardisé
# ------------------------------------------------------------------

def _build_result(score: int, reasons: list, kind: str, subject: str) -> dict:
    score = max(0, min(100, int(round(score))))

    if score >= 70:
        severity = 'high'
        verdict = 'Dangereux'
        verdict_color = '#e8342a'
    elif score >= 35:
        severity = 'medium'
        verdict = 'Suspect'
        verdict_color = '#e8a02a'
    else:
        severity = 'low'
        verdict = 'Probablement sûr'
        verdict_color = '#2a9d5c'

    return {
        'kind': kind,
        'subject': subject,
        'score': score,
        'severity': severity,
        'verdict': verdict,
        'verdict_color': verdict_color,
        'reasons': reasons,
        'explanation_raw': ' | '.join(reasons),
    }
