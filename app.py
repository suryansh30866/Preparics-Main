import os
import hmac
import time
import json
import urllib.request
import urllib.parse
from datetime import timedelta
from functools import wraps
from flask import (
    Flask,
    request,
    session,
    redirect,
    render_template,
    jsonify,
    send_from_directory,
    abort
)
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

app = Flask(__name__, template_folder=TEMPLATES_DIR)

# Security and Session Configuration
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', '90f55210444b111ccca6fc9762daab29f503d39483a4f9bb242ae0602d3f7abe'
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# In production, SESSION_COOKIE_SECURE must be True; it may remain False only for local HTTP development.
cookie_secure_env = os.environ.get('SESSION_COOKIE_SECURE')
if cookie_secure_env is not None:
    is_secure_cookie = cookie_secure_env.strip().lower() in ('true', '1', 'yes', 'on')
else:
    # Automatically enforce True in production (Render, production FLASK_ENV)
    is_secure_cookie = (
        os.environ.get('FLASK_ENV', '').strip().lower() == 'production'
        or os.environ.get('RENDER', '').strip().lower() == 'true'
    )
app.config['SESSION_COOKIE_SECURE'] = is_secure_cookie
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Expected Admin Credentials (from environment)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Batman')
ADMIN_PASSWORD_HASH = os.environ.get(
    'ADMIN_PASSWORD_HASH',
    'scrypt:32768:8:1'
)

# ---------------------------------------------------------------------------
# Brute-force & Rate Limiting Protection (In-Memory per IP)
# ---------------------------------------------------------------------------
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 600  # 10 minutes in seconds
failed_logins = {}

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = failed_logins.get(ip, [])
    valid_attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    failed_logins[ip] = valid_attempts
    return len(valid_attempts) >= MAX_FAILED_ATTEMPTS

def record_failed_attempt(ip: str):
    now = time.time()
    attempts = failed_logins.get(ip, [])
    valid_attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    valid_attempts.append(now)
    failed_logins[ip] = valid_attempts

def reset_failed_attempts(ip: str):
    if ip in failed_logins:
        del failed_logins[ip]

# ---------------------------------------------------------------------------
# Cloudflare Turnstile CAPTCHA Integration (Server-Side)
# ---------------------------------------------------------------------------
TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '0x4AAAAAAE7ba1nzBVSNJs1W')
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

def verify_turnstile(token: str, ip: str = None) -> tuple:
    """
    Validates a Cloudflare Turnstile token via the Cloudflare Siteverify API.
    Returns (is_valid: bool, message: str).
    """
    if not token or not str(token).strip():
        return False, "CAPTCHA challenge verification required. Please complete the CAPTCHA."

    if app.config.get('TESTING') and token == 'test-token':
        return True, "Testing bypass"

    if not TURNSTILE_SECRET_KEY:
        # If running in local dev and secret key is not provided, log and allow for testing
        if os.environ.get('FLASK_ENV') == 'development':
            print("Warning: TURNSTILE_SECRET_KEY is empty in development mode. Allowing bypass for testing.")
            return True, "Development bypass"
        return False, "Turnstile secret key is not configured on the server."

    verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": str(token).strip()
    }
    if ip:
        payload["remoteip"] = ip

    try:
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            verify_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Preparics-Turnstile/1.0"
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("success"):
                return True, "CAPTCHA verified successfully."
            error_codes = result.get("error-codes", [])
            error_details = ", ".join(error_codes) if error_codes else "Verification rejected"
            return False, f"CAPTCHA verification failed ({error_details}). Please try again."
    except Exception as e:
        print(f"Error validating Turnstile token: {e}")
        return False, "Unable to reach CAPTCHA verification service. Please try again."

# ---------------------------------------------------------------------------
# Firebase Realtime Database Integration (Server-Side)
# ---------------------------------------------------------------------------
FIREBASE_DATABASE_URL = os.environ.get(
    "FIREBASE_DATABASE_URL", "https://preparics-8bbcc-default-rtdb.firebaseio.com"
)

def fetch_firebase_users():
    """Retrieve and format all registered users from Firebase Realtime Database."""
    import urllib.request
    import json
    from datetime import datetime

    users_list = []
    try:
        users_url = f"{FIREBASE_DATABASE_URL}/users.json"
        req = urllib.request.Request(users_url, headers={"User-Agent": "Preparics-Admin/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        buy_users = {}
        try:
            buy_url = f"{FIREBASE_DATABASE_URL}/buy%20course%20users.json"
            breq = urllib.request.Request(buy_url, headers={"User-Agent": "Preparics-Admin/1.0"})
            with urllib.request.urlopen(breq, timeout=5) as bresp:
                bdata = json.loads(bresp.read().decode("utf-8"))
                if bdata and isinstance(bdata, dict):
                    buy_users = bdata
        except Exception:
            pass

        if data and isinstance(data, dict):
            for uid, u in data.items():
                if not isinstance(u, dict):
                    continue
                last_login_raw = u.get("lastLoginAt") or u.get("updatedAt")
                last_login_formatted = "-"
                if last_login_raw:
                    try:
                        ts = float(last_login_raw) / 1000 if float(last_login_raw) > 1e11 else float(last_login_raw)
                        last_login_formatted = datetime.fromtimestamp(ts).strftime("%b %d, %Y • %I:%M %p")
                    except Exception:
                        last_login_formatted = str(last_login_raw)

                has_bought_course = uid in buy_users
                users_list.append({
                    "uid": uid,
                    "name": u.get("name") or "Anonymous Student",
                    "email": u.get("email") or "-",
                    "phone": u.get("phone") or u.get("phoneNo") or "-",
                    "city": (u.get("city") or "-").title(),
                    "photoURL": u.get("photoURL") or "",
                    "lastLocation": u.get("lastLocation") or "-",
                    "lastDevice": u.get("lastDevice") or "-",
                    "lastLogin": last_login_formatted,
                    "profileCompleted": u.get("profileCompleted", False),
                    "hasBoughtCourse": has_bought_course,
                    "loginCount": len(u.get("loginHistory", {})) if isinstance(u.get("loginHistory"), dict) else 1
                })
        # Sort users by profile completed or latest entry
        users_list.sort(key=lambda x: x["name"].lower())
    except Exception as e:
        print(f"Warning: Failed to fetch users from Firebase: {e}")

    return users_list

def fetch_firebase_blogs():
    """Retrieve all published blogs from Firebase Realtime Database."""
    import urllib.request
    import json
    blogs_list = []
    try:
        url = f"{FIREBASE_DATABASE_URL}/blogs.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Preparics-Admin/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data and isinstance(data, dict):
                for bid, b in data.items():
                    if isinstance(b, dict):
                        b["id"] = bid
                        blogs_list.append(b)
        blogs_list.sort(key=lambda x: x.get("createdAt", 0), reverse=True)
    except Exception as e:
        print(f"Warning: Failed to fetch blogs from Firebase: {e}")
    return blogs_list


# Authentication Guard Decorator
# ---------------------------------------------------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            if request.path.startswith('/api/') or request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Admin authentication required. Access denied.'
                }), 401
            return redirect('/admin91939')
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------------------------
# Cloudflare Turnstile Public API Endpoints
# ---------------------------------------------------------------------------
@app.route('/api/turnstile-config', methods=['GET'])
def get_turnstile_config():
    """Returns the public Turnstile site key for client widget initialization."""
    return jsonify({
        'success': True,
        'siteKey': TURNSTILE_SITE_KEY
    }), 200

@app.route('/api/verify-turnstile', methods=['POST'])
def api_verify_turnstile():
    """
    Public API endpoint to verify Turnstile token before client-side operations
    such as Firebase Realtime Database writes.
    """
    client_ip = get_client_ip()
    if request.is_json:
        data = request.get_json(silent=True) or {}
        token = data.get('token') or data.get('turnstile_token') or data.get('cf-turnstile-response')
    else:
        token = request.form.get('token') or request.form.get('cf-turnstile-response')

    is_valid, message = verify_turnstile(token, client_ip)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': message
        }), 400

    return jsonify({
        'success': True,
        'message': message
    }), 200

# ---------------------------------------------------------------------------
# Admin Routes (Private Obscure URL: /admin91939)
# ---------------------------------------------------------------------------
@app.route('/admin91939', methods=['GET'])
def admin_login_page():
    if session.get('admin_authenticated'):
        return redirect('/admin91939/dashboard')
    return render_template('admin_login.html', turnstile_site_key=TURNSTILE_SITE_KEY)

@app.route('/admin91939/login', methods=['POST'])
def admin_login():
    client_ip = get_client_ip()

    if is_rate_limited(client_ip):
        return jsonify({
            'success': False,
            'message': 'Too many failed login attempts. Please wait 10 minutes before trying again.'
        }), 429

    if request.is_json:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
        turnstile_token = data.get('turnstile_token') or data.get('cf-turnstile-response', '')
    else:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        turnstile_token = request.form.get('cf-turnstile-response', '')

    # Enforce Turnstile validation BEFORE password checks
    is_valid_turnstile, turnstile_msg = verify_turnstile(turnstile_token, client_ip)
    if not is_valid_turnstile:
        if request.is_json:
            return jsonify({'success': False, 'message': turnstile_msg}), 400
        return render_template('admin_login.html', error=turnstile_msg, turnstile_site_key=TURNSTILE_SITE_KEY), 400

    user_match = hmac.compare_digest(username, ADMIN_USERNAME)
    password_match = check_password_hash(ADMIN_PASSWORD_HASH, password) if ADMIN_PASSWORD_HASH else False

    if user_match and password_match:
        reset_failed_attempts(client_ip)
        session.clear()
        session.permanent = True
        session['admin_authenticated'] = True
        session['admin_user'] = username
        session['login_time'] = time.time()

        if request.is_json:
            return jsonify({'success': True, 'redirect': '/admin91939/dashboard'}), 200
        return redirect('/admin91939/dashboard')
    else:
        record_failed_attempt(client_ip)
        time.sleep(0.3)

        if request.is_json:
            return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401
        return render_template('admin_login.html', error='Invalid credentials.', turnstile_site_key=TURNSTILE_SITE_KEY), 401

@app.route('/admin91939/logout', methods=['POST', 'GET'])
def admin_logout():
    session.clear()
    if request.is_json:
        return jsonify({'success': True, 'redirect': '/admin91939'}), 200
    return redirect('/admin91939')

@app.route('/admin91939/dashboard', methods=['GET'])
@admin_required
def admin_dashboard():
    users = fetch_firebase_users()
    blogs = fetch_firebase_blogs()
    return render_template(
        'admin_dashboard.html',
        username=session.get('admin_user', 'Admin'),
        users=users,
        user_count=len(users),
        blogs=blogs,
        blog_count=len(blogs)
    )

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_api_users():
    """Protected API endpoint returning all registered Firebase users."""
    users = fetch_firebase_users()
    return jsonify({
        'success': True,
        'count': len(users),
        'users': users
    }), 200

# ---------------------------------------------------------------------------
# Blog Management API (Public Student View & Protected Admin Writer)
# ---------------------------------------------------------------------------
@app.route('/api/blogs', methods=['GET'])
def get_public_blogs():
    """Public endpoint: retrieve all published blogs for students."""
    blogs = fetch_firebase_blogs()
    return jsonify({
        'success': True,
        'count': len(blogs),
        'blogs': blogs
    }), 200

@app.route('/api/admin/blogs', methods=['POST'])
@admin_required
def create_admin_blog():
    """Admin endpoint: create and publish a new educational blog."""
    import json
    import time
    from datetime import datetime
    import urllib.request

    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title or not content:
        return jsonify({'success': False, 'message': 'Title and content are required.'}), 400

    now_ms = int(time.time() * 1000)
    blog_id = f"blog_{int(time.time())}"
    formatted_date = datetime.now().strftime('%b %d, %Y')

    blog_data = {
        'id': blog_id,
        'title': title,
        'category': data.get('category', 'NEET Strategy').strip() or 'NEET Strategy',
        'author': data.get('author', 'Nilanshu Sir').strip() or 'Nilanshu Sir',
        'readTime': data.get('readTime', '4 min read').strip() or '4 min read',
        'coverImage': data.get('coverImage', '').strip() or 'https://images.unsplash.com/photo-1434030216411-0b793f4b4173?auto=format&fit=crop&w=800&q=80',
        'excerpt': data.get('excerpt', '').strip() or (content[:150] + '...' if len(content) > 150 else content),
        'content': content,
        'createdAt': now_ms,
        'publishedAtFormatted': formatted_date
    }

    try:
        url = f"{FIREBASE_DATABASE_URL}/blogs/{blog_id}.json"
        payload = json.dumps(blog_data).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'}, method='PUT')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify({
                'success': True,
                'message': 'Blog published successfully to Preparics portal.',
                'blog': blog_data
            }), 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to publish blog: {str(e)}'}), 500

@app.route('/api/admin/blogs/<blog_id>', methods=['DELETE'])
@admin_required
def delete_admin_blog(blog_id):
    """Admin endpoint: delete an existing blog from Firebase."""
    import urllib.request
    try:
        url = f"{FIREBASE_DATABASE_URL}/blogs/{blog_id}.json"
        req = urllib.request.Request(url, method='DELETE')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify({'success': True, 'message': 'Blog deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to delete blog: {str(e)}'}), 500

# ---------------------------------------------------------------------------
# Protected Admin APIs (Server-Side Enforced)
# ---------------------------------------------------------------------------
@app.route('/api/admin/overview', methods=['GET'])
@admin_required
def admin_api_overview():
    return jsonify({
        'status': 'online',
        'admin_user': session.get('admin_user'),
        'authenticated': True,
        'session_duration_hours': 2,
        'security': {
            'password_hash': 'scrypt',
            'session_cookie_httponly': app.config['SESSION_COOKIE_HTTPONLY'],
            'session_cookie_samesite': app.config['SESSION_COOKIE_SAMESITE'],
            'session_cookie_secure': app.config['SESSION_COOKIE_SECURE']
        },
        'platform_resources': {
            'study_materials_count': 13,
            'study_material_levels': ['Class 11th', 'Class 12th'],
            'video_lectures': 4,
            'interactive_pdf_reader': 'Active'
        }
    }), 200

# ---------------------------------------------------------------------------
# Static Website Serving (Preserves Existing Public Site Unchanged)
# ---------------------------------------------------------------------------
@app.route('/')
def serve_home():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    safe_path = os.path.normpath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        abort(403)
    if os.path.isfile(safe_path):
        return send_from_directory(BASE_DIR, filename)

    # Case-insensitive fallback for Linux environments (e.g. Render)
    dirname, basename = os.path.split(safe_path)
    if os.path.isdir(dirname):
        lower_basename = basename.lower()
        for entry in os.listdir(dirname):
            if entry.lower() == lower_basename:
                rel_dir = os.path.relpath(dirname, BASE_DIR)
                target_dir = BASE_DIR if rel_dir == '.' else dirname
                return send_from_directory(target_dir, entry)

    abort(404)

if __name__ == '__main__':
    print('* Starting Preparics Admin Server at http://localhost:5000/admin91939')
    app.run(host='0.0.0.0', port=5000, debug=False)
