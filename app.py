import os
import csv
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, render_template, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values


# -------------------- LOAD ENV -------------------- #
load_dotenv()
DB_URL = os.environ.get("DATABASE_URL")  # PostgreSQL connection string
UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = {"csv"}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.environ.get("APP_SECRET_KEY", "replace-me")
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT_MINUTES", 30))
app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT)
csrf = CSRFProtect(app)

# -------------------- ADMIN CREDENTIALS -------------------- #
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH") 
# or generate_password_hash(
#     os.environ.get("ADMIN_PASSWORD", "password")
# )

# -------------------- ENCRYPTION -------------------- #
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"Generated encryption key: {ENCRYPTION_KEY}")  # Save this to .env

fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_value(plain_text):
    if not plain_text:
        return ""
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_value(enc_text):
    if not enc_text:
        return ""
    return fernet.decrypt(enc_text.encode()).decode()


# -------------------- DATABASE -------------------- #
def init_db():
    """Create tables if not exist (run once)."""
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS memberships (
                    id SERIAL PRIMARY KEY,
                    member_id TEXT,
                    club_number TEXT,
                    club_name TEXT,
                    first_name TEXT,
                    middle_name TEXT,
                    last_name TEXT,
                    uploaded_at TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS uploads_meta (
                    id SERIAL PRIMARY KEY,
                    filename TEXT,
                    uploaded_at TIMESTAMP
                );
            """)
        conn.commit()

def get_db_conn():
    """Return a psycopg2 connection with RealDictCursor."""
    conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
    return conn


# -------------------- UTILS -------------------- #
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def normalize_id(id_value):
    if id_value is None:
        return ""
    return str(id_value).strip().replace(".0", "").lstrip("0")


# -------------------- AUTH -------------------- #
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please login to access this page.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -------------------- MEMBER FUNCTIONS -------------------- #
def fetch_member_clubs(member_id, cur):
    result = []
    cur.execute("SELECT member_id, club_number, club_name FROM memberships")
    rows = cur.fetchall()
    for r in rows:
        if decrypt_value(r['member_id']) == member_id:
            result.append((decrypt_value(r['club_number']), decrypt_value(r['club_name'])))
    return result

def check_eligibility_single_judge(judge_id, contestant_id, cur):
    judge_id = normalize_id(judge_id)
    contestant_id = normalize_id(contestant_id)

    judge_clubs = set(fetch_member_clubs(judge_id, cur))
    contestant_clubs = set(fetch_member_clubs(contestant_id, cur))

    judge_dict = {normalize_id(cn): name for cn, name in judge_clubs}
    contestant_dict = {normalize_id(cn): name for cn, name in contestant_clubs}

    common = []
    for club_num in judge_dict:
        if club_num in contestant_dict:
            common.append((club_num, judge_dict[club_num]))
    return common


# -------------------- ROUTES -------------------- #
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.permanent = True
            session["logged_in"] = True
            flash("✅ Logged in successfully.")
            return redirect(url_for("upload_page"))
        else:
            flash("❌ Invalid credentials.")
    csrf_token = generate_csrf()
    return render_template("login.html", csrf_token=csrf_token)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))


# -------------------- UPLOAD -------------------- #
@app.route("/upload", methods=["GET"])
@login_required
def upload_page():
    with get_db_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT filename, uploaded_at FROM uploads_meta ORDER BY id DESC LIMIT 1")
        meta = cur.fetchone()
        cur.execute("SELECT COUNT(*) AS cnt FROM memberships")
        member_count = cur.fetchone()['cnt']

    if meta:
        uploaded_dt = meta['uploaded_at']
        meta['uploaded_at_formatted'] = uploaded_dt.strftime("%d %b %Y, %H:%M UTC")

    csrf_token = generate_csrf()
    return render_template("upload.html", meta=meta, member_count=member_count, csrf_token=csrf_token)


@app.route("/upload", methods=["POST"])
@login_required
def upload_csv():
    if 'file' not in request.files:
        flash("No file part")
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash("No selected file")
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc")

        # 1. Read CSV
        csv_text = file.read().decode("utf-8")

        # 2. Encrypt and save
        encrypted_bytes = fernet.encrypt(csv_text.encode("utf-8"))
        with open(encrypted_path, "wb") as f:
            f.write(encrypted_bytes)

        uploaded_at = datetime.utcnow()

        # 3. Decrypt for DB processing
        decrypted_text = fernet.decrypt(encrypted_bytes).decode("utf-8")
        lines = decrypted_text.splitlines()

        if lines:
            lines = lines[1:]  # remove junk/header

        reader = csv.DictReader(lines)

        def normalize(value):
            if value is None:
                return ""
            return str(value).strip().lstrip("0")

        # Collect all rows into a list
        rows = []
        for row in reader:
            member_id = normalize(row.get('Member ID'))
            club_number = normalize(row.get('Club ID'))

            if member_id and club_number:
                rows.append((
                    encrypt_value(member_id),
                    encrypt_value(club_number),
                    encrypt_value((row.get('Club Name') or "").strip()),
                    encrypt_value((row.get('First Name') or "").strip()),
                    encrypt_value((row.get('Middle Name') or "").strip()),
                    encrypt_value((row.get('Last Name') or "").strip()),
                    uploaded_at
                ))

        # Bulk insert
        with get_db_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM memberships")

            insert_query = """
                INSERT INTO memberships 
                (member_id, club_number, club_name, first_name, middle_name, last_name, uploaded_at)
                VALUES %s
            """

            execute_values(cur, insert_query, rows)   # ***MAGIC SPEED BOOST***

            cur.execute("DELETE FROM uploads_meta")
            cur.execute(
                "INSERT INTO uploads_meta (filename, uploaded_at) VALUES (%s, %s)",
                (filename, uploaded_at)
            )

            conn.commit()

            cur.execute("SELECT COUNT(*) AS cnt FROM memberships")
            member_count = cur.fetchone()['cnt']

        flash(f"✅ Upload successful — {len(rows)} records inserted. Total: {member_count}. Uploaded on {uploaded_at}. Encrypted file saved as {filename}.enc")
        return redirect(url_for("upload_page"))

    flash("Only CSV files are allowed.")
    return redirect(request.url)



# -------------------- ELIGIBILITY CHECK -------------------- #
@app.route("/check", methods=["GET"])
def check_page():
    with get_db_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT uploaded_at, filename FROM uploads_meta ORDER BY id DESC LIMIT 1")
        meta = cur.fetchone()

    if meta:
        uploaded_dt = meta['uploaded_at']
        meta['uploaded_at_formatted'] = uploaded_dt.strftime("%d %b %Y, %H:%M UTC")
    csrf_token = generate_csrf()
    return render_template("check.html", meta=meta, csrf_token=csrf_token)


@app.route("/check", methods=["POST"])
def check_post():
    judge_id = normalize_id(request.form.get("judge_id", "").strip())
    contestants_raw = request.form.get("contestant_ids", "").strip()

    if not judge_id or not contestants_raw:
        flash("Provide judge ID and at least one contestant ID.")
        return redirect(url_for("check_page"))

    contestants = [
        normalize_id(c.strip())
        for c in contestants_raw.replace("\r", ",").replace("\n", ",").split(",")
        if c.strip()
    ]

    # Single DB connection for all queries
    with get_db_conn() as conn:
        cur = conn.cursor()

        # Judge info
        cur.execute("SELECT member_id, first_name, last_name FROM memberships")
        all_members = cur.fetchall()
        judge_name = None
        for r in all_members:
            if decrypt_value(r['member_id']) == judge_id:
                judge_name = f"{decrypt_value(r['first_name'])} {decrypt_value(r['last_name'])}".strip()
                break

        if judge_name is None:
            flash(f"❌ Judge with ID {judge_id} not found in the database.")
            return redirect(url_for("check_page"))

        # Process contestants
        results = []
        for cid in contestants:
            contestant_name = None
            for r in all_members:
                if decrypt_value(r['member_id']) == cid:
                    contestant_name = f"{decrypt_value(r['first_name'])} {decrypt_value(r['last_name'])}".strip()
                    break

            if contestant_name is None:
                results.append({
                    "contestant_id": cid,
                    "contestant_name": "❌ Member Not Found",
                    "common_clubs": [],
                    "eligible": False
                })
                continue

            common = check_eligibility_single_judge(judge_id, cid, cur)

            results.append({
                "contestant_id": cid,
                "contestant_name": contestant_name,
                "common_clubs": common,
                "eligible": (len(common) == 0)
            })

        # Last upload info
        cur.execute("SELECT uploaded_at FROM uploads_meta ORDER BY id DESC LIMIT 1")
        meta = cur.fetchone()
        if meta:
            uploaded_dt = meta['uploaded_at']
            meta['uploaded_at_formatted'] = uploaded_dt.strftime("%d %b %Y, %H:%M UTC")

    return render_template(
        "result.html",
        judge_id=judge_id,
        judge_name=judge_name,
        results=results,
        meta=meta
    )


# -------------------- MAIN -------------------- #
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
