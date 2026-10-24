import os
import io
import sqlite3
import hashlib
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "encrypted_files"
DB_PATH = DATA_DIR / "trustvault.db"
KEY_PATH = DATA_DIR / "fernet.key"
ALLOWED_EXTENSIONS = {"pdf", "txt", "doc", "docx", "png", "jpg", "jpeg", "xlsx", "csv"}
MAX_CONTENT_LENGTH = 15 * 1024 * 1024  # 15 MB

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("TRUSTVAULT_SECRET", "change-this-development-secret-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def get_fernet():
    env_key = os.environ.get("TRUSTVAULT_ENCRYPTION_KEY")
    if env_key:
        key = env_key.encode()
    else:
        # Local demo convenience. Keep this key private and back it up in real deployments.
        if not KEY_PATH.exists():
            KEY_PATH.write_bytes(Fernet.generate_key())
        key = KEY_PATH.read_bytes().strip()
    return Fernet(key)

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            shared_with INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL CHECK(permission IN ('read', 'download')),
            created_at TEXT NOT NULL,
            UNIQUE(document_id, shared_with)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id),
            document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
init_db()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def log_event(actor_id, document_id, action, details=""):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    with connect_db() as db:
        db.execute(
            "INSERT INTO audit_logs(actor_id, document_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (actor_id, document_id, action, details[:500], ip[:100], now())
        )

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" not in session:
        return None
    with connect_db() as db:
        return db.execute("SELECT id, username FROM users WHERE id = ?", (session["user_id"],)).fetchone()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_accessible_document(db, doc_id, user_id):
    doc = db.execute("""
        SELECT d.*, u.username AS owner_name,
               s.permission AS shared_permission
        FROM documents d
        JOIN users u ON u.id = d.owner_id
        LEFT JOIN shares s ON s.document_id = d.id AND s.shared_with = ?
        WHERE d.id = ? AND (d.owner_id = ? OR s.shared_with = ?)
    """, (user_id, doc_id, user_id, user_id)).fetchone()
    return doc

@app.context_processor
def inject_user():
    return {"logged_in_user": current_user()}

@app.route("/")
def index():
    if "user_id" not in session:
        return render_template("index.html")
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "danger")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
        else:
            try:
                with connect_db() as db:
                    db.execute("INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                               (username, generate_password_hash(password), now()))
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            log_event(user["id"], None, "LOGIN", "Successful sign-in")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    uid = session["user_id"]
    log_event(uid, None, "LOGOUT", "Signed out")
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    with connect_db() as db:
        owned = db.execute("""
            SELECT d.*, (SELECT COUNT(*) FROM shares s WHERE s.document_id=d.id) AS share_count
            FROM documents d WHERE d.owner_id=? ORDER BY d.created_at DESC
        """, (uid,)).fetchall()
        shared = db.execute("""
            SELECT d.*, u.username AS owner_name, s.permission AS shared_permission
            FROM shares s JOIN documents d ON d.id=s.document_id
            JOIN users u ON u.id=d.owner_id
            WHERE s.shared_with=? ORDER BY s.created_at DESC
        """, (uid,)).fetchall()
        users = db.execute("SELECT id, username FROM users WHERE id != ? ORDER BY username", (uid,)).fetchall()
    return render_template("dashboard.html", owned=owned, shared=shared, users=users)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("document")
    if not file or not file.filename:
        flash("Choose a file first.", "danger")
        return redirect(url_for("dashboard"))
    if not allowed_file(file.filename):
        flash("File type not allowed. See README for supported types.", "danger")
        return redirect(url_for("dashboard"))
    raw = file.read()
    if not raw:
        flash("The selected file is empty.", "danger")
        return redirect(url_for("dashboard"))
    if len(raw) > MAX_CONTENT_LENGTH:
        flash("File exceeds the 15 MB limit.", "danger")
        return redirect(url_for("dashboard"))
    safe_name = secure_filename(file.filename) or "document"
    stored_name = f"{os.urandom(16).hex()}.enc"
    digest = hashlib.sha256(raw).hexdigest()
    try:
        encrypted = get_fernet().encrypt(raw)
        (UPLOAD_DIR / stored_name).write_bytes(encrypted)
        with connect_db() as db:
            cur = db.execute("""
                INSERT INTO documents(owner_id, original_name, stored_name, mime_type, size_bytes, sha256, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session["user_id"], safe_name, stored_name, file.mimetype or "application/octet-stream",
                  len(raw), digest, now()))
            doc_id = cur.lastrowid
        log_event(session["user_id"], doc_id, "UPLOAD", f"Uploaded {safe_name}; SHA-256 {digest}")
        flash("Document encrypted and uploaded successfully.", "success")
    except Exception:
        try:
            (UPLOAD_DIR / stored_name).unlink(missing_ok=True)
        except OSError:
            pass
        app.logger.exception("Upload failed")
        flash("Upload failed. Check the server console for details.", "danger")
    return redirect(url_for("dashboard"))

@app.route("/share", methods=["POST"])
@login_required
def share():
    try:
        doc_id = int(request.form.get("document_id", "0"))
        recipient_id = int(request.form.get("recipient_id", "0"))
    except ValueError:
        abort(400)
    permission = request.form.get("permission", "read")
    if permission not in {"read", "download"}:
        abort(400)
    with connect_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=?",
                         (doc_id, session["user_id"])).fetchone()
        recipient = db.execute("SELECT id, username FROM users WHERE id=?", (recipient_id,)).fetchone()
        if not doc or not recipient or recipient_id == session["user_id"]:
            abort(404)
        try:
            db.execute("INSERT INTO shares(document_id, shared_with, permission, created_at) VALUES (?, ?, ?, ?)",
                       (doc_id, recipient_id, permission, now()))
            action = "SHARE"
            detail = f"Shared document {doc_id} with user {recipient['username']} ({permission})"
        except sqlite3.IntegrityError:
            db.execute("UPDATE shares SET permission=?, created_at=? WHERE document_id=? AND shared_with=?",
                       (permission, now(), doc_id, recipient_id))
            action = "UPDATE_SHARE"
            detail = f"Updated access for {recipient['username']} to {permission}"
    log_event(session["user_id"], doc_id, action, detail)
    flash("Access granted/updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/revoke/<int:share_id>", methods=["POST"])
@login_required
def revoke(share_id):
    with connect_db() as db:
        share_row = db.execute("""
            SELECT s.id, s.document_id FROM shares s
            JOIN documents d ON d.id=s.document_id
            WHERE s.id=? AND d.owner_id=?
        """, (share_id, session["user_id"])).fetchone()
        if not share_row:
            abort(404)
        db.execute("DELETE FROM shares WHERE id=?", (share_id,))
    log_event(session["user_id"], share_row["document_id"], "REVOKE_ACCESS", f"Revoked share {share_id}")
    flash("Shared access revoked.", "success")
    return redirect(url_for("document_detail", doc_id=share_row["document_id"]))

@app.route("/document/<int:doc_id>")
@login_required
def document_detail(doc_id):
    uid = session["user_id"]
    with connect_db() as db:
        doc = get_accessible_document(db, doc_id, uid)
        if not doc:
            abort(404)
        shares = []
        if doc["owner_id"] == uid:
            shares = db.execute("""
                SELECT s.id AS share_id, s.permission, s.created_at, u.username
                FROM shares s JOIN users u ON u.id=s.shared_with
                WHERE s.document_id=? ORDER BY s.created_at DESC
            """, (doc_id,)).fetchall()
    log_event(uid, doc_id, "VIEW_METADATA", f"Viewed metadata for {doc['original_name']}")
    return render_template("document.html", doc=doc, shares=shares)

@app.route("/document/<int:doc_id>/read")
@login_required
def read_document(doc_id):
    uid = session["user_id"]
    with connect_db() as db:
        doc = get_accessible_document(db, doc_id, uid)
        if not doc:
            abort(404)
        if doc["owner_id"] != uid and doc["shared_permission"] not in ("read", "download"):
            abort(403)
        encrypted_path = UPLOAD_DIR / doc["stored_name"]
        if not encrypted_path.exists():
            abort(404)
        try:
            plaintext = get_fernet().decrypt(encrypted_path.read_bytes())
        except (InvalidToken, OSError):
            app.logger.exception("Could not decrypt document")
            abort(500)
    log_event(uid, doc_id, "READ", f"Read/decrypted {doc['original_name']}")
    if doc["mime_type"].startswith("text/") or doc["original_name"].lower().endswith(".txt"):
        return render_template("read_text.html", doc=doc, content=plaintext.decode("utf-8", errors="replace"))
    # Non-text documents are returned as a download; this is also audited.
    log_event(uid, doc_id, "DOWNLOAD", f"Downloaded {doc['original_name']}")
    return send_file(io.BytesIO(plaintext), mimetype=doc["mime_type"], as_attachment=True,
                     download_name=doc["original_name"])

@app.route("/document/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    uid = session["user_id"]
    with connect_db() as db:
        doc = get_accessible_document(db, doc_id, uid)
        if not doc:
            abort(404)
        if doc["owner_id"] != uid and doc["shared_permission"] != "download":
            abort(403)
        encrypted_path = UPLOAD_DIR / doc["stored_name"]
        if not encrypted_path.exists():
            abort(404)
        try:
            plaintext = get_fernet().decrypt(encrypted_path.read_bytes())
        except (InvalidToken, OSError):
            abort(500)
    log_event(uid, doc_id, "DOWNLOAD", f"Downloaded {doc['original_name']}")
    return send_file(io.BytesIO(plaintext), mimetype=doc["mime_type"], as_attachment=True,
                     download_name=doc["original_name"])

@app.route("/audit")
@login_required
def audit():
    uid = session["user_id"]
    with connect_db() as db:
        rows = db.execute("""
            SELECT a.*, u.username, d.original_name
            FROM audit_logs a
            LEFT JOIN users u ON u.id=a.actor_id
            LEFT JOIN documents d ON d.id=a.document_id
            WHERE a.actor_id=? OR d.owner_id=?
            ORDER BY a.created_at DESC LIMIT 500
        """, (uid, uid)).fetchall()
    return render_template("audit.html", rows=rows)

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404

@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="The upload is too large. Maximum size is 15 MB."), 413

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )