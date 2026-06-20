import io
import csv
import os
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime

from functools import wraps

from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    send_from_directory,
    flash,
    session,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24).hex()
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
# Magic bytes for image validation
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8": "jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}

login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60


@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return dict(current_user=getattr(g, "user", None), csrf_token=session["csrf_token"])


def csrf_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            token = (request.form.get("csrf_token") or
                     request.args.get("csrf_token") or "")
            if not token or token != session.get("csrf_token"):
                flash("Session expired. Please try again.", "danger")
                if "user_id" in session:
                    return redirect(url_for("dashboard"))
                return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def is_login_rate_limited():
    ip = request.remote_addr or "unknown"
    now = time.time()
    window_start = now - LOGIN_WINDOW
    login_attempts[ip] = [t for t in login_attempts[ip] if t > window_start]
    return len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def record_login_attempt():
    ip = request.remote_addr or "unknown"
    login_attempts[ip].append(time.time())


DB_PATH = os.path.join(app.root_path, "lab.db")


class Database:
    """Thin wrapper around sqlite3 or psycopg2 for multi-backend support."""

    def __init__(self):
        self._pg_url = os.environ.get("DATABASE_URL")
        if self._pg_url:
            import psycopg2
            import psycopg2.extras
            self.conn = psycopg2.connect(
                self._pg_url,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            self.conn.autocommit = False
        else:
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")

    @property
    def _is_pg(self):
        return bool(self._pg_url)

    def _fix(self, sql):
        if not self._is_pg:
            return sql
        sql = sql.replace("?", "%s")
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        sql = sql.replace("REAL DEFAULT", "DOUBLE PRECISION DEFAULT")
        sql = sql.replace("REAL,", "DOUBLE PRECISION,")
        sql = sql.replace(" REAL ", " DOUBLE PRECISION ")
        return sql

    def execute(self, sql, params=None):
        cur = self.conn.cursor()
        cur.execute(self._fix(sql), params or ())
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_db():
    if "db" not in g:
        g.db = Database()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'manager' CHECK(role IN ('admin', 'manager'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT ''
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_tag TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            quantity INTEGER DEFAULT 1,
            location TEXT DEFAULT '',
            condition TEXT DEFAULT 'Good',
            vendor TEXT DEFAULT '',
            purchase_date TEXT DEFAULT '',
            purchase_price REAL DEFAULT 0,
            photo TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS checkout_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id INTEGER NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
            borrower_name TEXT NOT NULL,
            checkout_date TEXT NOT NULL,
            return_date TEXT,
            notes TEXT DEFAULT ''
        )
    """)
    db.commit()

    if not db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("manager", generate_password_hash("manager123"), "manager"),
        )
        db.commit()


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def next_asset_tag():
    db = get_db()
    row = db.execute("SELECT asset_tag FROM tools ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        num = int(row["asset_tag"].split("-")[1]) + 1
    else:
        num = 1
    return f"T-{num:03d}"


def save_photo(file):
    if file and allowed_file(file.filename):
        header = file.read(8)
        file.seek(0)
        valid = any(
            header.startswith(sig) for sig in IMAGE_SIGNATURES
        )
        if not valid:
            return ""
        name = secure_filename(file.filename)
        ts = datetime.now().strftime("%y%m%d%H%M%S")
        filename = f"{ts}_{name}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        return filename
    return ""


def safe_csv_val(value):
    s = str(value) if value is not None else ""
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r', '\n'):
        return "'" + s
    return s


# ─── Auth helpers ─────────────────────────────────────────────────────────────


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not g.user:
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


# ─── Auth Routes ──────────────────────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
@csrf_required
def login():
    if request.method == "POST":
        if is_login_rate_limited():
            flash("Too many login attempts. Try again later.", "danger")
            return render_template("login.html")
        record_login_attempt()
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["csrf_token"] = secrets.token_hex(16)
            session["user_id"] = user["id"]
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@csrf_required
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ─── Dashboard ───────────────────────────────────────────────────────────────


@app.route("/")
@login_required
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS cnt FROM tools").fetchone()["cnt"]
    checked_out = db.execute(
        "SELECT COUNT(DISTINCT tool_id) AS cnt FROM checkout_log WHERE return_date IS NULL"
    ).fetchone()["cnt"]
    low_stock = db.execute(
        "SELECT COUNT(*) AS cnt FROM tools WHERE quantity <= 2"
    ).fetchone()["cnt"]
    broken = db.execute(
        "SELECT COUNT(*) AS cnt FROM tools WHERE condition = 'Broken'"
    ).fetchone()["cnt"]

    recent = db.execute("""
        SELECT cl.id, cl.borrower_name, cl.checkout_date, cl.return_date,
               t.name AS tool_name, t.id AS tool_id
        FROM checkout_log cl
        JOIN tools t ON t.id = cl.tool_id
        ORDER BY cl.id DESC LIMIT 10
    """).fetchall()

    low_tools = db.execute("""
        SELECT id, name, quantity FROM tools WHERE quantity <= 2 ORDER BY quantity
    """).fetchall()

    return render_template(
        "dashboard.html",
        total=total,
        checked_out=checked_out,
        low_stock=low_stock,
        broken=broken,
        recent=recent,
        low_tools=low_tools,
    )


# ─── Categories ──────────────────────────────────────────────────────────────


@app.route("/categories")
@login_required
def category_list():
    db = get_db()
    cats = db.execute("""
        SELECT c.*, (SELECT COUNT(*) FROM tools t WHERE t.category_id = c.id) AS tool_count
        FROM categories c ORDER BY c.name
    """).fetchall()
    return render_template("categories.html", categories=cats)


@app.route("/categories/new", methods=["GET", "POST"])
@login_required
@admin_required
@csrf_required
def category_new():
    if request.method == "POST":
        name = request.form["name"].strip()
        desc = request.form.get("description", "").strip()
        if not name:
            flash("Category name is required.", "danger")
            return render_template("category_form.html", category=None)
        try:
            get_db().execute(
                "INSERT INTO categories (name, description) VALUES (?, ?)",
                (name, desc),
            )
            get_db().commit()
            flash("Category created.", "success")
            return redirect(url_for("category_list"))
        except Exception:
            flash("Category already exists.", "danger")
    return render_template("category_form.html", category=None)


@app.route("/categories/<int:cid>/edit", methods=["GET", "POST"])
@login_required
@admin_required
@csrf_required
def category_edit(cid):
    db = get_db()
    cat = db.execute("SELECT * FROM categories WHERE id = ?", (cid,)).fetchone()
    if not cat:
        flash("Category not found.", "danger")
        return redirect(url_for("category_list"))
    if request.method == "POST":
        name = request.form["name"].strip()
        desc = request.form.get("description", "").strip()
        if not name:
            flash("Category name is required.", "danger")
            return render_template("category_form.html", category=cat)
        try:
            db.execute(
                "UPDATE categories SET name = ?, description = ? WHERE id = ?",
                (name, desc, cid),
            )
            db.commit()
            flash("Category updated.", "success")
            return redirect(url_for("category_list"))
        except Exception:
            flash("Category name already exists.", "danger")
    return render_template("category_form.html", category=cat)


@app.route("/categories/<int:cid>/delete", methods=["POST"])
@login_required
@admin_required
@csrf_required
def category_delete(cid):
    get_db().execute("DELETE FROM categories WHERE id = ?", (cid,))
    get_db().commit()
    flash("Category deleted.", "success")
    return redirect(url_for("category_list"))


# ─── Tools ───────────────────────────────────────────────────────────────────


@app.route("/tools")
@login_required
def tool_list():
    db = get_db()
    q = request.args.get("q", "").strip()
    cat_filter = request.args.get("category", "").strip()
    cond_filter = request.args.get("condition", "").strip()

    sql = """
        SELECT t.*, c.name AS category_name
        FROM tools t
        LEFT JOIN categories c ON c.id = t.category_id
        WHERE 1=1
    """
    params = []

    if q:
        sql += " AND (t.name LIKE ? OR t.asset_tag LIKE ? OR t.location LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])
    if cat_filter:
        sql += " AND t.category_id = ?"
        params.append(cat_filter)
    if cond_filter:
        sql += " AND t.condition = ?"
        params.append(cond_filter)

    sql += " ORDER BY t.name"
    tools = db.execute(sql, params).fetchall()
    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()

    checked_out_ids = {
        r["tool_id"]
        for r in db.execute(
            "SELECT DISTINCT tool_id FROM checkout_log WHERE return_date IS NULL"
        ).fetchall()
    }

    return render_template(
        "tools.html",
        tools=tools,
        categories=categories,
        q=q,
        cat_filter=cat_filter,
        cond_filter=cond_filter,
        checked_out_ids=checked_out_ids,
    )


@app.route("/tools/new", methods=["GET", "POST"])
@login_required
@admin_required
@csrf_required
def tool_new():
    db = get_db()
    if request.method == "POST":
        tag = next_asset_tag()
        now = datetime.now().isoformat()
        photo = save_photo(request.files.get("photo"))
        try:
            qty = int(request.form["quantity"])
        except (ValueError, TypeError):
            qty = 1
        try:
            price = float(request.form.get("purchase_price", 0) or 0)
        except (ValueError, TypeError):
            price = 0

        db.execute(
            """INSERT INTO tools
            (asset_tag, name, description, category_id, quantity, location,
             condition, vendor, purchase_date, purchase_price, photo,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tag,
                request.form["name"],
                request.form.get("description", ""),
                request.form.get("category_id") or None,
                qty,
                request.form.get("location", ""),
                request.form.get("condition", "Good"),
                request.form.get("vendor", ""),
                request.form.get("purchase_date", ""),
                price,
                photo,
                now,
                now,
            ),
        )
        db.commit()
        flash(f"Tool created (Asset: {tag}).", "success")
        return redirect(url_for("tool_list"))

    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("tool_form.html", tool=None, categories=categories)


@app.route("/tools/<int:tid>")
@login_required
def tool_detail(tid):
    db = get_db()
    tool = db.execute(
        "SELECT t.*, c.name AS category_name FROM tools t LEFT JOIN categories c ON c.id = t.category_id WHERE t.id = ?",
        (tid,),
    ).fetchone()
    if not tool:
        flash("Tool not found.", "danger")
        return redirect(url_for("tool_list"))

    logs = db.execute(
        "SELECT * FROM checkout_log WHERE tool_id = ? ORDER BY id DESC",
        (tid,),
    ).fetchall()
    is_checked_out = any(log["return_date"] is None for log in logs)

    return render_template(
        "tool_detail.html", tool=tool, logs=logs, is_checked_out=is_checked_out
    )


@app.route("/tools/<int:tid>/edit", methods=["GET", "POST"])
@login_required
@admin_required
@csrf_required
def tool_edit(tid):
    db = get_db()
    tool = db.execute("SELECT * FROM tools WHERE id = ?", (tid,)).fetchone()
    if not tool:
        flash("Tool not found.", "danger")
        return redirect(url_for("tool_list"))

    if request.method == "POST":
        now = datetime.now().isoformat()
        photo = tool["photo"]
        new_photo = request.files.get("photo")
        if new_photo and new_photo.filename:
            photo = save_photo(new_photo)

        try:
            qty = int(request.form["quantity"])
        except (ValueError, TypeError):
            qty = 1
        try:
            price = float(request.form.get("purchase_price", 0) or 0)
        except (ValueError, TypeError):
            price = 0

        db.execute(
            """UPDATE tools SET
            name=?, description=?, category_id=?, quantity=?, location=?,
            condition=?, vendor=?, purchase_date=?, purchase_price=?, photo=?,
            updated_at=?
            WHERE id=?""",
            (
                request.form["name"],
                request.form.get("description", ""),
                request.form.get("category_id") or None,
                qty,
                request.form.get("location", ""),
                request.form.get("condition", "Good"),
                request.form.get("vendor", ""),
                request.form.get("purchase_date", ""),
                price,
                photo,
                now,
                tid,
            ),
        )
        db.commit()
        flash("Tool updated.", "success")
        return redirect(url_for("tool_detail", tid=tid))

    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    return render_template("tool_form.html", tool=tool, categories=categories)


@app.route("/tools/<int:tid>/delete", methods=["POST"])
@login_required
@admin_required
@csrf_required
def tool_delete(tid):
    db = get_db()
    db.execute("DELETE FROM checkout_log WHERE tool_id = ?", (tid,))
    db.execute("DELETE FROM tools WHERE id = ?", (tid,))
    db.commit()
    flash("Tool deleted.", "success")
    return redirect(url_for("tool_list"))


@app.route("/tools/<int:tid>/checkout", methods=["POST"])
@login_required
@csrf_required
def tool_checkout(tid):
    db = get_db()
    tool = db.execute("SELECT * FROM tools WHERE id = ?", (tid,)).fetchone()
    if not tool:
        flash("Tool not found.", "danger")
        return redirect(url_for("tool_list"))
    active = db.execute(
        "SELECT COUNT(*) AS cnt FROM checkout_log WHERE tool_id = ? AND return_date IS NULL",
        (tid,),
    ).fetchone()["cnt"]
    if active >= tool["quantity"]:
        flash("All units of this tool are already checked out.", "danger")
        return redirect(url_for("tool_detail", tid=tid))

    borrower = request.form.get("borrower_name", "").strip()
    if not borrower:
        flash("Borrower name is required.", "danger")
        return redirect(url_for("tool_detail", tid=tid))

    db.execute(
        "INSERT INTO checkout_log (tool_id, borrower_name, checkout_date, notes) VALUES (?, ?, ?, ?)",
        (tid, borrower, datetime.now().isoformat(), request.form.get("notes", "")),
    )
    db.commit()
    flash(f"Checked out to {borrower}.", "success")
    return redirect(url_for("tool_detail", tid=tid))


@app.route("/tools/<int:tid>/return", methods=["POST"])
@login_required
@csrf_required
def tool_return(tid):
    db = get_db()
    db.execute(
        "UPDATE checkout_log SET return_date = ? WHERE tool_id = ? AND return_date IS NULL",
        (datetime.now().isoformat(), tid),
    )
    db.commit()
    flash("Tool returned.", "success")
    return redirect(url_for("tool_detail", tid=tid))


@app.route("/tools/<int:tid>/qr")
@login_required
def tool_qr(tid):
    import qrcode

    db = get_db()
    tool = db.execute("SELECT * FROM tools WHERE id = ?", (tid,)).fetchone()
    if not tool:
        flash("Tool not found.", "danger")
        return redirect(url_for("tool_list"))

    url = url_for("tool_detail", tid=tid, _external=True)
    img = qrcode.make(url, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/tools/export")
@login_required
def tool_export():
    db = get_db()
    tools = db.execute("""
        SELECT t.*, c.name AS category_name
        FROM tools t LEFT JOIN categories c ON c.id = t.category_id
        ORDER BY t.name
    """).fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "Asset Tag", "Name", "Category", "Quantity", "Location", "Condition",
        "Vendor", "Purchase Date", "Purchase Price", "Created", "Updated",
    ])
    for t in tools:
        w.writerow([
            safe_csv_val(t["asset_tag"]), safe_csv_val(t["name"]),
            safe_csv_val(t["category_name"]), safe_csv_val(t["quantity"]),
            safe_csv_val(t["location"]), safe_csv_val(t["condition"]),
            safe_csv_val(t["vendor"]), safe_csv_val(t["purchase_date"]),
            safe_csv_val(t["purchase_price"]), safe_csv_val(t["created_at"]),
            safe_csv_val(t["updated_at"]),
        ])
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"lab-tools-{datetime.now().strftime('%Y%m%d')}.csv",
    )


# ─── Favicon ──────────────────────────────────────────────────────────────────


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


# ─── Uploaded files ──────────────────────────────────────────────────────────


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ─── QR Scan ─────────────────────────────────────────────────────────────────


@app.route("/scan")
@login_required
def scan_page():
    return render_template("scan.html")


@app.route("/debug")
@login_required
def debug_info():
    import logging
    logs = ""
    try:
        with open("/tmp/app.log") as f:
            logs = f.read()
    except Exception:
        logs = "no log file"
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    tools_count = db.execute("SELECT COUNT(*) AS cnt FROM tools").fetchone()["cnt"]
    return {
        "users": [dict(u) for u in users],
        "tools_count": tools_count,
        "log": logs[-2000],
        "db_path": DB_PATH,
    }





# ─── Error handling ──────────────────────────────────────────────────────────

import logging
logging.basicConfig(filename="/tmp/app.log", level=logging.ERROR,
                    format="%(asctime)s %(levelname)s %(message)s")

@app.errorhandler(500)
def handle_500(e):
    app.logger.error("500 on %s", request.url, exc_info=e)
    return "Internal Server Error", 500


# ─── Entry ───────────────────────────────────────────────────────────────────

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
