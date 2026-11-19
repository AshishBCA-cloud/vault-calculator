# Standard library
import base64
import hmac
import mimetypes
import os
import secrets
import sqlite3
import subprocess
import sys
from contextlib import closing
from functools import wraps
from pathlib import Path

# Third-party libraries (install using: pip install flask cryptography)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, Response, abort, jsonify, request, send_from_directory

BASE = Path(__file__).parent
DATA = BASE / "vault_data"
FILES = DATA / "files"
DB_PATH = DATA / "vault.db"
FILES.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(BASE / "static"), static_url_path="")

# Stores token-to-Fernet key objects. These remain only in server memory.
SESSIONS = {}


# ---------- database ----------
def run(sql, args=(), fetch=None):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, args)
        conn.commit()
        if fetch == "one":
            return cur.fetchone()
        if fetch == "all":
            return cur.fetchall()
        return cur.lastrowid


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value BLOB
            );
            CREATE TABLE IF NOT EXISTS items (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                kind          TEXT NOT NULL,      -- photo | video | app | file
                name          TEXT NOT NULL,
                mime          TEXT,
                size          INTEGER DEFAULT 0,
                path          TEXT,               -- Encrypted file name (NULL for app links)
                url           TEXT,               -- Stores app links
                original_path TEXT,               -- Original file location on the PC
                hidden        INTEGER DEFAULT 0,
                created_at    TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()


def migrate_db():
    """Adds the original_path column to an old database if it does not exist."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(items)")]
        if "original_path" not in cols:
            conn.execute("ALTER TABLE items ADD COLUMN original_path TEXT")
            conn.commit()


def get_setting(key):
    row = run("SELECT value FROM settings WHERE key = ?", (key,), fetch="one")
    return row["value"] if row else None


def set_setting(key, value):
    run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


init_db()
migrate_db()


# ---------- encryption ----------
def derive(pin, salt):
    """Generates a Fernet key and a verifier. The verifier checks the PIN without storing the actual PIN."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt, iterations=390_000)
    raw = kdf.derive(pin.encode())
    return base64.urlsafe_b64encode(raw[:32]), raw[32:]


def bearer_token():
    return request.headers.get("Authorization", "").removeprefix("Bearer ").strip()


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        fernet = SESSIONS.get(bearer_token())
        if not fernet:
            return jsonify(error="locked"), 401
        return fn(fernet, *args, **kwargs)
    return wrapper


# ---------- file helpers ----------
def secure_delete(path: Path):
    """Overwrites a file with random data before deleting it."""
    size = path.stat().st_size
    with open(path, "r+b") as f:
        remaining = size
        while remaining > 0:
            chunk = min(remaining, 1024 * 1024)
            f.write(secrets.token_bytes(chunk))
            remaining -= chunk
        f.flush()
        os.fsync(f.fileno())
    path.unlink()


def unique_path(p: Path) -> Path:
    """Creates a new file name like 'name (1).jpg' if the file already exists."""
    if not p.exists():
        return p
    n = 1
    while True:
        candidate = p.with_name(f"{p.stem} ({n}){p.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


# ---------- authentication routes ----------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/status")
def status():
    return jsonify(setup=get_setting("salt") is not None)


@app.post("/api/setup")
def setup():
    if get_setting("salt") is not None:
        return jsonify(error="PIN already set"), 400
    pin = (request.get_json(silent=True) or {}).get("pin", "")
    if len(pin) < 4:
        return jsonify(error="PIN must be at least 4 characters"), 400
    salt = os.urandom(16)
    _, verifier = derive(pin, salt)
    set_setting("salt", salt)
    set_setting("verifier", verifier)
    return jsonify(ok=True)


@app.post("/api/unlock")
def unlock():
    salt = get_setting("salt")
    if salt is None:
        return jsonify(error="setup_required"), 400
    pin = (request.get_json(silent=True) or {}).get("pin", "")
    fernet_key, verifier = derive(pin, salt)
    if not hmac.compare_digest(verifier, get_setting("verifier")):
        return jsonify(error="wrong_pin"), 403
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = Fernet(fernet_key)
    return jsonify(token=token)


@app.post("/api/lock")
def lock():
    SESSIONS.pop(bearer_token(), None)
    return jsonify(ok=True)


# ---------- items ----------
@app.get("/api/items")
@require_auth
def list_items(fernet):
    kind = request.args.get("kind")
    hidden = 1 if request.args.get("hidden") == "1" else 0

    sql = ("SELECT id, kind, name, mime, size, url, hidden, created_at "
           "FROM items WHERE hidden = ?")
    args = [hidden]
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    sql += " ORDER BY id DESC"

    rows = run(sql, args, fetch="all")
    return jsonify([dict(r) for r in rows])


@app.post("/api/items")
@require_auth
def add_item(fernet):
    """Handles a file uploaded through the browser. It has no original PC file path."""
    kind = request.form.get("kind", "file")
    if kind not in ("photo", "video", "app", "file"):
        return jsonify(error="bad kind"), 400
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify(error="no file"), 400

    data = upload.read()
    stored_name = secrets.token_hex(16)
    (FILES / stored_name).write_bytes(fernet.encrypt(data))

    item_id = run(
        "INSERT INTO items (kind, name, mime, size, path) VALUES (?, ?, ?, ?, ?)",
        (kind, upload.filename, upload.mimetype, len(data), stored_name),
    )
    return jsonify(id=item_id), 201


@app.post("/api/links")
@require_auth
def add_link(fernet):
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    url = body.get("url", "").strip()
    if not name or not url:
        return jsonify(error="name and url required"), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    item_id = run(
        "INSERT INTO items (kind, name, url) VALUES ('app', ?, ?)", (name, url)
    )
    return jsonify(id=item_id), 201


@app.post("/api/import-path")
@require_auth
def import_from_path(fernet):
    """Encrypts a PC file and saves it as hidden in the vault, then deletes the original file."""
    body = request.get_json(silent=True) or {}
    raw_path = body.get("path", "").strip().strip('"')
    kind = body.get("kind", "file")

    if kind not in ("photo", "video", "app", "file"):
        return jsonify(error="bad kind"), 400

    src = Path(raw_path)
    if not src.is_file():
        return jsonify(error="File not found. Please check the path."), 404

    if DATA.resolve() in src.resolve().parents:
        return jsonify(error="This file is already inside the vault."), 400

    # 1. First, save an encrypted copy inside the vault.
    data = src.read_bytes()
    stored_name = secrets.token_hex(16)
    (FILES / stored_name).write_bytes(fernet.encrypt(data))

    # 2. Create a database entry with hidden = 1 and the original file path.
    mime = mimetypes.guess_type(src.name)[0]
    item_id = run(
        "INSERT INTO items (kind, name, mime, size, path, hidden, original_path) "
        "VALUES (?, ?, ?, ?, ?, 1, ?)",
        (kind, src.name, mime, len(data), stored_name, str(src.resolve())),
    )

    # 3. Delete the original file only after saving its encrypted copy in the vault.
    try:
        secure_delete(src)
        return jsonify(id=item_id, deleted_original=True), 201
    except OSError as e:
        return jsonify(
            id=item_id,
            deleted_original=False,
            warning=f"File saved in the vault, but the original file could not be deleted: {e}",
        ), 201


@app.post("/api/items/<int:item_id>/restore")
@require_auth
def restore_item(fernet, item_id):
    """Restores a vault file to its original folder and then removes it from the vault."""
    row = run("SELECT * FROM items WHERE id = ?", (item_id,), fetch="one")
    if not row or not row["path"]:
        abort(404)

    # If the original path is not available (old or browser-uploaded file), restore it to Downloads.
    if row["original_path"]:
        target = Path(row["original_path"])
    else:
        target = Path.home() / "Downloads" / row["name"]
    target = unique_path(target)

    vault_file = FILES / row["path"]
    data = fernet.decrypt(vault_file.read_bytes())

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    except OSError as e:
        return jsonify(error=f"Could not restore the file to the PC: {e}"), 500

    # Remove the vault copy only after successfully writing the restored file.
    vault_file.unlink(missing_ok=True)
    run("DELETE FROM items WHERE id = ?", (item_id,))
    return jsonify(restored_to=str(target))


@app.get("/api/items/<int:item_id>/file")
@require_auth
def get_file(fernet, item_id):
    row = run("SELECT * FROM items WHERE id = ?", (item_id,), fetch="one")
    if not row or not row["path"]:
        abort(404)
    data = fernet.decrypt((FILES / row["path"]).read_bytes())
    return Response(data, mimetype=row["mime"] or "application/octet-stream")


@app.patch("/api/items/<int:item_id>")
@require_auth
def update_item(fernet, item_id):
    hidden = 1 if (request.get_json(silent=True) or {}).get("hidden") else 0
    run("UPDATE items SET hidden = ? WHERE id = ?", (hidden, item_id))
    return jsonify(ok=True)


@app.delete("/api/items/<int:item_id>")
@require_auth
def delete_item(fernet, item_id):
    row = run("SELECT path FROM items WHERE id = ?", (item_id,), fetch="one")
    if not row:
        abort(404)
    if row["path"]:
        file_path = FILES / row["path"]
        if file_path.exists():
            file_path.unlink()
    run("DELETE FROM items WHERE id = ?", (item_id,))
    return jsonify(ok=True)


PICKER_CODE = r'''
import tkinter as tk
from tkinter import filedialog
root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
path = filedialog.askopenfilename(title="Select a file to hide")
root.destroy()
print(path)
'''


@app.post("/api/pick-file")
@require_auth
def pick_file(fernet):
    """Opens the Windows file chooser and returns the path of the selected file."""
    result = subprocess.run(
        [sys.executable, "-c", PICKER_CODE],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return jsonify(error="Could not open the file chooser: " + result.stderr.strip()), 500
    return jsonify(path=result.stdout.strip())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)