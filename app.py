"""
PayamRasan Pro — Modern Telegram Web UI Clone
"""
import os, re, sqlite3, secrets, hashlib, hmac
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, request, redirect, url_for, session, g, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("CHAT_DB_PATH", os.path.join(APP_DIR, "chat.db"))
UPLOAD_DIR = os.environ.get("CHAT_UPLOAD_DIR", os.path.join(APP_DIR, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CHAT_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
ALLOWED_EXT = {"png","jpg","jpeg","gif","webp","pdf","txt","zip","mp3","wav","ogg","m4a","mp4","webm","docx","xlsx"}

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
          password_hash TEXT NOT NULL, bio TEXT DEFAULT '', avatar TEXT DEFAULT '',
          phone TEXT DEFAULT '+98 9•••••••••', birthday TEXT DEFAULT '1375/01/01',
          created_at TEXT NOT NULL, last_seen TEXT, online INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
          receiver_id INTEGER NOT NULL REFERENCES users(id), body TEXT DEFAULT '',
          msg_type TEXT DEFAULT 'text', attachment TEXT DEFAULT '', reply_to INTEGER DEFAULT 0,
          reaction TEXT DEFAULT '', pinned INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
          created_at TEXT NOT NULL, read_at TEXT);
        CREATE TABLE IF NOT EXISTS groups_chat(id INTEGER PRIMARY KEY, title TEXT NOT NULL, avatar TEXT DEFAULT '',
          owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS group_members(group_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member',
          PRIMARY KEY(group_id,user_id));
        """)

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def current_user():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user(): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def valid_username(u):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,24}", u or ""))

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()

def check_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split("$",1)
        return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)).split("$",1)[1], hash_hex)
    except Exception: return False

@app.route("/")
def index():
    if not current_user(): return redirect(url_for("login"))
    return render_template_string(PAGE, me=current_user())

@app.route("/register", methods=["GET","POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form.get("username","").strip().lstrip("@")
        display = request.form.get("display_name","").strip()[:50]
        password = request.form.get("password","")
        if not valid_username(username): error = "نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا _ باشد."
        elif len(password) < 8: error = "رمز عبور باید حداقل ۸ کاراکتر باشد."
        elif not display: error = "نام نمایشی را وارد کنید."
        else:
            try:
                cur = db().execute("INSERT INTO users(username,display_name,password_hash,created_at,last_seen) VALUES(?,?,?,?,?)",
                                   (username.lower(),display,hash_password(password),now(),now()))
                db().commit(); session.clear(); session["uid"] = cur.lastrowid
                return redirect(url_for("index"))
            except sqlite3.IntegrityError: error = "این نام کاربری قبلاً گرفته شده است."
    return render_template_string(AUTH, title="ساخت حساب کاربری", error=error, action="register")

@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username","").strip().lstrip("@").lower()
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password(request.form.get("password",""), user["password_hash"]):
            session.clear(); session["uid"] = user["id"]
            db().execute("UPDATE users SET online=1,last_seen=? WHERE id=?", (now(),user["id"])); db().commit()
            return redirect(url_for("index"))
        error = "نام کاربری یا رمز عبور نادرست است."
    return render_template_string(AUTH, title="ورود به پیام‌رسان پرو", error=error, action="login")

@app.route("/logout")
@login_required
def logout():
    u=current_user()
    if u: db().execute("UPDATE users SET online=0,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()
    session.clear()
    return redirect(url_for("login"))

@app.get("/api/me")
@login_required
def api_me():
    return jsonify(dict(current_user()))

@app.post("/api/profile")
@login_required
def profile():
    u=current_user(); data=request.get_json(silent=True) or {}
    name=str(data.get("display_name","")).strip()[:50]
    bio=str(data.get("bio","")).strip()[:240]
    phone=str(data.get("phone","")).strip()[:20]
    birthday=str(data.get("birthday","")).strip()[:20]
    avatar=str(data.get("avatar","")).strip()
    if not name: return jsonify(error="نام نمایشی لازم است"),400
    db().execute("UPDATE users SET display_name=?,bio=?,phone=?,birthday=?,avatar=? WHERE id=?",(name,bio,phone,birthday,avatar,u["id"]))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/dialogs")
@login_required
def get_dialogs():
    me=current_user()
    rows=db().execute("""
        SELECT u.id, u.username, u.display_name, u.avatar, u.online, u.last_seen,
               m.body as last_msg, m.created_at as last_time, m.read_at, m.sender_id
        FROM users u
        JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) OR (m.receiver_id = u.id AND m.sender_id = ?)
        WHERE m.id IN (
            SELECT MAX(id) FROM messages 
            WHERE sender_id = ? OR receiver_id = ?
            GROUP BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
        )
        ORDER BY m.id DESC
    """, (me["id"], me["id"], me["id"], me["id"], me["id"])).fetchall()
    return jsonify(dialogs=[dict(r) for r in rows])

@app.get("/api/users")
@login_required
def search_users():
    q=request.args.get("q","").strip().lstrip("@").lower()[:40]
    me=current_user()
    if not q: return jsonify(users=[])
    rows=db().execute("""SELECT id,username,display_name,bio,avatar,phone,birthday,online,last_seen FROM users
       WHERE id!=? AND (username LIKE ? OR display_name LIKE ?) ORDER BY online DESC LIMIT 30""",
       (me["id"],f"%{q}%",f"%{q}%")).fetchall()
    return jsonify(users=[dict(r) for r in rows])

@app.get("/api/messages/<int:other_id>")
@login_required
def get_messages(other_id):
    me=current_user()
    db().execute("UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL",(now(),other_id,me["id"]))
    db().commit()
    rows=db().execute("""SELECT m.*,u.username sender_username,u.display_name sender_name FROM messages m
       JOIN users u ON u.id=m.sender_id WHERE
       ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)) AND m.deleted=0
       ORDER BY m.id ASC LIMIT 300""",(me["id"],other_id,other_id,me["id"])).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

@app.post("/api/messages")
@login_required
def send_message():
    me=current_user(); data=request.get_json(silent=True) or {}
    try: rid=int(data.get("receiver_id"))
    except: return jsonify(error="نامعتبر"),400
    body=str(data.get("body","")).strip()
    msg_type=str(data.get("msg_type","text"))
    if not body: return jsonify(error="پیام خالی است"),400
    cur=db().execute("INSERT INTO messages(sender_id,receiver_id,body,msg_type,created_at) VALUES(?,?,?,?,?)",
                     (me["id"],rid,body,msg_type,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,sender_id=me["id"],receiver_id=rid,body=body,msg_type=msg_type,
             reaction='',created_at=now(),sender_username=me["username"],sender_name=me["display_name"],read_at=None)
    socketio.emit("new_message",msg,room=f"user:{rid}")
    socketio.emit("new_message",msg,room=f"user:{me['id']}")
    return jsonify(message=msg)

@app.post("/api/messages/<int:mid>/edit")
@login_required
def edit_message(mid):
    me=current_user(); data=request.get_json(silent=True) or {}
    body=str(data.get("body","")).strip()
    if not body: return jsonify(error="متن خالی است"), 400
    db().execute("UPDATE messages SET body=? WHERE id=? AND sender_id=?", (body, mid, me["id"]))
    db().commit()
    msg = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if msg:
        socketio.emit("update_message", dict(msg), room=f"user:{msg['receiver_id']}")
        socketio.emit("update_message", dict(msg), room=f"user:{me['id']}")
    return jsonify(ok=True)

@app.post("/api/messages/<int:mid>/delete")
@login_required
def delete_message(mid):
    me=current_user()
    msg = db().execute("SELECT * FROM messages WHERE id=? AND sender_id=?", (mid, me["id"])).fetchone()
    if msg:
        db().execute("UPDATE messages SET deleted=1 WHERE id=?", (mid,))
        db().commit()
        socketio.emit("delete_message", {"id": mid}, room=f"user:{msg['receiver_id']}")
        socketio.emit("delete_message", {"id": mid}, room=f"user:{me['id']}")
    return jsonify(ok=True)

@app.post("/api/messages/<int:mid>/react")
@login_required
def react_message(mid):
    me=current_user(); data=request.get_json(silent=True) or {}
    reaction=str(data.get("reaction","")).strip()
    db().execute("UPDATE messages SET reaction=? WHERE id=?", (reaction, mid))
    db().commit()
    msg = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if msg:
        socketio.emit("update_message", dict(msg), room=f"user:{msg['receiver_id']}")
        socketio.emit("update_message", dict(msg), room=f"user:{msg['sender_id']}")
    return jsonify(ok=True)

@app.post("/api/upload")
@login_required
def upload():
    f=request.files.get("file")
    if not f or not f.filename: return jsonify(error="فایلی انتخاب نشده"),400
    name=secure_filename(f.filename)
    ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT: return jsonify(error="پسوند مجاز نیست"),400
    token=secrets.token_hex(16)
    saved=f"{token}.{ext}"
    f.save(os.path.join(UPLOAD_DIR,saved))
    return jsonify(url=url_for("uploaded_file",name=saved),name=name)

@app.get("/uploads/<name>")
@login_required
def uploaded_file(name):
    from flask import send_from_directory
    return send_from_directory(UPLOAD_DIR,name)

@socketio.on("connect")
def on_connect():
    u=current_user()
    if u:
        join_room(f"user:{u['id']}")
        db().execute("UPDATE users SET online=1,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()

@socketio.on("disconnect")
def on_disconnect():
    u=current_user()
    if u:
        db().execute("UPDATE users SET online=0,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()

AUTH = r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}}</title>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" />
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Vazirmatn', sans-serif; }
body { background: #0f172a; min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #f8fafc; padding: 16px; }
.auth-card { width: min(400px, 100%); background: #1e293b; padding: 32px 24px; border-radius: 20px; text-align: center; border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); }
input { width: 100%; padding: 12px 16px; margin-bottom: 14px; background: #0b132b; border: 1px solid #334155; border-radius: 12px; color: white; outline: none; transition: 0.2s; }
input:focus { border-color: #2AABEE; box-shadow: 0 0 0 3px rgba(42,171,238,0.2); }
button { width: 100%; padding: 12px; background: #2AABEE; border: none; border-radius: 12px; color: white; font-weight: bold; cursor: pointer; transition: 0.2s; }
button:hover { background: #229ed9; }
.error { background: rgba(239,68,68,0.15); color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; border: 1px solid rgba(239,68,68,0.3); }
a { color: #2AABEE; text-decoration: none; font-size: 13px; font-weight: 500; }
a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="auth-card">
  <h2 style="margin-bottom: 20px; font-weight: 700; color: #f1f5f9;">{{title}}</h2>
  {% if error %}<div class="error">{{error}}</div>{% endif %}
  <form method="post">
    {% if action=='register' %}
    <input name="display_name" placeholder="نام و نام خانوادگی" required>
    {% endif %}
    <input name="username" placeholder="نام کاربری (آیدی بدون @)" required>
    <input name="password" type="password" placeholder="رمز عبور" required>
    <button type="submit">{{title}}</button>
  </form>
  <div style="margin-top: 18px;">
    {% if action=='login' %}<a href="{{url_for('register')}}">حساب کاربری ندارید؟ ثبت‌نام</a>{% else %}<a href="{{url_for('login')}}">قبلاً ثبت‌نام کرده‌اید؟ ورود</a>{% endif %}
  </div>
</div>
</body>
</html>
"""

PAGE = r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Telegram Pro</title>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" />
<style>
:root {
  --bg-main: #0e1621;
  --panel-bg: #17212b;
  --panel-hover: #202b38;
  --active-bg: #2b5278;
  --accent: #2AABEE;
  --bubble-out: #2b5278;
  --bubble-in: #182533;
  --text-muted: #8eabbf;
  --border-color: #0f151d;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Vazirmatn', sans-serif; -webkit-tap-highlight-color: transparent; }
body { background: var(--bg-main); color: white; height: 100vh; height: -webkit-fill-available; overflow: hidden; display: flex; }

.tg-app { display: flex; width: 100vw; height: 100%; position: relative; }

/* Left Nav Rail */
.folder-rail { width: 64px; background: #0e1621; border-left: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; padding: 14px 0; gap: 14px; z-index: 15; flex-shrink: 0; }
.folder-icon { width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center; font-size: 20px; color: var(--text-muted); cursor: pointer; transition: 0.2s; }
.folder-icon:hover { background: var(--panel-hover); color: white; }
.folder-icon.active { background: var(--panel-bg); color: var(--accent); }

/* Slide Menu Drawer */
.drawer-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 90; display: none; backdrop-filter: blur(2px); }
.drawer-overlay.active { display: block; }
.hamburger-menu {
  position: fixed; top: 0; right: -320px; width: 300px; height: 100%;
  background: var(--panel-bg); z-index: 100; transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  display: flex; flex-direction: column; border-left: 1px solid #232e3c;
}
.hamburger-menu.open { right: 0; }
.menu-header { background: #202b38; padding: 24px 20px; position: relative; border-bottom: 1px solid var(--border-color); }
.close-menu-btn { position: absolute; left: 16px; top: 16px; background: none; border: none; color: white; font-size: 18px; cursor: pointer; padding: 6px; border-radius: 50%; display: grid; place-items: center; }
.close-menu-btn:hover { background: rgba(255,255,255,0.1); }
.menu-avatar { width: 56px; height: 56px; border-radius: 50%; background: var(--accent); display: grid; place-items: center; font-size: 22px; font-weight: bold; background-size: cover; background-position: center; margin-bottom: 12px; }

.menu-items { padding: 8px 0; flex: 1; }
.menu-item { padding: 14px 20px; display: flex; align-items: center; gap: 16px; cursor: pointer; font-size: 14px; color: #e2e8f0; text-decoration: none; transition: 0.15s; }
.menu-item:hover { background: var(--panel-hover); }

/* Sidebar Chats */
.sidebar { width: 340px; background: var(--panel-bg); border-left: 1px solid var(--border-color); display: flex; flex-direction: column; z-index: 10; flex-shrink: 0; }
.sidebar-header { padding: 12px 14px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); }
.search-container { flex: 1; background: var(--bg-main); border-radius: 20px; display: flex; align-items: center; padding: 0 14px; height: 38px; }
.search-container input { width: 100%; background: none; border: none; color: white; outline: none; font-size: 13px; }

.chat-list { flex: 1; overflow-y: auto; }
.chat-row { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; transition: 0.15s; }
.chat-row:hover { background: var(--panel-hover); }
.chat-row.active { background: var(--active-bg); }
.avatar { width: 48px; height: 48px; border-radius: 50%; background: #2b5278; display: grid; place-items: center; font-weight: bold; flex-shrink: 0; background-size: cover; background-position: center; font-size: 16px; color: white; }

/* Main Chat Area */
.chat-main { flex: 1; display: flex; flex-direction: column; background: var(--bg-main); position: relative; height: 100%; min-width: 0; }
.chat-topbar { padding: 10px 16px; background: var(--panel-bg); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; height: 60px; flex-shrink: 0; }
.chat-topbar-info { display: flex; align-items: center; gap: 12px; cursor: pointer; min-width: 0; }
.back-btn-mobile { display: none; background: none; border: none; color: white; font-size: 22px; cursor: pointer; }

.chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; background: radial-gradient(circle at center, #0e1621 0%, #080c12 100%); }
.message-bubble { max-width: 75%; padding: 10px 14px; border-radius: 14px; font-size: 14px; position: relative; word-break: break-word; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
.message-bubble.mine { align-self: flex-end; background: var(--bubble-out); border-bottom-right-radius: 4px; }
.message-bubble:not(.mine) { align-self: flex-start; background: var(--bubble-in); border-bottom-left-radius: 4px; }
.msg-time { font-size: 10px; color: rgba(255,255,255,0.6); float: left; margin-top: 4px; margin-left: 6px; display: flex; align-items: center; gap: 3px; }

/* Composer / Input Area */
.chat-composer { padding: 12px 16px; background: var(--panel-bg); border-top: 1px solid var(--border-color); display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.composer-input { flex: 1; background: var(--bg-main); border: none; border-radius: 12px; color: white; padding: 10px 14px; font-size: 14px; outline: none; resize: none; height: 44px; max-height: 120px; }
.action-btn { background: none; border: none; color: var(--text-muted); font-size: 22px; cursor: pointer; padding: 6px; border-radius: 50%; flex-shrink: 0; transition: 0.15s; }
.action-btn:hover { color: white; background: rgba(255,255,255,0.05); }

/* Modals */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: grid; place-items: center; z-index: 1000; padding: 16px; backdrop-filter: blur(4px); }
.modal-card { width: min(420px, 100%); background: var(--panel-bg); border: 1px solid #232e3c; padding: 24px; border-radius: 20px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); max-height: 90vh; overflow-y: auto; }
.hidden { display: none !important; }

.reaction-bar { display: flex; gap: 8px; background: var(--panel-bg); padding: 8px 12px; border-radius: 24px; border: 1px solid #232e3c; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
.reaction-btn { background: none; border: none; font-size: 18px; cursor: pointer; transition: transform 0.1s; }
.reaction-btn:hover { transform: scale(1.2); }

@media (max-width: 768px) {
  .folder-rail { width: 56px; }
  .sidebar { width: calc(100vw - 56px); position: absolute; right: 56px; top: 0; height: 100%; z-index: 5; }
  .sidebar.mobile-hidden { display: none; }
  .chat-main { width: 100vw; position: absolute; inset: 0; z-index: 20; transform: translateX(100%); transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1); }
  .chat-main.mobile-active { transform: translateX(0); }
  .back-btn-mobile { display: inline-block; }
}
</style>
</head>
<body>

<div class="tg-app">
  <!-- Left Nav Rail -->
  <div class="folder-rail">
    <div class="folder-icon active" id="fAll" onclick="switchFolder('all')" title="گفتگوها">💬</div>
    <div class="folder-icon" onclick="openProfileModal()" title="تنظیمات پروفایل">⚙️</div>
  </div>

  <!-- Slide Menu Drawer -->
  <div class="drawer-overlay" id="drawerOverlay" onclick="toggleMenu()"></div>
  <div class="hamburger-menu" id="hamburgerMenu">
    <div class="menu-header">
      <button class="close-menu-btn" onclick="toggleMenu()">✕</button>
      <div class="menu-avatar" id="mAvatar"></div>
      <div style="font-weight: 700; font-size: 16px;" id="mName"></div>
      <div style="font-size: 13px; color: var(--accent); margin-top: 2px;" id="mUser"></div>
    </div>
    <div class="menu-items">
      <div class="menu-item" onclick="toggleMenu(); openProfileModal()"><span>👤</span> تنظیمات پروفایل</div>
      <a href="{{url_for('logout')}}" class="menu-item" style="color: #ff6b6b;"><span>🚪</span> خروج از حساب</a>
    </div>
  </div>

  <!-- Sidebar -->
  <aside class="sidebar" id="sidebarPanel">
    <div class="sidebar-header">
      <button class="action-btn" onclick="toggleMenu()" title="منو">☰</button>
      <div class="search-container">
        <input id="searchInput" placeholder="جستجو آیدی (مثلا ali)..." oninput="searchUsers()">
      </div>
    </div>
    <div class="chat-list" id="chatList"></div>
  </aside>

  <!-- Main Chat Panel -->
  <main class="chat-main" id="chatMainPanel">
    <header class="chat-topbar">
      <div class="chat-topbar-info" onclick="openHeaderProfile()">
        <button class="back-btn-mobile" onclick="closeChatMobile(event)">⬅</button>
        <div class="avatar" id="activeAvatar" style="width:40px; height:40px;">💬</div>
        <div>
          <div style="font-size:15px; font-weight:700;" id="chatTitle">تلگرام پرو</div>
          <div style="font-size:12px; color: var(--text-muted);" id="chatStatus">لطفاً یک گفتگو انتخاب کنید</div>
        </div>
      </div>
    </header>

    <div class="chat-messages" id="chatMessages">
      <div style="margin: auto; text-align: center; color: var(--text-muted); font-size: 14px;">
        یک مخاطب را از جستجو یا لیست انتخاب کنید تا چت آغاز شود 🚀
      </div>
    </div>

    <form class="chat-composer" onsubmit="sendMessage(event)">
      <button type="button" class="action-btn" onclick="$('fileInput').click()" title="ارسال فایل/عکس">📎</button>
      <input type="file" id="fileInput" hidden onchange="handleFileUpload(this)">
      <textarea id="messageInput" class="composer-input" placeholder="نوشتن پیام..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage(event)}"></textarea>
      <button type="submit" class="action-btn" style="color: var(--accent);" title="ارسال">➤</button>
    </form>
  </main>
</div>

<!-- Modal Container -->
<div id="modalOverlay" class="modal-overlay hidden" onclick="if(event.target===this) closeModal()">
  <div class="modal-card" id="modalContent"></div>
</div>

<script>
const meId = {{me['id']}};
let activeUser = null;
const $ = id => document.getElementById(id);

function toggleMenu() {
  $('hamburgerMenu').classList.toggle('open');$('drawerOverlay').classList.toggle('active');
}
function closeModal() { $('modalOverlay').classList.add('hidden'); }
function closeChatMobile(e) { e?.stopPropagation(); $('chatMainPanel').classList.remove('mobile-active'); }

async function api(url, opts={}) {
  let r = await fetch(url, {...opts, headers:{'Content-Type':'application/json', ...(opts.headers||{})}});
  let d = await r.json().catch(()=>({}));
  if(!r.ok) throw Error(d.error || 'خطا در شبکه');
  return d;
}

async function init() {
  let me = await api('/api/me');
  $('mName').textContent = me.display_name;
  $('mUser').textContent = '@' + me.username;
  if(me.avatar) $('mAvatar').style.backgroundImage = `url('${me.avatar}')`;
  else $('mAvatar').textContent = me.display_name[0];
  loadDialogs();
}

async function loadDialogs() {
  let d = await api('/api/dialogs');
  $('chatList').innerHTML = d.dialogs.map(u => `
    <div class="chat-row ${activeUser?.id===u.id?'active':''}" onclick="openUserChat(${u.id},'${esc(u.display_name)}','${esc(u.username)}','${esc(u.avatar||'')}')">
      <div class="avatar" style="${u.avatar?`background-image:url('${u.avatar}')`:''}">${u.avatar?'':u.display_name[0]}</div>
      <div style="flex:1; min-width:0;">
        <div style="display:flex; justify-content:space-between; font-size:14px; font-weight:600;">
          <span>${esc(u.display_name)}</span>
          <span style="font-size:11px; color:var(--text-muted);">${(u.last_time||'').slice(11,16)}</span>
        </div>
        <div style="font-size:13px; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:2px;">${esc(u.last_msg)}</div>
      </div>
    </div>
  `).join('') || '<div style="padding:30px; text-align:center; color:var(--text-muted); font-size:13px;">هنوز گفتگویی ندارید.<br>از طریق جستجو آیدی مخاطب را پیدا کنید.</div>';
}

async function searchUsers() {
  let q = $('searchInput').value.trim();
  if(!q) return loadDialogs();
  let d = await api('/api/users?q=' + encodeURIComponent(q));
  $('chatList').innerHTML = d.users.map(u => `
    <div class="chat-row" onclick="openUserChat(${u.id},'${esc(u.display_name)}','${esc(u.username)}','${esc(u.avatar||'')}')">
      <div class="avatar" style="${u.avatar?`background-image:url('${u.avatar}')`:''}">${u.avatar?'':u.display_name[0]}</div>
      <div>
        <div style="font-size:14px; font-weight:600;">${esc(u.display_name)}</div>
        <div style="font-size:12px; color:var(--accent);">@${esc(u.username)}</div>
      </div>
    </div>
  `).join('') || '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:13px;">کاربری پیدا نشد.</div>';
}

async function openUserChat(id, name, username, avatar) {
  activeUser = {id, name, username, avatar};
  $('chatTitle').textContent = name;
  $('chatStatus').textContent = '@' + username;
  if(avatar) $('activeAvatar').style.backgroundImage = `url('${avatar}')`;
  else { $('activeAvatar').style.backgroundImage = '';$('activeAvatar').textContent = name[0]; }
  
  let d = await api('/api/messages/' + id);
  $('chatMessages').innerHTML = '';
  d.messages.forEach(appendMessage);
  scrollBottom();
  if(window.innerWidth <= 768) $('chatMainPanel').classList.add('mobile-active');
  loadDialogs();
}

function appendMessage(m) {
  let isMine = m.sender_id === meId;
  let el = document.createElement('div');
  el.className = `message-bubble ${isMine?'mine':''}`;
  
  let ticks = isMine ? (m.read_at ? ' <span style="color:#38bdf8;">✓✓</span>' : ' <span>✓</span>') : '';
  let bodyHtml = esc(m.body);
  if(m.msg_type === 'image') bodyHtml = `<img src="${esc(m.body)}" style="max-width:100%; border-radius:10px; display:block;">`;
  
  el.innerHTML = `
    <div>${bodyHtml}</div>
    <div class="msg-time">${(m.created_at||'').slice(11,16)}${ticks}</div>
    ${m.reaction ? `<div style="font-size:13px; margin-top:4px;">${m.reaction}</div>` : ''}
  `;
  el.onclick = () => showMessageMenu(m);
  $('chatMessages').appendChild(el);
}

function showMessageMenu(m) {
  $('modalContent').innerHTML = `
    <div style="display:flex; flex-direction:column; gap:10px;">
      <div style="text-align:center; font-size:13px; color:var(--text-muted); margin-bottom:4px;">واکنش سریع</div>
      <div class="reaction-bar" style="justify-content:center;">
        <button class="reaction-btn" onclick="reactMsg(${m.id},'👍')">👍</button>
        <button class="reaction-btn" onclick="reactMsg(${m.id},'❤️')">❤️</button>
        <button class="reaction-btn" onclick="reactMsg(${m.id},'😂')">😂</button>
        <button class="reaction-btn" onclick="reactMsg(${m.id},'🔥')">🔥</button>
        <button class="reaction-btn" onclick="reactMsg(${m.id},'👏')">👏</button>
      </div>
      ${m.sender_id === meId ? `<button onclick="editMsgPrompt(${m.id},'${esc(m.body)}')" style="padding:10px; background:#1e293b; border:1px solid #334155; color:white; border-radius:10px; cursor:pointer;">ویرایش پیام</button>` : ''}
      ${m.sender_id === meId ? `<button onclick="deleteMsg(${m.id})" style="padding:10px; background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:#fca5a5; border-radius:10px; cursor:pointer;">حذف پیام</button>` : ''}
      <button onclick="closeModal()" style="padding:10px; background:var(--accent); border:none; color:white; border-radius:10px; font-weight:bold; cursor:pointer; margin-top:6px;">بستن</button>
    </div>
  `;
  $('modalOverlay').classList.remove('hidden');
}

async function reactMsg(id, r) { await api(`/api/messages/${id}/react`, {method:'POST', body:JSON.stringify({reaction:r})}); closeModal(); reloadChat(); }
async function deleteMsg(id) { await api(`/api/messages/${id}/delete`, {method:'POST'}); closeModal(); reloadChat(); }
async function editMsgPrompt(id, old) {
  let txt = prompt('متن جدید پیام:', old);
  if(txt) { await api(`/api/messages/${id}/edit`, {method:'POST', body:JSON.stringify({body:txt})}); closeModal(); reloadChat(); }
}
async function reloadChat() { if(activeUser) openUserChat(activeUser.id, activeUser.name, activeUser.username, activeUser.avatar); }

async function sendMessage(e) {
  e?.preventDefault();
  let body = $('messageInput').value.trim();
  if(!body || !activeUser) return;
  let d = await api('/api/messages', {method:'POST', body:JSON.stringify({receiver_id: activeUser.id, body})});
  appendMessage(d.message);
  $('messageInput').value = '';
  scrollBottom();
  loadDialogs();
}

async function handleFileUpload(input) {
  let f = input.files[0]; if(!f || !activeUser) return;
  let fd = new FormData(); fd.append('file', f);
  let r = await fetch('/api/upload', {method:'POST', body:fd});
  let d = await r.json();
  if(r.ok) {
    let m = await api('/api/messages', {method:'POST', body:JSON.stringify({receiver_id: activeUser.id, body: location.origin + d.url, msg_type: 'image'})});
    appendMessage(m.message);
    scrollBottom();
    loadDialogs();
  }
}

async function openProfileModal() {
  let me = await api('/api/me');
  $('modalContent').innerHTML = `
    <h3 style="margin-bottom:16px; font-weight:700;">تنظیمات پروفایل</h3>
    <form onsubmit="updateProfile(event)" style="display:flex; flex-direction:column; gap:12px;">
      <div>
        <label style="font-size:12px; color:var(--text-muted);">نام نمایشی</label>
        <input id="pName" value="${esc(me.display_name)}" style="width:100%; padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px; margin-top:4px;" required>
      </div>
      <div>
        <label style="font-size:12px; color:var(--text-muted);">بیوگرافی</label>
        <textarea id="pBio" style="width:100%; padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px; margin-top:4px; height:70px; resize:none;">${esc(me.bio||'')}</textarea>
      </div>
      <div>
        <label style="font-size:12px; color:var(--text-muted);">لینک عکس پروفایل (URL)</label>
        <input id="pAvatar" value="${esc(me.avatar||'')}" placeholder="https://..." style="width:100%; padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px; margin-top:4px;">
      </div>
      <button type="submit" style="width:100%; padding:12px; background:var(--accent); border:none; color:white; border-radius:10px; font-weight:bold; cursor:pointer; margin-top:6px;">ذخیره تغییرات</button>
    </form>
  `;
  $('modalOverlay').classList.remove('hidden');
}

async function updateProfile(e) {
  e.preventDefault();
  let data = {
    display_name: $('pName').value.trim(),
    bio: $('pBio').value.trim(),
    avatar: $('pAvatar').value.trim(),
    phone: '', birthday: ''
  };
  await api('/api/profile', {method:'POST', body:JSON.stringify(data)});
  closeModal();
  init();
}

async function openHeaderProfile() {
  if(!activeUser) return;
  let d = await api('/api/users?q=' + encodeURIComponent(activeUser.username));
  let u = d.users.find(x => x.id === activeUser.id) || activeUser;
  $('modalContent').innerHTML = `
    <div style="text-align:center;">
      <div class="avatar" style="width:72px; height:72px; margin:0 auto 12px; font-size:24px; ${u.avatar?`background-image:url('${u.avatar}')`:''}">${u.avatar?'':u.display_name[0]}</div>
      <h3 style="font-weight:700;">${esc(u.display_name)}</h3>
      <div style="color:var(--accent); font-size:13px; margin-top:2px;">@${esc(u.username)}</div>
      <p style="margin:14px 0; font-size:13px; color:var(--text-muted); background:#0e1621; padding:10px; border-radius:10px;">${esc(u.bio||'بدون بیوگرافی')}</p>
      <button onclick="closeModal()" style="width:100%; padding:10px; background:var(--accent); border:none; color:white; border-radius:10px; font-weight:bold; cursor:pointer;">بستن</button>
    </div>
  `;
  $('modalOverlay').classList.remove('hidden');
}

function switchFolder(f) { loadDialogs(); }
function scrollBottom() { $('chatMessages').scrollTop = $('chatMessages').scrollHeight; }
function esc(s) { return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const socket = io();
socket.on('new_message', m => { if(activeUser && (m.sender_id===activeUser.id || m.sender_id===meId)) { appendMessage(m); scrollBottom(); } loadDialogs(); });
socket.on('update_message', () => reloadChat());
socket.on('delete_message', () => reloadChat());

init();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    socketio.run(app, host=os.environ.get("HOST","0.0.0.0"), port=int(os.environ.get("PORT","5000")), debug=False, allow_unsafe_werkzeug=True)