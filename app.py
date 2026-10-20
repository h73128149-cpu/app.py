"""
PayamRasan Pro — Ultimate Telegram Clone (Desktop & Mobile Responsive)
Run locally: pip install flask flask-socketio eventlet && python app.py
"""
import os, re, sqlite3, secrets, hashlib, hmac
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, request, redirect, url_for, session, g, jsonify, render_template_string, abort
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
          msg_type TEXT DEFAULT 'text', attachment TEXT DEFAULT '', pinned INTEGER DEFAULT 0,
          deleted INTEGER DEFAULT 0, created_at TEXT NOT NULL, read_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, id);
        CREATE TABLE IF NOT EXISTS saved_messages(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          body TEXT NOT NULL, msg_type TEXT DEFAULT 'text', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks(blocker_id INTEGER, blocked_id INTEGER, PRIMARY KEY(blocker_id, blocked_id));
        CREATE TABLE IF NOT EXISTS groups_chat(id INTEGER PRIMARY KEY, title TEXT NOT NULL,
          owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS group_members(group_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member',
          PRIMARY KEY(group_id,user_id));
        CREATE TABLE IF NOT EXISTS group_messages(id INTEGER PRIMARY KEY, group_id INTEGER,
          sender_id INTEGER, body TEXT NOT NULL, msg_type TEXT DEFAULT 'text', created_at TEXT NOT NULL);
        """)
        columns = [row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()]
        if "phone" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT '+98 9•••••••••'")
        if "birthday" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN birthday TEXT DEFAULT '1375/01/01'")

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

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

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
            db().execute("UPDATE users SET last_seen=? WHERE id=?", (now(),user["id"])); db().commit()
            return redirect(url_for("index"))
        error = "نام کاربری یا رمز عبور نادرست است."
    return render_template_string(AUTH, title="ورود به پیام‌رسان", error=error, action="login")

@app.route("/logout")
@login_required
def logout():
    u=current_user()
    if u:
        db().execute("UPDATE users SET online=0,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()
    session.clear()
    return redirect(url_for("login"))

@app.get("/api/me")
@login_required
def api_me():
    u=current_user()
    if not u: return jsonify(error="کاربر پیدا نشد"), 404
    u_dict = dict(u)
    return jsonify({
        "id": u_dict.get("id"),
        "username": u_dict.get("username",""),
        "display_name": u_dict.get("display_name",""),
        "bio": u_dict.get("bio",""),
        "avatar": u_dict.get("avatar",""),
        "phone": u_dict.get("phone","+98 9•••••••••"),
        "birthday": u_dict.get("birthday","1375/01/01"),
        "online": u_dict.get("online",0),
        "last_seen": u_dict.get("last_seen","")
    })

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
    if avatar:
        db().execute("UPDATE users SET display_name=?,bio=?,phone=?,birthday=?,avatar=? WHERE id=?",(name,bio,phone,birthday,avatar,u["id"]))
    else:
        db().execute("UPDATE users SET display_name=?,bio=?,phone=?,birthday=? WHERE id=?",(name,bio,phone,birthday,u["id"]))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/users")
@login_required
def search_users():
    q=request.args.get("q","").strip().lstrip("@").lower()[:40]
    me=current_user()
    if not q: return jsonify(users=[])
    rows=db().execute("""SELECT id,username,display_name,bio,avatar,phone,birthday,online,last_seen FROM users
       WHERE id!=? AND (username LIKE ? OR display_name LIKE ?) ORDER BY online DESC, username LIMIT 30""",
       (me["id"],f"%{q}%",f"%{q}%")).fetchall()
    return jsonify(users=[dict(r) for r in rows])

@app.get("/api/messages/<int:other_id>")
@login_required
def get_messages(other_id):
    me=current_user()
    if other_id == me["id"]: return jsonify(messages=[])
    blocked=db().execute("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
                         (me["id"],other_id,other_id,me["id"])).fetchone()
    if blocked: return jsonify(error="این گفتگو در دسترس نیست"),403
    db().execute("UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL",(now(),other_id,me["id"]))
    db().commit()
    rows=db().execute("""SELECT m.*,u.username sender_username,u.display_name sender_name FROM messages m
       JOIN users u ON u.id=m.sender_id WHERE
       (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
       ORDER BY m.id DESC LIMIT 300""",(me["id"],other_id,other_id,me["id"])).fetchall()
    return jsonify(messages=[dict(r) for r in reversed(rows)])

@app.post("/api/messages")
@login_required
def send_message():
    me=current_user(); data=request.get_json(silent=True) or {}
    try: rid=int(data.get("receiver_id"))
    except (TypeError,ValueError): return jsonify(error="گیرنده نامعتبر است"),400
    body=str(data.get("body","")).strip()
    msg_type=str(data.get("msg_type","text"))
    if not body and msg_type=='text': return jsonify(error="متن پیام خالی است"),400
    if rid==me["id"] or not db().execute("SELECT id FROM users WHERE id=?",(rid,)).fetchone(): return jsonify(error="کاربر پیدا نشد"),404
    cur=db().execute("INSERT INTO messages(sender_id,receiver_id,body,msg_type,created_at) VALUES(?,?,?,?,?)",(me["id"],rid,body,msg_type,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,sender_id=me["id"],receiver_id=rid,body=body,msg_type=msg_type,created_at=now(),
             sender_username=me["username"],sender_name=me["display_name"],read_at=None,pinned=0)
    socketio.emit("new_message",msg,room=f"user:{rid}")
    socketio.emit("new_message",msg,room=f"user:{me['id']}")
    return jsonify(message=msg)

@app.get("/api/saved")
@login_required
def get_saved_messages():
    me = current_user()
    rows = db().execute("SELECT * FROM saved_messages WHERE user_id=? ORDER BY id DESC", (me["id"],)).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

@app.post("/api/saved")
@login_required
def add_saved_message():
    me = current_user(); data = request.get_json(silent=True) or {}
    body = str(data.get("body","")).strip()
    msg_type = str(data.get("msg_type","text"))
    if not body: return jsonify(error="پیام خالی است"), 400
    cur = db().execute("INSERT INTO saved_messages(user_id,body,msg_type,created_at) VALUES(?,?,?,?)", (me["id"], body, msg_type, now()))
    db().commit()
    return jsonify(message=dict(id=cur.lastrowid, body=body, msg_type=msg_type, created_at=now()))

@app.post("/api/messages/<int:mid>/delete")
@login_required
def delete_message(mid):
    me=current_user()
    cur=db().execute("UPDATE messages SET deleted=1,body='' WHERE id=? AND sender_id=?",(mid,me["id"]))
    db().commit()
    if not cur.rowcount: return jsonify(error="پیام پیدا نشد"),404
    return jsonify(ok=True)

@app.post("/api/messages/<int:mid>/pin")
@login_required
def pin_message(mid):
    me=current_user()
    msg = db().execute("SELECT * FROM messages WHERE id=? AND (sender_id=? OR receiver_id=?)", (mid, me["id"], me["id"])).fetchone()
    if not msg: return jsonify(error="پیام یافت نشد"), 404
    new_pin = 0 if msg["pinned"] else 1
    db().execute("UPDATE messages SET pinned=0 WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)", 
                 (msg["sender_id"], msg["receiver_id"], msg["receiver_id"], msg["sender_id"]))
    db().execute("UPDATE messages SET pinned=? WHERE id=?", (new_pin, mid))
    db().commit()
    return jsonify(ok=True, pinned=new_pin)

@app.get("/api/messages/pinned/<int:other_id>")
@login_required
def get_pinned_message(other_id):
    me = current_user()
    msg = db().execute("""SELECT * FROM messages WHERE pinned=1 AND 
        ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))""", 
        (me["id"], other_id, other_id, me["id"])).fetchone()
    return jsonify(message=dict(msg) if msg else None)

@app.post("/api/block/<int:other_id>")
@login_required
def block_user(other_id):
    me=current_user()
    if other_id==me["id"]: return jsonify(error="نامعتبر"),400
    db().execute("INSERT OR IGNORE INTO blocks VALUES(?,?)",(me["id"],other_id)); db().commit()
    return jsonify(ok=True)

@app.post("/api/upload")
@login_required
def upload():
    f=request.files.get("file")
    if not f or not f.filename: return jsonify(error="فایلی انتخاب نشده"),400
    name=secure_filename(f.filename)
    ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT: return jsonify(error="پسوند فایل مجاز نیست"),400
    token=secrets.token_hex(16)
    saved=f"{token}.{ext}"
    f.save(os.path.join(UPLOAD_DIR,saved))
    return jsonify(url=url_for("uploaded_file",name=saved),name=name)

@app.get("/uploads/<name>")
@login_required
def uploaded_file(name):
    from flask import send_from_directory
    if not re.fullmatch(r"[a-f0-9]{32}\.[a-z0-9]{1,8}",name): abort(404)
    return send_from_directory(UPLOAD_DIR,name,as_attachment=True)

@app.post("/api/groups")
@login_required
def create_group():
    me=current_user(); data=request.get_json(silent=True) or {}
    title=str(data.get("title","")).strip()[:80]
    if not title: return jsonify(error="نام گروه لازم است"),400
    cur=db().execute("INSERT INTO groups_chat(title,owner_id,created_at) VALUES(?,?,?)",(title,me["id"],now()))
    gid=cur.lastrowid
    db().execute("INSERT INTO group_members(group_id,user_id,role) VALUES(?,?,?)",(gid,me["id"],"admin"))
    db().commit()
    return jsonify(id=gid,title=title)

@app.get("/api/groups")
@login_required
def groups():
    me=current_user()
    rows=db().execute("""SELECT g.id,g.title,g.created_at FROM groups_chat g JOIN group_members m ON m.group_id=g.id
       WHERE m.user_id=? ORDER BY g.id DESC""",(me["id"],)).fetchall()
    return jsonify(groups=[dict(r) for r in rows])

@app.get("/api/groups/<int:gid>/messages")
@login_required
def group_messages(gid):
    me=current_user()
    if not db().execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,me["id"])).fetchone(): abort(403)
    rows=db().execute("""SELECT gm.*,u.username,u.display_name FROM group_messages gm JOIN users u ON u.id=gm.sender_id
      WHERE gm.group_id=? ORDER BY gm.id DESC LIMIT 200""",(gid,)).fetchall()
    return jsonify(messages=[dict(r) for r in reversed(rows)])

@app.post("/api/groups/<int:gid>/messages")
@login_required
def post_group_message(gid):
    me=current_user(); data=request.get_json(silent=True) or {}; body=str(data.get("body","")).strip()
    msg_type=str(data.get("msg_type","text"))
    if not body: return jsonify(error="پیام نامعتبر"),400
    if not db().execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,me["id"])).fetchone(): abort(403)
    cur=db().execute("INSERT INTO group_messages(group_id,sender_id,body,msg_type,created_at) VALUES(?,?,?,?,?)",(gid,me["id"],body,msg_type,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,group_id=gid,sender_id=me["id"],body=body,msg_type=msg_type,created_at=now(),
             username=me["username"],display_name=me["display_name"])
    members=db().execute("SELECT user_id FROM group_members WHERE group_id=?",(gid,)).fetchall()
    for m in members: socketio.emit("group_message",msg,room=f"user:{m['user_id']}")
    return jsonify(message=msg)

@socketio.on("connect")
def on_connect(auth=None):
    u=current_user()
    if not u: return False
    join_room(f"user:{u['id']}")
    db().execute("UPDATE users SET online=1,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()
    emit("presence",{"user_id":u["id"],"online":True},broadcast=True)

@socketio.on("disconnect")
def on_disconnect(reason=None):
    u=current_user()
    if u:
        db().execute("UPDATE users SET online=0,last_seen=? WHERE id=?",(now(),u["id"])); db().commit()
        emit("presence",{"user_id":u["id"],"online":False},broadcast=True)


AUTH = r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>{{title}} | پیام‌رسان پرو</title>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
<style>
:root {
  --accent: #2AABEE;
  --bg-grad: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
  --card-bg: rgba(30, 41, 59, 0.85);
  --border: rgba(255, 255, 255, 0.08);
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Vazirmatn', sans-serif; }
body { background: var(--bg-grad); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #f8fafc; padding: 16px; }
.auth-card {
  width: min(420px, 100%); background: var(--card-bg); backdrop-filter: blur(24px);
  border: 1px solid var(--border); padding: 36px 24px; border-radius: 24px;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.6); text-align: center;
}
.logo-icon {
  width: 68px; height: 68px; background: linear-gradient(135deg, #2AABEE, #1d7bb8);
  border-radius: 50%; display: inline-flex; align-items: center; justify-content: center;
  margin-bottom: 18px; color: white; font-size: 30px; box-shadow: 0 10px 25px rgba(42, 171, 238, 0.4);
}
h1 { font-size: 22px; font-weight: 700; margin-bottom: 6px; }
p.subtitle { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
.form-group { margin-bottom: 14px; text-align: right; }
input {
  width: 100%; padding: 13px 16px; background: rgba(15, 23, 42, 0.7);
  border: 1px solid var(--border); border-radius: 12px; color: white; font-size: 14px; outline: none;
  transition: all 0.2s;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px rgba(42, 171, 238, 0.2); }
button {
  width: 100%; padding: 14px; background: linear-gradient(135deg, #2AABEE, #1d7bb8);
  border: none; border-radius: 12px; color: white; font-size: 15px; font-weight: 700; cursor: pointer;
  margin-top: 10px; box-shadow: 0 8px 20px rgba(42, 171, 238, 0.3); transition: transform 0.2s;
}
button:hover { transform: translateY(-2px); }
.error { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; padding: 10px; border-radius: 10px; font-size: 13px; margin-bottom: 16px; }
.footer-link { margin-top: 20px; font-size: 13px; color: #94a3b8; }
.footer-link a { color: var(--accent); text-decoration: none; font-weight: 600; }
</style>
</head>
<body>
<div class="auth-card">
  <div class="logo-icon">✈</div>
  <h1>{{title}}</h1>
  <p class="subtitle">نسخه دسکتاپ و موبایل پیشرفته</p>
  {% if error %}<div class="error">{{error}}</div>{% endif %}
  <form method="post">
    {% if action=='register' %}
    <div class="form-group"><input name="display_name" placeholder="نام نمایشی" maxlength="50" required></div>
    {% endif %}
    <div class="form-group"><input name="username" placeholder="نام کاربری (بدون @)" autocomplete="username" required></div>
    <div class="form-group"><input name="password" type="password" placeholder="رمز عبور" autocomplete="current-password" required></div>
    <button type="submit">{{title}}</button>
  </form>
  <div class="footer-link">
    {% if action=='login' %}حساب کاربری نداری؟ <a href="{{url_for('register')}}">ثبت‌نام</a>{% else %}قبلاً ثبت‌نام کردی؟ <a href="{{url_for('login')}}">ورود</a>{% endif %}
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
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Telegram Desktop & Mobile Pro</title>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
<style>
:root {
  --bg-main: #0e1621;
  --panel-bg: #17212b;
  --panel-hover: #202b38;
  --active-bg: #2b5278;
  --border-color: #0f1621;
  --text-primary: #f5f5f5;
  --text-muted: #8eabbf;
  --accent: #2AABEE;
  --bubble-out: #2b5278;
  --bubble-in: #182533;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Vazirmatn', sans-serif; -webkit-tap-highlight-color: transparent; }
body { background: var(--bg-main); color: var(--text-primary); height: 100vh; overflow: hidden; display: flex; }

.tg-app { display: flex; width: 100vw; height: 100vh; position: relative; overflow: hidden; }

/* Left Folder Navigation Bar */
.folder-rail { width: 68px; background: #0e1621; border-left: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; padding: 12px 0; gap: 16px; z-index: 15; flex-shrink: 0; }
.folder-icon { width: 44px; height: 44px; border-radius: 12px; display: grid; place-items: center; font-size: 18px; color: var(--text-muted); cursor: pointer; transition: all 0.2s; position: relative; }
.folder-icon:hover, .folder-icon.active { background: #17212b; color: var(--accent); }

/* Hamburger Slide Menu */
.hamburger-menu {
  position: absolute; top: 0; right: -300px; width: 300px; height: 100%;
  background: var(--panel-bg); border-left: 1px solid #232e3c; z-index: 100;
  transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: flex; flex-direction: column;
  box-shadow: -5px 0 25px rgba(0,0,0,0.5);
}
.hamburger-menu.open { right: 0; }
.menu-header { background: #232e3c; padding: 24px 20px; display: flex; flex-direction: column; gap: 10px; }
.menu-avatar { width: 54px; height: 54px; border-radius: 50%; background: var(--accent); display: grid; place-items: center; font-size: 22px; font-weight: bold; color: white; background-size: cover; background-position: center; }
.menu-items { padding: 12px 0; overflow-y: auto; flex: 1; }
.menu-item { padding: 12px 22px; display: flex; align-items: center; gap: 16px; cursor: pointer; font-size: 14px; color: #d7e1ed; text-decoration: none; }
.menu-item:hover { background: var(--panel-hover); }

/* Left Sidebar */
.sidebar { width: 320px; background: var(--panel-bg); border-left: 1px solid var(--border-color); display: flex; flex-direction: column; z-index: 10; flex-shrink: 0; }
.sidebar-header { padding: 10px 14px; display: flex; align-items: center; gap: 10px; background: var(--panel-bg); }
.menu-btn { background: none; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; padding: 6px; border-radius: 50%; }
.menu-btn:hover { background: var(--panel-hover); color: white; }
.search-container { flex: 1; background: #0e1621; border-radius: 20px; display: flex; align-items: center; padding: 0 14px; height: 38px; }
.search-container input { width: 100%; background: none; border: none; color: white; outline: none; font-size: 13px; }

.chat-list { flex: 1; overflow-y: auto; }
.chat-row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; cursor: pointer; transition: background 0.15s; }
.chat-row:hover, .chat-row.active { background: var(--panel-hover); }
.chat-row.active { background: var(--active-bg); }
.avatar { width: 48px; height: 48px; border-radius: 50%; background: #2b5278; display: grid; place-items: center; font-weight: bold; color: white; flex-shrink: 0; background-size: cover; background-position: center; }
.chat-info { flex: 1; min-width: 0; border-bottom: 1px solid rgba(255,255,255,0.03); padding-bottom: 8px; }
.chat-name-row { display: flex; justify-content: space-between; font-size: 14px; font-weight: 600; margin-bottom: 3px; }
.chat-preview { font-size: 12px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Main Chat Window */
.chat-main { flex: 1; display: flex; flex-direction: column; background: var(--bg-main); position: relative; min-width: 0; }
.chat-topbar { padding: 10px 16px; background: var(--panel-bg); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; z-index: 5; height: 60px; }
.chat-topbar-info { display: flex; align-items: center; gap: 12px; cursor: pointer; min-width: 0; }
.top-title { font-size: 15px; font-weight: bold; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.top-status { font-size: 12px; color: var(--text-muted); }
.topbar-actions { display: flex; gap: 4px; align-items: center; position: relative; flex-shrink: 0; }

.back-btn-mobile { display: none; background: none; border: none; color: white; font-size: 20px; cursor: pointer; padding: 4px 8px 4px 0; }

/* Header Dropdown Menu */
.header-dropdown-menu {
  position: absolute; top: 45px; left: 0; width: 220px;
  background: var(--panel-bg); border: 1px solid #232e3c; border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.6); display: flex; flex-direction: column; z-index: 100; padding: 6px 0;
}
.header-dropdown-item { padding: 10px 16px; display: flex; align-items: center; gap: 12px; font-size: 13px; color: #d7e1ed; cursor: pointer; }
.header-dropdown-item:hover { background: var(--panel-hover); }
.header-dropdown-item.danger { color: #ff6961; }

.pinned-banner { background: var(--panel-bg); border-bottom: 1px solid var(--border-color); padding: 8px 16px; display: flex; align-items: center; justify-content: space-between; font-size: 13px; border-right: 3px solid var(--accent); }

.chat-messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; background-color: var(--bg-main); background-size: cover; background-position: center; }
.message-bubble { max-width: 75%; padding: 8px 12px 6px 12px; border-radius: 12px; font-size: 14px; position: relative; line-height: 1.5; word-wrap: break-word; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
.message-bubble.mine { align-self: flex-end; background: var(--bubble-out); border-top-left-radius: 12px; border-top-right-radius: 2px; }
.message-bubble:not(.mine) { align-self: flex-start; background: var(--bubble-in); border-top-left-radius: 2px; border-top-right-radius: 12px; }
.msg-time { font-size: 10px; color: rgba(255,255,255,0.6); float: left; margin-top: 4px; margin-right: 8px; display: flex; align-items: center; gap: 2px; }

.chat-composer { padding: 10px 16px; background: var(--panel-bg); display: flex; align-items: center; gap: 8px; position: relative; }
.composer-input { flex: 1; background: var(--bg-main); border: none; border-radius: 10px; color: white; padding: 10px 14px; font-size: 14px; outline: none; resize: none; height: 44px; max-height: 120px; }
.action-icon-btn { background: none; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; padding: 8px; border-radius: 50%; flex-shrink: 0; }
.action-icon-btn:hover { background: var(--panel-hover); color: white; }

/* Telegram Attachment Popup Menu */
.attach-menu {
  position: absolute; bottom: 65px; right: 16px; width: 190px;
  background: var(--panel-bg); border: 1px solid #232e3c; border-radius: 12px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.5); display: flex; flex-direction: column; z-index: 50; padding: 6px 0;
}
.attach-item { padding: 10px 16px; display: flex; align-items: center; gap: 12px; font-size: 13px; color: #d7e1ed; cursor: pointer; }
.attach-item:hover { background: var(--panel-hover); }

/* Modals */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: grid; place-items: center; z-index: 1000; padding: 16px; }
.modal-card { width: min(440px, 100%); background: var(--panel-bg); border: 1px solid #232e3c; padding: 24px; border-radius: 16px; box-shadow: 0 15px 40px rgba(0,0,0,0.6); max-height: 90vh; overflow-y: auto; }
.hidden { display: none !important; }
.empty-placeholder { margin: auto; text-align: center; color: var(--text-muted); font-size: 14px; padding: 20px; }

/* Mobile Responsiveness Styles */
@media (max-width: 768px) {
  .folder-rail { width: 56px; gap: 12px; }
  .folder-icon { width: 38px; height: 38px; font-size: 16px; }
  .sidebar { width: calc(100vw - 56px); position: absolute; right: 56px; top: 0; height: 100%; transition: transform 0.3s ease; z-index: 5; }
  .sidebar.mobile-hidden { transform: translateX(100%); pointer-events: none; }
  .chat-main { width: 100vw; position: absolute; inset: 0; z-index: 20; transform: translateX(100%); transition: transform 0.3s ease; }
  .chat-main.mobile-active { transform: translateX(0); }
  .back-btn-mobile { display: inline-block; }
  .message-bubble { max-width: 85%; }
}
</style>
</head>
<body>

<div class="tg-app" id="app">
  <!-- Folder Rail Left Bar -->
  <div class="folder-rail">
    <div class="folder-icon active" id="fFolderAll" onclick="switchFolder('all')" title="همه گفتگوها">💬</div>
    <div class="folder-icon" id="fFolderPv" onclick="switchFolder('pv')" title="پیوی‌ها (PV)">👤</div>
    <div class="folder-icon" id="fFolderGroups" onclick="switchFolder('groups')" title="گروه‌ها">👥</div>
  </div>

  <!-- Hamburger Slide Menu -->
  <div class="hamburger-menu" id="hamburgerMenu">
    <div class="menu-header">
      <div class="menu-avatar" id="menuAvatarBox" style="{% if me['avatar'] %}background-image: url('{{me['avatar']}}'){% endif %}">
        {% if not me['avatar'] %}{{me['display_name'][0]}}{% endif %}
      </div>
      <div style="font-weight: bold; font-size: 15px;">{{me['display_name']}}</div>
      <div style="font-size: 12px; color: var(--text-muted);">@{{me['username']}}</div>
    </div>
    <div class="menu-items">
      <div class="menu-item" onclick="openProfileModal()"><span>👤</span> تنظیمات پروفایل و تصویر</div>
      <div class="menu-item" onclick="openSavedMessages()"><span>💾</span> پیام‌های ذخیره‌شده (Saved Messages)</div>
      <a href="{{url_for('logout')}}" class="menu-item" style="color: #ff6961;"><span>🚪</span> خروج از حساب</a>
    </div>
  </div>

  <!-- Left Sidebar -->
  <aside class="sidebar" id="sidebarPanel">
    <div class="sidebar-header">
      <button class="menu-btn" onclick="toggleMenu()">☰</button>
      <div class="search-container">
        <input id="searchInput" placeholder="جستجوی آیدی یا نام..." oninput="searchUsers()">
      </div>
    </div>
    <div class="chat-list" id="chatList">
      <div class="empty-placeholder">آیدی یا نام کاربر را در بالا جستجو کنید.</div>
    </div>
  </aside>

  <!-- Main Chat Window -->
  <main class="chat-main" id="chatMainPanel">
    <header class="chat-topbar">
      <div class="chat-topbar-info" onclick="openHeaderProfile()">
        <button class="back-btn-mobile" onclick="closeChatMobile(event)">⬅</button>
        <div class="avatar" id="activeAvatar" style="width: 38px; height: 38px; font-size: 15px;">💬</div>
        <div style="min-width:0;">
          <div class="top-title" id="chatTitle">تلگرام پرو</div>
          <div class="top-status" id="chatStatus">یک مخاطب را جستجو کنید</div>
        </div>
      </div>
      <div class="topbar-actions">
        <button class="action-icon-btn" onclick="pinCurrentMessage()" title="پین کردن">📌</button>
        <button class="action-icon-btn" onclick="toggleHeaderMenu(event)" title="گزینه‌ها">⋮</button>
        <div class="header-dropdown-menu hidden" id="headerDropdownMenu">
          <div class="header-dropdown-item" onclick="alert('اعلان‌ها بی‌صدا شدند')">🔕 Mute notifications</div>
          <div class="header-dropdown-item" onclick="openHeaderProfile()">👤 View profile</div>
          <div class="header-dropdown-item" onclick="$('wallpaperFileInput').click()">🖼 Set Wallpaper from File</div>
          <div class="header-dropdown-item danger" onclick="clearHistoryAction()">🗑 Clear history</div>
          <div class="header-dropdown-item danger" onclick="blockUserAction()">🚫 Delete chat / Block</div>
        </div>
      </div>
    </header>

    <input type="file" id="wallpaperFileInput" accept="image/*" hidden onchange="handleWallpaperSelected(this)">
    <div id="pinnedBannerContainer"></div>

    <div class="chat-messages" id="chatMessages">
      <div class="empty-placeholder">گفتگویی انتخاب نشده است.</div>
    </div>

    <form class="chat-composer" id="composerForm" onsubmit="sendMessage(event)">
      <button type="button" class="action-icon-btn" onclick="toggleAttachMenu()" title="پیوست فایل">📎</button>
      
      <!-- Attachment Popup Menu -->
      <div class="attach-menu hidden" id="attachMenu">
        <div class="attach-item" onclick="triggerFileUpload('image/*')"><span>🖼</span> Photo or video</div>
        <div class="attach-item" onclick="triggerFileUpload('audio/*')"><span>🎵</span> Music / Audio</div>
        <div class="attach-item" onclick="sendLocationMessage()"><span>📍</span> Location</div>
      </div>
      <input type="file" id="hiddenFileInput" hidden onchange="handleFileSelected(this)">

      <textarea id="messageInput" class="composer-input" placeholder="نوشتن پیام..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage(event)}"></textarea>
      
      <button type="button" class="action-icon-btn" id="voiceBtn" onclick="recordVoiceMessage()" title="ضبط ویس">🎙</button>
      <button type="submit" class="action-icon-btn" style="color: var(--accent);" title="ارسال">➤</button>
    </form>
  </main>
</div>

<!-- Modal Box -->
<div id="modalOverlay" class="modal-overlay hidden" onclick="if(event.target===this) closeModal()">
  <div class="modal-card" id="modalCardContent"></div>
</div>

<script>
const meId = {{me['id']}};
let activeUser = null, activeGroup = null, isSavedChat = false, currentFolder = 'all', knownMsgs = new Set(), socket = null;
let myAvatarUrl = "{{me['avatar']}}";
const $ = id => document.getElementById(id);

function toggleMenu() { $('hamburgerMenu').classList.toggle('open'); }
function closeModal() { 
  $('modalOverlay').classList.add('hidden'); 
  $('attachMenu').classList.add('hidden'); 
  $('headerDropdownMenu').classList.add('hidden');
}
function toggleAttachMenu() { $('attachMenu').classList.toggle('hidden'); }
function toggleHeaderMenu(e) { e.stopPropagation(); $('headerDropdownMenu').classList.toggle('hidden'); }

function openChatMobile() {
  if (window.innerWidth <= 768) {
    $('chatMainPanel').classList.add('mobile-active');
  }
}

function closeChatMobile(e) {
  e?.stopPropagation();
  $('chatMainPanel').classList.remove('mobile-active');
}

function switchFolder(folder) {
  currentFolder = folder;
  document.querySelectorAll('.folder-icon').forEach(el => el.classList.remove('active'));
  if(folder === 'all') $('fFolderAll').classList.add('active');
  if(folder === 'pv') $('fFolderPv').classList.add('active');
  if(folder === 'groups') $('fFolderGroups').classList.add('active');

  if(folder === 'groups') loadGroups();
  else {
    $('chatList').innerHTML = '<div class="empty-placeholder">آیدی یا نام کاربر را جستجو کنید.</div>';
  }
}

async function api(url, opts={}) {
  let r = await fetch(url, {...opts, headers:{'Content-Type':'application/json', ...(opts.headers||{})}});
  let d = await r.json().catch(()=>({}));
  if(!r.ok) throw Error(d.error || 'خطا در ارتباط با سرور');
  return d;
}

async function searchUsers() {
  if(currentFolder === 'groups') return;
  let q = $('searchInput').value.trim();
  if(!q) { $('chatList').innerHTML = '<div class="empty-placeholder">نام یا آیدی کاربر را وارد کنید.</div>'; return; }
  try {
    let d = await api('/api/users?q=' + encodeURIComponent(q));
    $('chatList').innerHTML = d.users.map(u => {
      let avatarStyle = u.avatar ? `background-image: url('${u.avatar}');` : '';
      let avatarText = u.avatar ? '' : esc(u.display_name[0]);
      return `
        <div class="chat-row ${activeUser?.id === u.id ? 'active':''}" onclick="openUserChat(${u.id}, '${esc(u.display_name)}', '${esc(u.username)}', '${esc(u.avatar||'')}')">
          <div class="avatar" style="${avatarStyle}">${avatarText}</div>
          <div class="chat-info">
            <div class="chat-name-row"><span>${esc(u.display_name)}</span><span style="font-size:10px; color:var(--text-muted);">${u.online ? 'آنلاین' : ''}</span></div>
            <div class="chat-preview">@${esc(u.username)}</div>
          </div>
        </div>
      `;
    }).join('') || '<div class="empty-placeholder">کاربری با این مشخصات یافت نشد</div>';
  } catch(e){}
}

async function loadGroups() {
  try {
    let d = await api('/api/groups');
    $('chatList').innerHTML = d.groups.map(g => `
      <div class="chat-row" onclick="openGroupChat(${g.id}, '${esc(g.title)}')">
        <div class="avatar">#</div>
        <div class="chat-info">
          <div class="chat-name-row"><span>${esc(g.title)}</span></div>
          <div class="chat-preview">گروه تلگرامی</div>
        </div>
      </div>
    `).join('') || '<div class="empty-placeholder">گروهی ندارید</div>';
  } catch(e){}
}

async function openUserChat(id, name, username, avatar) {
  activeGroup = null; isSavedChat = false; activeUser = {id, name, username, avatar};
  knownMsgs.clear();
  $('chatTitle').textContent = name;
  $('chatStatus').textContent = 'آخرین بازدید اخیراً';
  if(avatar) {
    $('activeAvatar').style.backgroundImage = `url('${avatar}')`;
    $('activeAvatar').textContent = '';
  } else {
    $('activeAvatar').style.backgroundImage = '';
    $('activeAvatar').textContent = name[0];
  }
  $('chatMessages').innerHTML = '';
  await loadPinnedMessage(id);
  let d = await api('/api/messages/' + id);
  d.messages.forEach(appendMessage);
  scrollChatToBottom();
  openChatMobile();
}

async function openSavedMessages() {
  toggleMenu();
  activeGroup = null; activeUser = null; isSavedChat = true;
  knownMsgs.clear();
  $('chatTitle').textContent = 'پیام‌های ذخیره‌شده';
  $('chatStatus').textContent = 'فضای ابری شخصی';
  $('activeAvatar').style.backgroundImage = '';
  $('activeAvatar').textContent = '💾';
  $('pinnedBannerContainer').innerHTML = '';
  $('chatMessages').innerHTML = '';
  let d = await api('/api/saved');
  d.messages.forEach(m => renderMessageElement(m, 'mine', $('chatMessages')));
  scrollChatToBottom();
  openChatMobile();
}

async function openGroupChat(id, title) {
  activeUser = null; isSavedChat = false; activeGroup = {id, title};
  knownMsgs.clear();
  $('chatTitle').textContent = title;
  $('chatStatus').textContent = 'گروه';
  $('activeAvatar').style.backgroundImage = '';
  $('activeAvatar').textContent = '#';
  $('chatMessages').innerHTML = '';
  $('pinnedBannerContainer').innerHTML = '';
  let d = await api('/api/groups/' + id + '/messages');
  d.messages.forEach(m => renderMessageElement(m, m.sender_id === meId ? 'mine' : '', $('chatMessages'), m.username));
  scrollChatToBottom();
  openChatMobile();
}

function renderMessageElement(m, bubbleClass, container, senderName=null) {
  if(knownMsgs.has(m.id)) return;
  knownMsgs.add(m.id);
  let el = document.createElement('div');
  el.className = 'message-bubble ' + bubbleClass;
  
  let contentHtml = esc(m.body);
  if(m.msg_type === 'image') contentHtml = `<img src="${esc(m.body)}" style="max-width:100%; border-radius:8px; display:block;">`;
  else if(m.msg_type === 'audio') contentHtml = `<audio controls src="${esc(m.body)}" style="width:200px; max-width:100%;"></audio>`;
  else if(m.msg_type === 'location') contentHtml = `📍 <b>موقعیت مکانی:</b><br><a href="${esc(m.body)}" target="_blank" style="color:#38bdf8;">مشاهده در نقشه ↗</a>`;
  else if(m.msg_type === 'voice') contentHtml = `🎙 <b>پیام صوتی:</b><br><audio controls src="${esc(m.body)}" style="width:180px; max-width:100%;"></audio>`;

  let headerTag = senderName ? `<div style="font-size:11px; color:var(--accent); font-weight:bold; margin-bottom:2px;">@${esc(senderName)}</div>` : '';
  el.innerHTML = `${headerTag}${contentHtml}<div class="msg-time">${(m.created_at||'').slice(11,16)}</div>`;
  container.appendChild(el);
}

function appendMessage(m) {
  renderMessageElement(m, m.sender_id === meId ? 'mine' : '', $('chatMessages'));
}

async function sendMessage(e) {
  e?.preventDefault();
  let body = $('messageInput').value.trim();
  if(!body) return;
  sendPayload(body, 'text');
}

async function sendPayload(body, msgType) {
  try {
    if(isSavedChat) {
      let d = await api('/api/saved', {method:'POST', body:JSON.stringify({body, msg_type: msgType})});
      renderMessageElement(d.message, 'mine', $('chatMessages'));
    } else if(activeGroup) {
      let d = await api('/api/groups/' + activeGroup.id + '/messages', {method:'POST', body:JSON.stringify({body, msg_type: msgType})});
      appendGroupMessage(d.message);
    } else if(activeUser) {
      let d = await api('/api/messages', {method:'POST', body:JSON.stringify({receiver_id:activeUser.id, body, msg_type: msgType})});
      appendMessage(d.message);
    } else {
      alert('لطفاً یک گفتگو را انتخاب کنید.');
      return;
    }
    $('messageInput').value = '';
    scrollChatToBottom();
  } catch(err) { alert(err.message); }
}

function appendGroupMessage(m) {
  renderMessageElement(m, m.sender_id === meId ? 'mine' : '', $('chatMessages'), m.username);
}

function triggerFileUpload(accept) {
  toggleAttachMenu();
  $('hiddenFileInput').accept = accept;
  $('hiddenFileInput').click();
}

async function handleFileSelected(input) {
  let f = input.files[0];
  if(!f) return;
  let fd = new FormData(); fd.append('file', f);
  try {
    let r = await fetch('/api/upload', {method:'POST', body:fd});
    let d = await r.json();
    if(!r.ok) throw Error(d.error || 'خطا در آپلود');
    let fileUrl = location.origin + d.url;
    let mType = 'image';
    if(f.type.includes('audio') || f.name.endsWith('.mp3') || f.name.endsWith('.wav')) mType = 'audio';
    sendPayload(fileUrl, mType);
  } catch(e) { alert(e.message); }
  input.value = '';
}

async function handleWallpaperSelected(input) {
  let f = input.files[0];
  if(!f) return;
  let fd = new FormData(); fd.append('file', f);
  try {
    let r = await fetch('/api/upload', {method:'POST', body:fd});
    let d = await r.json();
    if(r.ok) {
      let wallUrl = location.origin + d.url;
      $('chatMessages').style.backgroundImage = `url('${wallUrl}')`;
    }
  } catch(e) { alert(e.message); }
  input.value = '';
}

function clearHistoryAction() {
  if(confirm('آیا از پاک کردن تاریخچه گفتگو مطمئن هستید؟')) {
    $('chatMessages').innerHTML = '<div class="empty-placeholder">تاریخچه پاک شد.</div>';
  }
}

function sendLocationMessage() {
  toggleAttachMenu();
  if(!navigator.geolocation) { alert('GPS پشتیبانی نمی‌شود.'); return; }
  navigator.geolocation.getCurrentPosition(pos => {
    let lat = pos.coords.latitude, lon = pos.coords.longitude;
    sendPayload(`https://maps.google.com/?q=${lat},${lon}`, 'location');
  }, () => { alert('خطا در دریافت لوکیشن.'); });
}

function recordVoiceMessage() {
  if(!navigator.mediaDevices?.getUserMedia) { alert('میکروفون غیرفعال است.'); return; }
  navigator.mediaDevices.getUserMedia({audio:true}).then(stream => {
    let recorder = new MediaRecorder(stream);
    let chunks = [];
    recorder.ondataavailable = e => chunks.push(e.data);
    recorder.onstop = async () => {
      let blob = new Blob(chunks, {type:'audio/webm'});
      let f = new File([blob], 'voice.webm', {type:'audio/webm'});
      let fd = new FormData(); fd.append('file', f);
      let r = await fetch('/api/upload', {method:'POST', body:fd});
      let d = await r.json();
      if(r.ok) { sendPayload(location.origin + d.url, 'voice'); }
      stream.getTracks().forEach(t => t.stop());
    };
    recorder.start();
    alert('در حال ضبط صدا... پس از ۴ ثانیه ارسال می‌شود.');
    setTimeout(() => recorder.stop(), 4000);
  });
}

async function pinCurrentMessage() {
  if(!activeUser) { alert('فقط در چت خصوصی'); return; }
  let lastId = Array.from(knownMsgs).pop();
  if(!lastId) return;
  try {
    await api('/api/messages/' + lastId + '/pin', {method:'POST'});
    loadPinnedMessage(activeUser.id);
  } catch(e){}
}

async function loadPinnedMessage(otherId) {
  try {
    let d = await api('/api/messages/pinned/' + otherId);
    if(d.message) {
      $('pinnedBannerContainer').innerHTML = `<div class="pinned-banner"><span>📌 <b>پیام پین شده:</b> ${esc(d.message.body)}</span></div>`;
    } else {
      $('pinnedBannerContainer').innerHTML = '';
    }
  } catch(e){}
}

function scrollChatToBottom() { $('chatMessages').scrollTop = $('chatMessages').scrollHeight; }
function esc(s) { return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function openHeaderProfile() {
  if(!activeUser) return;
  try {
    let d = await api('/api/users?q=' + encodeURIComponent(activeUser.username));
    let u = d.users.find(x => x.id === activeUser.id) || activeUser;
    let avStyle = u.avatar ? `background-image: url('${u.avatar}');` : '';
    let avText = u.avatar ? '' : esc(u.display_name[0]);
    $('modalCardContent').innerHTML = `
      <div style="text-align:center; margin-bottom:16px;">
        <div class="avatar" style="width:72px; height:72px; font-size:28px; margin:0 auto 10px; ${avStyle}">${avText}</div>
        <h3 style="font-size:18px;">${esc(u.display_name)}</h3>
        <div style="font-size:13px; color:var(--accent);">@${esc(u.username)}</div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">${u.online ? 'آنلاین' : 'آفلاین'}</div>
      </div>
      <div style="background:#0e1621; padding:12px; border-radius:10px; margin-bottom:12px; font-size:13px;">
        <div style="color:var(--text-muted); font-size:11px; margin-bottom:4px;">شماره تلفن</div>
        <div>${esc(u.phone || '+98 9•••••••••')}</div>
      </div>
      <div style="background:#0e1621; padding:12px; border-radius:10px; margin-bottom:12px; font-size:13px;">
        <div style="color:var(--text-muted); font-size:11px; margin-bottom:4px;">تاریخ تولد</div>
        <div>${esc(u.birthday || 'ثبت نشده')}</div>
      </div>
      <div style="background:#0e1621; padding:12px; border-radius:10px; margin-bottom:16px; font-size:13px;">
        <div style="color:var(--text-muted); font-size:11px; margin-bottom:4px;">بیوگرافی</div>
        <div>${esc(u.bio || 'بدون بیوگرافی')}</div>
      </div>
      <button onclick="closeModal()" style="width:100%; padding:10px; background:var(--accent); border:none; border-radius:8px; color:white; font-weight:bold; cursor:pointer;">بستن</button>
    `;
    $('modalOverlay').classList.remove('hidden');
  } catch(e){
    alert('خطا در دریافت اطلاعات پروفایل');
  }
}

async function openProfileModal() {
  toggleMenu();
  try {
    let u = await api('/api/me');
    let avStyle = u.avatar ? `background-image: url('${u.avatar}');` : '';
    let avText = u.avatar ? '' : esc(u.display_name[0]);
    $('modalCardContent').innerHTML = `
      <h3 style="margin-bottom:14px">تنظیمات پروفایل</h3>
      <div style="text-align:center; margin-bottom:14px;">
        <div class="avatar" id="editAvatarPreview" style="width:70px; height:70px; font-size:26px; margin:0 auto 8px; ${avStyle}">${avText}</div>
        <button type="button" onclick="$('avatarFileInput').click()" style="padding:6px 12px; background:#2b5278; border:none; border-radius:6px; color:white; font-size:12px; cursor:pointer;">آپلود عکس پروفایل</button>
        <input type="file" id="avatarFileInput" accept="image/*" hidden onchange="uploadAvatarFile(this)">
      </div>
      <div style="margin-bottom:10px"><label style="font-size:12px; color:var(--text-muted)">نام نمایشی</label><input id="modalName" value="${esc(u.display_name)}" style="width:100%; padding:10px; background:#0e1621; border:1px solid #232e3c; border-radius:8px; color:white; margin-top:4px;"></div>
      <div style="margin-bottom:10px"><label style="font-size:12px; color:var(--text-muted)">شماره تلفن</label><input id="modalPhone" value="${esc(u.phone)}" style="width:100%; padding:10px; background:#0e1621; border:1px solid #232e3c; border-radius:8px; color:white; margin-top:4px;"></div>
      <div style="margin-bottom:10px"><label style="font-size:12px; color:var(--text-muted)">تاریخ تولد</label><input id="modalBday" value="${esc(u.birthday)}" style="width:100%; padding:10px; background:#0e1621; border:1px solid #232e3c; border-radius:8px; color:white; margin-top:4px;"></div>
      <div style="margin-bottom:14px"><label style="font-size:12px; color:var(--text-muted)">بیوگرافی</label><textarea id="modalBio" style="width:100%; padding:10px; background:#0e1621; border:1px solid #232e3c; border-radius:8px; color:white; margin-top:4px;">${esc(u.bio)}</textarea></div>
      <button onclick="saveProfileChanges()" style="width:100%; padding:10px; background:var(--accent); border:none; border-radius:8px; color:white; font-weight:bold; cursor:pointer;">ذخیره تغییرات</button>
      <button onclick="closeModal()" style="width:100%; padding:10px; background:transparent; border:none; color:var(--text-muted); margin-top:6px; cursor:pointer;">انصراف</button>
    `;
    $('modalOverlay').classList.remove('hidden');
  } catch(e) {
    alert('دریافت پروفایل با خطا مواجه شد');
  }
}

async function uploadAvatarFile(input) {
  let f = input.files[0];
  if(!f) return;
  let fd = new FormData(); fd.append('file', f);
  let r = await fetch('/api/upload', {method:'POST', body:fd});
  let d = await r.json();
  if(r.ok) {
    myAvatarUrl = location.origin + d.url;
    $('editAvatarPreview').style.backgroundImage = `url('${myAvatarUrl}')`;
    $('editAvatarPreview').textContent = '';
  }
}

async function saveProfileChanges() {
  try {
    await api('/api/profile', {
      method:'POST', 
      body:JSON.stringify({
        display_name: $('modalName').value, 
        phone: $('modalPhone').value,
        birthday: $('modalBday').value,
        bio: $('modalBio').value,
        avatar: myAvatarUrl
      })
    });
    closeModal();
    location.reload();
  } catch(e) {
    alert(e.message);
  }
}

function blockUserAction() {
  if(!activeUser) return;
  if(confirm('آیا از مسدودسازی کاربر مطمئن هستید؟')) {
    api('/api/block/' + activeUser.id, {method:'POST'}).then(()=> { alert('کاربر مسدود شد'); location.reload(); });
  }
}

document.addEventListener('click', () => { $('headerDropdownMenu').classList.add('hidden'); });

try {
  socket = io();
  socket.on('new_message', m => {
    if(activeUser && (m.sender_id === activeUser.id || m.sender_id === meId)) { appendMessage(m); scrollChatToBottom(); }
  });
  socket.on('group_message', m => {
    if(activeGroup && m.group_id === activeGroup.id) { appendGroupMessage(m); scrollChatToBottom(); }
  });
} catch(e){}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    socketio.run(app, host=os.environ.get("HOST","127.0.0.1"), port=int(os.environ.get("PORT","5000")), debug=False)