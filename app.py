"""
PayamRasan Pro — Fixed & Complete Telegram Clone
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
        CREATE TABLE IF NOT EXISTS user_blocks(
          blocker_id INTEGER NOT NULL REFERENCES users(id), blocked_id INTEGER NOT NULL REFERENCES users(id),
          PRIMARY KEY(blocker_id, blocked_id));
        CREATE TABLE IF NOT EXISTS hidden_chats(
          user_id INTEGER NOT NULL REFERENCES users(id), other_id INTEGER NOT NULL REFERENCES users(id),
          PRIMARY KEY(user_id, other_id));
        CREATE TABLE IF NOT EXISTS user_settings(
          user_id INTEGER PRIMARY KEY REFERENCES users(id), chat_background TEXT DEFAULT '',
          show_last_seen INTEGER DEFAULT 1, theme TEXT DEFAULT 'dark');
        CREATE TABLE IF NOT EXISTS device_accounts(
          device_token TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL, PRIMARY KEY(device_token,user_id));
        CREATE TABLE IF NOT EXISTS chat_groups(
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS group_members(
          group_id INTEGER NOT NULL REFERENCES chat_groups(id), user_id INTEGER NOT NULL REFERENCES users(id),
          PRIMARY KEY(group_id,user_id));
        CREATE TABLE IF NOT EXISTS group_messages(
          id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES chat_groups(id),
          sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT DEFAULT '',
          msg_type TEXT DEFAULT 'text', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS group_invites(
          id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES chat_groups(id),
          token TEXT UNIQUE NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
        """)
        # Ensure settings exist for existing accounts
        c.execute("INSERT OR IGNORE INTO user_settings(user_id) SELECT id FROM users")

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
    device_token = request.cookies.get("pr_device") or secrets.token_urlsafe(24)
    if request.method == "POST":
        username = request.form.get("username"," ").strip().lstrip("@")
        display = request.form.get("display_name","").strip()[:50]
        password = request.form.get("password","")
        count = db().execute("SELECT COUNT(*) FROM device_accounts WHERE device_token=?", (device_token,)).fetchone()[0]
        if count >= 2:
            error = "روی این مرورگر حداکثر دو حساب می‌توانی بسازی. برای امنیت، کوکی مرورگر را پاک نکن تا محدودیت دور زده نشود."
        elif not valid_username(username): error = "نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا _ باشد."
        elif len(password) < 8: error = "رمز عبور باید حداقل ۸ کاراکتر باشد."
        elif not display: error = "نام نمایشی را وارد کنید."
        else:
            try:
                cur = db().execute("INSERT INTO users(username,display_name,password_hash,created_at,last_seen) VALUES(?,?,?,?,?)",
                                   (username.lower(),display,hash_password(password),now(),now()))
                db().execute("INSERT INTO device_accounts(device_token,user_id,created_at) VALUES(?,?,?)", (device_token,cur.lastrowid,now()))
                db().commit(); session.clear(); session["uid"] = cur.lastrowid
                response = redirect(url_for("index"))
                response.set_cookie("pr_device", device_token, max_age=60*60*24*365, httponly=True, samesite="Lax")
                return response
            except sqlite3.IntegrityError: error = "این نام کاربری قبلاً گرفته شده است."
    response = app.make_response(render_template_string(AUTH, title="ساخت حساب کاربری", error=error, action="register"))
    response.set_cookie("pr_device", device_token, max_age=60*60*24*365, httponly=True, samesite="Lax")
    return response

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
        WHERE NOT EXISTS (SELECT 1 FROM hidden_chats h WHERE h.user_id=? AND h.other_id=u.id)
          AND m.id IN (
            SELECT MAX(id) FROM messages 
            WHERE sender_id = ? OR receiver_id = ?
            GROUP BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
        )
        ORDER BY m.id DESC
    """, (me["id"], me["id"], me["id"], me["id"], me["id"], me["id"])).fetchall()
    
    dialogs = [dict(r) for r in rows]
    # Ensure Saved Messages is always present
    if not any(d['id'] == me['id'] for d in dialogs):
        dialogs.insert(0, {
            "id": me['id'], "username": me['username'], "display_name": "پیام‌های ذخیره‌شده (Saved Messages)",
            "avatar": me['avatar'], "online": 1, "last_seen": now(), "last_msg": "خوش آمدید", "last_time": now()
        })
    return jsonify(dialogs=dialogs)

@app.get("/api/users")
@login_required
def search_users():
    q=request.args.get("q","").strip().lstrip("@").lower()[:40]
    me=current_user()
    if not q: return jsonify(users=[])
    rows=db().execute("""SELECT id,username,display_name,bio,avatar,phone,birthday,online,last_seen FROM users
       WHERE id!=? AND (username LIKE ? OR display_name LIKE ?) ORDER BY online DESC LIMIT 30""",
       (me["id"],f"%{q}%",f"%{q}%")).fetchall()
    users=[]
    for r in rows:
        item=dict(r)
        setting=db().execute("SELECT show_last_seen FROM user_settings WHERE user_id=?",(item["id"],)).fetchone()
        if setting and not setting["show_last_seen"]:
            item["last_seen"]=None
        users.append(item)
    return jsonify(users=users)

@app.get("/api/messages/<int:other_id>")
@login_required
def get_messages(other_id):
    me=current_user()
    db().execute("UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL",(now(),other_id,me["id"]))
    db().commit()
    if other_id == me["id"]:
        rows=db().execute("SELECT m.*,u.username sender_username,u.display_name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.sender_id=? AND m.receiver_id=? AND m.deleted=0 ORDER BY m.id ASC LIMIT 300",(me["id"],me["id"])).fetchall()
    else:
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
    if rid != me["id"]:
        blocked = db().execute("SELECT 1 FROM user_blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
                               (me["id"],rid,rid,me["id"])).fetchone()
        if blocked: return jsonify(error="ارسال پیام به این کاربر ممکن نیست؛ یکی از طرفین بلاک کرده است."),403
    cur=db().execute("INSERT INTO messages(sender_id,receiver_id,body,msg_type,created_at) VALUES(?,?,?,?,?)",
                     (me["id"],rid,body,msg_type,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,sender_id=me["id"],receiver_id=rid,body=body,msg_type=msg_type,
             reaction='',created_at=now(),sender_username=me["username"],sender_name=me["display_name"],read_at=None)
    socketio.emit("new_message",msg,room=f"user:{rid}")
    if rid != me["id"]:
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


@app.get("/api/settings")
@login_required
def get_settings():
    u=current_user()
    db().execute("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)",(u["id"],))
    row=db().execute("SELECT * FROM user_settings WHERE user_id=?",(u["id"],)).fetchone()
    return jsonify(dict(row))

@app.post("/api/settings")
@login_required
def save_settings():
    u=current_user(); data=request.get_json(silent=True) or {}
    bg=str(data.get("chat_background","")).strip()[:500]
    if bg and not (re.fullmatch(r"#[0-9a-fA-F]{3,8}",bg) or bg.startswith("https://") or bg.startswith("http://")):
        return jsonify(error="پس‌زمینه باید رنگ HEX یا لینک تصویر باشد"),400
    db().execute("INSERT OR IGNORE INTO user_settings(user_id) VALUES(?)",(u["id"],))
    theme=str(data.get("theme","dark"))[:24]
    if theme not in {"dark","telegram","neon","crimson","matrix","amoled"}: theme="dark"
    db().execute("UPDATE user_settings SET chat_background=?,show_last_seen=?,theme=? WHERE user_id=?",
                 (bg,1 if data.get("show_last_seen") else 0,theme,u["id"]))
    db().commit()
    return jsonify(ok=True)

@app.post("/api/block/<int:other_id>")
@login_required
def block_user(other_id):
    me=current_user()
    if other_id==me["id"]: return jsonify(error="نمی‌توانی خودت را بلاک کنی"),400
    if not db().execute("SELECT id FROM users WHERE id=?",(other_id,)).fetchone(): return jsonify(error="کاربر پیدا نشد"),404
    db().execute("INSERT OR IGNORE INTO user_blocks(blocker_id,blocked_id) VALUES(?,?)",(me["id"],other_id))
    db().commit()
    return jsonify(ok=True)

@app.delete("/api/chats/<int:other_id>")
@login_required
def delete_chat(other_id):
    me=current_user()
    db().execute("INSERT OR IGNORE INTO hidden_chats(user_id,other_id) VALUES(?,?)",(me["id"],other_id))
    db().commit()
    return jsonify(ok=True)

@app.post("/api/groups")
@login_required
def create_group():
    me=current_user(); data=request.get_json(silent=True) or {}
    title=str(data.get("title","")).strip()[:80]
    if not title: return jsonify(error="نام گروه را وارد کن"),400
    cur=db().execute("INSERT INTO chat_groups(title,owner_id,created_at) VALUES(?,?,?)",(title,me["id"],now()))
    gid=cur.lastrowid
    db().execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)",(gid,me["id"]))
    members=data.get("members",[])
    if not isinstance(members,list): members=[]
    for raw in members[:100]:
        try: uid=int(raw)
        except (TypeError,ValueError): continue
        if db().execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone():
            db().execute("INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)",(gid,uid))
    db().commit()
    return jsonify(ok=True,id=gid,title=title)

@app.get("/api/groups")
@login_required
def list_groups():
    me=current_user()
    rows=db().execute("""SELECT g.id,g.title,g.owner_id,g.created_at FROM chat_groups g
        JOIN group_members gm ON gm.group_id=g.id WHERE gm.user_id=? ORDER BY g.id DESC""",(me["id"],)).fetchall()
    return jsonify(groups=[dict(r) for r in rows])

@app.get("/api/groups/<int:gid>/messages")
@login_required
def get_group_messages(gid):
    me=current_user()
    member=db().execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,me["id"])).fetchone()
    if not member: return jsonify(error="عضو این گروه نیستی"),403
    rows=db().execute("SELECT gm.*,u.username sender_username,u.display_name sender_name FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE gm.group_id=? ORDER BY gm.id ASC LIMIT 500",(gid,)).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

@app.post("/api/groups/<int:gid>/messages")
@login_required
def send_group_message(gid):
    me=current_user(); data=request.get_json(silent=True) or {}
    body=str(data.get("body","")).strip(); msg_type=str(data.get("msg_type","text"))
    if not body: return jsonify(error="پیام خالی است"),400
    member=db().execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,me["id"])).fetchone()
    if not member: return jsonify(error="عضو این گروه نیستی"),403
    cur=db().execute("INSERT INTO group_messages(group_id,sender_id,body,msg_type,created_at) VALUES(?,?,?,?,?)",(gid,me["id"],body,msg_type,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,group_id=gid,sender_id=me["id"],body=body,msg_type=msg_type,created_at=now(),sender_username=me["username"],sender_name=me["display_name"])
    members=db().execute("SELECT user_id FROM group_members WHERE group_id=?",(gid,)).fetchall()
    for member in members: socketio.emit("group_message",msg,room=f"user:{member['user_id']}")
    return jsonify(message=msg)

@app.post("/api/groups/<int:gid>/members")
@login_required
def add_group_members(gid):
    me=current_user(); data=request.get_json(silent=True) or {}
    group=db().execute("SELECT owner_id FROM chat_groups WHERE id=?",(gid,)).fetchone()
    if not group: return jsonify(error="گروه پیدا نشد"),404
    if group["owner_id"]!=me["id"]: return jsonify(error="فقط سازنده گروه می‌تواند عضو اضافه کند"),403
    members=data.get("members",[])
    if not isinstance(members,list): return jsonify(error="فهرست اعضا نامعتبر است"),400
    added=0
    for raw in members[:100]:
        try: uid=int(raw)
        except (TypeError,ValueError): continue
        if db().execute("SELECT 1 FROM users WHERE id=?",(uid,)).fetchone():
            db().execute("INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)",(gid,uid)); added+=1
    db().commit(); return jsonify(ok=True,added=added)

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

@socketio.on("typing")
def on_typing(data):
    """Relay typing state only from an authenticated user to a valid recipient."""
    u = current_user()
    if not u or not isinstance(data, dict):
        return
    try:
        receiver_id = int(data.get("receiver_id"))
    except (TypeError, ValueError):
        return
    if receiver_id == u["id"]:
        return
    exists = db().execute("SELECT id FROM users WHERE id=?", (receiver_id,)).fetchone()
    if not exists:
        return
    emit("typing_status", {
        "sender_id": u["id"],
        "sender_name": u["display_name"],
        "is_typing": bool(data.get("is_typing"))
    }, room=f"user:{receiver_id}")

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
.auth-card { width: min(400px, 100%); background: #1e293b; padding: 32px 24px; border-radius: 20px; text-align: center; border: 1px solid rgba(255,255,255,0.08); }
input { width: 100%; padding: 12px 16px; margin-bottom: 14px; background: #0b132b; border: 1px solid #334155; border-radius: 12px; color: white; outline: none; }
button { width: 100%; padding: 12px; background: #2AABEE; border: none; border-radius: 12px; color: white; font-weight: bold; cursor: pointer; }
.error { background: rgba(239,68,68,0.15); color: #fca5a5; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 14px; }
a { color: #2AABEE; text-decoration: none; font-size: 13px; }

/* Theme overrides: make every main surface respond to the selected theme */
body[data-theme="dark"] .chat-main,
body[data-theme="telegram"] .chat-main,
body[data-theme="neon"] .chat-main,
body[data-theme="crimson"] .chat-main,
body[data-theme="matrix"] .chat-main,
body[data-theme="amoled"] .chat-main { background:var(--bg-main) !important; }
body[data-theme] .folder-rail { background:var(--bg-main) !important; border-color:var(--border-color) !important; }
body[data-theme] .sidebar,
body[data-theme] .sidebar-header,
body[data-theme] .chat-topbar,
body[data-theme] .chat-composer,
body[data-theme] .modal-card { background:var(--panel-bg) !important; border-color:var(--border-color) !important; }
body[data-theme] .search-container,
body[data-theme] .composer-input { background:var(--bg-main) !important; border-color:var(--border-color) !important; }
body[data-theme] .chat-messages { background-color:var(--bg-main) !important; }
body[data-theme] .chat-row:hover { background:var(--panel-hover) !important; }
body[data-theme] .chat-row.active { background:var(--active-bg) !important; }
body[data-theme] .message-bubble.mine { background:var(--bubble-out) !important; }
body[data-theme] .message-bubble:not(.mine) { background:var(--bubble-in) !important; }
body[data-theme] .action-btn:hover { background:var(--panel-hover) !important; }
body[data-theme] .folder-icon.active { background:var(--panel-bg) !important; color:var(--accent) !important; }
body[data-theme] button[onclick="saveAppSettings()"] { background:var(--accent) !important; }

</style>
</head>
<body>
<div class="auth-card">
  <h2 style="margin-bottom: 20px; font-weight: 700;">{{title}}</h2>
  {% if error %}<div class="error">{{error}}</div>{% endif %}
  <form method="post">
    {% if action=='register' %}
    <input name="display_name" placeholder="نام نمایشی" required>
    {% endif %}
    <input name="username" placeholder="نام کاربری (آیدی)" required>
    <input name="password" type="password" placeholder="رمز عبور" required>
    <button type="submit">{{title}}</button>
  </form>
  <div style="margin-top: 18px;">
    {% if action=='login' %}<a href="{{url_for('register')}}">ساخت حساب جدید</a>{% else %}<a href="{{url_for('login')}}">ورود به حساب</a>{% endif %}
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
html { height: 100%; }
body { background: var(--bg-main); color: white; height: 100vh; height: 100dvh; overflow: hidden; display: flex; }
button, input, textarea { font: inherit; }
button { touch-action: manipulation; }

.tg-app { display: flex; width: 100%; height: 100%; min-width: 0; position: relative; }
@media (min-width: 769px) {
  .tg-app { max-width: 1800px; margin-inline: auto; }
  .chat-main { min-width: 0; }
  .chat-messages { padding: clamp(20px, 3vw, 42px); }
  .message-bubble { max-width: min(72%, 760px); }
}
.folder-rail { width: 64px; background: #0e1621; border-left: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; padding: 14px 0; gap: 14px; z-index: 15; flex-shrink: 0; }
.folder-icon { width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center; font-size: 20px; color: var(--text-muted); cursor: pointer; }
.folder-icon.active { background: var(--panel-bg); color: var(--accent); }

.sidebar { width: 340px; background: var(--panel-bg); border-left: 1px solid var(--border-color); display: flex; flex-direction: column; z-index: 10; flex-shrink: 0; }
.sidebar-header { padding: 12px 14px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); }
.search-container { flex: 1; background: var(--bg-main); border-radius: 20px; display: flex; align-items: center; padding: 0 14px; height: 38px; }
.search-container input { width: 100%; background: none; border: none; color: white; outline: none; font-size: 13px; }

.chat-list { flex: 1; overflow-y: auto; }
.chat-row { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; }
.chat-row:hover { background: var(--panel-hover); transform:translateX(-2px); }
.chat-row { transition:background .16s,transform .16s; border-bottom:1px solid #ffffff05; }
.message-bubble { animation: bubbleIn .16s ease-out; }
@keyframes bubbleIn {from{opacity:.4;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.chat-topbar-info:hover {opacity:.9}
select, input, textarea { accent-color:var(--accent); }
.chat-row.active { background: var(--active-bg); }
.avatar { width: 48px; height: 48px; border-radius: 50%; background: #2b5278; display: grid; place-items: center; font-weight: bold; flex-shrink: 0; background-size: cover; background-position: center; font-size: 16px; color: white; }

.chat-main { flex: 1; display: flex; flex-direction: column; background: var(--bg-main); position: relative; height: 100%; min-width: 0; }
.chat-topbar { padding: 10px 16px; background: var(--panel-bg); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; height: 60px; flex-shrink: 0; }
.chat-topbar-info { display: flex; align-items: center; gap: 12px; cursor: pointer; min-width: 0; }
.back-btn-mobile { display: none; background: none; border: none; color: white; font-size: 22px; cursor: pointer; }

.chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; background: var(--bg-main); }
.message-bubble { max-width: 75%; padding: 10px 14px; border-radius: 14px; font-size: 14px; position: relative; word-break: break-word; }
.message-bubble.mine { align-self: flex-end; background: var(--bubble-out); }
.message-bubble:not(.mine) { align-self: flex-start; background: var(--bubble-in); }
.msg-time { font-size: 10px; color: rgba(255,255,255,0.6); float: left; margin-top: 4px; margin-left: 6px; display: flex; align-items: center; gap: 3px; }

.chat-composer { padding: 12px 16px; background: var(--panel-bg); border-top: 1px solid var(--border-color); display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.composer-input { flex: 1; background: var(--bg-main); border: none; border-radius: 12px; color: white; padding: 10px 14px; font-size: 14px; outline: none; resize: none; height: 44px; }
.action-btn { background: none; border: none; color: var(--text-muted); font-size: 22px; cursor: pointer; padding: 6px; border-radius: 50%; flex-shrink: 0; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: grid; place-items: center; z-index: 1000; padding: 16px; }
.modal-card { width: min(420px, 100%); background: var(--panel-bg); border: 1px solid #232e3c; padding: 24px; border-radius: 20px; max-height: 90vh; overflow-y: auto; }
.hidden { display: none !important; }

@media (max-width: 768px) {
  .folder-rail { width: 52px; padding-top: 10px; gap: 10px; }
  .folder-icon { width: 40px; height: 40px; }
  .sidebar { width: calc(100% - 52px); position: absolute; right: 52px; top: 0; height: 100%; height: 100dvh; z-index: 5; }
  .sidebar.mobile-hidden { display: none; }
  .chat-main { width: 100%; position: absolute; inset: 0; z-index: 20; transform: translateX(100%); transition: transform 0.25s ease; height: 100%; height: 100dvh; }
  .chat-main.mobile-active { transform: translateX(0); }
  .back-btn-mobile { display: inline-block; }
  .chat-topbar { padding: 8px 10px; height: 56px; }
  .chat-messages { padding: 12px 10px; gap: 8px; }
  .message-bubble { max-width: 88%; padding: 9px 11px; }
  .chat-composer { padding: 8px; gap: 5px; }
  .composer-input { min-width: 0; padding: 9px 10px; height: 42px; }
  .action-btn { font-size: 20px; padding: 5px; }
  .modal-card { padding: 18px; max-height: 86dvh; }
}
/* PayamRasan signature theme: Telegram-like desktop layout with a richer neon finish */
:root {
  --bg-main:#0b111b; --panel-bg:#111c2b; --panel-hover:#1b2a3d;
  --active-bg:#24496d; --accent:#43c6ff; --bubble-out:#245a83;
  --bubble-in:#172536; --text-muted:#91a8c0; --border-color:#26364a;
}
body { background: radial-gradient(ellipse at 75% 0%, #13243a 0%, #0b111b 48%, #080d15 100%); }
.tg-app { max-width:none; }
.folder-rail { background:#080e17; border-left:1px solid #26364a; box-shadow:8px 0 30px #0002; }
.folder-icon { transition:transform .18s, background .18s, color .18s; }
.folder-icon:hover { transform:translateY(-2px); background:#1a2c40; color:#fff; }
.sidebar { width:clamp(300px, 31vw, 410px); background:rgba(15,26,40,.97); border-left:1px solid #26364a; }
.sidebar-header { min-height:72px; padding:15px 16px; background:linear-gradient(135deg,#14253a,#101a29); }
.search-container { border:1px solid #2b4057; background:#0b1421; border-radius:13px; height:42px; transition:border .2s, box-shadow .2s; }
.search-container:focus-within { border-color:var(--accent); box-shadow:0 0 0 3px #43c6ff18; }
.chat-row { padding:13px 16px; border-bottom:1px solid #ffffff06; transition:background .15s; }
.chat-row.active { background:linear-gradient(90deg,#214e75,#1a3854); box-shadow:inset -3px 0 var(--accent); }
.avatar { box-shadow:0 3px 12px #0003; border:1px solid #ffffff12; }
.chat-main { background:radial-gradient(ellipse at 50% 0%,#132238 0%,#0b1420 62%); }
.chat-topbar { background:rgba(16,28,43,.97); border-bottom:1px solid #2a3b50; box-shadow:0 4px 18px #0002; }
.chat-messages { background-image:radial-gradient(#6ba6d008 1px,transparent 1px); background-size:18px 18px; }
.message-bubble { border:1px solid #ffffff0a; box-shadow:0 4px 14px #00012; border-radius:16px 16px 5px 16px; }
.message-bubble:not(.mine) { border-radius:16px 16px 16px 5px; }
.message-bubble.mine { background:linear-gradient(135deg,#245b84,#1e496d); }
.chat-composer { background:rgba(16,28,43,.98); border-top:1px solid #2a3b50; }
.composer-input { border:1px solid #263b52; background:#0b1421; border-radius:15px; }
.composer-input:focus { border-color:#43c6ff88; }
.action-btn { transition:transform .15s,color .15s,background .15s; }
.action-btn:hover { color:#fff; background:#263b52; transform:scale(1.06); }
.modal-card { background:linear-gradient(145deg,#17263a,#101a29); border:1px solid #344a64; box-shadow:0 24px 90px #0009; }
.chat-list::-webkit-scrollbar,.chat-messages::-webkit-scrollbar { width:6px; }
.chat-list::-webkit-scrollbar-thumb,.chat-messages::-webkit-scrollbar-thumb { background:#344b63; border-radius:8px; }
@media (min-width:769px) { .chat-topbar { height:72px; } .message-bubble { max-width:min(68%,760px); } }
</style>
</head>
<body>

<div class="tg-app">
  <div class="folder-rail">
    <div class="folder-icon active" onclick="switchFolder('all')">💬</div>
    <div class="folder-icon" onclick="openProfileModal()" title="پروفایل من">👤</div>
    <div class="folder-icon" onclick="openAppSettings()" title="تنظیمات و تم‌ها">🎨</div>
    <div class="folder-icon" onclick="createGroup()" title="ساخت گروه">👥</div>
  </div>

  <aside class="sidebar" id="sidebarPanel">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 17px 4px;background:linear-gradient(135deg,#14253a,#101a29);">
      <div style="display:flex;align-items:center;gap:10px;min-width:0;">
        <div style="width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#43c6ff,#635bff);box-shadow:0 5px 18px #43c6ff30;font-size:20px;">✦</div>
        <div><div style="font-weight:800;letter-spacing:.2px;font-size:15px;">PayamRasan <span style="color:#43c6ff">Pro</span></div><div style="font-size:10px;color:#91a8c0;">PRIVATE MESSENGER</div></div>
      </div>
      <button type="button" title="حساب فعلی و مدیریت حساب‌ها" onclick="accountInfo()" style="border:1px solid #30465f;background:#0b1421;color:#a9c9e8;border-radius:11px;padding:8px 10px;cursor:pointer;">👤 حساب</button>
    </div>
    <div class="sidebar-header">
      <div class="search-container">
        <input id="searchInput" placeholder="جستجو آیدی..." oninput="searchUsers()">
      </div>
    </div>
    <div class="chat-list" id="chatList"></div>
  </aside>

  <main class="chat-main" id="chatMainPanel">
    <header class="chat-topbar">
      <div class="chat-topbar-info" onclick="openHeaderProfile()">
        <button class="back-btn-mobile" onclick="closeChatMobile(event)">⬅</button>
        <div class="avatar" id="activeAvatar" style="width:40px; height:40px;">💬</div>
        <div>
          <div style="font-size:15px; font-weight:700;" id="chatTitle">تلگرام پرو</div>
          <div style="font-size:12px; color: var(--text-muted);" id="chatStatus">انتخاب گفتگو</div>
        </div>
      </div>
    </header>

    <div class="chat-messages" id="chatMessages">
      <div style="margin: auto; text-align: center; color: var(--text-muted); font-size: 14px;">یک مخاطب را انتخاب کنید</div>
    </div>

    <form class="chat-composer" onsubmit="sendMessage(event)">
      <button type="button" class="action-btn" onclick="$('fileInput').click()" title="ارسال فایل">📎</button>
      <input type="file" id="fileInput" hidden onchange="handleFileUpload(this)">
      <button type="button" class="action-btn" id="voiceBtn" onclick="toggleVoiceRecording()" title="ضبط پیام صوتی">🎙️</button>
      <textarea id="messageInput" class="composer-input" placeholder="نوشتن پیام..." oninput="notifyTyping()" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage(event)}"></textarea>
      <button type="submit" class="action-btn" style="color: var(--accent);">➤</button>
    </form>
  </main>
</div>

<div id="modalOverlay" class="modal-overlay hidden" onclick="if(event.target===this) closeModal()">
  <div class="modal-card" id="modalContent"></div>
</div>

<script>
const meId = {{me['id']}};
let activeUser = null;
let activeGroup = null;
const $ = id => document.getElementById(id);
function closeModal() { $('modalOverlay').classList.add('hidden'); }
function accountInfo() {
  $('modalContent').innerHTML = `<h3 style="margin-bottom:12px">مدیریت حساب</h3><p style="color:var(--text-muted);line-height:1.9;font-size:13px">این مرورگر برای ساخت حداکثر دو حساب محدود شده است. برای ورود به حساب دیگر از خروج استفاده کن و با حساب دوم وارد شو. محدودیت به شناسهٔ ذخیره‌شده در کوکی مرورگر وابسته است و محدودیت هویتیِ ضدتقلب محسوب نمی‌شود.</p><button onclick="location.href='/logout'" style="margin-top:16px;padding:11px;border:0;border-radius:10px;background:var(--accent);color:#06121e;font-weight:bold;width:100%;cursor:pointer">خروج از حساب</button><button onclick="closeModal()" style="margin-top:8px;padding:10px;border:1px solid #30465f;border-radius:10px;background:transparent;color:white;width:100%;cursor:pointer">بستن</button>`;
  $('modalOverlay').classList.remove('hidden');
}
function closeChatMobile(e) { e?.stopPropagation(); $('chatMainPanel').classList.remove('mobile-active'); }

async function api(url, opts={}) {
  let r = await fetch(url, {...opts, headers:{'Content-Type':'application/json', ...(opts.headers||{})}});
  let d = await r.json().catch(()=>({}));
  if(!r.ok) throw Error(d.error || 'خطا');
  return d;
}

async function loadDialogs() {
  activeGroup = null;
  let d = await api('/api/dialogs');
  $('chatList').innerHTML = d.dialogs.map(u => `
    <div class="chat-row ${activeUser?.id===u.id?'active':''}" onclick="openUserChat(${u.id},'${esc(u.display_name)}','${esc(u.username)}','${esc(u.avatar||'')}')">
      <div class="avatar" style="${u.avatar?`background-image:url('${u.avatar}')`:''}">${u.avatar?'':u.display_name[0]}</div>
      <div style="flex:1; min-width:0;">
        <div style="display:flex; justify-content:space-between; font-size:14px; font-weight:600;">
          <span>${esc(u.display_name)}</span>
          <span style="font-size:11px; color:var(--text-muted);">${(u.last_time||'').slice(11,16)}</span>
        </div>
        <div style="font-size:13px; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${esc(u.last_msg)}</div>
      </div>
    </div>
  `).join('');
}

async function loadGroups() {
  try {
    const d = await api('/api/groups');
    $('chatList').innerHTML = d.groups.map(g => `<div class="chat-row" onclick="openGroupChat(${g.id},'${esc(g.title)}')"><div class="avatar">👥</div><div><div style="font-weight:600">${esc(g.title)}</div><div style="font-size:12px;color:var(--text-muted)">گفتگوی گروهی · #${g.id}</div></div></div>`).join('') || '<div style="padding:20px;color:var(--text-muted)">هنوز گروهی نداری؛ روی 👥 بزن.</div>';
  } catch(e) { alert(e.message); }
}
async function openGroupChat(id, title) {
  activeGroup = {id, title}; activeUser = null;
  $('chatTitle').textContent = title; $('chatStatus').textContent = 'گروه · پیام‌رسان پرو';
  $('activeAvatar').style.backgroundImage=''; $('activeAvatar').textContent='👥';
  const d = await api('/api/groups/'+id+'/messages');
  $('chatMessages').innerHTML=''; seenMessageIds.clear(); d.messages.forEach(m => appendMessage(m, true)); scrollBottom();
  if(window.innerWidth<=768) $('chatMainPanel').classList.add('mobile-active');
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
  `).join('');
}

function updateChatPresence(user) {
  if (!activeUser || user.id !== activeUser.id) return;
  const status = $('chatStatus');
  if (user.online) {
    status.textContent = '● آنلاین';
    status.style.color = '#4ade80';
  } else if (user.last_seen) {
    status.textContent = 'آخرین بازدید: ' + formatLastSeen(user.last_seen);
    status.style.color = 'var(--text-muted)';
  } else {
    status.textContent = 'آخرین بازدید مخفی است';
    status.style.color = 'var(--text-muted)';
  }
}

async function openUserChat(id, name, username, avatar) {
  activeGroup = null;
  activeUser = {id, name, username, avatar};
  $('chatTitle').textContent = name;
  $('chatStatus').textContent = '@' + username;
  try {
    const profileData = await api('/api/users?q=' + encodeURIComponent(username));
    const profile = profileData.users.find(x => x.id === id);
    if (profile) updateChatPresence(profile);
  } catch (_) {}
  if(avatar) $('activeAvatar').style.backgroundImage = `url('${avatar}')`;
  else { $('activeAvatar').style.backgroundImage = '';$('activeAvatar').textContent = name[0]; }
  
  const settings = await api('/api/settings'); applyChatBackground(settings.chat_background||'');
  let d = await api('/api/messages/' + id);
  $('chatMessages').innerHTML = '';
  seenMessageIds.clear();
  d.messages.forEach(appendMessage);
  scrollBottom();
  if(window.innerWidth <= 768) $('chatMainPanel').classList.add('mobile-active');
  loadDialogs();
}

let typingStopTimer = null;
let lastTypingSent = 0;
function notifyTyping() {
  if (!activeUser || activeGroup) return;
  const value = $('messageInput').value.trim();
  const nowMs = Date.now();
  if (value && nowMs - lastTypingSent > 700) {
    socket.emit('typing', {receiver_id: activeUser.id, is_typing: true});
    lastTypingSent = nowMs;
  }
  clearTimeout(typingStopTimer);
  typingStopTimer = setTimeout(() => {
    if (activeUser && !activeGroup) socket.emit('typing', {receiver_id: activeUser.id, is_typing: false});
  }, 1500);
}

async function sendMessage(e) {
  e?.preventDefault();
  let body = $('messageInput').value.trim();
  if(!body || (!activeUser && !activeGroup)) return;
  if (activeUser && !activeGroup) socket.emit('typing', {receiver_id: activeUser.id, is_typing: false});
  let d;
  if(activeGroup) d = await api('/api/groups/'+activeGroup.id+'/messages', {method:'POST', body:JSON.stringify({body})});
  else d = await api('/api/messages', {method:'POST', body:JSON.stringify({receiver_id: activeUser.id, body})});
  appendMessage(d.message, !!activeGroup);
  $('messageInput').value = '';
  scrollBottom();
  if(!activeGroup) loadDialogs();
}

async function handleFileUpload(input) {
  let f = input.files[0]; if(!f || (!activeUser && !activeGroup)) return;
  let fd = new FormData(); fd.append('file', f);
  let r = await fetch('/api/upload', {method:'POST', body:fd});
  let d = await r.json();
  if(r.ok) {
    let m = await api('/api/messages', {method:'POST', body:JSON.stringify({receiver_id: activeUser.id, body: location.origin + d.url, msg_type: (f.name.match(/\.(mp3|wav|ogg|m4a|webm)$/i) ? 'voice' : (f.type.startsWith('image/') ? 'image' : 'file'))})});
    appendMessage(m.message);
    scrollBottom();
    loadDialogs();
  }
}

async function openProfileModal() {
  let me = await api('/api/me');
  let settings = await api('/api/settings');
  $('modalContent').innerHTML = `
    <h3 style="margin-bottom:16px;">پروفایل من</h3><p style="color:var(--text-muted);font-size:12px;margin-bottom:12px">اطلاعات و عکس پروفایل خودت را ویرایش کن.</p>
    <form onsubmit="updateProfile(event)" style="display:flex; flex-direction:column; gap:12px;">
      <input id="pName" value="${esc(me.display_name)}" style="padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px;" required>
      <textarea id="pBio" style="padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px; height:70px; resize:none;">${esc(me.bio||'')}</textarea>
      <input id="pAvatar" value="${esc(me.avatar||'')}" placeholder="لینک عکس پروفایل (اختیاری)" style="padding:10px; background:#0e1621; border:1px solid #334155; color:white; border-radius:10px;">
      <label for="pAvatarFile" style="font-size:13px;color:var(--text-muted);">یا انتخاب عکس از دستگاه</label>
      <input id="pAvatarFile" type="file" accept="image/png,image/jpeg,image/gif,image/webp" style="width:100%;padding:8px;background:#0e1621;color:white;border-radius:10px;">
      <img id="pAvatarPreview" alt="پیش‌نمایش عکس پروفایل" class="${me.avatar ? '' : 'hidden'}" src="${esc(me.avatar||'')}" style="width:76px;height:76px;object-fit:cover;border-radius:50%;align-self:center;">
      <label style="font-size:13px">پس‌زمینه گفتگو (رنگ یا آدرس تصویر)</label>
      <input id="pBackground" value="${esc(settings.chat_background||'')}" placeholder="#0e1621 یا لینک تصویر" style="padding:10px;background:#0e1621;border:1px solid #334155;color:white;border-radius:10px;">
      <label style="display:flex;gap:8px;align-items:center;font-size:13px"><input id="pLastSeen" type="checkbox" ${settings.show_last_seen ? 'checked' : ''} style="width:auto;margin:0"> نمایش آخرین بازدید من</label>
      <button type="submit" style="padding:12px; background:var(--accent); border:none; color:white; border-radius:10px; font-weight:bold; cursor:pointer;">ذخیره</button>
    </form>
  `;
  $('modalOverlay').classList.remove('hidden');
  $('pAvatarFile').addEventListener('change', () => {
    const file = $('pAvatarFile').files[0];
    if (!file) return;
    const preview = $('pAvatarPreview');
    preview.src = URL.createObjectURL(file);
    preview.classList.remove('hidden');
  });
}

async function openAppSettings() {
  const d = await api('/api/settings');
  $('modalContent').innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><div style="font-size:25px">🎨</div><div><h3>تنظیمات برنامه</h3><div style="font-size:12px;color:var(--text-muted);margin-top:3px">ظاهر، حریم خصوصی و تجربهٔ گفتگو</div></div></div><hr style="border:0;border-top:1px solid var(--border-color);margin:12px 0">
    <label style="display:block;margin:10px 0">پس‌زمینه چت (رنگ مثل #101820 یا لینک تصویر)</label>
    <input id="settingBg" value="${esc(d.chat_background||'')}" placeholder="#101820 یا https://..." style="width:100%;padding:10px;background:#0e1621;color:white;border:1px solid #334155;border-radius:8px">
    <label style="display:flex;gap:8px;align-items:center;margin:14px 0"><input id="settingSeen" type="checkbox" ${d.show_last_seen?'checked':''} style="width:auto"> اجازه نمایش آخرین بازدید من</label>
    <label style="display:block;margin:12px 0 6px">انتخاب تم</label><select id="settingTheme" onchange="applyTheme(this.value)" style="width:100%;padding:11px;background:var(--bg-main);color:white;border:1px solid var(--border-color);border-radius:9px"><option value="dark" ${d.theme==='dark'?'selected':''}>🌌 Dark Pro</option><option value="telegram" ${d.theme==='telegram'?'selected':''}>🔵 Telegram Blue</option><option value="neon" ${d.theme==='neon'?'selected':''}>💜 Neon Cyber</option><option value="crimson" ${d.theme==='crimson'?'selected':''}>🔴 Crimson</option><option value="matrix" ${d.theme==='matrix'?'selected':''}>🟢 Matrix</option><option value="amoled" ${d.theme==='amoled'?'selected':''}>⚫ AMOLED</option></select><div style="display:flex;gap:7px;margin:10px 0 16px;flex-wrap:wrap"><span style="width:22px;height:22px;border-radius:50%;background:#43c6ff;border:2px solid #ffffff55"></span><span style="width:22px;height:22px;border-radius:50%;background:#b66cff;border:2px solid #ffffff55"></span><span style="width:22px;height:22px;border-radius:50%;background:#ff4568;border:2px solid #ffffff55"></span><span style="width:22px;height:22px;border-radius:50%;background:#49ff8b;border:2px solid #ffffff55"></span><span style="font-size:11px;color:var(--text-muted);align-self:center">با انتخاب تم، پیش‌نمایش فوری می‌بینی.</span></div>
    <button onclick="saveAppSettings()" style="padding:11px;background:var(--accent);border:0;color:white;border-radius:10px">ذخیره تنظیمات</button>
    <button onclick="closeModal()" style="padding:11px;background:#334155;border:0;color:white;border-radius:10px;margin-right:6px">بستن</button>`;
}
async function saveAppSettings() {
  try { const bg=$('settingBg').value.trim(); await api('/api/settings',{method:'POST',body:JSON.stringify({chat_background:bg,show_last_seen:$('settingSeen').checked,theme:$('settingTheme').value})}); applyChatBackground(bg); applyTheme($('settingTheme').value); alert('تنظیمات ذخیره شد'); closeModal(); }
  catch(e){ alert(e.message); }
}

async function updateProfile(e) {
  e.preventDefault();
  let avatar = $('pAvatar').value.trim();
  const avatarFile = $('pAvatarFile')?.files?.[0];
  if (avatarFile) {
    const fd = new FormData();
    fd.append('file', avatarFile);
    const uploaded = await fetch('/api/upload', {method:'POST', body:fd});
    const uploadData = await uploaded.json();
    if (!uploaded.ok) { alert(uploadData.error || 'بارگذاری عکس انجام نشد'); return; }
    avatar = location.origin + uploadData.url;
  }
  await api('/api/profile', {method:'POST', body:JSON.stringify({display_name: $('pName').value.trim(), bio: $('pBio').value.trim(), avatar, phone:'', birthday:''})});
  await api('/api/settings', {method:'POST', body:JSON.stringify({chat_background:$('pBackground').value.trim(), show_last_seen:$('pLastSeen').checked, theme:(await api('/api/settings')).theme||'dark'})});
  applyChatBackground($('pBackground').value.trim());
  closeModal();
  loadDialogs();
}

async function openHeaderProfile() {
  if(!activeUser || activeGroup) return;
  let u = {...activeUser};
  try {
    const d = await api('/api/users?q=' + encodeURIComponent(activeUser.username));
    u = {...u, ...(d.users.find(x => x.id === activeUser.id) || {})};
  } catch (_) {}
  const online = !!u.online;
  const seen = online ? '● آنلاین' : (u.last_seen ? 'آخرین بازدید ' + formatLastSeen(u.last_seen) : 'آخرین بازدید مخفی است');
  const avatarStyle = u.avatar ? `background-image:url('${esc(u.avatar)}');background-size:cover;background-position:center;` : '';
  const safeName = esc(u.display_name || activeUser.name || 'مخاطب');
  const safeUsername = esc(u.username || activeUser.username || '');
  $('modalContent').innerHTML = `
    <div style="position:relative;margin:-4px -4px 0;">
      <button onclick="closeModal()" aria-label="بستن" style="position:absolute;left:0;top:0;border:0;background:transparent;color:#dce6ef;font-size:25px;cursor:pointer">×</button>
      <div style="text-align:center;padding:10px 18px 16px;">
        <div class="avatar" style="width:82px;height:82px;margin:0 auto 10px;font-size:27px;${avatarStyle}">${u.avatar?'':safeName.slice(0,1)}</div>
        <h3 style="font-size:19px;margin-bottom:4px">${safeName}</h3>
        <div style="font-size:13px;color:var(--accent)">@${safeUsername}</div>
        <div style="font-size:12px;color:${online?'#4ade80':'var(--text-muted)'};margin-top:7px">${esc(seen)}</div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin:0 0 16px">
        <button onclick="closeModal();focusMessageInput()" style="border:0;border-radius:12px;background:var(--bg-main);color:white;padding:11px 3px;cursor:pointer"><div style="font-size:20px">☏</div><small>پیام</small></button>
        <button onclick="toggleContactMute()" style="border:0;border-radius:12px;background:var(--bg-main);color:white;padding:11px 3px;cursor:pointer"><div style="font-size:20px">🔕</div><small>بی‌صدا</small></button>
        <button onclick="alert('تماس صوتی هنوز به سرور تماس متصل نشده است.')" style="border:0;border-radius:12px;background:var(--bg-main);color:white;padding:11px 3px;cursor:pointer"><div style="font-size:20px">📞</div><small>تماس</small></button>
        <button onclick="showContactMore()" style="border:0;border-radius:12px;background:var(--bg-main);color:white;padding:11px 3px;cursor:pointer"><div style="font-size:20px">•••</div><small>بیشتر</small></button>
      </div>
      <div style="background:var(--bg-main);border-radius:12px;padding:13px 14px;display:grid;gap:13px;font-size:13px">
        ${u.phone?`<div><div>${esc(u.phone)}</div><small style="color:var(--text-muted)">شماره تلفن</small></div>`:''}
        <div><div style="line-height:1.8;overflow-wrap:anywhere">${esc(u.bio||'بدون بیوگرافی')}</div><small style="color:var(--text-muted)">بیوگرافی</small></div>
        <div><div style="color:var(--accent)">@${safeUsername}</div><small style="color:var(--text-muted)">نام کاربری</small></div>
        ${u.birthday?`<div><div>${esc(u.birthday)}</div><small style="color:var(--text-muted)">تاریخ تولد</small></div>`:''}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px">
        <button onclick="showContactMedia()" style="border:1px solid var(--border-color);border-radius:10px;background:transparent;color:var(--accent);padding:10px;cursor:pointer">🖼 رسانه‌های گفتگو</button>
        <button onclick="closeModal();openUserChat(${Number(u.id||activeUser.id)},'${safeName}','${safeUsername}','${esc(u.avatar||'')}')" style="border:1px solid var(--border-color);border-radius:10px;background:transparent;color:white;padding:10px;cursor:pointer">رفتن به گفتگو</button>
      </div>
    </div>`;
  $('modalOverlay').classList.remove('hidden');
}
function focusMessageInput(){ $('messageInput')?.focus(); }
function toggleContactMute(){
  const key='pr-muted-'+(activeUser?.id||'');
  const muted=localStorage.getItem(key)==='1';
  localStorage.setItem(key,muted?'0':'1');
  alert(muted?'اعلان‌های این مخاطب در این مرورگر از حالت بی‌صدا خارج شد.':'این مخاطب در این مرورگر بی‌صدا شد.');
}
function showContactMore(){
  $('modalContent').innerHTML=`<h3 style="margin-bottom:14px">مدیریت مخاطب</h3><button onclick="blockContactDemo()" style="width:100%;padding:12px;margin-bottom:8px;border:1px solid #793b45;border-radius:10px;background:#351c24;color:#ff9ca8;cursor:pointer">🚫 مسدود کردن مخاطب</button><button onclick="openHeaderProfile()" style="width:100%;padding:11px;border:1px solid var(--border-color);border-radius:10px;background:transparent;color:white;cursor:pointer">بازگشت به پروفایل</button>`;
}
function blockContactDemo(){ alert('مسدودسازی سمت سرور هنوز پیاده‌سازی نشده؛ این دکمه فعلاً اقدامی روی حساب انجام نمی‌دهد.'); }
function showContactMedia(){ alert('نمایش جداگانهٔ رسانه‌های گفتگو هنوز به API اختصاصی نیاز دارد.'); }


function formatLastSeen(value) {
  if (!value) return 'نامشخص';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'نامشخص';
  return d.toLocaleString('fa-IR');
}
async function editMessage(id, oldBody) {
  const body = prompt('متن جدید پیام:', oldBody);
  if (body === null || !body.trim()) return;
  try { await api(`/api/messages/${id}/edit`, {method:'POST', body:JSON.stringify({body:body.trim()})}); await refreshActiveChat(); }
  catch(e) { alert(e.message); }
}
async function deleteMessage(id) {
  if (!confirm('این پیام حذف شود؟')) return;
  try { await api(`/api/messages/${id}/delete`, {method:'POST'}); await refreshActiveChat(); }
  catch(e) { alert(e.message); }
}
async function refreshActiveChat() {
  if (!activeUser) return;
  const d = await api('/api/messages/' + activeUser.id);
  $('chatMessages').innerHTML = ''; seenMessageIds.clear(); d.messages.forEach(appendMessage); scrollBottom();
}
async function blockUser(id) {
  if (!confirm('این کاربر بلاک شود؟')) return;
  await api('/api/block/' + id, {method:'POST'}); closeModal();
  $('chatMessages').innerHTML = '<div style="margin:auto;color:var(--text-muted)">این کاربر بلاک شد.</div>';
  activeUser = null; loadDialogs();
}
async function deleteChat(id) {
  if (!confirm('گفتگو فقط از فهرست شما حذف شود؟ پیام‌های طرف مقابل پاک نمی‌شوند.')) return;
  await api('/api/chats/' + id, {method:'DELETE'}); closeModal(); activeUser=null;
  $('chatMessages').innerHTML='<div style="margin:auto;color:var(--text-muted)">گفتگو حذف شد.</div>'; loadDialogs();
}
function applyTheme(theme) {
  const root=document.documentElement;
  const allowed=['dark','telegram','neon','crimson','matrix','amoled'];
  if (!allowed.includes(theme)) theme='dark';
  const themes={
    dark:['#0b111b','#111c2b','#1b2a3d','#24496d','#43c6ff','#245a83','#172536','#91a8c0','#26364a'],
    telegram:['#0e1621','#17212b','#202b38','#2b5278','#2AABEE','#2b5278','#182533','#8eabbf','#0f151d'],
    neon:['#080914','#111126','#202044','#352c72','#b66cff','#4b3187','#19182d','#b9b4dc','#322d55'],
    crimson:['#10090c','#211219','#38202a','#612637','#ff4568','#70253a','#29151e','#c9a4ae','#40202b'],
    matrix:['#030906','#09150e','#10271a','#17472c','#49ff8b','#1a6338','#0d2015','#8ebba0','#163522'],
    amoled:['#000000','#050505','#151515','#222222','#39bfff','#202020','#101010','#999999','#242424']
  };
  const t=themes[theme];
  ['--bg-main','--panel-bg','--panel-hover','--active-bg','--accent','--bubble-out','--bubble-in','--text-muted','--border-color'].forEach((k,i)=>root.style.setProperty(k,t[i]));
  document.body.dataset.theme=theme;
  /* The original visual skin used fixed gradients, so update the page surface too. */
  document.body.style.background=t[0];
  try { localStorage.setItem('pr-theme',theme); } catch(e) {}
}
function applyChatBackground(value) {
  const box = $('chatMessages');
  if (!box) return;
  if (/^#[0-9a-f]{3,8}$/i.test(value)) { box.style.backgroundImage='none'; box.style.backgroundColor=value; }
  else if (/^https?:\/\//i.test(value)) { box.style.backgroundColor=''; box.style.backgroundImage=`linear-gradient(#0e162199,#0e162199),url("${value.replace(/["\\]/g,'')}")`; box.style.backgroundSize='cover'; box.style.backgroundPosition='center'; }
  else { box.style.backgroundImage='none'; box.style.backgroundColor=''; }
}
let recorder = null, recordingChunks = [];
async function toggleVoiceRecording() {
  const btn = $('voiceBtn');
  if (recorder && recorder.state === 'recording') { recorder.stop(); btn.textContent='🎙️'; btn.style.color=''; return; }
  if (!activeUser && !activeGroup) { alert('اول یک گفتگو انتخاب کن.'); return; }
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) { alert('ضبط صدا در این مرورگر پشتیبانی نمی‌شود. در HTTPS یا localhost امتحان کن.'); return; }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio:true});
    recorder = new MediaRecorder(stream); recordingChunks=[];
    recorder.ondataavailable = e => { if (e.data.size) recordingChunks.push(e.data); };
    recorder.onstop = async () => {
      stream.getTracks().forEach(t=>t.stop());
      const blob = new Blob(recordingChunks, {type:recorder.mimeType || 'audio/webm'});
      if (!blob.size) return;
      const fd = new FormData(); fd.append('file', blob, 'voice.webm');
      const up = await fetch('/api/upload',{method:'POST',body:fd}); const ud = await up.json();
      if (!up.ok) { alert(ud.error || 'ارسال صدا ناموفق بود'); return; }
      const payload={body:location.origin+ud.url,msg_type:'voice'};
      const sent = activeGroup ? await api('/api/groups/'+activeGroup.id+'/messages',{method:'POST',body:JSON.stringify(payload)}) : await api('/api/messages',{method:'POST',body:JSON.stringify({...payload,receiver_id:activeUser.id})});
      appendMessage(sent.message, !!activeGroup); scrollBottom(); if(!activeGroup) loadDialogs();
    };
    recorder.start(); btn.textContent='⏹️'; btn.style.color='#f87171';
  } catch(e) { alert('اجازه دسترسی به میکروفون داده نشد یا ضبط صدا ممکن نیست.'); }
}
async function createGroup() {
  const title = prompt('نام گروه را وارد کن:');
  if (!title?.trim()) return;
  const membersText = prompt('آیدی اعضا را با کاما جدا کن (مثلاً 2,3). خودت هم عضو می‌شوی:');
  const memberIds = (membersText||'').split(',').map(x=>parseInt(x.trim(),10)).filter(Number.isInteger);
  try {
    const d = await api('/api/groups',{method:'POST',body:JSON.stringify({title:title.trim(),members:memberIds})});
    await loadGroups(); await openGroupChat(d.id,d.title);
  } catch(e) { alert(e.message); }
}

function switchFolder(f) { loadDialogs(); }
function scrollBottom() { $('chatMessages').scrollTop =$('chatMessages').scrollHeight; }
function esc(s) { return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const seenMessageIds = new Set();
function messageMenu(m,isGroup=false) {
  const choices=[];
  choices.push(['📋 کپی متن',()=>navigator.clipboard?.writeText(m.body||'')]);
  choices.push(['↩️ پاسخ',()=>{ $('messageInput').value='↩ '+(m.sender_name||m.sender_username||'')+': '+(m.body||'').slice(0,100)+'\n'; $('messageInput').focus(); }]);
  if(!isGroup && m.sender_id===meId){ choices.push(['✏️ ویرایش',()=>editMessage(m.id,m.body||'')]); choices.push(['🗑️ حذف',()=>deleteMessage(m.id)]); }
  const html=`<h3 style="margin-bottom:12px">گزینه‌های پیام</h3>${choices.map((c,i)=>`<button onclick="runMessageChoice(${i})" style="display:block;width:100%;padding:11px;margin:6px 0;background:#172536;color:white;border:1px solid #344a64;border-radius:9px;text-align:right">${c[0]}</button>`).join('')}<button onclick="closeModal()" style="width:100%;padding:10px;background:transparent;color:#9fb2c7;border:0">بستن</button>`;
  window._messageChoices=choices; $('modalContent').innerHTML=html; $('modalOverlay').classList.remove('hidden');
}
function runMessageChoice(i){const c=window._messageChoices?.[i];if(c){closeModal();Promise.resolve(c[1]()).catch(()=>{});}}
function appendMessage(m, isGroup=false) {
  if (m.id != null && seenMessageIds.has(m.id)) return;
  if (m.id != null) seenMessageIds.add(m.id);
  let isMine = m.sender_id === meId;
  let el = document.createElement('div');
  el.dataset.messageId = m.id ?? '';
  el.title = 'برای گزینه‌های بیشتر راست‌کلیک کنید';
  el.addEventListener('contextmenu', ev => { ev.preventDefault(); messageMenu(m, isGroup); });
  el.className = `message-bubble ${isMine?'mine':''}`;
  let ticks = isMine ? (m.read_at ? ' <span style="color:#38bdf8;">✓✓</span>' : ' <span>✓</span>') : '';
  let bodyHtml = esc(m.body);
  if(m.msg_type === 'image') bodyHtml = `<img src="${esc(m.body)}" style="max-width:100%; max-height:360px; border-radius:10px; object-fit:contain;">`;
  else if(m.msg_type === 'voice') bodyHtml = `<div style="min-width:220px"><div>🎙️ پیام صوتی</div><audio controls preload="metadata" src="${esc(m.body)}" style="width:100%;max-width:280px"></audio></div>`;
  else if(m.msg_type === 'file') bodyHtml = `<a href="${esc(m.body)}" target="_blank" rel="noopener" style="color:#7dd3fc">📎 دریافت فایل</a>`;
  let actions = (!isGroup && isMine) ? `<div style="display:flex;gap:8px;margin-top:6px"><button onclick="editMessage(${m.id},${JSON.stringify(m.body||'')})" style="background:none;border:0;color:#bae6fd;cursor:pointer">ویرایش</button><button onclick="deleteMessage(${m.id})" style="background:none;border:0;color:#fca5a5;cursor:pointer">حذف</button></div>` : '';
  let sender = isGroup ? `<div style="font-size:11px;color:#7dd3fc;margin-bottom:4px">${esc(m.sender_name||m.sender_username||'کاربر')}</div>` : '';
  el.innerHTML = `${sender}<div>${bodyHtml}</div>${actions}<div class="msg-time">${(m.created_at||'').slice(11,16)}${ticks}</div>`;
  $('chatMessages').appendChild(el);
}

if ('Notification' in window && Notification.permission === 'default') {
  // Permission is requested only after the user explicitly interacts with the page.
  document.addEventListener('click', function askNotificationPermission() {
    if (Notification.permission === 'default') Notification.requestPermission();
    document.removeEventListener('click', askNotificationPermission);
  }, {once:true});
}
const socket = io();
let typingResetTimer = null;
socket.on('typing_status', data => {
  if (!activeUser || activeGroup || data.sender_id !== activeUser.id) return;
  const status = $('chatStatus');
  if (data.is_typing) {
    status.textContent = 'در حال نوشتن…';
    status.style.color = 'var(--accent)';
    clearTimeout(typingResetTimer);
    typingResetTimer = setTimeout(async () => {
      if (!activeUser || activeGroup) return;
      try {
        const d = await api('/api/users?q=' + encodeURIComponent(activeUser.username));
        const u = d.users.find(x => x.id === activeUser.id);
        if (u) updateChatPresence(u); else status.textContent = '@' + activeUser.username;
      } catch (_) { status.textContent = '@' + activeUser.username; }
    }, 2200);
  } else {
    clearTimeout(typingResetTimer);
    status.textContent = '@' + activeUser.username;
  }
});
socket.on('group_message', m => { if(activeGroup && activeGroup.id===m.group_id){ appendMessage(m,true); scrollBottom(); } });
socket.on('update_message', m => {
  if (activeUser && (m.sender_id === activeUser.id || m.receiver_id === activeUser.id)) refreshActiveChat();
});
socket.on('delete_message', () => { if (activeUser) refreshActiveChat(); });
socket.on('new_message', m => {
  const belongsToOpenChat = activeUser &&
    ((m.sender_id === meId && m.receiver_id === activeUser.id) ||
     (m.sender_id === activeUser.id && m.receiver_id === meId) ||
     (activeUser.id === meId && m.sender_id === meId && m.receiver_id === meId));
  if (belongsToOpenChat) {
    appendMessage(m);
    scrollBottom();
  }
  if (m.receiver_id === meId && m.sender_id !== meId) {
    if ('Notification' in window && Notification.permission === 'granted' &&
        (document.hidden || !belongsToOpenChat)) {
      new Notification('پیام جدید از ' + (m.sender_name || 'یک کاربر'), {
        body: m.msg_type === 'image' ? 'یک فایل برای شما فرستاده شد' : (m.body || 'پیام جدید'),
        tag: 'message-' + m.id
      });
    }
    if (navigator.vibrate) navigator.vibrate([120, 60, 120]);
  }
  loadDialogs();
});

loadDialogs();
api('/api/settings').then(x => {applyChatBackground(x.chat_background || ''); applyTheme(x.theme||'dark');}).catch(()=>{applyTheme(localStorage.getItem('pr-theme')||'dark');});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    socketio.run(app, host=os.environ.get("HOST","0.0.0.0"), port=int(os.environ.get("PORT","5000")), debug=False, allow_unsafe_werkzeug=True)