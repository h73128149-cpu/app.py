"""
Rango — Fixed & Complete Telegram Clone
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
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set COOKIE_SECURE=1 in production (HTTPS); keep local HTTP development usable by default.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
ALLOWED_EXT = {"png","jpg","jpeg","gif","webp","pdf","txt","zip","mp3","wav","ogg","m4a","mp4","webm","docx","xlsx"}

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user(): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=()")
    return response

@app.get("/healthz")
def healthz():
    return jsonify(status="ok", service="Rango")


# RANGO Android mandatory update configuration.
# Change RANGO_MIN_VERSION only after the matching APK has been tested and published.
RANGO_LATEST_VERSION = int(os.environ.get("RANGO_LATEST_VERSION", "2"))
RANGO_MIN_VERSION = int(os.environ.get("RANGO_MIN_VERSION", "2"))
RANGO_UPDATE_URL = os.environ.get("RANGO_UPDATE_URL", "https://t.me/PAYA_app")

@app.get("/api/app-version")
def app_version():
    return jsonify({
        "latest_version": RANGO_LATEST_VERSION,
        "minimum_version": RANGO_MIN_VERSION,
        "update_url": RANGO_UPDATE_URL,
        "force_update": True,
        "message": "نسخه جدید رنگو آماده است. برای ادامه، برنامه را به‌روزرسانی کنید."
    })

@app.before_request
def enforce_rango_android_minimum_version():
    # This blocks older official Android WebView builds. User-Agent checks are a
    # compatibility gate, not cryptographic proof; API authorization must remain server-side.
    ua = request.headers.get("User-Agent", "")
    if request.endpoint == "app_version" or request.path == "/healthz":
        return None
    match = re.search(r"(?:RANGO|PAYA)-Android/(\d+)", ua, re.IGNORECASE)
    if not match:
        return None
    try:
        installed = int(match.group(1))
    except (TypeError, ValueError):
        return None
    if installed < RANGO_MIN_VERSION:
        if request.path.startswith("/api/") or request.path.startswith("/socket.io"):
            return jsonify(error="update_required", minimum_version=RANGO_MIN_VERSION,
                           update_url=RANGO_UPDATE_URL,
                           message="برای ادامه، رنگو را به‌روزرسانی کنید."), 426
        return ("<!doctype html><html lang='fa' dir='rtl'><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>به‌روزرسانی رنگو</title><body style='font-family:sans-serif;"
                "background:#111827;color:white;text-align:center;padding:3rem'>"
                "<h2>نسخه جدید رنگو لازم است</h2><p>برای ادامه، برنامه را به‌روزرسانی کنید.</p>"
                f"<a style='color:#93c5fd' href='{RANGO_UPDATE_URL}'>رفتن به کانال آپدیت</a>"
                "</body></html>", 426, {"Content-Type": "text/html; charset=utf-8"})

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
          show_last_seen INTEGER DEFAULT 1, theme TEXT DEFAULT 'dark', profile_color TEXT DEFAULT '#30251f', notifications_enabled INTEGER DEFAULT 1, auto_download INTEGER DEFAULT 0, notification_sound INTEGER DEFAULT 1);
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
        CREATE TABLE IF NOT EXISTS archived_chats(
          user_id INTEGER NOT NULL REFERENCES users(id), other_id INTEGER NOT NULL REFERENCES users(id),
          archived_at TEXT NOT NULL, PRIMARY KEY(user_id,other_id));
        CREATE TABLE IF NOT EXISTS pinned_chats(
          user_id INTEGER NOT NULL REFERENCES users(id), other_id INTEGER NOT NULL REFERENCES users(id),
          pinned_at TEXT NOT NULL, PRIMARY KEY(user_id,other_id));
        CREATE TABLE IF NOT EXISTS user_subscriptions(
          user_id INTEGER PRIMARY KEY REFERENCES users(id), plan TEXT NOT NULL DEFAULT 'free',
          status TEXT NOT NULL DEFAULT 'inactive', starts_at TEXT, expires_at TEXT, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS message_rate_limits(
          user_id INTEGER NOT NULL REFERENCES users(id), bucket INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(user_id,bucket));
        CREATE TABLE IF NOT EXISTS stories(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          body TEXT NOT NULL DEFAULT '', media_url TEXT DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
        """)
        # Backward-compatible migrations for databases created by older versions
        cols={r[1] for r in c.execute("PRAGMA table_info(user_settings)").fetchall()}
        for name, ddl in [("profile_color", "TEXT DEFAULT '#30251f'"), ("notifications_enabled", "INTEGER DEFAULT 1"), ("auto_download", "INTEGER DEFAULT 0"), ("notification_sound", "INTEGER DEFAULT 1")]:
            if name not in cols: c.execute(f"ALTER TABLE user_settings ADD COLUMN {name} {ddl}")
        # Ensure settings exist for existing accounts
        c.execute("INSERT OR IGNORE INTO user_settings(user_id) SELECT id FROM users")

# WSGI hosts (for example gunicorn app:app) import this module without running __main__.
# Initialize tables during import so the first request does not fail with "no such table".
init_db()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def configured_admin_username():
    return os.environ.get("ADMIN_USERNAME", "Pv_HE33AM").strip().lstrip("@").lower()

def is_admin_account(user):
    return bool(user and user["username"].lower() == configured_admin_username())

def admin_session_verified(user):
    return bool(is_admin_account(user) and session.get("admin_verified_uid") == user["id"])

@app.post("/api/admin/verify")
@login_required
def admin_verify():
    u=current_user()
    if not is_admin_account(u):
        return jsonify(error="این حساب، حساب ادمین نیست."),403
    # Basic session-based throttling against repeated PIN guesses.
    now_ts=__import__('time').time()
    if session.get("admin_lock_until", 0) > now_ts:
        return jsonify(error="تلاش‌های زیاد؛ کمی بعد دوباره امتحان کن."),429
    data=request.get_json(silent=True) or {}
    expected=os.environ.get("ADMIN_ACCESS_CODE", "1390")
    supplied=str(data.get("code", ""))
    if not hmac.compare_digest(supplied, expected):
        fails=int(session.get("admin_pin_fails", 0))+1
        session["admin_pin_fails"]=fails
        if fails >= 5:
            session["admin_lock_until"]=now_ts+300
            session["admin_pin_fails"]=0
        return jsonify(error="کد ادمین اشتباه است."),403
    session.pop("admin_pin_fails", None); session.pop("admin_lock_until", None)
    session["admin_verified_uid"]=u["id"]
    return jsonify(ok=True, is_admin=True)

@app.get("/api/admin/status")
@login_required
def admin_status():
    u=current_user()
    return jsonify(is_admin=admin_session_verified(u), is_admin_account=is_admin_account(u), verified=admin_session_verified(u), configured=True)

@app.post("/api/admin/subscription")
@login_required
def admin_set_subscription():
    u=current_user()
    if not admin_session_verified(u):
        return jsonify(error="ابتدا با حساب ادمین وارد شو و کد ادمین را تأیید کن."),403
    data=request.get_json(silent=True) or {}
    target=str(data.get("username", "")).strip().lstrip("@").lower()
    action=str(data.get("action", "pro")).lower()
    user=db().execute("SELECT id,username FROM users WHERE username=?",(target,)).fetchone()
    if not user: return jsonify(error="این آیدی در پیام‌رسان پیدا نشد."),404
    if action=="free":
        db().execute("INSERT INTO user_subscriptions(user_id,plan,status,starts_at,expires_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan='free',status='inactive',expires_at=NULL,updated_at=excluded.updated_at",(user['id'],'free','inactive',None,None,now()))
        db().commit(); return jsonify(ok=True,username=target,plan="free")
    start=datetime.now(timezone.utc); expiry=start.replace() + __import__('datetime').timedelta(days=30)
    db().execute("INSERT INTO user_subscriptions(user_id,plan,status,starts_at,expires_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan='pro',status='active',starts_at=excluded.starts_at,expires_at=excluded.expires_at,updated_at=excluded.updated_at",(user['id'],'pro','active',start.isoformat(timespec='seconds'),expiry.isoformat(timespec='seconds'),now()))
    db().commit(); return jsonify(ok=True,username=target,plan="pro",expires_at=expiry.isoformat(timespec='seconds'))

@app.get("/api/stories")
@login_required
def get_stories():
    db().execute("DELETE FROM stories WHERE expires_at<=?",(now(),)); db().commit()
    rows=db().execute("SELECT s.id,s.user_id,s.body,s.media_url,s.created_at,s.expires_at,u.username,u.display_name,u.avatar FROM stories s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100").fetchall()
    return jsonify(stories=[dict(r) for r in rows])

@app.post("/api/stories")
@login_required
def create_story():
    u=current_user(); data=request.get_json(silent=True) or {}
    body=str(data.get('body','')).strip()[:500]
    media=str(data.get('media_url','')).strip()[:1000]
    if not body and not media: return jsonify(error="متن استوری یا لینک رسانه را وارد کن."),400
    if media and not (media.startswith('https://') or media.startswith('http://')): return jsonify(error="لینک رسانه معتبر نیست."),400
    start=datetime.now(timezone.utc); expiry=start+__import__('datetime').timedelta(hours=24)
    cur=db().execute("INSERT INTO stories(user_id,body,media_url,created_at,expires_at) VALUES(?,?,?,?,?)",(u['id'],body,media,start.isoformat(timespec='seconds'),expiry.isoformat(timespec='seconds')))
    db().commit(); return jsonify(ok=True,id=cur.lastrowid,expires_at=expiry.isoformat(timespec='seconds'))

@app.delete("/api/stories/<int:story_id>")
@login_required
def delete_story(story_id):
    u=current_user(); cur=db().execute("DELETE FROM stories WHERE id=? AND user_id=?",(story_id,u['id'])); db().commit()
    if not cur.rowcount: return jsonify(error="استوری پیدا نشد یا متعلق به شما نیست."),404
    return jsonify(ok=True)

def current_user():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None

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
               m.body as last_msg, m.created_at as last_time, m.read_at, m.sender_id,
               EXISTS(SELECT 1 FROM pinned_chats pc WHERE pc.user_id=? AND pc.other_id=u.id) AS chat_pinned
        FROM users u
        JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) OR (m.receiver_id = u.id AND m.sender_id = ?)
        WHERE NOT EXISTS (SELECT 1 FROM hidden_chats h WHERE h.user_id=? AND h.other_id=u.id)
          AND NOT EXISTS (SELECT 1 FROM archived_chats a WHERE a.user_id=? AND a.other_id=u.id)
          AND m.id IN (
            SELECT MAX(id) FROM messages 
            WHERE sender_id = ? OR receiver_id = ?
            GROUP BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
        )
        ORDER BY EXISTS(SELECT 1 FROM pinned_chats pc WHERE pc.user_id=? AND pc.other_id=u.id) DESC, m.id DESC
    """, (me["id"], me["id"], me["id"], me["id"], me["id"], me["id"], me["id"], me["id"], me["id"])).fetchall()
    
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
        item["is_admin"] = is_admin_account(item)
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
    msg = db().execute("SELECT * FROM messages WHERE id=? AND sender_id=? AND deleted=0", (mid, me["id"])).fetchone()
    if not msg:
        return jsonify(error="پیام پیدا نشد یا اجازهٔ ویرایش آن را نداری"), 404
    db().execute("UPDATE messages SET body=? WHERE id=? AND sender_id=?", (body, mid, me["id"]))
    db().commit()
    updated = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    socketio.emit("update_message", dict(updated), room=f"user:{msg['receiver_id']}")
    socketio.emit("update_message", dict(updated), room=f"user:{me['id']}")
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
    reaction=str(data.get("reaction","")).strip()[:16]
    allowed_reactions={"", "👍", "❤️", "😂", "😮", "😢", "🔥", "👏", "🤔"}
    if reaction not in allowed_reactions:
        return jsonify(error="واکنش پشتیبانی نمی‌شود"), 400
    msg = db().execute("SELECT * FROM messages WHERE id=? AND deleted=0 AND (sender_id=? OR receiver_id=?)", (mid, me["id"], me["id"])).fetchone()
    if not msg:
        return jsonify(error="پیام پیدا نشد یا دسترسی ندارید"), 404
    db().execute("UPDATE messages SET reaction=? WHERE id=?", (reaction, mid))
    db().commit()
    updated = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    socketio.emit("update_message", dict(updated), room=f"user:{msg['receiver_id']}")
    socketio.emit("update_message", dict(updated), room=f"user:{msg['sender_id']}")
    return jsonify(ok=True)

@app.get("/api/chats/<int:other_id>/media")
@login_required
def chat_media(other_id):
    me=current_user()
    if other_id != me["id"] and not db().execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone():
        return jsonify(error="کاربر پیدا نشد"), 404
    rows=db().execute("""SELECT id,sender_id,receiver_id,body,msg_type,created_at FROM messages
        WHERE deleted=0 AND ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
        AND msg_type IN ('image','file','voice') ORDER BY id DESC LIMIT 100""",
        (me["id"],other_id,other_id,me["id"])).fetchall()
    return jsonify(items=[dict(r) for r in rows])

@app.post("/api/messages/<int:mid>/pin")
@login_required
def pin_message(mid):
    me=current_user()
    msg=db().execute("SELECT * FROM messages WHERE id=? AND deleted=0 AND (sender_id=? OR receiver_id=?)",(mid,me["id"],me["id"])).fetchone()
    if not msg:
        return jsonify(error="پیام پیدا نشد یا دسترسی ندارید"),404
    new_value=0 if msg["pinned"] else 1
    db().execute("UPDATE messages SET pinned=? WHERE id=?",(new_value,mid)); db().commit()
    updated=db().execute("SELECT * FROM messages WHERE id=?",(mid,)).fetchone()
    socketio.emit("update_message",dict(updated),room=f"user:{msg['sender_id']}")
    socketio.emit("update_message",dict(updated),room=f"user:{msg['receiver_id']}")
    return jsonify(ok=True,pinned=bool(new_value))

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
    if theme not in {"dark","light"}: theme="dark"
    profile_color=str(data.get("profile_color", "#30251f"))[:20]
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", profile_color): profile_color="#30251f"
    notifications=1 if data.get("notifications_enabled", True) else 0
    auto_download=1 if data.get("auto_download", False) else 0
    notification_sound=1 if data.get("notification_sound", True) else 0
    db().execute("UPDATE user_settings SET chat_background=?,show_last_seen=?,theme=?,profile_color=?,notifications_enabled=?,auto_download=?,notification_sound=? WHERE user_id=?",
                 (bg,1 if data.get("show_last_seen") else 0,theme,profile_color,notifications,auto_download,notification_sound,u["id"]))
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


@app.get("/api/users/contacts")
@login_required
def list_contacts():
    me=current_user()
    rows=db().execute("SELECT id,username,display_name,avatar,online,last_seen FROM users WHERE id!=? ORDER BY online DESC,display_name COLLATE NOCASE LIMIT 100",(me["id"],)).fetchall()
    return jsonify(users=[{**dict(r), "is_admin": is_admin_account(r)} for r in rows])

@app.get("/api/messages/search")
@login_required
def search_messages():
    me=current_user(); q=str(request.args.get("q","")).strip()[:120]
    try: other_id=int(request.args.get("other_id", "0"))
    except (ValueError,TypeError): other_id=0
    if len(q)<2: return jsonify(results=[])
    like="%"+q.replace("%", "\\%").replace("_", "\\_")+"%"
    if other_id and other_id != me["id"]:
        sql="""SELECT m.*,u.username sender_username,u.display_name sender_name FROM messages m
          JOIN users u ON u.id=m.sender_id WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
          AND m.deleted=0 AND m.body LIKE ? ESCAPE '\\'"""
        params=[me["id"],other_id,other_id,me["id"],like]
    else:
        sql="""SELECT m.*,u.username sender_username,u.display_name sender_name FROM messages m
          JOIN users u ON u.id=m.sender_id WHERE (m.sender_id=? OR m.receiver_id=?) AND m.deleted=0 AND m.body LIKE ? ESCAPE '\\'"""
        params=[me["id"],me["id"],like]
    rows=db().execute(sql+" ORDER BY m.id DESC LIMIT 50",params).fetchall()
    return jsonify(results=[dict(r) for r in rows])

@app.post("/api/messages/<int:mid>/forward")
@login_required
def forward_message(mid):
    me=current_user(); data=request.get_json(silent=True) or {}
    try: rid=int(data.get("receiver_id"))
    except (TypeError,ValueError): return jsonify(error="مقصد نامعتبر است"),400
    src=db().execute("SELECT * FROM messages WHERE id=? AND deleted=0 AND (sender_id=? OR receiver_id=?)",(mid,me["id"],me["id"])).fetchone()
    if not src: return jsonify(error="پیام پیدا نشد یا دسترسی ندارید"),404
    if rid!=me["id"] and not db().execute("SELECT id FROM users WHERE id=?",(rid,)).fetchone(): return jsonify(error="مخاطب پیدا نشد"),404
    if rid!=me["id"] and db().execute("SELECT 1 FROM user_blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",(me["id"],rid,rid,me["id"])).fetchone(): return jsonify(error="ارسال به این مخاطب مجاز نیست"),403
    body=str(src["body"] or "")[:10000]
    cur=db().execute("INSERT INTO messages(sender_id,receiver_id,body,msg_type,attachment,created_at) VALUES(?,?,?,?,?,?)",(me["id"],rid,body,src["msg_type"],src["attachment"],now()))
    db().commit()
    msg=dict(id=cur.lastrowid,sender_id=me["id"],receiver_id=rid,body=body,msg_type=src["msg_type"],attachment=src["attachment"],reaction="",created_at=now(),sender_username=me["username"],sender_name=me["display_name"],read_at=None,forwarded=1)
    socketio.emit("new_message",msg,room=f"user:{rid}")
    if rid!=me["id"]: socketio.emit("new_message",msg,room=f"user:{me['id']}")
    return jsonify(ok=True,message=msg)

@app.get("/api/chats/archived")
@login_required
def get_archived_chats():
    me=current_user()
    rows=db().execute("""SELECT u.id,u.username,u.display_name,u.avatar,u.online,a.archived_at FROM archived_chats a
       JOIN users u ON u.id=a.other_id WHERE a.user_id=? ORDER BY a.archived_at DESC""",(me["id"],)).fetchall()
    return jsonify(chats=[dict(r) for r in rows])

@app.post("/api/chats/<int:other_id>/archive")
@login_required
def archive_chat(other_id):
    me=current_user()
    if other_id==me["id"]: return jsonify(error="پیام‌های ذخیره‌شده قابل بایگانی نیستند"),400
    if not db().execute("SELECT id FROM users WHERE id=?",(other_id,)).fetchone(): return jsonify(error="کاربر پیدا نشد"),404
    db().execute("INSERT OR REPLACE INTO archived_chats(user_id,other_id,archived_at) VALUES(?,?,?)",(me["id"],other_id,now()))
    db().commit(); return jsonify(ok=True)

@app.post("/api/chats/<int:other_id>/unarchive")
@login_required
def unarchive_chat(other_id):
    me=current_user(); db().execute("DELETE FROM archived_chats WHERE user_id=? AND other_id=?",(me["id"],other_id)); db().commit()
    return jsonify(ok=True)

@app.post("/api/chats/<int:other_id>/pin")
@login_required
def pin_chat(other_id):
    me=current_user()
    if other_id == me["id"]: return jsonify(error="گفتگوی پیام‌های ذخیره‌شده قابل سنجاق است اما این عملیات فعلاً پشتیبانی نمی‌شود"),400
    if not db().execute("SELECT id FROM users WHERE id=?",(other_id,)).fetchone(): return jsonify(error="کاربر پیدا نشد"),404
    exists=db().execute("SELECT 1 FROM pinned_chats WHERE user_id=? AND other_id=?",(me["id"],other_id)).fetchone()
    if exists: db().execute("DELETE FROM pinned_chats WHERE user_id=? AND other_id=?",(me["id"],other_id)); pinned=False
    else: db().execute("INSERT OR IGNORE INTO pinned_chats(user_id,other_id,pinned_at) VALUES(?,?,?)",(me["id"],other_id,now())); pinned=True
    db().commit(); return jsonify(ok=True,pinned=pinned)

@app.get("/api/subscription")
@login_required
def subscription_status():
    me=current_user(); row=db().execute("SELECT * FROM user_subscriptions WHERE user_id=?",(me["id"],)).fetchone()
    return jsonify(subscription=dict(row) if row else {"plan":"free","status":"inactive","expires_at":None}, payment_connected=False)

@app.post("/api/messages/<int:mid>/reply")
@login_required
def reply_message(mid):
    me=current_user(); data=request.get_json(silent=True) or {}
    body=str(data.get("body", "")).strip()[:10000]
    if not body: return jsonify(error="متن پاسخ خالی است"),400
    src=db().execute("SELECT * FROM messages WHERE id=? AND deleted=0 AND (sender_id=? OR receiver_id=?)",(mid,me["id"],me["id"])).fetchone()
    if not src: return jsonify(error="پیام اصلی پیدا نشد"),404
    rid=src["receiver_id"] if src["sender_id"]==me["id"] else src["sender_id"]
    if src["sender_id"]==me["id"] and src["receiver_id"]==me["id"]: rid=me["id"]
    cur=db().execute("INSERT INTO messages(sender_id,receiver_id,body,msg_type,reply_to,created_at) VALUES(?,?,?,?,?,?)",(me["id"],rid,body,"text",mid,now()))
    db().commit()
    msg=dict(id=cur.lastrowid,sender_id=me["id"],receiver_id=rid,body=body,msg_type="text",reply_to=mid,reaction="",created_at=now(),sender_username=me["username"],sender_name=me["display_name"],read_at=None)
    socketio.emit("new_message",msg,room=f"user:{rid}")
    if rid!=me["id"]: socketio.emit("new_message",msg,room=f"user:{me['id']}")
    return jsonify(ok=True,message=msg)

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


/* Strict monochrome palette: only black and white themes */
:root { --text-main:#fff; --button-text:#000; }
body[data-theme="dark"] { color:#fff !important; }
body[data-theme="dark"] .chat-main, body[data-theme="dark"] .chat-messages { background:#000 !important; }
body[data-theme="dark"] .sidebar, body[data-theme="dark"] .sidebar-header, body[data-theme="dark"] .chat-topbar, body[data-theme="dark"] .chat-composer, body[data-theme="dark"] .modal-card { background:#101010 !important; }
body[data-theme="dark"] .chat-row.active { background:#303030 !important; }
body[data-theme="dark"] .message-bubble.mine { background:#292929 !important; }
body[data-theme="dark"] .message-bubble:not(.mine) { background:#151515 !important; }
body[data-theme="light"] { color:#111 !important; }
body[data-theme="light"] .chat-main, body[data-theme="light"] .chat-messages { background:#fff !important; }
body[data-theme="light"] .sidebar, body[data-theme="light"] .sidebar-header, body[data-theme="light"] .chat-topbar, body[data-theme="light"] .chat-composer, body[data-theme="light"] .modal-card { background:#f5f5f5 !important; color:#111 !important; }
body[data-theme="light"] .chat-row.active { background:#ddd !important; }
body[data-theme="light"] .message-bubble.mine { background:#e5e5e5 !important; color:#111 !important; }
body[data-theme="light"] .message-bubble:not(.mine) { background:#f2f2f2 !important; color:#111 !important; }
body[data-theme="light"] input, body[data-theme="light"] textarea, body[data-theme="light"] select { color:#111 !important; }


.pr-dialog-head{display:flex;gap:13px;align-items:flex-start;margin:4px 0 18px}.pr-dialog-icon{width:42px;height:42px;flex:0 0 42px;display:grid;place-items:center;border-radius:14px;background:var(--panel-hover);border:1px solid var(--border-color);font-size:22px}.pr-dialog-head h3{margin:2px 0 7px;font-size:17px}.pr-dialog-head p{margin:0;color:var(--text-muted);line-height:1.8;font-size:13px;overflow-wrap:anywhere}.pr-dialog-actions{display:flex;gap:9px;margin-top:16px}.pr-dialog-actions button{flex:1;padding:11px 14px;border-radius:11px;cursor:pointer;font-weight:700}.pr-btn-primary{border:1px solid var(--border-color);background:var(--accent);color:var(--button-text,#000)}.pr-btn-secondary{border:1px solid var(--border-color);background:var(--panel-hover);color:var(--text-main,#fff)}.pr-dialog-input{box-sizing:border-box;width:100%;resize:vertical;min-height:90px;padding:12px;border-radius:12px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-main,#fff);font:inherit;outline:none}.pr-dialog-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #8882}
</style>

<style id="pr-enhancements">
.system-notice{margin:auto;max-width:390px;padding:28px 24px;text-align:center;border:1px solid var(--border-color);border-radius:20px;background:var(--panel-bg);box-shadow:0 18px 55px #0003;animation:prNoticeIn .22s ease-out}
.system-notice-icon{font-size:36px;margin-bottom:12px}.system-notice strong{font-size:18px}.system-notice p{margin:10px 0 18px;color:var(--text-muted);line-height:1.8;font-size:13px}.system-notice button{border:1px solid var(--border-color);border-radius:10px;padding:9px 15px;background:var(--bg-main);color:var(--text-main,white);cursor:pointer}
@keyframes prNoticeIn{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
</style>

<style id="pr-premium-auth">
:root{color-scheme:dark}
body{position:relative;isolation:isolate;background:#050505!important;overflow-x:hidden;padding:24px}
body:before{content:"";position:fixed;inset:0;z-index:-2;linear-gradient(145deg,#080808,#111 55%,#080808)}
body:after{content:"";position:fixed;inset:0;z-index:-1;opacity:.18;pointer-events:none;background-image:none}
.auth-card{position:relative;width:min(460px,100%);padding:clamp(28px,5vw,46px);text-align:right;border-radius:20px;background:#141414!important;border:1px solid #292929;box-shadow:0 18px 48px #0008;backdrop-filter:none;overflow:hidden;animation:prAuthIn .28s ease-out both}
.auth-card:before{content:"PR";display:grid;place-items:center;width:66px;height:66px;margin:0 0 24px auto;border-radius:22px;background:#e7e7e7;color:#080808;font-size:25px;font-weight:900;letter-spacing:-1px;box-shadow:none;transform:none}
.auth-card:after{content:"PRIVATE • FAST • CONNECTED";display:block;margin-top:28px;padding-top:18px;border-top:1px solid #ffffff13;color:#777;font-size:10px;letter-spacing:2px;text-align:center;direction:ltr}
.auth-card h2{font-size:clamp(23px,4vw,30px)!important;line-height:1.5;margin-bottom:7px!important;color:#fff;letter-spacing:-.7px}
.auth-card h2:after{content:"ارتباطی ساده، تجربه‌ای حرفه‌ای";display:block;margin-top:7px;color:#888;font-size:12px;font-weight:400;letter-spacing:0}
.auth-card form{margin-top:25px}
.auth-card input{height:54px;padding:0 17px;margin-bottom:13px;border:1px solid #ffffff17;border-radius:15px;background:#050505!important;color:#fff;transition:border .2s,box-shadow .2s,transform .2s}
.auth-card input::placeholder{color:#777}
.auth-card input:focus{border-color:#e5e5e5;box-shadow:0 0 0 4px #ffffff0b;transform:translateY(-1px)}
.auth-card button{height:54px;margin-top:5px;border-radius:15px;background:#e5e5e5!important;color:#050505!important;font-size:15px;font-weight:750;box-shadow:none;transition:background .18s}
.auth-card button:hover{transform:translateY(-2px);filter:brightness(1.08)}
.auth-card a{display:inline-flex;margin-top:3px;color:#eee!important;font-size:13px;text-decoration:underline;text-decoration-color:#555;text-underline-offset:5px}
.error{border:1px solid #ffffff20;background:#ffffff0c!important;color:#fff!important;border-radius:13px}
@keyframes prAuthIn{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}
@media(max-width:480px){body{padding:16px}.auth-card{border-radius:23px;padding:28px 22px}.auth-card:before{width:58px;height:58px}}
.auth-live-badge{display:inline-flex;align-items:center;gap:8px;border:1px solid #ffffff18;background:#ffffff08;color:#bdbdbd;padding:7px 11px;border-radius:99px;font-size:11px;margin-bottom:17px}
.auth-live-badge span{width:7px;height:7px;border-radius:50%;background:#f5f5f5;box-shadow:0 0 13px #fff;animation:authPulse 1.8s infinite}
.auth-lead{color:#929292;font-size:13px;line-height:1.9;margin-top:4px}
.auth-password-wrap{position:relative}.auth-password-wrap input{padding-left:76px!important}.auth-password-wrap .auth-eye{position:absolute;left:8px;top:5px;width:auto;height:42px!important;margin:0;padding:0 11px;background:#1b1b1b!important;border:1px solid #333!important;color:#ddd!important;font-size:11px;box-shadow:none!important}
.auth-card .auth-submit{display:flex;align-items:center;justify-content:center;gap:12px;background:#e5e5e5!important;animation:none;color:#050505!important}
.auth-switch{display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;margin-top:20px;font-size:12px;color:#888}.auth-switch a{margin:0!important;text-decoration:none!important;color:#fff!important;font-weight:800}
.auth-benefits{display:flex;justify-content:center;gap:8px;flex-wrap:wrap;margin-top:25px}.auth-benefits span{font-size:10px;color:#8b8b8b;padding:7px 9px;border:1px solid #ffffff10;border-radius:99px;background:#ffffff04}
@keyframes authPulse{50%{opacity:.4;box-shadow:0 0 3px #fff}}@keyframes authShine{0%,100%{background-position:0 0}50%{background-position:100% 0}}
@media(max-width:420px){.auth-benefits{gap:5px}.auth-benefits span{font-size:9px;padding:6px 7px}}
</style>
</head>
<body>
<div class="auth-card">
  <div class="auth-live-badge"><span></span> پیام‌رسان خصوصی نسل جدید</div>
  <h2 style="margin-bottom: 20px; font-weight: 700;">{{title}}</h2>
  <p class="auth-lead">گفت‌وگوهای تو، با ظاهر و تجربه‌ای متفاوت.</p>
  {% if error %}<div class="error">{{error}}</div>{% endif %}
  <form method="post">
    {% if action=='register' %}
    <input name="display_name" placeholder="نام نمایشی" required>
    {% endif %}
    <input name="username" placeholder="نام کاربری (آیدی)" required>
    <div class="auth-password-wrap"><input id="authPassword" name="password" type="password" placeholder="رمز عبور" autocomplete="current-password" required><button class="auth-eye" type="button" onclick="const p=document.getElementById('authPassword');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'نمایش':'مخفی'">نمایش</button></div>
    <button class="auth-submit" type="submit"><span>{{title}}</span><span aria-hidden="true"> ← </span></button>
  </form>
  <div class="auth-switch">
    {% if action=='login' %}<span>هنوز حساب نداری؟</span><a href="{{url_for('register')}}">ساخت حساب جدید ↗</a>{% else %}<span>قبلاً ثبت‌نام کردی؟</span><a href="{{url_for('login')}}">ورود به حساب ↗</a>{% endif %}
  </div>
  <div class="auth-benefits"><span>🔒 ارتباط خصوصی</span><span>⚡ سریع و سبک</span><span>✦ طراحی PRO</span></div>
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
/* Rango signature theme: Telegram-like desktop layout with a richer neon finish */
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
<style id="pr-premium-app">
/* Premium monochrome redesign — keeps the existing app structure and handlers */
:root{--bg-main:#080808;--panel-bg:#111;--panel-hover:#1c1c1c;--active-bg:#292929;--accent:#f4f4f4;--bubble-out:#303030;--bubble-in:#171717;--text-muted:#969696;--border-color:#292929;--text-main:#f5f5f5;--button-text:#080808}
body{background:#070707!important;color:#f5f5f5}
.tg-app{background:#080808;isolation:isolate}
.folder-rail{background:#080808!important;border-color:#242424!important;box-shadow:8px 0 30px #0005;padding-top:18px;gap:15px}
.folder-icon{border:1px solid transparent;color:#858585;transition:all .2s ease}
.folder-icon:hover{background:#1b1b1b!important;color:#fff;transform:translateY(-2px)}
.folder-icon.active{background:#f1f1f1!important;color:#090909!important;box-shadow:0 7px 22px #fff1}
.sidebar{background:linear-gradient(180deg,#121212,#0b0b0b)!important;border-color:#252525!important;box-shadow:12px 0 35px #0002}
.sidebar-header{background:#101010!important;border-bottom:1px solid #292929!important;padding:17px 16px;gap:12px}
.search-container{background:#080808!important;border:1px solid #292929!important;border-radius:14px;height:44px}
.search-container:focus-within{border-color:#777!important;box-shadow:0 0 0 3px #fff0a!important}
.search-container input{color:#fff!important}
.chat-row{padding:14px 16px;border-bottom:1px solid #ffffff08;transition:background .18s,transform .18s}
.chat-row:hover{background:#1b1b1b!important;transform:translateX(-2px)}
.chat-row.active{background:linear-gradient(100deg,#252525,#171717)!important;box-shadow:inset -3px 0 #f3f3f3}
.avatar{background-color:#303030!important;color:#fff!important;border:1px solid #ffffff20;box-shadow:0 5px 18px #0008}
.chat-main{background:radial-gradient(ellipse at 50% -15%,#171717,#080808 62%)!important}
.chat-topbar{height:72px;background:#101010f5!important;border-bottom:1px solid #282828!important;box-shadow:0 6px 25px #0004;padding-inline:20px;backdrop-filter:blur(18px)}
.chat-topbar-info{gap:14px}
.chat-messages{background-color:#090909!important;background-image:radial-gradient(#ffffff09 1px,transparent 1px)!important;background-size:22px 22px!important;padding:clamp(16px,3vw,36px)}
.message-bubble{padding:11px 15px;border:1px solid #ffffff0b;box-shadow:0 5px 20px #0003;font-size:14px;line-height:1.8}
.message-bubble.mine{background:linear-gradient(145deg,#383838,#242424)!important;color:#fff;border-radius:18px 18px 5px 18px}
.message-bubble:not(.mine){background:linear-gradient(145deg,#1b1b1b,#141414)!important;color:#f1f1f1;border-radius:18px 18px 18px 5px}
.msg-time{color:#aaa!important}
.chat-composer{background:#101010f5!important;border-top:1px solid #292929!important;padding:13px 18px;backdrop-filter:blur(18px)}
.composer-input{background:#080808!important;border:1px solid #2b2b2b!important;border-radius:15px;color:#fff!important;transition:border .2s,box-shadow .2s}
.composer-input:focus{border-color:#777!important;box-shadow:0 0 0 3px #ffffff09}
.action-btn{color:#aaa!important;transition:all .18s}
.action-btn:hover{background:#292929!important;color:#fff!important;transform:scale(1.07)}
.modal-overlay{background:#000b!important;backdrop-filter:blur(9px)}
.modal-card{background:linear-gradient(145deg,#191919,#0d0d0d)!important;border:1px solid #373737!important;border-radius:23px!important;box-shadow:0 30px 100px #000c!important;color:#f5f5f5}
.modal-card input,.modal-card textarea,.modal-card select{background:#080808!important;color:#fff!important;border:1px solid #303030!important;border-radius:12px}
button{transition:filter .18s,transform .18s}
button:hover{filter:brightness(1.12)}
input,textarea,select{accent-color:#fff}
.chat-list::-webkit-scrollbar,.chat-messages::-webkit-scrollbar{width:6px}
.chat-list::-webkit-scrollbar-thumb,.chat-messages::-webkit-scrollbar-thumb{background:#3a3a3a;border-radius:10px}
.system-notice{background:linear-gradient(145deg,#191919,#0d0d0d)!important;border-color:#353535!important}
.system-notice button{background:#f1f1f1!important;color:#080808!important;border:0!important;font-weight:800}
/* White theme remains strictly monochrome */
body[data-theme="light"]{--bg-main:#f5f5f5;--panel-bg:#fff;--panel-hover:#eee;--active-bg:#e4e4e4;--accent:#111;--bubble-out:#dedede;--bubble-in:#f1f1f1;--text-muted:#666;--border-color:#ddd;color:#111!important;background:#f5f5f5!important}
body[data-theme="light"] .tg-app,body[data-theme="light"] .folder-rail,body[data-theme="light"] .chat-main,body[data-theme="light"] .chat-messages{background:#f5f5f5!important;color:#111!important}
body[data-theme="light"] .sidebar,body[data-theme="light"] .sidebar-header,body[data-theme="light"] .chat-topbar,body[data-theme="light"] .chat-composer,body[data-theme="light"] .modal-card{background:#fff!important;color:#111!important;border-color:#ddd!important}
body[data-theme="light"] .chat-row.active{background:#e6e6e6!important;box-shadow:inset -3px 0 #111}
body[data-theme="light"] .message-bubble,body[data-theme="light"] .message-bubble.mine,body[data-theme="light"] .message-bubble:not(.mine){background:#e6e6e6!important;color:#111!important;border-color:#ddd}
body[data-theme="light"] .composer-input,body[data-theme="light"] .search-container,body[data-theme="light"] .modal-card input,body[data-theme="light"] .modal-card textarea,body[data-theme="light"] .modal-card select{background:#f7f7f7!important;color:#111!important;border-color:#ddd!important}
body[data-theme="light"] .folder-icon{color:#555}
body[data-theme="light"] .folder-icon.active{background:#111!important;color:#fff!important}
body[data-theme="light"] .avatar{background:#ddd!important;color:#111!important;border-color:#ccc}
@media(min-width:769px){.sidebar{width:clamp(320px,29vw,410px)}.chat-messages{padding:clamp(24px,3vw,44px)}.message-bubble{max-width:min(70%,760px)}}
@media(max-width:768px){.sidebar{background:#0c0c0c!important}.chat-topbar{height:60px;padding-inline:10px}.chat-composer{padding:9px}.chat-messages{padding:12px 10px}.message-bubble{max-width:88%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
<style id="pr-cinematic-redesign">
:root{--bg-main:#050607;--panel-bg:#0b0e10;--panel-hover:#171b1e;--active-bg:#202427;--accent:#e8e8e8;--bubble-out:#292d30;--bubble-in:#111518;--text-muted:#92999d;--border-color:#252b2f;color-scheme:dark}
body{background:#050607!important;background-image:radial-gradient(ellipse at 50% 20%,#22272b55,transparent 55%),linear-gradient(135deg,#030405,#0b0e10 52%,#020303)!important}
.tg-app{background:transparent;gap:0;padding:7px;}
.folder-rail,.sidebar,.chat-main,.chat-topbar,.chat-composer,.modal-card{background:rgba(8,11,13,.94)!important;border-color:#252b2f!important}
.folder-rail{border:1px solid #252b2f;border-radius:18px 0 0 18px;backdrop-filter:blur(20px);padding-top:18px}
.folder-icon{border:1px solid transparent;transition:.2s;color:#aeb4b8}
.folder-icon:hover,.folder-icon.active{background:linear-gradient(145deg,#282d31,#111416)!important;border-color:#3c4246;color:#fff!important;box-shadow:0 8px 24px #0008}
.sidebar{border-block:1px solid #252b2f;backdrop-filter:blur(20px)}
.sidebar-header,.chat-topbar{border-bottom:1px solid #252b2f!important;background:linear-gradient(180deg,#111518,#090b0d)!important}
.search-container,.composer-input{background:#050708!important;border:1px solid #282e32!important;border-radius:15px!important}
.search-container:focus-within,.composer-input:focus{border-color:#777!important;box-shadow:0 0 0 3px #fff08}
.chat-row{margin:4px 7px;border:1px solid transparent!important;border-radius:14px;transition:background .2s,border-color .2s,transform .2s}
.chat-row:hover{background:#171b1e!important;border-color:#2a3034!important;transform:translateX(-2px)}
.chat-row.active{background:linear-gradient(110deg,#252a2d,#111416)!important;border-color:#363d41!important;box-shadow:inset -2px 0 #ddd}
.avatar{background:linear-gradient(145deg,#656b70,#171a1c)!important;border:1px solid #464d52;box-shadow:0 4px 12px #0008}
.chat-messages{background-color:transparent!important;background-image:radial-gradient(ellipse at 50% 45%,#151a1d80,transparent 65%),linear-gradient(135deg,#050708,#0b0e10 55%,#050607)!important}
.message-bubble{border:1px solid #30373b!important;border-radius:17px!important;box-shadow:0 7px 22px #0004;backdrop-filter:blur(8px)}
.message-bubble.mine{background:linear-gradient(145deg,#303639,#1b1f22)!important;color:#fff!important;border-bottom-right-radius:5px!important}
.message-bubble:not(.mine){background:linear-gradient(145deg,#171b1e,#0d1012)!important;color:#f2f2f2!important;border-bottom-left-radius:5px!important}
.chat-composer{border:1px solid #282e32!important;border-radius:20px!important;margin:8px!important;padding:10px!important;box-shadow:0 12px 30px #0006}
button,.action-btn{transition:transform .18s,filter .18s,background .18s;border-radius:12px}
button:hover,.action-btn:hover{filter:brightness(1.15);transform:translateY(-1px)}
.modal-overlay{backdrop-filter:blur(12px);background:#000b!important}
.modal-card{border:1px solid #343b40!important;border-radius:24px!important;box-shadow:0 28px 90px #000c,inset 0 1px #ffffff08!important}
.modal-card input,.modal-card textarea,.modal-card select{background:#050708!important;border:1px solid #2b3236!important;border-radius:12px!important;color:#f5f5f5!important}
.system-notice{background:linear-gradient(145deg,#191d20,#080a0b)!important;border-color:#3a4145!important}
*{scrollbar-width:thin;scrollbar-color:#3b4246 transparent}
.chat-list::-webkit-scrollbar-thumb,.chat-messages::-webkit-scrollbar-thumb{background:#3b4246;border-radius:20px}
body[data-theme="light"]{--bg-main:#f1f1f1;--panel-bg:#fff;--panel-hover:#ededed;--active-bg:#e1e1e1;--accent:#111;--bubble-out:#dedede;--bubble-in:#fff;--text-muted:#626262;--border-color:#d4d4d4;color-scheme:light;background:#f1f1f1!important;background-image:radial-gradient(ellipse at 50% 20%,#fff,transparent 60%)!important}
body[data-theme="light"] .folder-rail,body[data-theme="light"] .sidebar,body[data-theme="light"] .chat-main,body[data-theme="light"] .chat-topbar,body[data-theme="light"] .chat-composer,body[data-theme="light"] .modal-card{background:#fff!important;color:#111!important;border-color:#d4d4d4!important}
body[data-theme="light"] .chat-messages{background:#f2f2f2!important;background-image:radial-gradient(ellipse at 50% 45%,#fff,transparent 70%)!important}
body[data-theme="light"] .message-bubble,body[data-theme="light"] .message-bubble.mine,body[data-theme="light"] .message-bubble:not(.mine){background:#fff!important;color:#111!important;border-color:#ddd!important}
body[data-theme="light"] .chat-row.active{background:#e7e7e7!important;border-color:#d2d2d2!important}
body[data-theme="light"] .search-container,body[data-theme="light"] .composer-input,body[data-theme="light"] .modal-card input,body[data-theme="light"] .modal-card textarea,body[data-theme="light"] .modal-card select{background:#f7f7f7!important;color:#111!important;border-color:#ddd!important}
@media(max-width:768px){.tg-app{padding:0}.folder-rail{border-radius:0;width:54px}.sidebar{border-radius:0}.chat-composer{margin:5px!important}.message-bubble{max-width:88%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}

/* ULTIMATE VISUAL PACK: monochrome luxury + premium storefront + emoji/sticker tray */
.pr-top-actions{display:flex;align-items:center;gap:7px;padding:10px 14px 13px;background:#0c0c0c;border-bottom:1px solid #242424}
.pr-pro-shop{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 13px;border-radius:15px;border:1px solid #444;background:linear-gradient(110deg,#292929,#111);color:#fff;cursor:pointer;text-align:right;box-shadow:0 8px 25px #0007}
.pr-pro-shop b{font-size:12px;letter-spacing:.3px}.pr-pro-shop small{display:block;color:#aaa;font-size:10px;margin-top:3px}
.pr-crown{display:grid;place-items:center;width:35px;height:35px;border-radius:12px;background:linear-gradient(145deg,#f4f4f4,#999);color:#080808;font-size:20px;box-shadow:0 0 25px #fff2}
.pr-composer-tools{display:flex;gap:5px;align-items:center}
.pr-tool-btn{width:39px;height:40px;border:1px solid #2b2b2b;background:#151515;color:#eee;border-radius:13px;cursor:pointer;font-size:19px}
.pr-tool-btn:hover{background:#303030;transform:translateY(-2px)}
.pr-premium-hero{position:relative;overflow:hidden;padding:24px;border:1px solid #3b3b3b;border-radius:22px;background:radial-gradient(ellipse at 90% 0%,#ffffff22,transparent 45%),linear-gradient(135deg,#222,#090909);margin-bottom:16px}
.pr-premium-hero:after{content:'✦';position:absolute;right:22px;bottom:-42px;font-size:150px;color:#ffffff08;pointer-events:none}
.pr-premium-hero .eyebrow{font-size:10px;letter-spacing:3px;color:#aaa}.pr-premium-hero h2{font-size:28px;margin:12px 0 8px;letter-spacing:-1px}.pr-premium-hero p{color:#aaa;font-size:12px;line-height:1.9;max-width:360px}
.pr-plan-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.pr-plan{padding:16px;border:1px solid #333;border-radius:18px;background:linear-gradient(145deg,#181818,#0b0b0b)}.pr-plan.featured{border-color:#aaa;box-shadow:inset 0 0 0 1px #ffffff10}.pr-plan h3{font-size:14px;margin:8px 0}.pr-plan .price{font-size:23px;font-weight:900}.pr-plan p{font-size:11px;color:#999;line-height:1.8;min-height:40px}.pr-plan button,.pr-shop-cta{width:100%;border:1px solid #eee;border-radius:12px;padding:11px;background:#eee;color:#080808;font-weight:900;cursor:pointer;margin-top:10px}.pr-plan button.secondary{background:#171717;color:#eee;border-color:#3b3b3b}
.pr-perks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.pr-perk{padding:12px;border:1px solid #292929;border-radius:13px;background:#101010}.pr-perk b{display:block;font-size:12px;margin:7px 0 4px}.pr-perk span{font-size:10px;color:#999;line-height:1.7}
.pr-picker-tabs{display:flex;gap:7px;margin:12px 0}.pr-picker-tabs button{flex:1;border:1px solid #333;background:#111;color:#eee;padding:9px;border-radius:11px;cursor:pointer}.pr-picker-tabs button.active{background:#eee;color:#111}
.pr-emoji-grid{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:4px}.pr-emoji-grid button{background:#151515;border:1px solid #292929;border-radius:10px;padding:7px 0;font-size:23px;cursor:pointer}.pr-sticker-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.pr-sticker{min-height:92px;background:linear-gradient(145deg,#202020,#101010);border:1px solid #343434;border-radius:15px;color:white;font-size:34px;cursor:pointer}.pr-sticker small{display:block;font-size:10px;color:#aaa;margin-top:4px}
.pr-message-sticker{font-size:64px;line-height:1.2;padding:8px 12px;min-width:88px;min-height:82px;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at 30% 20%,#ffffff12,transparent 55%),linear-gradient(145deg,#1e1e1e,#0c0c0c);border:1px solid #ffffff16;border-radius:20px;filter:drop-shadow(0 8px 18px #0005)}
.pr-badge{display:inline-block;border:1px solid #555;border-radius:999px;padding:4px 8px;font-size:10px;color:#ddd}
@keyframes prShine{0%,100%{box-shadow:0 0 0 #fff0}50%{box-shadow:0 0 24px #fff2}}
.pr-pro-shop{animation:prShine 4s ease-in-out infinite}
@media(max-width:520px){.pr-plan-grid{grid-template-columns:1fr}.pr-emoji-grid{grid-template-columns:repeat(7,minmax(0,1fr))}.pr-premium-hero h2{font-size:24px}}



/* ═══════════ RANGO: CINEMATIC ULTRA VISUAL EXPERIENCE ═══════════ */
:root{
 --pr-white:#f8f8f8;--pr-silver:#bfc3c7;--pr-line:rgba(255,255,255,.105);
 --pr-glass:rgba(17,17,17,.82);--pr-glow:rgba(255,255,255,.12);
}
html{background:#050505}
body{position:relative;isolation:isolate;background:#050505!important}
body:before{content:"";position:fixed;inset:-25%;z-index:-2;pointer-events:none;background:
 radial-gradient(ellipse at 18% 18%,rgba(255,255,255,.085),transparent 27%),
 radial-gradient(ellipse at 82% 75%,rgba(180,180,180,.065),transparent 29%),
 radial-gradient(ellipse at 52% 110%,rgba(255,255,255,.045),transparent 35%),#050505;
 animation:prAmbient 18s ease-in-out infinite alternate;transform:translateZ(0)}
body:after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.22;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:48px 48px;mask-image:radial-gradient(ellipse at center,#000 10%,transparent 82%)}
.tg-app{gap:0;padding:9px;overflow:hidden;background:transparent;animation:prAppEnter .65s cubic-bezier(.2,.8,.2,1) both}
.folder-rail{margin:0 5px 0 0;border:1px solid var(--pr-line)!important;border-radius:23px;background:linear-gradient(180deg,rgba(25,25,25,.92),rgba(7,7,7,.96))!important;box-shadow:0 18px 55px #0008,inset 0 1px #ffffff0d;backdrop-filter:blur(24px);padding-top:18px;gap:13px}
.folder-icon{position:relative;border:1px solid transparent;transition:transform .28s cubic-bezier(.2,.8,.2,1),background .28s,color .28s,box-shadow .28s;overflow:hidden}
.folder-icon:before{content:"";position:absolute;inset:0;border-radius:inherit;background:linear-gradient(135deg,#ffffff20,transparent 60%);opacity:0;transition:opacity .25s}
.folder-icon:hover{transform:translateY(-3px) scale(1.055);background:#242424!important;color:#fff!important;border-color:#ffffff20;box-shadow:0 8px 22px #0008}
.folder-icon:hover:before,.folder-icon.active:before{opacity:1}
.folder-icon.active{background:linear-gradient(145deg,#f4f4f4,#a7a7a7)!important;color:#080808!important;border-color:#fff;box-shadow:0 5px 25px #ffffff22,inset 0 1px #fff}
.sidebar{position:relative;overflow:hidden;margin:0 5px;border:1px solid var(--pr-line)!important;border-radius:24px;background:linear-gradient(160deg,rgba(21,21,21,.97),rgba(8,8,8,.96))!important;box-shadow:0 22px 65px #0008,inset 0 1px #ffffff0b;backdrop-filter:blur(26px)}
.sidebar:after{content:"";position:absolute;left:-65px;top:-100px;width:210px;height:210px;border-radius:50%;background:#fff;filter:blur(100px);opacity:.045;pointer-events:none}
.sidebar>div:first-child{position:relative!important;background:linear-gradient(120deg,#202020,#0b0b0b)!important;border-bottom:1px solid #ffffff10!important;padding:17px!important}
.sidebar>div:first-child>div:first-child>div:first-child{background:linear-gradient(145deg,#fff,#9a9a9a)!important;color:#080808;box-shadow:0 0 0 5px #ffffff08,0 9px 30px #fff2!important;animation:prLogoFloat 5s ease-in-out infinite}
.sidebar>div:first-child span{color:#fff!important}
.sidebar>div:first-child button{background:#151515!important;color:#eee!important;border-color:#444!important;transition:all .22s}
.sidebar>div:first-child button:hover{background:#fff!important;color:#080808!important;transform:translateY(-2px)}
.sidebar-header{background:transparent!important;border-color:#ffffff0e!important;padding:14px!important}
.search-container{height:43px!important;border:1px solid #ffffff12!important;border-radius:15px!important;background:#080808!important;transition:all .25s;box-shadow:inset 0 1px #ffffff06}
.search-container:focus-within{border-color:#888!important;box-shadow:0 0 0 4px #ffffff08,0 8px 24px #0005;transform:translateY(-1px)}
.pr-top-actions{background:transparent!important;border-color:#ffffff0a!important;padding:2px 13px 14px!important}
.pr-pro-shop{position:relative;isolation:isolate;overflow:hidden;border:1px solid #555!important;border-radius:17px!important;background:linear-gradient(115deg,#292929,#111 55%,#1c1c1c)!important;box-shadow:0 10px 32px #0008,inset 0 1px #ffffff16!important;transition:transform .28s,box-shadow .28s,border-color .28s!important}
.pr-pro-shop:before{content:"";position:absolute;inset:-60% auto -60% -35%;width:30%;transform:rotate(20deg);background:linear-gradient(90deg,transparent,#ffffff20,transparent);animation:prSweep 5s ease-in-out infinite;z-index:-1}
.pr-pro-shop:hover{transform:translateY(-3px) scale(1.012)!important;border-color:#aaa!important;box-shadow:0 16px 36px #000b,0 0 28px #ffffff0c!important}
.pr-crown{background:linear-gradient(145deg,#fff,#a3a3a3)!important;box-shadow:0 0 0 4px #ffffff08,0 0 30px #ffffff18!important;animation:prCrownPulse 3s ease-in-out infinite}
.chat-list{padding:4px 5px 12px;scrollbar-width:thin;scrollbar-color:#484848 transparent}
.chat-row{position:relative;isolation:isolate;overflow:hidden;margin:4px 5px!important;padding:12px 12px!important;border:1px solid transparent!important;border-radius:16px!important;animation:prRowIn .38s both;transition:transform .24s,background .24s,border-color .24s,box-shadow .24s!important}
.chat-row:before{content:"";position:absolute;inset:0;z-index:-1;background:linear-gradient(105deg,#ffffff0b,transparent 58%);opacity:0;transition:opacity .25s}
.chat-row:hover{transform:translateX(-4px) scale(1.008)!important;background:#1b1b1b!important;border-color:#ffffff12!important;box-shadow:0 8px 24px #0005}
.chat-row:hover:before{opacity:1}
.chat-row.active{background:linear-gradient(105deg,#292929,#141414)!important;border-color:#555!important;box-shadow:inset -3px 0 #fff,0 8px 25px #0005!important}
.avatar{position:relative;overflow:hidden;border:1px solid #ffffff22!important;background:linear-gradient(145deg,#555,#171717)!important;box-shadow:0 5px 18px #0008,inset 0 1px #ffffff18!important;transition:transform .28s,box-shadow .28s!important}
.chat-row:hover .avatar{transform:rotate(-5deg) scale(1.06);box-shadow:0 0 0 4px #ffffff08,0 8px 24px #0009!important}
.chat-main{position:relative;overflow:hidden;border:1px solid var(--pr-line)!important;border-radius:24px!important;background:rgba(7,7,7,.91)!important;box-shadow:0 22px 70px #0009,inset 0 1px #ffffff08;backdrop-filter:blur(24px)}
.chat-main:before{content:"";position:absolute;inset:0;pointer-events:none;z-index:0;opacity:.24;background:radial-gradient(ellipse at 50% 0%,#ffffff12,transparent 45%),linear-gradient(135deg,transparent 35%,#ffffff03 50%,transparent 65%);background-size:auto,220% 220%;animation:prSurfaceDrift 20s ease infinite}
.chat-main>*{position:relative;z-index:1}
.chat-topbar{height:74px!important;padding:12px 19px!important;background:linear-gradient(110deg,rgba(22,22,22,.97),rgba(9,9,9,.96))!important;border-bottom:1px solid #ffffff12!important;box-shadow:0 8px 30px #0004}
.chat-topbar-info{border-radius:15px;padding:3px;transition:transform .22s,opacity .22s}
.chat-topbar-info:hover{transform:translateX(-2px);opacity:1!important}
#chatTitle{letter-spacing:-.3px}
#chatStatus{color:#999!important}
.chat-messages{position:relative;background:transparent!important;background-image:radial-gradient(ellipse at 50% 45%,#ffffff07,transparent 63%)!important;scrollbar-width:thin;scrollbar-color:#444 transparent}
.message-bubble{position:relative;overflow:hidden;padding:12px 15px!important;border:1px solid #ffffff14!important;border-radius:19px!important;box-shadow:0 10px 28px #0005,inset 0 1px #ffffff09!important;backdrop-filter:blur(12px);transition:transform .2s,box-shadow .2s;animation:prMessageIn .38s cubic-bezier(.2,.8,.2,1) both!important}
.message-bubble:after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(115deg,#ffffff08,transparent 42%);opacity:.7}
.message-bubble:hover{transform:translateY(-2px);box-shadow:0 14px 34px #0007,inset 0 1px #ffffff0d!important}
.message-bubble.mine{background:linear-gradient(145deg,#303030,#191919)!important;border-bottom-right-radius:6px!important}
.message-bubble:not(.mine){background:linear-gradient(145deg,#1b1b1b,#101010)!important;border-bottom-left-radius:6px!important}
.chat-composer{position:relative;gap:9px!important;margin:11px!important;padding:10px!important;border:1px solid #ffffff17!important;border-radius:22px!important;background:linear-gradient(145deg,rgba(25,25,25,.97),rgba(9,9,9,.98))!important;box-shadow:0 15px 40px #0008,inset 0 1px #ffffff0a!important;transition:border-color .25s,box-shadow .25s}
.chat-composer:focus-within{border-color:#777!important;box-shadow:0 0 0 4px #ffffff08,0 18px 50px #000b,inset 0 1px #ffffff12!important}
.composer-input{min-height:42px!important;max-height:150px!important;padding:11px 13px!important;border-radius:15px!important;background:#080808!important;border:1px solid #ffffff10!important;color:#fff!important;transition:border-color .2s,background .2s!important}
.composer-input::placeholder{color:#777!important}
.pr-tool-btn,.action-btn{position:relative;overflow:hidden;background:linear-gradient(145deg,#1c1c1c,#0d0d0d)!important;border:1px solid #ffffff15!important;color:#eee!important;box-shadow:inset 0 1px #ffffff08;transition:transform .22s,background .22s,border-color .22s,box-shadow .22s!important}
.pr-tool-btn:after,.action-btn:after{content:"";position:absolute;inset:0;background:linear-gradient(135deg,#ffffff12,transparent 65%);opacity:0;transition:opacity .2s}
.pr-tool-btn:hover,.action-btn:hover{transform:translateY(-3px) scale(1.035)!important;background:#292929!important;border-color:#777!important;box-shadow:0 9px 23px #0008,0 0 20px #ffffff08!important}
.pr-tool-btn:hover:after,.action-btn:hover:after{opacity:1}
.chat-composer button[type="submit"]{background:linear-gradient(145deg,#fff,#bdbdbd)!important;color:#050505!important;border-color:#fff!important;box-shadow:0 6px 22px #ffffff15!important}
.chat-composer button[type="submit"]:hover{box-shadow:0 8px 30px #ffffff2b!important}
.modal-overlay{background:rgba(0,0,0,.76)!important;backdrop-filter:blur(18px) saturate(.6)!important;animation:prFade .2s ease both}
.modal-card{position:relative;overflow:hidden;background:linear-gradient(145deg,#1b1b1b,#080808)!important;border:1px solid #ffffff22!important;border-radius:26px!important;box-shadow:0 35px 110px #000e,inset 0 1px #ffffff10!important;animation:prModalIn .35s cubic-bezier(.2,.8,.2,1) both!important}
.modal-card:before{content:"";position:absolute;top:0;left:12%;right:12%;height:1px;background:linear-gradient(90deg,transparent,#fff7,transparent);pointer-events:none}
.system-notice{background:linear-gradient(145deg,#1c1c1c,#080808)!important;border-color:#ffffff20!important;box-shadow:0 28px 80px #000b,inset 0 1px #ffffff0c!important}
.pr-premium-hero{background:radial-gradient(ellipse at 90% 0%,#ffffff24,transparent 42%),linear-gradient(135deg,#242424,#080808 75%)!important;border-color:#666!important;box-shadow:0 18px 50px #0007,inset 0 1px #ffffff14}
.pr-premium-hero:after{animation:prHeroFloat 7s ease-in-out infinite}
.pr-plan{transition:transform .25s,border-color .25s,box-shadow .25s!important}
.pr-plan:hover{transform:translateY(-5px);border-color:#888!important;box-shadow:0 16px 35px #0009,0 0 25px #ffffff07!important}
.pr-plan.featured{background:linear-gradient(145deg,#242424,#0b0b0b)!important;border-color:#aaa!important}
.pr-perk{transition:transform .22s,border-color .22s,background .22s}
.pr-perk:hover{transform:translateY(-3px);border-color:#777;background:#171717}
.pr-emoji-grid button,.pr-sticker{transition:transform .2s,background .2s,border-color .2s,box-shadow .2s!important}
.pr-emoji-grid button:hover,.pr-sticker:hover{transform:translateY(-4px) scale(1.07)!important;background:#303030!important;border-color:#888!important;box-shadow:0 10px 25px #0008,0 0 20px #ffffff08!important}
.pr-message-sticker{animation:prStickerPop .42s cubic-bezier(.16,1,.3,1) both;box-shadow:0 15px 35px #0007,inset 0 1px #ffffff12!important}
button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid #aaa!important;outline-offset:3px}
::-webkit-scrollbar{width:7px;height:7px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#383838;border-radius:99px;border:2px solid transparent;background-clip:padding-box}::-webkit-scrollbar-thumb:hover{background:#666;background-clip:padding-box}
@keyframes prAmbient{0%{transform:translate3d(-1.5%,0,0) scale(1)}100%{transform:translate3d(1.5%,-1%,0) scale(1.04)}}
@keyframes prAppEnter{from{opacity:0;transform:translateY(12px) scale(.99);filter:blur(5px)}to{opacity:1;transform:translateY(0) scale(1);filter:blur(0)}}
@keyframes prLogoFloat{0%,100%{transform:translateY(0) rotate(0)}50%{transform:translateY(-3px) rotate(2deg)}}
@keyframes prSweep{0%,62%,100%{left:-45%;opacity:0}68%{opacity:1}86%{left:125%;opacity:0}}
@keyframes prCrownPulse{0%,100%{box-shadow:0 0 0 4px #ffffff08,0 0 18px #ffffff10}50%{box-shadow:0 0 0 5px #ffffff0c,0 0 32px #ffffff25}}
@keyframes prRowIn{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}
@keyframes prMessageIn{from{opacity:0;transform:translateY(10px) scale(.985);filter:blur(2px)}to{opacity:1;transform:translateY(0) scale(1);filter:blur(0)}}
@keyframes prSurfaceDrift{0%,100%{background-position:center,0% 50%}50%{background-position:center,100% 50%}}
@keyframes prModalIn{from{opacity:0;transform:translateY(14px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes prFade{from{opacity:0}to{opacity:1}}
@keyframes prHeroFloat{0%,100%{transform:translateY(0) rotate(0)}50%{transform:translateY(-12px) rotate(3deg)}}
@keyframes prStickerPop{0%{opacity:0;transform:scale(.55) rotate(-8deg)}70%{opacity:1;transform:scale(1.08) rotate(2deg)}100%{transform:scale(1) rotate(0)}}
@media(max-width:768px){
 .tg-app{padding:0!important;gap:0!important}.folder-rail{margin:0!important;border-radius:0 0 0 0!important;border-top:0!important;border-bottom:0!important}.sidebar{margin:0!important;border-radius:0!important;border-top:0!important;border-bottom:0!important}.chat-main{border-radius:0!important;border:0!important}.chat-topbar{height:68px!important;padding:10px 12px!important}.chat-composer{margin:7px!important;padding:8px!important;border-radius:18px!important}.message-bubble{max-width:88%!important}.sidebar>div:first-child{padding:13px!important}
}
@media(max-width:420px){.folder-rail{width:48px!important;padding-inline:3px!important}.folder-icon{width:38px;height:38px;font-size:18px}.sidebar{width:min(292px,calc(100vw - 48px))!important}.pr-tool-btn{width:34px!important;height:37px!important;font-size:17px!important}.chat-composer{gap:5px!important}.composer-input{font-size:13px!important}}
@media(prefers-reduced-motion:reduce){body:before,.sidebar>div:first-child>div:first-child>div:first-child,.pr-pro-shop:before,.pr-crown,.chat-row,.message-bubble,.pr-message-sticker,.modal-card{animation:none!important}*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}

</style>
</head>
<body>

<style id="pr-mobile-fix-and-polish">
html,body{width:100%;max-width:100%;overflow:hidden}body{overscroll-behavior:none}.tg-app{width:100%;max-width:100%;min-width:0;overflow:hidden;gap:0}.sidebar,.chat-main,.folder-rail{min-width:0}.sidebar-header>*,.chat-topbar>*,.chat-composer>*{min-width:0}.pr-top-actions{flex-wrap:wrap}.pr-pro-shop{max-width:100%;min-width:0}.pr-pro-shop *{overflow-wrap:anywhere}.chat-row,.chat-topbar-info,.message-bubble{overflow-wrap:anywhere}
@media(max-width:768px){
 .tg-app{display:block!important;padding:0!important;width:100vw!important;height:100dvh!important;overflow:hidden!important}
 .folder-rail{display:flex!important;position:absolute!important;right:0!important;top:0!important;bottom:0!important;width:54px!important;height:100dvh!important;padding:16px 5px!important;gap:13px!important;align-items:center!important;justify-content:flex-start!important;background:linear-gradient(180deg,#111315,#070808)!important;border-left:1px solid #292929!important;z-index:18!important;box-shadow:-8px 0 26px #0005!important}
 .folder-icon{width:42px!important;height:42px!important;min-width:42px!important;border-radius:15px!important;font-size:20px!important;border:1px solid #ffffff0c!important;background:#171819!important;color:#aeb4b8!important}
 .folder-icon.active{background:linear-gradient(145deg,#f8f8f8,#aaa)!important;color:#090909!important;box-shadow:0 0 20px #ffffff22!important}
 .sidebar{display:flex!important;position:absolute!important;inset:0!important;right:54px!important;left:0!important;top:0!important;width:calc(100% - 54px)!important;max-width:calc(100% - 54px)!important;height:100%!important;height:100dvh!important;transform:none!important;border:0!important;border-radius:0!important;z-index:10!important}
 .chat-main{display:flex!important;position:absolute!important;inset:0!important;right:0!important;left:0!important;width:100%!important;max-width:100%!important;height:100%!important;height:100dvh!important;transform:translateX(105%)!important;z-index:30!important;transition:transform .28s cubic-bezier(.2,.8,.2,1)!important}
 .chat-main.mobile-active{transform:translateX(0)!important}
 .sidebar.mobile-hidden{display:none!important}
 .sidebar-header{padding:12px!important;min-height:66px!important}
 .pr-top-actions{padding:9px 11px!important}
 .pr-pro-shop{padding:12px!important}
 .chat-topbar{padding:8px 10px!important;min-width:0!important}
 .chat-topbar-info{flex:1;overflow:hidden}
 .chat-topbar-info>*{min-width:0}
 .chat-messages{padding:12px 10px!important;min-width:0!important}
 .chat-composer{margin:5px!important;padding:7px!important;gap:4px!important;max-width:calc(100% - 10px)!important}
 .composer-input{min-width:0!important;width:100%!important}
 .pr-tool-btn{flex:0 0 35px!important;width:35px!important;height:37px!important}
 .modal-card{width:min(440px,calc(100vw - 24px))!important;max-width:calc(100vw - 24px)!important}
}
@media(max-width:380px){.folder-rail{width:48px!important;padding-inline:3px!important}.sidebar{right:48px!important;width:calc(100% - 48px)!important;max-width:calc(100% - 48px)!important}.pr-pro-shop small{font-size:9px}.pr-crown{width:31px;height:31px}.chat-composer{gap:2px!important}.pr-tool-btn{flex-basis:32px!important;width:32px!important;font-size:16px!important}.action-btn{font-size:18px!important;padding:3px!important}}
@media(prefers-reduced-motion:reduce){.auth-live-badge span,.auth-submit{animation:none!important}}
/* FINAL POLISH: mobile-first layout, clearer hierarchy, premium controls */
:root{--pr-glow:0 0 28px #ffffff0b}
*{box-sizing:border-box}
html,body{max-width:100%;overflow-x:hidden!important}
button,input,textarea{font:inherit}
button{ -webkit-tap-highlight-color:transparent }
.tg-app{isolation:isolate;background:radial-gradient(ellipse at 50% -20%,#ffffff0b,transparent 55%),#070707!important}
.folder-rail{background:linear-gradient(180deg,#111,#080808)!important;border-color:#ffffff12!important}
.sidebar{background:linear-gradient(180deg,#111111f5,#080808f8)!important;border-color:#ffffff14!important;box-shadow:20px 0 60px #0004}
.chat-main{background:radial-gradient(ellipse at 50% 0%,#ffffff07,transparent 45%),#080808!important;border-color:#ffffff13!important}
.chat-topbar{background:#0b0b0beF!important;border-bottom:1px solid #ffffff12!important;backdrop-filter:blur(18px)}
.chat-composer{border:1px solid #ffffff18!important;background:linear-gradient(145deg,#171717,#0b0b0b)!important;box-shadow:0 12px 36px #0007,inset 0 1px #ffffff08!important}
.composer-input{outline:none!important}
.chat-row{border:1px solid transparent!important;transition:background .2s,border-color .2s,transform .2s!important}
.chat-row:hover{background:#ffffff08!important;border-color:#ffffff10!important;transform:translateX(-2px)}
.chat-row.active{background:linear-gradient(100deg,#ffffff12,#ffffff05)!important;border-color:#ffffff16!important}
.action-btn,.pr-tool-btn{transition:transform .18s,background .18s,border-color .18s!important}
.action-btn:active,.pr-tool-btn:active,button:active{transform:scale(.96)}
.pr-pro-shop{position:relative;overflow:hidden;border:1px solid #ffffff24!important;background:linear-gradient(120deg,#222,#101010 55%,#1a1a1a)!important;box-shadow:var(--pr-glow),inset 0 1px #ffffff0c!important}
.pr-pro-shop:after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(110deg,transparent 20%,#ffffff0b 48%,transparent 70%);transform:translateX(-120%);animation:prFinalShine 7s ease-in-out infinite}
@keyframes prFinalShine{0%,65%,100%{transform:translateX(-120%)}85%{transform:translateX(120%)}}
.message-bubble{overflow-wrap:anywhere;word-break:break-word;box-shadow:0 8px 25px #0003}
img,video,canvas,svg{max-width:100%}
.modal-overlay{padding:12px!important;overflow-y:auto!important}
.modal-card{max-height:calc(100dvh - 24px)!important;overflow-y:auto!important}
@media(max-width:768px){
 body{padding:0!important;margin:0!important;width:100%!important;min-width:0!important}
 .tg-app{position:fixed!important;inset:0!important;width:100vw!important;height:100dvh!important;max-width:100vw!important;min-width:0!important;display:block!important;padding:0!important;margin:0!important;overflow:hidden!important}
 .sidebar,.chat-main{box-sizing:border-box!important;min-width:0!important;max-width:100vw!important}
 .sidebar{padding-bottom:env(safe-area-inset-bottom)!important}
 .chat-main{padding-bottom:env(safe-area-inset-bottom)!important}
 .chat-messages{min-width:0!important;overflow-x:hidden!important}
 .chat-topbar{gap:7px!important}
 .chat-topbar-info{min-width:0!important;flex:1 1 auto!important}
 .chat-topbar-info h3,.chat-topbar-info div{overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
 .chat-composer{width:calc(100% - 12px)!important;box-sizing:border-box!important}
 .composer-input{flex:1 1 30px!important;min-width:0!important}
 .pr-emoji-grid{grid-template-columns:repeat(7,minmax(0,1fr))!important}
}
@media(max-width:390px){
 .sidebar-header{padding:10px!important}
 .pr-top-actions{padding:7px!important}
 .pr-pro-shop{gap:8px!important;padding:10px!important}
 .pr-pro-shop small{line-height:1.5!important}
 .chat-composer{gap:3px!important}
 .pr-tool-btn{flex:0 0 31px!important;width:31px!important;height:34px!important;padding:0!important}
 .message-bubble{max-width:90%!important;font-size:14px!important}
}
@media(prefers-reduced-motion:reduce){.pr-pro-shop:after{animation:none!important}}
</style>
<style id="pr-reference-mobile-navigation">
.pr-bottom-nav{display:none}
@media(max-width:768px){
 body.pr-chat-open .pr-bottom-nav{display:none!important}
 .pr-bottom-nav{position:fixed;z-index:80;left:12px;right:12px;bottom:calc(9px + env(safe-area-inset-bottom));height:76px;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:3px;padding:6px;background:rgba(28,28,28,.94);border:1px solid rgba(255,255,255,.08);border-radius:28px;box-shadow:0 12px 45px #0009,inset 0 1px #ffffff0c;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}
 .pr-nav-item{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;min-width:0;border:0;border-radius:22px;background:transparent;color:#b7b7b7;font:inherit;cursor:pointer;transition:background .22s,color .22s,transform .22s}
 .pr-nav-item>span{font-size:27px;line-height:1.05;font-weight:400}.pr-nav-item>b{font-size:11px;font-weight:650;white-space:nowrap}.pr-nav-item.active{background:#383633;color:#f7eadb;box-shadow:inset 0 1px #ffffff0b}.pr-nav-item:active{transform:scale(.94)}
 .pr-nav-item i{position:absolute;top:6px;right:calc(50% - 25px);font-size:8px;font-style:normal;color:#e8d1b9;background:#b49a82;border:2px solid #383633;border-radius:20px;min-width:15px;height:15px;display:grid;place-items:center}
 .pr-nav-item:not([data-view="chats"]) i{display:none}.pr-nav-avatar{width:27px;height:27px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#bfa38a,#665246);color:white!important;font-size:16px!important}
 .tg-app{padding-bottom:96px!important}.sidebar{padding-bottom:94px!important}.chat-list{padding-bottom:96px!important}.chat-main{padding-bottom:86px!important}.chat-composer{margin-bottom:8px!important}.chat-messages{padding-bottom:24px!important}
 .folder-rail{display:none!important}.sidebar{right:0!important;left:0!important;width:100%!important;max-width:100%!important;border-radius:0!important}.sidebar.mobile-hidden{display:none!important}
 .chat-main{display:none!important}.chat-main.mobile-active{display:flex!important;position:fixed!important;z-index:35!important;inset:0!important;width:100vw!important;height:100dvh!important;padding-bottom:0!important}
 body.pr-profile-view .tg-app{pointer-events:none;opacity:.72}
}
@media(min-width:769px){.pr-bottom-nav{display:none!important}}
</style>

<style id="pr-screen-design-system">
.pr-screen-head,.pr-profile-top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.pr-eyebrow{font-size:10px;letter-spacing:2px;color:#b8a18c;font-weight:800}.pr-screen-head h2{font-size:25px;margin:5px 0}.pr-screen-head p{color:#999;font-size:12px;line-height:1.8;margin:0 0 14px}.pr-close-round{width:34px;height:34px;border:1px solid #ffffff18;border-radius:50%;background:#ffffff09;color:#eee;font-size:22px;cursor:pointer}.pr-search-field{width:100%;box-sizing:border-box;padding:14px 16px;border:1px solid #ffffff13;border-radius:17px;background:#ffffff08;color:#fff;outline:none;font:inherit}.pr-search-field:focus{border-color:#b49a82;box-shadow:0 0 0 3px #b49a821c}.pr-contact-results{display:flex;flex-direction:column;gap:5px;max-height:min(55vh,480px);overflow:auto;margin-top:12px}.pr-contact-row{display:flex;align-items:center;gap:12px;width:100%;padding:11px;border:1px solid transparent;border-radius:16px;background:#ffffff05;color:#eee;text-align:right;cursor:pointer}.pr-contact-row:hover{background:#ffffff0b;border-color:#ffffff10}.pr-contact-avatar{width:46px;height:46px;flex:0 0 46px;display:grid;place-items:center;border-radius:50%;background-color:#66564a;background-size:cover;background-position:center;font-size:20px}.pr-contact-copy{display:flex;flex-direction:column;gap:5px;min-width:0;flex:1}.pr-contact-copy b{font-size:14px}.pr-contact-copy small{font-size:11px;color:#999}.pr-contact-go{font-size:20px;color:#b49a82}.pr-empty-state{text-align:center;color:#999;padding:25px 10px;font-size:13px;line-height:1.9}.pr-profile-hero{margin:-5px -5px 14px;padding:20px 17px 17px;border-radius:22px;background:radial-gradient(circle at 50% 0,#a47b5238,transparent 50%),linear-gradient(145deg,#30251f,#151515 75%);text-align:center;border:1px solid #ffffff0d}.pr-profile-top{text-align:right}.pr-profile-avatar{width:108px;height:108px;margin:14px auto 12px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#c4a58a,#5b4638);border:4px solid #ffffff17;box-shadow:0 10px 35px #0007;font-size:42px}.pr-profile-hero h2{font-family:Georgia,serif;font-size:29px;margin:0 0 5px}.pr-profile-handle{font-size:13px;color:#a9a9a9}.pr-online-pill{display:inline-flex;align-items:center;gap:6px;margin-top:12px;padding:6px 11px;border-radius:99px;background:#ffffff0b;color:#d2c2b2;font-size:11px}.pr-online-pill i{width:6px;height:6px;border-radius:50%;background:#68d391}.pr-profile-actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:20px}.pr-profile-actions button{display:flex;flex-direction:column;align-items:center;gap:8px;padding:12px 5px;border:1px solid #ffffff0b;border-radius:15px;background:#ffffff08;color:#eee;font:inherit;font-size:11px;cursor:pointer}.pr-profile-actions button span{font-size:22px}.pr-profile-details{display:flex;flex-direction:column;gap:0}.pr-profile-details>div{padding:13px 5px;border-bottom:1px solid #ffffff0d;display:flex;flex-direction:column;gap:6px}.pr-profile-details small{color:#888;font-size:11px}.pr-profile-details b{font-weight:500;font-size:14px;overflow-wrap:anywhere}.pr-logout-btn{width:100%;padding:13px;margin-top:14px;border:1px solid #8d34342c;border-radius:14px;background:#8d343414;color:#e9a0a0;font:inherit;cursor:pointer}
.pr-profile-hero{transition:background .35s ease,transform .25s;animation:prProfileIn .42s cubic-bezier(.2,.8,.2,1)}
@keyframes prProfileIn{from{opacity:0;transform:translateY(9px) scale(.985)}to{opacity:1;transform:none}}
.pr-profile-avatar{transition:background .25s,transform .25s,box-shadow .25s}.pr-profile-avatar:active{transform:scale(.96)}
.pr-color-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:14px 0 18px}
.pr-color-swatch{height:36px;border-radius:12px;border:2px solid #ffffff25;box-shadow:inset 0 1px #ffffff30,0 4px 12px #0003;cursor:pointer;transition:transform .18s,box-shadow .18s;position:relative}
.pr-color-swatch:hover{transform:translateY(-3px) scale(1.04)}.pr-color-swatch.selected{outline:2px solid #fff;outline-offset:2px;box-shadow:0 0 0 5px #ffffff12}
.pr-chat-menu{position:fixed;z-index:100001;min-width:220px;padding:7px;border:1px solid #ffffff18;border-radius:18px;background:rgba(24,24,24,.97);box-shadow:0 18px 60px #000a;backdrop-filter:blur(22px);animation:prMenuIn .16s ease-out}
@keyframes prMenuIn{from{opacity:0;transform:translateY(7px) scale(.97)}to{opacity:1;transform:none}}
.pr-chat-menu button{display:flex;align-items:center;gap:10px;width:100%;padding:12px;border:0;border-radius:12px;background:transparent;color:#eee;font:inherit;text-align:right;cursor:pointer;transition:background .16s,transform .16s}
.pr-chat-menu button:hover{background:#ffffff10;transform:translateX(-2px)}.pr-chat-menu button.danger{color:#ff9b9b}
.pr-settings-section{margin:14px 0;padding:14px;border:1px solid var(--border-color);border-radius:16px;background:var(--panel-bg)}.pr-settings-section h4{margin:0 0 12px;font-size:14px}.pr-setting-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;color:var(--text-main,white);font-size:13px}.pr-setting-row+.pr-setting-row{border-top:1px solid var(--border-color)}.pr-setting-row input[type=checkbox]{accent-color:#b49a82;width:19px;height:19px}
.chat-row.pr-pinned:after{content:'📌';position:absolute;left:12px;bottom:8px;font-size:11px;opacity:.85}

</style>

<div class="tg-app">
  <div class="folder-rail">
    <div class="folder-icon active" onclick="switchFolder('all')">💬</div>
    <div class="folder-icon" onclick="openProfileModal()" title="پروفایل من">👤</div>
    <div class="folder-icon" onclick="openAppSettings()" title="تنظیمات و تم‌ها">🎨</div>
  </div>

  <aside class="sidebar" id="sidebarPanel">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 17px 4px;background:linear-gradient(135deg,#14253a,#101a29);">
      <div style="display:flex;align-items:center;gap:10px;min-width:0;">
        <div style="width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#43c6ff,#635bff);box-shadow:0 5px 18px #43c6ff30;font-size:20px;">✦</div>
        <div><div style="font-weight:800;letter-spacing:.2px;font-size:15px;">Rango <span style="color:#43c6ff">Pro</span></div><div style="font-size:10px;color:#91a8c0;">PRIVATE MESSENGER · <span style="color:#ddd">✦ PRO</span></div></div>
      </div>
      <button type="button" title="حساب فعلی و مدیریت حساب‌ها" onclick="accountInfo()" style="border:1px solid #30465f;background:#0b1421;color:#a9c9e8;border-radius:11px;padding:8px 10px;cursor:pointer;">👤 حساب</button>
    </div>
    <div class="sidebar-header">
      <div class="search-container">
        <input id="searchInput" placeholder="جستجو آیدی..." oninput="searchUsers()">
        <div class="pr-quick-actions" style="display:flex;gap:6px;margin-top:7px"><button type="button" onclick="searchMessagesScreen()" style="flex:1;padding:7px 5px;font-size:11px;border-radius:10px;background:#292929;color:#eee;border:1px solid #ffffff12">🔎 پیام‌ها</button><button type="button" onclick="showArchivedChats()" style="flex:1;padding:7px 5px;font-size:11px;border-radius:10px;background:#292929;color:#eee;border:1px solid #ffffff12">📦 بایگانی</button></div>
      </div>
    </div>
    <div class="pr-top-actions"><button type="button" class="pr-story-launch" onclick="openStories()">⭕ استوری</button><button class="pr-pro-shop" type="button" onclick="openPremiumShop()"><span><b>✦ عضویت PRO MAX</b><small>استیکرهای خاص • ظاهر لوکس • قابلیت‌های ویژه</small></span><span class="pr-crown">♛</span></button></div>
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
      <div class="pr-composer-tools"><button type="button" class="pr-tool-btn" onclick="openEmojiPicker('emoji')" title="ایموجی">😊</button><button type="button" class="pr-tool-btn" onclick="openEmojiPicker('sticker')" title="استیکر">🧸</button></div>
      <input type="file" id="fileInput" hidden onchange="handleFileUpload(this)">
      <button type="button" class="action-btn" id="voiceBtn" onclick="toggleVoiceRecording()" title="ضبط پیام صوتی">🎙️</button>
      <textarea id="messageInput" class="composer-input" placeholder="نوشتن پیام..." oninput="notifyTyping()" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage(event)}"></textarea>
      <button type="submit" class="action-btn" style="color: var(--accent);">➤</button>
    </form>
  </main>
</div>

<nav class="pr-bottom-nav" aria-label="ناوبری اصلی">
  <button type="button" class="pr-nav-item active" data-view="chats" onclick="prNavigate('chats')"><span>☏</span><b>گفتگوها</b><i id="prUnreadBadge">●</i></button>
  <button type="button" class="pr-nav-item" data-view="contacts" onclick="prNavigate('contacts')"><span>◎</span><b>مخاطبین</b></button>
  <button type="button" class="pr-nav-item" data-view="settings" onclick="prNavigate('settings')"><span>⚙</span><b>تنظیمات</b></button>
  <button type="button" class="pr-nav-item" data-view="profile" onclick="prNavigate('profile')"><span class="pr-nav-avatar">✦</span><b>پروفایل</b></button>
</nav>

<div id="modalOverlay" class="modal-overlay hidden" onclick="if(event.target===this) closeModal()">
  <div class="modal-card" id="modalContent"></div>
</div>

<style id="pr-mobile-performance-polish">
@media(max-width:768px){
 html{height:100%;height:100dvh;overscroll-behavior:none;-webkit-text-size-adjust:100%}
 body{overscroll-behavior:none;-webkit-tap-highlight-color:transparent}
 .chat-main.mobile-active{display:flex!important;flex-direction:column!important;min-height:0!important;padding-bottom:env(safe-area-inset-bottom)!important}
 .chat-topbar{flex:0 0 auto!important;min-height:62px!important;padding-top:max(8px,env(safe-area-inset-top))!important}
 .chat-messages{flex:1 1 auto!important;min-height:0!important;overscroll-behavior:contain!important;scroll-behavior:auto!important;padding:14px 11px 18px!important;contain:layout paint style}
 .message-bubble{max-width:min(84%,420px)!important;border-radius:18px!important;line-height:1.7!important;box-shadow:0 2px 8px #0002!important}
 .message-bubble img{display:block;height:auto;max-height:42dvh!important;object-fit:contain!important}
 .chat-composer{flex:0 0 auto!important;width:calc(100% - 16px)!important;margin:7px 8px max(8px,env(safe-area-inset-bottom))!important;padding:7px!important;border-radius:22px!important;background:rgba(22,22,22,.97)!important;box-shadow:0 4px 18px #0004!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
 .composer-input{font-size:16px!important;line-height:1.45!important;min-height:42px!important;max-height:120px!important}
 .pr-bottom-nav{backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:0 6px 22px #0006!important}
 .pr-chat-menu{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
 .pr-chat-loading{min-height:38vh;display:flex;align-items:center;justify-content:center;gap:7px;flex-wrap:wrap;align-content:center;color:#a9a9a9;font-size:13px}
 .pr-chat-loading span{width:7px;height:7px;border-radius:50%;background:#b49a82;animation:prLoadDot 1s infinite ease-in-out}
 .pr-chat-loading span:nth-child(2){animation-delay:.15s}.pr-chat-loading span:nth-child(3){animation-delay:.3s}.pr-chat-loading small{flex-basis:100%;text-align:center;margin-top:8px;font-size:12px}
 @keyframes prLoadDot{0%,80%,100%{transform:translateY(0);opacity:.45}40%{transform:translateY(-5px);opacity:1}}
}
@media(prefers-reduced-motion:reduce){.pr-chat-loading span{animation:none!important}}
</style>
<style>.pr-admin-badge{display:inline-flex;align-items:center;gap:4px;margin-inline-start:6px;padding:2px 7px;border-radius:999px;background:linear-gradient(135deg,#d6bd8d,#8e7047);color:#17120c;font-size:10px;font-weight:900;vertical-align:middle;white-space:nowrap;box-shadow:0 0 12px #c9a66b33}.pr-admin-badge:before{content:"";position:absolute}</style>
<script>
window.PR_ADMIN_TELEGRAM_USERNAME = 'Pv_HE33AM';
function prAdminBadge(username){return String(username||'').replace(/^@/,'').toLowerCase()==='pv_he33am' ? '<span class="pr-admin-badge" title="مدیر رسمی پیام‌رسان">🛡️ ادمین</span>' : '';}
function prSetNav(view){document.querySelectorAll('.pr-nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view===view));}
function prNavigate(view){
 prSetNav(view);
 if(view==='chats'){document.body.classList.remove('pr-profile-view','pr-chat-open');$('chatMainPanel').classList.remove('mobile-active');$('sidebarPanel').classList.remove('mobile-hidden');activeUser=null;activeGroup=null;loadDialogs();return;}
 if(view==='settings'){openAppSettings();return;}
 if(view==='profile'){openProfileScreen();return;}
 if(view==='contacts'){openContactsScreen();return;}
}
async function openContactsScreen(){
 $('modalContent').innerHTML=`<div class="pr-screen-head"><div><div class="pr-eyebrow">YOUR PEOPLE</div><h2>مخاطبین</h2><p>با جست‌وجوی نام یا آیدی، گفتگو را شروع کن.</p></div><button class="pr-close-round" onclick="closeModal()">×</button></div><input id="prContactsSearch" class="pr-search-field" placeholder="🔎 جست‌وجوی نام یا آیدی..." oninput="searchContactsScreen()" autocomplete="off"><div id="prContactsResults" class="pr-contact-results"><div class="pr-empty-state">برای پیدا کردن افراد، نام یا آیدی را بنویس.</div></div>`;
 $('modalOverlay').classList.remove('hidden');setTimeout(()=>$('prContactsSearch')?.focus(),80);
}
async function searchContactsScreen(){const q=$('prContactsSearch')?.value.trim();const box=$('prContactsResults');if(!q){box.innerHTML='<div class="pr-empty-state">برای پیدا کردن افراد، نام یا آیدی را بنویس.</div>';return;}box.innerHTML='<div class="pr-empty-state">در حال جست‌وجو…</div>';try{const d=await api('/api/users?q='+encodeURIComponent(q));box.innerHTML=d.users.length?d.users.map(u=>`<button class="pr-contact-row" onclick="closeModal();openUserChat(${u.id},'${esc(u.display_name)}','${esc(u.username)}','${esc(u.avatar||'')}')"><span class="pr-contact-avatar" style="${u.avatar?`background-image:url('${esc(u.avatar)}')`:''}">${u.avatar?'':esc((u.display_name||'?').slice(0,1))}</span><span class="pr-contact-copy"><b>${esc(u.display_name)}${prAdminBadge(u.username)}</b><small>@${esc(u.username)} · ${u.online?'آنلاین':'کاربر پیام‌رسان'}</small></span><span class="pr-contact-go">↗</span></button>`).join(''):'<div class="pr-empty-state">کاربری پیدا نشد.</div>';}catch(e){box.innerHTML=`<div class="pr-empty-state">${esc(e.message||'جست‌وجو ناموفق بود')}</div>`;}}
const PR_PROFILE_COLORS=['#30251f','#452b3a','#26354f','#173f3a','#56352a','#4a3d70','#5b2630','#3d4148','#6b4c2a','#244a66','#36523b','#171717'];
function renderProfileColors(selected){return PR_PROFILE_COLORS.map(c=>`<button class="pr-color-swatch ${c.toLowerCase()===String(selected).toLowerCase()?'selected':''}" style="background:${c}" title="${c}" aria-label="انتخاب رنگ ${c}" onclick="saveProfileColor('${c}')"></button>`).join('')}
async function saveProfileColor(color){try{const d=await api('/api/settings');await api('/api/settings',{method:'POST',body:JSON.stringify({...d,profile_color:color})});const hero=document.querySelector('.pr-profile-hero');if(hero)hero.style.background=`radial-gradient(circle at 50% 0,${color}aa,transparent 58%),linear-gradient(145deg,${color},#111 82%)`;const grid=$('profileColorGrid');if(grid)grid.innerHTML=renderProfileColors(color);showToast('رنگ پس‌زمینهٔ پروفایل ذخیره شد 🎨')}catch(e){showToast(e.message||'ذخیره رنگ انجام نشد')}}
async function openProfileScreen(){try{const u=await api('/api/me');const avatar=u.avatar?`background-image:url('${esc(u.avatar)}');background-size:cover;background-position:center;`:'';const name=esc(u.display_name||u.username||'کاربر');$('modalContent').innerHTML=`<div class="pr-profile-hero"><div class="pr-profile-top"><span class="pr-eyebrow">YOUR SPACE · RANGO</span><button class="pr-close-round" onclick="closeModal()">×</button></div><div class="pr-profile-avatar" style="${avatar}">${u.avatar?'':'✦'}</div><h2>${name}${prAdminBadge(u.username)}</h2><div class="pr-profile-handle">@${esc(u.username||'')}</div><span class="pr-online-pill"><i></i> حساب فعال</span><div class="pr-profile-actions"><button onclick="closeModal();openProfileModal()"><span>📷</span>ویرایش اطلاعات</button><button onclick="closeModal();openAppSettings()"><span>⚙️</span>تنظیمات</button><button onclick="closeModal();openPremiumShop()"><span>👑</span>اشتراک PRO</button><button onclick="closeModal();openAdminPanel()"><span>🛡️</span>پنل ادمین</button></div></div><section class="pr-settings-section"><h4>🎨 رنگ پس‌زمینهٔ پروفایل</h4><div class="pr-color-grid" id="profileColorGrid">${renderProfileColors((await api('/api/settings')).profile_color||'#30251f')}</div><small style="color:#999">یکی از ۱۲ رنگ را انتخاب کن؛ انتخابت برای حسابت ذخیره می‌شود.</small></section><div class="pr-profile-details"><div><small>درباره من</small><b>${esc(u.bio||'هنوز توضیحی ثبت نشده است.')}</b></div><div><small>نام کاربری</small><b>@${esc(u.username||'—')}</b></div><div><small>وضعیت</small><b>فعال در پیام‌رسان</b></div></div><button class="pr-logout-btn" onclick="location.href='/logout'">↪ خروج از حساب</button>`;const ps=await api('/api/settings');if(ps.profile_color){const hero=document.querySelector('.pr-profile-hero');if(hero)hero.style.background=`radial-gradient(circle at 50% 0,${ps.profile_color}aa,transparent 58%),linear-gradient(145deg,${ps.profile_color},#111 82%)`;} $('modalOverlay').classList.remove('hidden');}catch(e){showToast(e.message||'بارگذاری پروفایل ناموفق بود');}}

const meId = {{me['id']}};
let activeUser = null;
let activeGroup = null;
const $ = id => document.getElementById(id);
function closeModal() {
  $('modalOverlay').classList.add('hidden');
  if (typeof window.__prDialogResolve === 'function') {
    const resolve = window.__prDialogResolve; window.__prDialogResolve = null; resolve(null);
  }
}
function showConfirm(message, title='تأیید عملیات') {
  return new Promise(resolve => {
    window.__prDialogResolve = value => { window.__prDialogResolve = null; resolve(value === true); };
    $('modalContent').innerHTML = `<div class="pr-dialog-head"><div class="pr-dialog-icon">?</div><div><h3>${esc(title)}</h3><p>${esc(message)}</p></div></div><div class="pr-dialog-actions"><button class="pr-btn-secondary" onclick="resolvePrDialog(false)">انصراف</button><button class="pr-btn-primary" onclick="resolvePrDialog(true)">تأیید</button></div>`;
    $('modalOverlay').classList.remove('hidden');
  });
}
function showInput(message, initialValue='', title='ویرایش') {
  return new Promise(resolve => {
    window.__prDialogResolve = value => { window.__prDialogResolve = null; resolve(value); };
    $('modalContent').innerHTML = `<div class="pr-dialog-head"><div class="pr-dialog-icon">✎</div><div><h3>${esc(title)}</h3><p>${esc(message)}</p></div></div><textarea id="prDialogInput" class="pr-dialog-input" rows="4">${esc(initialValue)}</textarea><div class="pr-dialog-actions"><button class="pr-btn-secondary" onclick="resolvePrDialog(null)">انصراف</button><button class="pr-btn-primary" onclick="resolvePrDialog(document.getElementById('prDialogInput').value)">ذخیره</button></div>`;
    $('modalOverlay').classList.remove('hidden');
    setTimeout(() => $('prDialogInput')?.focus(), 30);
  });
}
function resolvePrDialog(value) {
  const resolve = window.__prDialogResolve;
  window.__prDialogResolve = null;
  $('modalOverlay').classList.add('hidden');
  if (typeof resolve === 'function') resolve(value);
}
function accountInfo() {
  $('modalContent').innerHTML = `<h3 style="margin-bottom:12px">مدیریت حساب</h3><p style="color:var(--text-muted);line-height:1.9;font-size:13px">این مرورگر برای ساخت حداکثر دو حساب محدود شده است. برای ورود به حساب دیگر از خروج استفاده کن و با حساب دوم وارد شو. محدودیت به شناسهٔ ذخیره‌شده در کوکی مرورگر وابسته است و محدودیت هویتیِ ضدتقلب محسوب نمی‌شود.</p><button onclick="location.href='/logout'" style="margin-top:16px;padding:11px;border:0;border-radius:10px;background:var(--accent);color:#06121e;font-weight:bold;width:100%;cursor:pointer">خروج از حساب</button><button onclick="closeModal()" style="margin-top:8px;padding:10px;border:1px solid #30465f;border-radius:10px;background:transparent;color:white;width:100%;cursor:pointer">بستن</button>`;
  $('modalOverlay').classList.remove('hidden');
}
function closeChatMobile(e) { e?.stopPropagation(); $('chatMainPanel').classList.remove('mobile-active'); document.body.classList.remove('pr-chat-open'); $('sidebarPanel').classList.remove('mobile-hidden'); }

async function api(url, opts={}) {
  let r = await fetch(url, {...opts, headers:{'Content-Type':'application/json', ...(opts.headers||{})}});
  let d = await r.json().catch(()=>({}));
  if(!r.ok) throw Error(d.error || 'خطا');
  return d;
}

let prChatLongPressTimer=null;let prChatMenuNode=null;
function cancelChatLongPress(){if(prChatLongPressTimer){clearTimeout(prChatLongPressTimer);prChatLongPressTimer=null}}
function startChatLongPress(ev,id,name,pinned){cancelChatLongPress();const t=ev.touches?.[0];const x=t?.clientX??innerWidth/2,y=t?.clientY??innerHeight/2;prChatLongPressTimer=setTimeout(()=>showChatMenu({clientX:x,clientY:y,preventDefault(){}},id,name,pinned),520)}
function closeChatMenu(){prChatMenuNode?.remove();prChatMenuNode=null;document.removeEventListener('click',closeChatMenu)}
function showChatMenu(ev,id,name,pinned){ev.preventDefault?.();closeChatMenu();const menu=document.createElement('div');menu.className='pr-chat-menu';menu.innerHTML=`<div style="padding:9px 12px 10px;color:#b49a82;font-size:12px;font-weight:800">${esc(name)}</div><button onclick="chatMenuAction('pin',${id})">📌 ${pinned?'برداشتن سنجاق':'سنجاق‌کردن گفتگو'}</button><button onclick="chatMenuAction('archive',${id})">🗃️ بایگانی گفتگو</button><button onclick="chatMenuAction('delete',${id})" class="danger">🗑️ حذف از فهرست</button>`;document.body.appendChild(menu);const x=Math.min(Math.max(8,ev.clientX||innerWidth/2),innerWidth-235),y=Math.min(Math.max(8,ev.clientY||innerHeight/2),innerHeight-190);menu.style.left=x+'px';menu.style.top=y+'px';prChatMenuNode=menu;setTimeout(()=>document.addEventListener('click',closeChatMenu,{once:true}),0)}
async function chatMenuAction(action,id){closeChatMenu();try{if(action==='pin'){const r=await api(`/api/chats/${id}/pin`,{method:'POST'});showToast(r.pinned?'گفتگو سنجاق شد 📌':'سنجاق گفتگو برداشته شد');await loadDialogs()}else if(action==='archive'){if(!(await showConfirm('این گفتگو به بایگانی منتقل شود؟','بایگانی گفتگو')))return;await api(`/api/chats/${id}/archive`,{method:'POST'});if(activeUser?.id===id){activeUser=null;$('chatMessages').innerHTML=''}showToast('گفتگو بایگانی شد');await loadDialogs()}else if(action==='delete'){if(!(await showConfirm('گفتگو فقط از فهرست شما حذف شود؟ پیام‌های طرف مقابل پاک نمی‌شوند.','حذف گفتگو')))return;await api(`/api/chats/${id}`,{method:'DELETE'});if(activeUser?.id===id){activeUser=null;$('chatMessages').innerHTML=''}showToast('گفتگو از فهرست حذف شد');await loadDialogs()}}catch(e){showToast(e.message||'عملیات انجام نشد')}}
async function loadDialogs() {
  activeGroup = null;
  let d = await api('/api/dialogs');
  $('chatList').innerHTML = d.dialogs.map(u => `
    <div class="chat-row ${activeUser?.id===u.id?'active':''} ${u.chat_pinned?'pr-pinned':''}" data-chat-id="${u.id}" onclick="openUserChat(${u.id},'${esc(u.display_name)}','${esc(u.username)}','${esc(u.avatar||'')}')" oncontextmenu="event.preventDefault();showChatMenu(event,${u.id},'${esc(u.display_name)}',${!!u.chat_pinned})" ontouchstart="startChatLongPress(event,${u.id},'${esc(u.display_name)}',${!!u.chat_pinned})" ontouchend="cancelChatLongPress()" ontouchmove="cancelChatLongPress()">
      <div class="avatar" style="${u.avatar?`background-image:url('${u.avatar}')`:''}">${u.avatar?'':u.display_name[0]}</div>
      <div style="flex:1; min-width:0;">
        <div style="display:flex; justify-content:space-between; font-size:14px; font-weight:600;">
          <span>${esc(u.display_name)}${prAdminBadge(u.username)}</span>
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
  } catch(e) { showToast(e.message); }
}
async function openGroupChat(id, title) {
  const requestId = ++prOpenChatRequest;
  activeGroup = {id, title}; activeUser = null;
  $('chatTitle').textContent = title; $('chatStatus').textContent = 'گروه · پیام‌رسان پرو';
  $('activeAvatar').style.backgroundImage=''; $('activeAvatar').textContent='👥';
  $('chatMessages').innerHTML = '<div class="pr-chat-loading" role="status"><span></span><span></span><span></span><small>در حال بارگذاری گروه…</small></div>';
  if(window.innerWidth<=768) { $('chatMainPanel').classList.add('mobile-active'); document.body.classList.add('pr-chat-open'); }
  try {
    const d = await api('/api/groups/'+id+'/messages');
    if (requestId !== prOpenChatRequest || !activeGroup || activeGroup.id !== id) return;
    $('chatMessages').innerHTML=''; seenMessageIds.clear(); (d.messages || []).forEach(m => appendMessage(m, true)); scrollBottom();
  } catch (e) {
    if (requestId === prOpenChatRequest) $('chatMessages').innerHTML = '<div class="pr-empty-state">بارگذاری گروه ناموفق بود. دوباره تلاش کن.</div>';
  }
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

let prChatSettingsCache = null;
let prChatSettingsCachedAt = 0;
let prOpenChatRequest = 0;

async function openUserChat(id, name, username, avatar) {
  const requestId = ++prOpenChatRequest;
  activeGroup = null;
  activeUser = {id, name, username, avatar};
  $('chatTitle').textContent = name || 'گفتگو';
  $('chatStatus').textContent = username ? '@' + username : 'در حال اتصال…';
  $('chatMessages').innerHTML = '<div class="pr-chat-loading" role="status"><span></span><span></span><span></span><small>در حال بارگذاری گفتگو…</small></div>';
  seenMessageIds.clear();
  if (avatar) $('activeAvatar').style.backgroundImage = `url('${avatar}')`;
  else { $('activeAvatar').style.backgroundImage = ''; $('activeAvatar').textContent = (name || '?').slice(0,1); }
  if (window.innerWidth <= 768) {
    $('chatMainPanel').classList.add('mobile-active');
    document.body.classList.add('pr-chat-open');
  }

  // Messages are the critical path; optional profile/settings requests never delay first render.
  const profilePromise = username ? api('/api/users?q=' + encodeURIComponent(username)).catch(() => null) : Promise.resolve(null);
  const now = Date.now();
  const settingsPromise = (prChatSettingsCache && now - prChatSettingsCachedAt < 60000)
    ? Promise.resolve(prChatSettingsCache)
    : api('/api/settings').then(v => { prChatSettingsCache = v; prChatSettingsCachedAt = Date.now(); return v; }).catch(() => ({}));
  try {
    const d = await api('/api/messages/' + id);
    if (requestId !== prOpenChatRequest || !activeUser || activeUser.id !== id) return;
    $('chatMessages').innerHTML = '';
    seenMessageIds.clear();
    (d.messages || []).forEach(m => appendMessage(m));
    scrollBottom();
    loadDialogs().catch(() => {});
    Promise.all([profilePromise, settingsPromise]).then(([profileData, settings]) => {
      if (requestId !== prOpenChatRequest || !activeUser || activeUser.id !== id) return;
      const profile = profileData?.users?.find(x => x.id === id);
      if (profile) updateChatPresence(profile);
      if (settings) applyChatBackground(settings.chat_background || '');
    }).catch(() => {});
  } catch (e) {
    if (requestId === prOpenChatRequest) $('chatMessages').innerHTML = '<div class="pr-empty-state">بارگذاری گفتگو ناموفق بود. اتصال اینترنت را بررسی و دوباره تلاش کن.</div>';
  }
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

const PR_EMOJIS = ['😀','😃','😄','😁','😆','🥹','😂','🤣','😊','😎','😍','🥰','😘','😜','🤪','🤔','🫡','🥳','😴','😭','😤','😈','👻','💀','🤖','🔥','✨','💯','❤️','🖤','🤍','💔','💘','💎','👑','⚡','🌙','⭐','🌹','🫶','👏','👍','👎','🙏','🤝','💪','🎉','🎁','🚀','🐈','🐼','🦋','🌈','🍕','☕','🎮','🏆','⚽','🎧','💬','🧸','🫠','🫣'];
const PR_STICKERS = [['😎','خفن'],['👑','سلطان'],['🖤','دارک'],['🔥','آتشین'],['🥹','احساسی'],['💀','ری‌اکشن'],['🫡','چشم قربان'],['🦋','خاص'],['🐼','پاندا'],['🤡','شوخی'],['🚀','بزن بریم'],['✨','درخشان']];
function openEmojiPicker(tab='emoji'){
 const emojiHtml=()=>`<div class="pr-emoji-grid">${PR_EMOJIS.map(x=>`<button type="button" onclick="insertPRToken('${x}')">${x}</button>`).join('')}</div>`;
 const stickerHtml=()=>`<div class="pr-sticker-grid">${PR_STICKERS.map(x=>`<button class="pr-sticker" type="button" onclick="sendPRSticker('${x[0]}','${x[1]}')">${x[0]}<small>${x[1]}</small></button>`).join('')}</div><p style="font-size:10px;color:#888;line-height:1.8;margin-top:12px">این بستهٔ استیکر فعلاً با ایموجی‌های بزرگ ارسال می‌شود؛ برای استیکرهای تصویری واقعی باید فایل‌های استیکر به سرور اضافه شوند.</p>`;
 $('modalContent').innerHTML=`<div style="display:flex;align-items:center;justify-content:space-between"><div><h3>ایموجی و استیکر</h3><p style="font-size:11px;color:#999;margin-top:5px">حالتت رو با یه واکنش نشون بده ✨</p></div><span class="pr-badge">RANGO PRO</span></div><div class="pr-picker-tabs"><button id="prEmojiTab" class="${tab==='emoji'?'active':''}" onclick="switchPRPicker('emoji')">😊 ایموجی</button><button id="prStickerTab" class="${tab==='sticker'?'active':''}" onclick="switchPRPicker('sticker')">🧸 استیکر</button></div><div id="prPickerBody">${tab==='emoji'?emojiHtml():stickerHtml()}</div><button onclick="closeModal()" style="width:100%;padding:10px;border:1px solid #333;border-radius:12px;background:#111;color:#ddd;margin-top:12px">بستن</button>`;
 window.prEmojiHtml=emojiHtml;window.prStickerHtml=stickerHtml;$('modalOverlay').classList.remove('hidden');
}
function switchPRPicker(tab){$('prEmojiTab').classList.toggle('active',tab==='emoji');$('prStickerTab').classList.toggle('active',tab==='sticker');$('prPickerBody').innerHTML=tab==='emoji'?window.prEmojiHtml():window.prStickerHtml();}
function insertPRToken(token){const input=$('messageInput');if(!input)return;const start=input.selectionStart??input.value.length;const end=input.selectionEnd??start;input.value=input.value.slice(0,start)+token+input.value.slice(end);input.focus();input.selectionStart=input.selectionEnd=start+token.length;closeModal();}
async function sendPRSticker(emoji,label){
 if(!activeUser&&!activeGroup){showToast('اول یک گفتگو انتخاب کن.');return;}
 closeModal();
 try {
   const payload={body:emoji,msg_type:'sticker'};
   const d=activeGroup
     ? await api('/api/groups/'+activeGroup.id+'/messages',{method:'POST',body:JSON.stringify(payload)})
     : await api('/api/messages',{method:'POST',body:JSON.stringify({...payload,receiver_id:activeUser.id})});
   appendMessage(d.message,!!activeGroup); scrollBottom();
   if(!activeGroup) loadDialogs();
 } catch(e) { showToast(e.message||'ارسال استیکر انجام نشد'); }
}
function openPremiumShop(){
 const isDemo=localStorage.getItem('pr_demo_premium')==='1';
 $('modalContent').innerHTML=`<div class="pr-premium-hero"><div class="eyebrow">RANGO • EXCLUSIVE</div><h2>پیام‌رسان، در سطح بالاتر. ✦</h2><p>ظاهر لوکس‌تر، شخصی‌سازی بیشتر و تجربه‌ای خاص‌تر برای گفتگوهایت. این بخش فعلاً پیش‌نمایش فروشگاه اشتراک است.</p><span class="pr-badge">${isDemo?'عضویت نمایشی فعال است':'PRO MEMBERSHIP'}</span></div><div class="pr-perks"><div class="pr-perk">🎨<b>پوسته‌های اختصاصی</b><span>ظاهرهای سینمایی و شیشه‌ای برای برنامه</span></div><div class="pr-perk">🧸<b>بسته‌های استیکر</b><span>مجموعه‌های واکنش و استیکرهای خاص</span></div><div class="pr-perk">👑<b>نشان پرو</b><span>نشان ویژه کنار نام و پروفایل</span></div><div class="pr-perk">✨<b>افکت‌های پیام</b><span>نمایش‌های جذاب برای پیام‌های منتخب</span></div><div class="pr-perk">🪄<b>پروفایل شخصی‌سازی‌شده</b><span>قاب و استایل نمایشی اختصاصی</span></div><div class="pr-perk">🚀<b>قابلیت‌های آینده</b><span>امکانات جدید در نسخه‌های بعدی</span></div></div><div class="pr-plan-grid"><div class="pr-plan"><span class="pr-badge">شروع ساده</span><h3>PRO ماهانه</h3><div class="price">۵۰٬۰۰۰ تومان</div><p>اشتراک یک‌ماههٔ PRO؛ درخواست خرید را برای ادمین تلگرام بفرست.</p><button class="secondary" onclick="requestProPurchase()">🛒 درخواست خرید اشتراک</button></div><div class="pr-plan featured"><span class="pr-badge">پیشنهاد ویژه</span><h3>PRO MAX</h3><div class="price">۵۰٬۰۰۰ تومان / ماه</div><p>پس از بررسی واریز، ادمین اشتراک را فعال می‌کند.</p><button onclick="requestProPurchase()">👑 خرید PRO MAX</button></div></div><p style="font-size:10px;color:#888;line-height:1.9;margin-top:14px">پرداخت مستقیم در سایت انجام نمی‌شود. با زدن دکمه، پیام آماده در تلگرام باز می‌شود؛ پس از بررسی پرداخت، ادمین اشتراک را فعال می‌کند.</p><button onclick="closeModal()" style="width:100%;margin-top:8px;padding:10px;background:#111;color:#ddd;border:1px solid #333;border-radius:12px">برگشت به گفتگو</button>`;
 $('modalOverlay').classList.remove('hidden');
}
async function requestProPurchase(){
 try{const me=await api('/api/me');const msg=`سلام، درخواست خرید اشتراک Rango دارم.\nآیدی: @${me.username}\nمبلغ: ۵۰٬۰۰۰ تومان\nمدت: یک ماه\nلطفاً اطلاعات پرداخت را ارسال کنید.`;const admin=(window.PR_ADMIN_TELEGRAM_USERNAME||'YOUR_TELEGRAM_USERNAME').replace(/^@/,'');if(!admin||admin==='YOUR_TELEGRAM_USERNAME'){showToast('ابتدا ADMIN_TELEGRAM_USERNAME را در تنظیمات سرور روی آیدی تلگرام خودت تنظیم کن.');return;}window.location.href=`https://t.me/${encodeURIComponent(admin)}?text=${encodeURIComponent(msg)}`;}catch(e){showToast(e.message||'بازکردن درخواست خرید ناموفق بود');}
}
async function openStories(){
 try{const d=await api('/api/stories');const me=await api('/api/me');const list=d.stories.map(s=>`<article class="pr-story-card"><b>${esc(s.display_name||s.username)}</b> <small>@${esc(s.username)} · ${new Date(s.created_at).toLocaleString()}</small>${s.media_url?`<p><a href="${esc(s.media_url)}" target="_blank" rel="noopener">🖼️ مشاهدهٔ رسانه</a></p>`:''}<p style="white-space:pre-wrap">${esc(s.body||'')}</p>${s.user_id===me.id?`<button onclick="deleteStory(${s.id})">🗑️ حذف استوری من</button>`:''}</article>`).join('');$('modalContent').innerHTML=`<div class="pr-screen-head"><div><div class="pr-eyebrow">STORIES · 24 HOURS</div><h2>استوری‌ها ✨</h2><p>استوری‌ها پس از ۲۴ ساعت منقضی می‌شوند.</p></div><button class="pr-close-round" onclick="closeModal()">×</button></div><div class="pr-admin-panel"><textarea id="prStoryText" maxlength="500" placeholder="چی می‌خوای به اشتراک بذاری؟" style="width:100%;box-sizing:border-box;min-height:90px;background:#111;color:#fff;border:1px solid #ffffff20;border-radius:12px;padding:12px"></textarea><input id="prStoryMedia" placeholder="لینک تصویر/ویدئو (اختیاری)" style="width:100%;box-sizing:border-box;padding:11px;background:#111;color:#fff;border:1px solid #ffffff20;border-radius:10px;margin-top:8px"><button onclick="publishStory()" style="margin-top:8px;padding:11px 15px;border:0;border-radius:11px;background:linear-gradient(135deg,#b49a82,#6c5544);color:#fff;font-weight:800">＋ انتشار استوری</button></div><h3>استوری‌های اخیر</h3>${list||'<div class="pr-empty-state">هنوز استوری‌ای منتشر نشده.</div>'}`;$('modalOverlay').classList.remove('hidden');}catch(e){showToast(e.message||'بارگذاری استوری‌ها ناموفق بود')}
}
async function publishStory(){try{await api('/api/stories',{method:'POST',body:JSON.stringify({body:$('prStoryText').value.trim(),media_url:$('prStoryMedia').value.trim()})});showToast('استوری تا ۲۴ ساعت نمایش داده می‌شود ✨');openStories()}catch(e){showToast(e.message||'انتشار استوری ناموفق بود')}}
async function deleteStory(id){if(!await showConfirm('این استوری حذف شود؟','حذف استوری'))return;try{await api('/api/stories/'+id,{method:'DELETE'});showToast('استوری حذف شد');openStories()}catch(e){showToast(e.message||'حذف ناموفق بود')}}
async function openAdminPanel(){try{const st=await api('/api/admin/status');if(!st.is_admin_account){showToast('این حساب ادمین نیست. با آیدی @Pv_HE33AM وارد شو.');return;}if(!st.verified){const code=await showInput('کد ورود ادمین را وارد کن.','', 'تأیید هویت ادمین 🛡️');if(code===null)return;await api('/api/admin/verify',{method:'POST',body:JSON.stringify({code})});}const verified=await api('/api/admin/status');if(!verified.is_admin){showToast('تأیید هویت ادمین انجام نشد.');return;}$('modalContent').innerHTML=`<div class="pr-screen-head"><div><div class="pr-eyebrow">ADMIN CONSOLE · VERIFIED</div><h2>پنل مدیریت 🛡️</h2><p>مدیریت اشتراک کاربران برای ۳۰ روز.</p></div><button class="pr-close-round" onclick="closeModal()">×</button></div><div class="pr-admin-panel"><label>آیدی کاربر</label><input id="prAdminTarget" placeholder="username بدون @" autocomplete="off"><div style="display:flex;gap:8px;flex-wrap:wrap"><button onclick="adminChangePro('pro')" style="padding:11px;border:0;border-radius:10px;background:#b49a82;color:#111;font-weight:800">👑 تبدیل به PRO</button><button onclick="adminChangePro('free')" style="padding:11px;border:1px solid #ffffff22;border-radius:10px;background:#222;color:#fff">لغو PRO</button></div><small style="display:block;margin-top:10px;color:#aaa;line-height:1.7">دسترسی ادمین فقط برای @Pv_HE33AM پس از تأیید کد فعال می‌شود.</small></div>`;$('modalOverlay').classList.remove('hidden')}catch(e){showToast(e.message||'خطای پنل ادمین')}}
async function adminChangePro(action){try{const username=$('prAdminTarget').value.trim().replace(/^@/,'');const d=await api('/api/admin/subscription',{method:'POST',body:JSON.stringify({username,action})});showToast(action==='pro'?`@${d.username} به مدت ۳۰ روز PRO شد`:`اشتراک @${d.username} لغو شد`)}catch(e){showToast(e.message||'تغییر اشتراک ناموفق بود')}}
function activateDemoPremium(){localStorage.setItem('pr_demo_premium','1');showToast('حالت نمایشی PRO فعال شد؛ پرداختی انجام نشده است.');openPremiumShop();}

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
  const lang = getAppLanguage();
  const en = lang === 'en';
  $('modalContent').innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><div style="font-size:25px">⚙️</div><div><h3>${en?'App settings':'تنظیمات برنامه'}</h3><div style="font-size:12px;color:var(--text-muted);margin-top:3px">${en?'Appearance, privacy and chat experience':'ظاهر، حریم خصوصی و تجربهٔ گفتگو'}</div></div></div><hr style="border:0;border-top:1px solid var(--border-color);margin:12px 0">
    <label style="display:block;margin:10px 0">${en?'App language':'زبان برنامه'}</label>
    <select id="settingLanguage" onchange="applyLanguage(this.value)" style="width:100%;padding:11px;background:var(--bg-main);color:var(--text-main,white);border:1px solid var(--border-color);border-radius:9px"><option value="fa" ${!en?'selected':''}>فارسی</option><option value="en" ${en?'selected':''}>English</option></select>
    <label style="display:block;margin:12px 0 6px">${en?'Chat background (HEX color or image URL)':'پس‌زمینه چت (رنگ HEX یا لینک تصویر)'}</label>
    <input id="settingBg" value="${esc(d.chat_background||'')}" placeholder="#101010 or https://..." style="width:100%;padding:10px;background:var(--bg-main);color:var(--text-main,white);border:1px solid var(--border-color);border-radius:8px">
    <label style="display:flex;gap:8px;align-items:center;margin:14px 0"><input id="settingSeen" type="checkbox" ${d.show_last_seen?'checked':''} style="width:auto"> ${en?'Allow others to see my last seen':'اجازه نمایش آخرین بازدید من'}</label>
    <label style="display:block;margin:12px 0 6px">${en?'Color theme':'تم رنگی'}</label><select id="settingTheme" onchange="applyTheme(this.value)" style="width:100%;padding:11px;background:var(--bg-main);color:var(--text-main,white);border:1px solid var(--border-color);border-radius:9px"><option value="dark" ${d.theme!=='light'?'selected':''}>⚫ ${en?'Black':'سیاه'}</option><option value="light" ${d.theme==='light'?'selected':''}>⚪ ${en?'White':'سفید'}</option></select>
    <div style="font-size:12px;color:var(--text-muted);margin:10px 0 16px">${en?'Only black and white themes are available for now.':'فعلاً فقط تم‌های سیاه و سفید فعال هستند.'}</div>
    <div class="pr-settings-section"><h4>🔔 اعلان‌ها و دانلود</h4>
      <label class="pr-setting-row"><span>فعال‌بودن اعلان‌های داخل برنامه</span><input id="settingNotifications" type="checkbox" ${d.notifications_enabled!==0?'checked':''}></label>
      <label class="pr-setting-row"><span>دانلود خودکار رسانه‌ها</span><input id="settingAutoDownload" type="checkbox" ${d.auto_download?'checked':''}></label>
      <label class="pr-setting-row"><span>صدای اعلان پیام جدید</span><input id="settingNotificationSound" type="checkbox" ${d.notification_sound!==0?'checked':''}></label>
      <small style="color:var(--text-muted);line-height:1.8">دانلود خودکار در این نسخه فقط ترجیح کاربر را ذخیره می‌کند؛ دانلود رسانه‌ها همچنان تابع نوع فایل و رفتار مرورگر است.</small>
    </div>
    <button onclick="saveAppSettings()" style="padding:12px 16px;background:linear-gradient(135deg,var(--accent),#b49a82);border:1px solid var(--border-color);color:var(--button-text,white);border-radius:13px;box-shadow:0 8px 22px #0003;transition:transform .2s,filter .2s">${en?'Save settings':'ذخیره تنظیمات ✓'}</button>
    <button onclick="closeModal()" style="padding:11px;background:var(--panel-hover);border:1px solid var(--border-color);color:var(--text-main,white);border-radius:10px;margin-right:6px">${en?'Close':'بستن'}</button>`;
  $('modalOverlay').classList.remove('hidden');
}
async function saveAppSettings() {
  try { const bg=$('settingBg').value.trim(); const lang=$('settingLanguage')?.value || getAppLanguage(); localStorage.setItem('pr-language',lang); await api('/api/settings',{method:'POST',body:JSON.stringify({chat_background:bg,show_last_seen:$('settingSeen').checked,theme:$('settingTheme').value,notifications_enabled:$('settingNotifications')?.checked??true,auto_download:$('settingAutoDownload')?.checked??false,notification_sound:$('settingNotificationSound')?.checked??true,profile_color:(await api('/api/settings')).profile_color||'#30251f'})}); window.prUserSettings={notifications_enabled:$('settingNotifications')?.checked??true,notification_sound:$('settingNotificationSound')?.checked??true,auto_download:$('settingAutoDownload')?.checked??false}; applyChatBackground(bg); applyTheme($('settingTheme').value); applyLanguage(lang); showToast(lang==='en'?'Settings saved':'تنظیمات ذخیره شد'); closeModal(); }
  catch(e){ showToast(e.message); }
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
    if (!uploaded.ok) { showToast(uploadData.error || 'بارگذاری عکس انجام نشد'); return; }
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
        <button onclick="showToast('تماس صوتی هنوز به سرور تماس متصل نشده است.')" style="border:0;border-radius:12px;background:var(--bg-main);color:white;padding:11px 3px;cursor:pointer"><div style="font-size:20px">📞</div><small>تماس</small></button>
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
  showToast(muted?'اعلان‌های این مخاطب در این مرورگر از حالت بی‌صدا خارج شد.':'این مخاطب در این مرورگر بی‌صدا شد.');
}
function showContactMore(){
  $('modalContent').innerHTML=`<h3 style="margin-bottom:14px">مدیریت مخاطب</h3><button onclick="blockContactDemo()" style="width:100%;padding:12px;margin-bottom:8px;border:1px solid #793b45;border-radius:10px;background:#351c24;color:#ff9ca8;cursor:pointer">🚫 مسدود کردن مخاطب</button><button onclick="openHeaderProfile()" style="width:100%;padding:11px;border:1px solid var(--border-color);border-radius:10px;background:transparent;color:white;cursor:pointer">بازگشت به پروفایل</button>`;
}
async function blockContactDemo(){
  if (!activeUser) return;
  const en=getAppLanguage()==='en';
  if (!(await showConfirm(en?'Block this contact? They will not be able to message you.':'این مخاطب مسدود شود؟ پس از مسدودسازی امکان پیام‌دادن بین شما محدود می‌شود.','مسدودسازی مخاطب'))) return;
  const blockedName=activeUser.display_name || activeUser.username || (en?'Contact':'مخاطب');
  try {
    await api('/api/block/'+activeUser.id,{method:'POST'});
    closeModal();
    showToast(en?'🚫 Contact blocked':'🚫 مخاطب مسدود شد');
    $('chatMessages').innerHTML=`<div class="system-notice"><div class="system-notice-icon">🚫</div><strong>${en?'Contact blocked':'مخاطب مسدود شد'}</strong><p>${en?'You blocked this contact. Messages between you are restricted.':'این مخاطب را مسدود کردی. ارسال پیام بین شما محدود شده است.'}</p><button onclick="loadDialogs()">${en?'Back to chats':'بازگشت به گفتگوها'}</button></div>`;
    activeUser=null;
    loadDialogs();
  } catch(e){ showToast('⚠️ '+e.message); }
}
async function showContactMedia(){
  if (!activeUser) return;
  try {
    const d=await api('/api/chats/'+activeUser.id+'/media');
    const en=getAppLanguage()==='en';
    const items=d.items||[];
    $('modalContent').innerHTML=`<h3 style="margin-bottom:12px">${en?'Shared media':'رسانه‌های گفتگو'}</h3>${items.length?items.map(x=>{
      const url=esc(x.body||'');
      const label=x.msg_type==='image'?'🖼 Image':x.msg_type==='voice'?'🎙 Voice message':'📎 File';
      return `<div style="padding:10px;margin:6px 0;border:1px solid var(--border-color);border-radius:9px;overflow-wrap:anywhere">${label}<div><a href="${url}" target="_blank" rel="noopener" style="color:var(--accent)">${url}</a></div><small style="color:var(--text-muted)">${esc((x.created_at||'').replace('T',' ').slice(0,16))}</small></div>`;
    }).join(''):`<p style="color:var(--text-muted)">${en?'No shared media yet.':'هنوز رسانه‌ای در این گفتگو نیست.'}</p>`}<button onclick="openHeaderProfile()" style="margin-top:10px;padding:10px;border:1px solid var(--border-color);border-radius:9px;background:transparent;color:var(--text-main,white)">${en?'Back':'بازگشت'}</button>`;
  } catch(e){ showToast(e.message); }
}


function showToast(message) {
  let el=document.getElementById('prToast');
  if(!el){ el=document.createElement('div'); el.id='prToast'; el.setAttribute('role','status'); el.style.cssText='position:fixed;z-index:99999;bottom:24px;left:50%;transform:translateX(-50%);max-width:calc(100vw - 32px);padding:12px 18px;border:1px solid var(--border-color);border-radius:14px;background:var(--panel-bg);color:var(--text-main,white);box-shadow:0 12px 40px #0008;font-size:14px;text-align:center;opacity:0;transition:opacity .18s'; document.body.appendChild(el); }
  el.textContent=message; el.style.opacity='1'; clearTimeout(window.__prToastTimer); window.__prToastTimer=setTimeout(()=>{el.style.opacity='0'},2600);
}
function formatLastSeen(value) {
  if (!value) return 'نامشخص';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'نامشخص';
  return d.toLocaleString('fa-IR');
}
async function editMessage(id, oldBody) {
  const body = await showInput('متن جدید پیام:', oldBody, 'ویرایش پیام');
  if (body === null || !body.trim()) return;
  try { await api(`/api/messages/${id}/edit`, {method:'POST', body:JSON.stringify({body:body.trim()})}); await refreshActiveChat(); }
  catch(e) { showToast(e.message); }
}
async function deleteMessage(id) {
  if (!(await showConfirm('این پیام حذف شود؟','حذف پیام'))) return;
  try { await api(`/api/messages/${id}/delete`, {method:'POST'}); await refreshActiveChat(); }
  catch(e) { showToast(e.message); }
}
async function refreshActiveChat() {
  if (!activeUser) return;
  const d = await api('/api/messages/' + activeUser.id);
  $('chatMessages').innerHTML = ''; seenMessageIds.clear(); d.messages.forEach(appendMessage); scrollBottom();
}
async function blockUser(id) {
  const en=getAppLanguage()==='en';
  if (!(await showConfirm(en?'Block this user?':'این کاربر مسدود شود؟','مسدودسازی کاربر'))) return;
  try {
    await api('/api/block/' + id, {method:'POST'}); closeModal();
    $('chatMessages').innerHTML = `<div class="system-notice"><div class="system-notice-icon">🚫</div><strong>${en?'User blocked':'کاربر مسدود شد'}</strong><p>${en?'Messaging with this user is now restricted.':'ارسال پیام بین شما محدود شده است.'}</p><button onclick="loadDialogs()">${en?'Back to chats':'بازگشت به گفتگوها'}</button></div>`;
    showToast(en?'🚫 User blocked':'🚫 کاربر مسدود شد'); activeUser = null; loadDialogs();
  } catch(e) { showToast('⚠️ '+e.message); }
}
async function deleteChat(id) {
  if (!(await showConfirm('گفتگو فقط از فهرست شما حذف شود؟ پیام‌های طرف مقابل پاک نمی‌شوند.','حذف گفتگو'))) return;
  await api('/api/chats/' + id, {method:'DELETE'}); closeModal(); activeUser=null;
  $('chatMessages').innerHTML='<div style="margin:auto;color:var(--text-muted)">گفتگو حذف شد.</div>'; loadDialogs();
}
function applyTheme(theme) {
  const root=document.documentElement;
  if (!['dark','light'].includes(theme)) theme='dark';
  const themes={
    dark: {bg:'#000000',panel:'#101010',hover:'#202020',active:'#303030',accent:'#ffffff',out:'#292929',inside:'#151515',muted:'#b8b8b8',border:'#383838',text:'#ffffff',buttonText:'#000000'},
    light:{bg:'#ffffff',panel:'#f5f5f5',hover:'#e9e9e9',active:'#dddddd',accent:'#111111',out:'#e5e5e5',inside:'#f2f2f2',muted:'#555555',border:'#d0d0d0',text:'#111111',buttonText:'#ffffff'}
  };
  const t=themes[theme];
  const vars={'--bg-main':t.bg,'--panel-bg':t.panel,'--panel-hover':t.hover,'--active-bg':t.active,'--accent':t.accent,'--bubble-out':t.out,'--bubble-in':t.inside,'--text-muted':t.muted,'--border-color':t.border,'--text-main':t.text,'--button-text':t.buttonText};
  Object.entries(vars).forEach(([k,v])=>root.style.setProperty(k,v));
  document.body.dataset.theme=theme;
  document.body.style.background=t.bg;
  document.body.style.color=t.text;
  document.querySelectorAll('.sidebar-header, .sidebar > div:first-child').forEach(el=>{el.style.background=t.panel;});
  try { localStorage.setItem('pr-theme',theme); } catch(e) {}
}
function getAppLanguage() {
  try { return localStorage.getItem('pr-language') === 'en' ? 'en' : 'fa'; } catch(e) { return 'fa'; }
}
function applyLanguage(lang) {
  lang = lang === 'en' ? 'en' : 'fa';
  try { localStorage.setItem('pr-language',lang); } catch(e) {}
  document.documentElement.lang=lang;
  document.documentElement.dir=lang==='fa'?'rtl':'ltr';
  document.body.dir=document.documentElement.dir;
  const en=lang==='en';
  const search=$('searchInput'); if(search) search.placeholder=en?'Search username...':'جستجو آیدی...';
  const title=$('chatTitle'); if(title && !activeUser && !activeGroup) title.textContent=en?'Rango':'تلگرام پرو';
  const status=$('chatStatus'); if(status && !activeUser && !activeGroup) status.textContent=en?'Select a chat':'انتخاب گفتگو';
  const input=$('messageInput'); if(input) input.placeholder=en?'Write a message...':'نوشتن پیام...';
  const settingsBtn=document.querySelector('.folder-icon[onclick="openAppSettings()"]'); if(settingsBtn) settingsBtn.title=en?'Settings and themes':'تنظیمات و تم‌ها';
  const profileBtn=document.querySelector('.folder-icon[onclick="openProfileModal()"]'); if(profileBtn) profileBtn.title=en?'My profile':'پروفایل من';
  const accountBtn=document.querySelector('button[onclick="accountInfo()"]'); if(accountBtn) {accountBtn.title=en?'Current account and account management':'حساب فعلی و مدیریت حساب‌ها'; accountBtn.textContent=en?'👤 Account':'👤 حساب';}
  const empty=$('chatMessages')?.querySelector('div[style*="margin: auto"]');
  if(empty && !activeUser && !activeGroup) empty.textContent=en?'Select a conversation':'یک مخاطب را انتخاب کنید';
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
  if (!activeUser && !activeGroup) { showToast('اول یک گفتگو انتخاب کن.'); return; }
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) { showToast('ضبط صدا در این مرورگر پشتیبانی نمی‌شود. در HTTPS یا localhost امتحان کن.'); return; }
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
      if (!up.ok) { showToast(ud.error || 'ارسال صدا ناموفق بود'); return; }
      const payload={body:location.origin+ud.url,msg_type:'voice'};
      const sent = activeGroup ? await api('/api/groups/'+activeGroup.id+'/messages',{method:'POST',body:JSON.stringify(payload)}) : await api('/api/messages',{method:'POST',body:JSON.stringify({...payload,receiver_id:activeUser.id})});
      appendMessage(sent.message, !!activeGroup); scrollBottom(); if(!activeGroup) loadDialogs();
    };
    recorder.start(); btn.textContent='⏹️'; btn.style.color='#f87171';
  } catch(e) { showToast('اجازه دسترسی به میکروفون داده نشد یا ضبط صدا ممکن نیست.'); }
}
async function createGroup() {
  showToast(getAppLanguage()==='en'?'Groups are temporarily disabled.':'بخش گروه‌ها فعلاً غیرفعال است.');
  return;
  const title = await showInput('نام گروه را وارد کن:', '', 'ساخت گروه');
  if (!title?.trim()) return;
  const membersText = await showInput('آیدی اعضا را با کاما جدا کن (مثلاً 2,3). خودت هم عضو می‌شوی:', '', 'اعضای گروه');
  const memberIds = (membersText||'').split(',').map(x=>parseInt(x.trim(),10)).filter(Number.isInteger);
  try {
    const d = await api('/api/groups',{method:'POST',body:JSON.stringify({title:title.trim(),members:memberIds})});
    await loadGroups(); await openGroupChat(d.id,d.title);
  } catch(e) { showToast(e.message); }
}

function switchFolder(f) { loadDialogs(); }
function scrollBottom() { $('chatMessages').scrollTop =$('chatMessages').scrollHeight; }
function esc(s) { return String(s??'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const seenMessageIds = new Set();
function messageMenu(m,isGroup=false) {
  const choices=[];
  choices.push(['📋 کپی متن',()=>navigator.clipboard?.writeText(m.body||'')]);
  choices.push(['↩️ پاسخ',()=>replyToMessage(m)]);
  if(!isGroup) choices.push(['➡️ فوروارد پیام',()=>forwardMessage(m.id)]);
  if(!isGroup){ choices.push([m.pinned?'📌 برداشتن سنجاق':'📌 سنجاق کردن',()=>togglePinMessage(m.id)]); choices.push(['👍 واکنش',()=>reactToMessage(m.id)]); }
  if(!isGroup && activeUser && activeUser.id!==meId) choices.push(['📦 انتقال گفتگو به بایگانی',()=>archiveActiveChat()]);
  if(!isGroup && m.sender_id===meId){ choices.push(['✏️ ویرایش',()=>editMessage(m.id,m.body||'')]); choices.push(['🗑️ حذف',()=>deleteMessage(m.id)]); }
  const html=`<h3 style="margin-bottom:12px">گزینه‌های پیام</h3>${choices.map((c,i)=>`<button onclick="runMessageChoice(${i})" style="display:block;width:100%;padding:11px;margin:6px 0;background:#172536;color:white;border:1px solid #344a64;border-radius:9px;text-align:right">${c[0]}</button>`).join('')}<button onclick="closeModal()" style="width:100%;padding:10px;background:transparent;color:#9fb2c7;border:0">بستن</button>`;
  window._messageChoices=choices; $('modalContent').innerHTML=html; $('modalOverlay').classList.remove('hidden');
}
function runMessageChoice(i){const c=window._messageChoices?.[i];if(c){closeModal();Promise.resolve(c[1]()).catch(()=>{});}}

async function replyToMessage(m){
 const body=await showInput('پاسخت را بنویس:', '', 'پاسخ به پیام'); if(body===null||!body.trim())return;
 try{await api('/api/messages/'+m.id+'/reply',{method:'POST',body:JSON.stringify({body:body.trim()})});await refreshActiveChat();showToast('پاسخ ارسال شد');}
 catch(e){showToast(e.message||'ارسال پاسخ ناموفق بود');}
}
async function forwardMessage(mid){
 try{
  const d=await api('/api/users/contacts');
  const users=d.users||[];
  if(!users.length){showToast('برای فوروارد، ابتدا مخاطب را از بخش مخاطبین پیدا کن.');return;}
  $('modalContent').innerHTML=`<div class="pr-screen-head"><div><div class="pr-eyebrow">FORWARD MESSAGE</div><h2>انتخاب مقصد</h2><p>پیام را برای کدام مخاطب بفرستم؟</p></div><button class="pr-close-round" onclick="closeModal()">×</button></div><div class="pr-contact-results">${users.map(u=>`<button class="pr-contact-row" onclick="confirmForward(${mid},${u.id})"><span class="pr-contact-avatar">${esc((u.display_name||'?').slice(0,1))}</span><span class="pr-contact-copy"><b>${esc(u.display_name)}</b><small>@${esc(u.username)}</small></span><span class="pr-contact-go">↗</span></button>`).join('')}</div>`;$('modalOverlay').classList.remove('hidden');
 }catch(e){showToast(e.message||'فوروارد ناموفق بود');}
}
async function confirmForward(mid,rid){try{await api('/api/messages/'+mid+'/forward',{method:'POST',body:JSON.stringify({receiver_id:rid})});closeModal();showToast('پیام فوروارد شد');}catch(e){showToast(e.message||'فوروارد ناموفق بود');}}
async function archiveActiveChat(){
 if(!activeUser||activeUser.id===meId){showToast('این گفتگو قابل بایگانی نیست');return;}
 const ok=await showConfirm('این گفتگو از فهرست اصلی خارج و به بایگانی منتقل شود؟','بایگانی گفتگو');if(!ok)return;
 try{await api('/api/chats/'+activeUser.id+'/archive',{method:'POST'});showToast('گفتگو بایگانی شد');activeUser=null;$('chatMainPanel').classList.remove('mobile-active');await loadDialogs();}
 catch(e){showToast(e.message||'بایگانی ناموفق بود');}
}
async function searchMessagesScreen(){
 const content=`<div class="pr-screen-head"><div><div class="pr-eyebrow">MESSAGE INDEX</div><h2>جست‌وجوی پیام‌ها</h2><p>عبارت حداقل دوحرفی را وارد کن.</p></div><button class="pr-close-round" onclick="closeModal()">×</button></div><input id="prMsgSearch" class="pr-search-field" placeholder="جست‌وجو در پیام‌ها..." autocomplete="off"><div id="prMsgResults" class="pr-contact-results"></div>`;
 $('modalContent').innerHTML=content;$('modalOverlay').classList.remove('hidden');
 $('prMsgSearch').addEventListener('input',async ev=>{const q=ev.target.value.trim(),box=$('prMsgResults');if(q.length<2){box.innerHTML='<div class="pr-empty-state">حداقل دو حرف بنویس.</div>';return;}box.innerHTML='<div class="pr-empty-state">در حال جست‌وجو…</div>';try{const d=await api('/api/messages/search?q='+encodeURIComponent(q));box.innerHTML=d.results.length?d.results.map(m=>`<button class="pr-contact-row" onclick="closeModal();openUserChat(${m.sender_id===meId?m.receiver_id:m.sender_id},'گفتگو','', '')"><span class="pr-contact-copy"><b>${esc(m.sender_name||m.sender_username||'پیام')}</b><small>${esc(m.body||'')}</small></span><span class="pr-contact-go">↗</span></button>`).join(''):'<div class="pr-empty-state">پیامی پیدا نشد.</div>';}catch(e){box.innerHTML=`<div class="pr-empty-state">${esc(e.message||'خطا در جست‌وجو')}</div>`;}});$('prMsgSearch').focus();
}
async function showArchivedChats(){
 try{const d=await api('/api/chats/archived');$('modalContent').innerHTML=`<div class="pr-screen-head"><div><div class="pr-eyebrow">ARCHIVE</div><h2>گفتگوهای بایگانی‌شده</h2></div><button class="pr-close-round" onclick="closeModal()">×</button></div>`+(d.chats.length?d.chats.map(c=>`<div class="pr-contact-row"><span class="pr-contact-copy"><b>${esc(c.display_name)}</b><small>@${esc(c.username)}</small></span><button style="width:auto;padding:8px 12px" onclick="unarchiveChat(${c.id})">بازگردانی</button></div>`).join(''):'<div class="pr-empty-state">بایگانی خالی است.</div>');$('modalOverlay').classList.remove('hidden');}catch(e){showToast(e.message||'خطا در بایگانی');}
}
async function unarchiveChat(id){try{await api('/api/chats/'+id+'/unarchive',{method:'POST'});await showArchivedChats();await loadDialogs();showToast('گفتگو بازگردانی شد');}catch(e){showToast(e.message||'خطا');}}

async function togglePinMessage(id){try{const d=await api('/api/messages/'+id+'/pin',{method:'POST'});await refreshActiveChat();showToast(d.pinned?'پیام سنجاق شد':'سنجاق پیام برداشته شد');}catch(e){showToast(e.message);}}
async function reactToMessage(id){const reaction=await showInput('واکنش را انتخاب کن: 👍 ❤️ 😂 😮 😢 🔥 👏 🤔','👍','واکنش به پیام');if(reaction===null)return;try{await api('/api/messages/'+id+'/react',{method:'POST',body:JSON.stringify({reaction:reaction.trim()})});await refreshActiveChat();}catch(e){showToast(e.message);}}
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
  if(m.msg_type === 'sticker') bodyHtml = `<div class="pr-message-sticker" role="img" aria-label="استیکر">${esc(m.body)}</div>`;
  else if(m.msg_type === 'image') bodyHtml = `<img src="${esc(m.body)}" style="max-width:100%; max-height:360px; border-radius:10px; object-fit:contain;">`;
  else if(m.msg_type === 'voice') bodyHtml = `<div style="min-width:220px"><div>🎙️ پیام صوتی</div><audio controls preload="metadata" src="${esc(m.body)}" style="width:100%;max-width:280px"></audio></div>`;
  else if(m.msg_type === 'file') bodyHtml = `<a href="${esc(m.body)}" target="_blank" rel="noopener" style="color:#7dd3fc">📎 دریافت فایل</a>`;
  let actions = (!isGroup && isMine) ? `<div style="display:flex;gap:8px;margin-top:6px"><button onclick="editMessage(${m.id},${JSON.stringify(m.body||'')})" style="background:none;border:0;color:#bae6fd;cursor:pointer">ویرایش</button><button onclick="deleteMessage(${m.id})" style="background:none;border:0;color:#fca5a5;cursor:pointer">حذف</button></div>` : '';
  let sender = isGroup ? `<div style="font-size:11px;color:#7dd3fc;margin-bottom:4px">${esc(m.sender_name||m.sender_username||'کاربر')}</div>` : '';
  el.innerHTML = `${sender}${m.pinned?'<div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">📌 پیام سنجاق‌شده</div>':''}<div>${bodyHtml}</div>${m.reaction?`<div style="font-size:14px;margin-top:4px">${esc(m.reaction)}</div>`:''}${actions}<div class="msg-time">${(m.created_at||'').slice(11,16)}${ticks}</div>`;
  $('chatMessages').appendChild(el);
}

document.addEventListener('keydown', ev=>{if((ev.ctrlKey||ev.metaKey)&&ev.key.toLowerCase()==='k'){ev.preventDefault();searchMessagesScreen();}if((ev.ctrlKey||ev.metaKey)&&ev.shiftKey&&ev.key.toLowerCase()==='a'){ev.preventDefault();showArchivedChats();}});
if ('Notification' in window && Notification.permission === 'default') {
  // Permission is requested only after the user explicitly interacts with the page.
  document.addEventListener('click', function askNotificationPermission() {
    if (window.prUserSettings?.notifications_enabled !== false && Notification.permission === 'default') Notification.requestPermission();
    document.removeEventListener('click', askNotificationPermission);
  }, {once:true});
}
window.prUserSettings = {notifications_enabled:true, notification_sound:true, auto_download:false};
function playPRNotificationTone(){try{if(window.prUserSettings?.notification_sound===false)return;const C=window.AudioContext||window.webkitAudioContext;if(!C)return;const c=new C(),o=c.createOscillator(),g=c.createGain();o.type='sine';o.frequency.value=740;g.gain.setValueAtTime(0.0001,c.currentTime);g.gain.exponentialRampToValueAtTime(0.045,c.currentTime+0.015);g.gain.exponentialRampToValueAtTime(0.0001,c.currentTime+0.16);o.connect(g);g.connect(c.destination);o.start();o.stop(c.currentTime+0.17);o.onended=()=>c.close();}catch(_){}}
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
    if (window.prUserSettings?.notifications_enabled !== false) playPRNotificationTone();
    if (window.prUserSettings?.notifications_enabled !== false && 'Notification' in window && Notification.permission === 'granted' &&
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
api('/api/settings').then(x => {window.prUserSettings={notifications_enabled:x.notifications_enabled!==0,notification_sound:x.notification_sound!==0,auto_download:!!x.auto_download};applyChatBackground(x.chat_background || ''); applyTheme(x.theme==='light'?'light':'dark'); applyLanguage(getAppLanguage());}).catch(()=>{applyTheme(localStorage.getItem('pr-theme')==='light'?'light':'dark'); applyLanguage(getAppLanguage());});
</script>
<style id="pr-final-product-polish">
:root{color-scheme:dark;--pr-accent:#7dd3fc;--pr-accent-soft:rgba(125,211,252,.12);--pr-line:rgba(255,255,255,.085)}
button,input,textarea{font-family:inherit}button{touch-action:manipulation}button:focus-visible,[role="button"]:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid var(--pr-accent);outline-offset:2px}
.chat-row{position:relative;min-height:70px;padding:10px 13px!important;border-bottom:1px solid rgba(255,255,255,.035)!important;transition:background .16s ease,border-color .16s ease}
.chat-row:hover{background:rgba(255,255,255,.045)!important}.chat-row.active{background:rgba(125,211,252,.09)!important;box-shadow:inset -3px 0 var(--pr-accent)}
.avatar{flex-shrink:0;overflow:hidden;background-color:#26303b!important;background-size:cover!important;background-position:center!important}
.chat-topbar{background:rgba(17,19,24,.96)!important;border-bottom:1px solid var(--pr-line)!important}
.chat-composer{border:1px solid var(--pr-line)!important;background:#17191f!important;box-shadow:0 8px 26px rgba(0,0,0,.18)!important}
.composer-input{min-width:0!important;resize:none!important}.action-btn,.pr-tool-btn{flex-shrink:0;transition:transform .12s ease,background .12s ease!important}.action-btn:active,.pr-tool-btn:active{transform:scale(.94)}
.pr-bottom-nav{border-color:rgba(255,255,255,.1)!important;background:#15171c!important;box-shadow:0 8px 28px rgba(0,0,0,.28)!important}
.pr-nav-item.active{background:var(--pr-accent-soft)!important;color:#d9f3ff!important}.pr-nav-item.active:after{content:"";position:absolute;top:4px;width:18px;height:3px;border-radius:9px;background:var(--pr-accent)}
.pr-search-field,.search-container input{min-height:44px;border-radius:14px!important}
.modal-card{border:1px solid var(--pr-line)!important;box-shadow:0 20px 70px rgba(0,0,0,.45)!important}
.pr-contact-row,.pr-profile-actions button,.pr-setting-row{transition:background .16s ease,border-color .16s ease}
.pr-contact-row:active,.pr-profile-actions button:active{transform:scale(.99)}img{max-width:100%}
@media(max-width:768px){.tg-app{height:100dvh!important;min-height:0!important;overflow:hidden!important}.sidebar{height:100dvh!important;overflow:hidden!important}.chat-list{overscroll-behavior:contain!important;-webkit-overflow-scrolling:touch!important}.chat-main.mobile-active{overflow:hidden!important;overscroll-behavior:none!important}.chat-messages{overflow-y:auto!important;-webkit-overflow-scrolling:touch!important;scrollbar-width:thin!important;contain:layout paint!important}.chat-topbar{padding-left:10px!important;padding-right:10px!important}.chat-composer{gap:5px!important}.composer-input{padding:10px 9px!important}.pr-bottom-nav{height:70px!important;left:10px!important;right:10px!important;bottom:calc(8px + env(safe-area-inset-bottom))!important;border-radius:23px!important}.pr-nav-item>span{font-size:24px!important}.pr-nav-item>b{font-size:10px!important}.modal-overlay{padding:12px!important;align-items:flex-end!important}.modal-card{width:100%!important;max-width:560px!important;max-height:min(86dvh,760px)!important;overflow:auto!important;border-radius:24px 24px 18px 18px!important;padding:18px!important}.pr-contact-results{max-height:52dvh!important}}
@media(min-width:769px){.modal-card{max-height:90vh;overflow:auto}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}
</style>
</body>
</html>
"""

if __name__ == "__main__":
    socketio.run(app, host=os.environ.get("HOST","0.0.0.0"), port=int(os.environ.get("PORT","5000")), debug=False, allow_unsafe_werkzeug=True)

# Keyboard shortcuts are installed client-side in the main application template.
