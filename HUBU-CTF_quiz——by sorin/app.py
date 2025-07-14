import os
import sqlite3
import hashlib
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = os.getenv("DATABASE", "quiz.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change_me_to_a_random_secret")
DEBUG      = os.getenv("FLASK_DEBUG", "0") == "1"

ADMIN_NAME = "hubuctfadmin"
ADMIN_DEFAULT_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
BONUS_VALUES = {0: 100, 1: 50, 2: 20}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    TEMPLATES_AUTO_RELOAD=True,
)

# -------- DB helpers ----------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False, isolation_level=None)
        db.row_factory = sqlite3.Row
    return db

def query_db(q, args=(), one=False):
    cur = get_db().execute(q, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def exec_db(q, args=()):
    cur = get_db().execute(q, args)
    get_db().commit()
    cur.close()

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        answer_hash TEXT NOT NULL,
        points INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        submitted_hash TEXT NOT NULL,
        is_correct INTEGER NOT NULL,
        bonus INTEGER NOT NULL DEFAULT 0,
        submitted_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(question_id) REFERENCES questions(id)
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS recent_events (
        id INTEGER PRIMARY KEY,
        event TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """
    get_db().executescript(schema)
    # create admin
    admin = query_db("SELECT * FROM users WHERE name=?", (ADMIN_NAME,), one=True)
    if not admin:
        exec_db("INSERT INTO users (name, password_hash, is_admin, created_at) VALUES (?,?,1,?)",
                (ADMIN_NAME, generate_password_hash(ADMIN_DEFAULT_PASSWORD), datetime.now(timezone.utc).isoformat()))
    # 清理旧事件
    exec_db("DELETE FROM recent_events WHERE created_at < datetime('now', '-1 day')")
with app.app_context():
    init_db()

# ---------- auth utils -----------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return query_db("SELECT * FROM users WHERE id=?", (uid,), one=True)

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper
def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u or not u["is_admin"]:
            abort(403)
        return f(*a, **kw)
    return wrapper

# ---------- auth routes ----------
@app.route("/")
def root():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        pwd  = request.form.get("password","")
        if not name or not pwd:
            flash("用户名和密码不能为空")
            return redirect(url_for("register"))
        if query_db("SELECT 1 FROM users WHERE name=?", (name,), one=True):
            flash("用户名已存在")
            return redirect(url_for("register"))
        exec_db("INSERT INTO users (name,password_hash,created_at) VALUES (?,?,?)",
                (name, generate_password_hash(pwd), datetime.now(timezone.utc).isoformat()))
        flash("注册成功，请登录")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        pwd  = request.form.get("password","")
        user = query_db("SELECT * FROM users WHERE name=?", (name,), one=True)
        if not user or not check_password_hash(user["password_hash"], pwd):
            flash("用户名或密码错误")
            return redirect(url_for("login"))
        session["user_id"] = user["id"]
        flash("登录成功")
        return redirect(url_for("admin_dashboard" if user["is_admin"] else "quiz"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("已退出")
    return redirect(url_for("login"))

# -------- helper for ranking -----
def compute_rank(user_id):
    rows = query_db(
        """
        SELECT u.id,
               COALESCE(SUM(CASE WHEN s.is_correct=1 THEN q.points + s.bonus ELSE 0 END),0) AS score,
               MAX(s.submitted_at) AS last_submit
        FROM users u
        LEFT JOIN submissions s ON s.user_id = u.id
        LEFT JOIN questions q ON q.id = s.question_id
        WHERE u.is_admin = 0
        GROUP BY u.id
        ORDER BY score DESC, last_submit ASC
        """)
    for idx, r in enumerate(rows, 1):
        if r["id"] == user_id:
            return idx, r["score"]
    return None, 0

# -------- quiz routes ------------
@app.route("/quiz")
@login_required
def quiz():
    user = current_user()
    if user["is_admin"]:
        return redirect(url_for("admin_dashboard"))

    rank, score = compute_rank(user["id"])
    questions = query_db("SELECT id, title, description FROM questions ORDER BY id")
    solved = {q["id"]: bool(query_db("SELECT 1 FROM submissions WHERE user_id=? AND question_id=? AND is_correct=1",
                                      (user["id"], q["id"]), one=True)) for q in questions}
    notices = query_db("SELECT message FROM notifications ORDER BY id DESC LIMIT 10")
    return render_template("quiz.html", user=user, rank=rank, score=score,
                           questions=questions, solved=solved, notices=notices)

@app.route("/submit/<int:qid>", methods=["POST"])
@login_required
def submit(qid):
    user = current_user()
    if user["is_admin"]:
        flash("管理员无法答题")
        return redirect(url_for("admin_dashboard"))
    answer = request.form.get("answer","").strip()
    if not answer:
        flash("请输入答案")
        return redirect(url_for("quiz"))
    if query_db("SELECT 1 FROM submissions WHERE user_id=? AND question_id=? AND is_correct=1",
                (user["id"], qid), one=True):
        flash("已解出，重复提交不计分")
        return redirect(url_for("quiz"))
    answer_hash = hashlib.sha256(answer.encode()).hexdigest()
    qrow = query_db("SELECT title, answer_hash, points FROM questions WHERE id=?", (qid,), one=True)
    if not qrow:
        flash("题目不存在")
        return redirect(url_for("quiz"))
    is_correct = int(answer_hash == qrow["answer_hash"])
    bonus = 0
    first_rank = None
    if is_correct:
        cnt = query_db("SELECT COUNT(DISTINCT user_id) AS c FROM submissions WHERE question_id=? AND is_correct=1",
                       (qid,), one=True)["c"]
        first_rank = cnt  # 0 for first solver
        bonus = BONUS_VALUES.get(cnt, 0)
        
        # 添加事件记录
        event_msg = f"{user['name']} 解出了题目《{qrow['title']}》"
        if bonus > 0:
            event_msg += f"，获得 {qrow['points'] + bonus} 分（含 {bonus} 分加成）"
        exec_db("INSERT INTO recent_events (event, created_at) VALUES (?,?)",
                (event_msg, datetime.now(timezone.utc).isoformat()))
        
        # 三血通知
        if cnt < 3:
            blood_names = {0: "一血", 1: "二血", 2: "三血"}
            exec_db("INSERT INTO notifications (message, created_at) VALUES (?,?)",
                    (f"{user['name']} 获得了题目《{qrow['title']}》的{blood_names[cnt]}！",
                     datetime.now(timezone.utc).isoformat()))
    exec_db("INSERT INTO submissions (user_id,question_id,submitted_hash,is_correct,bonus,submitted_at) "
            "VALUES (?,?,?,?,?,?)",
            (user["id"], qid, answer_hash, is_correct, bonus, datetime.now(timezone.utc).isoformat()))
    if is_correct:
        msg = f"回答正确！+{qrow['points']}分"
        if bonus > 0:
            msg += f"（+{bonus}分加成）"
        if first_rank == 0:
            msg = "（一血！）" + msg
        elif first_rank == 1:
            msg = "（二血！）" + msg
        elif first_rank == 2:
            msg = "（三血！）" + msg
    else:
        msg = "答案错误"
    flash(msg)
    return redirect(url_for("quiz"))

# -------- leaderboard ----------
@app.route("/leaderboard")
@login_required
def leaderboard():
    rows = query_db(
        """
        SELECT u.name,
               COALESCE(SUM(CASE WHEN s.is_correct=1 THEN q.points + s.bonus ELSE 0 END),0) AS score,
               MAX(s.submitted_at) AS last_submit
        FROM users u
        LEFT JOIN submissions s ON s.user_id = u.id
        LEFT JOIN questions q ON q.id = s.question_id
        WHERE u.is_admin = 0
        GROUP BY u.id
        ORDER BY score DESC, last_submit ASC
        """)
    
    # 获取最近事件
    events = query_db("SELECT event FROM recent_events ORDER BY id DESC LIMIT 10")
    
    # 获取小排行榜数据
    # 一血王
    first_blood_kings = query_db("""
        SELECT u.name, COUNT(*) AS count
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        WHERE s.bonus = 100 AND s.is_correct = 1
        GROUP BY s.user_id
        ORDER BY count DESC
        LIMIT 3
    """)
    
    # 0解王（唯一解出题目的用户）
    unique_solvers = query_db("""
        SELECT u.name, COUNT(DISTINCT s.question_id) AS count
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        WHERE s.is_correct = 1
        AND s.question_id IN (
            SELECT question_id
            FROM submissions
            WHERE is_correct = 1
            GROUP BY question_id
            HAVING COUNT(DISTINCT user_id) = 1
        )
        GROUP BY s.user_id
        ORDER BY count DESC
        LIMIT 3
    """)
    
    # 做题王（解题数量最多）
    problem_solvers = query_db("""
        SELECT u.name, COUNT(DISTINCT s.question_id) AS count
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        WHERE s.is_correct = 1
        GROUP BY s.user_id
        ORDER BY count DESC
        LIMIT 3
    """)
    
    return render_template("leaderboard.html", rows=rows, events=events,
                          first_blood_kings=first_blood_kings,
                          unique_solvers=unique_solvers,
                          problem_solvers=problem_solvers)

# -------- admin routes ----------
@app.route("/admin")
@admin_required
def admin_dashboard():
    questions = query_db("SELECT * FROM questions ORDER BY id")
    return render_template("admin.html", questions=questions)

@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():
    title = request.form.get("title","").strip()
    description = request.form.get("description","").strip()
    answer = request.form.get("answer","").strip()
    points = request.form.get("points","").strip()
    if not title or not answer or not points.isdigit():
        flash("信息不完整")
        return redirect(url_for("admin_dashboard"))
    exec_db("INSERT INTO questions (title, description, answer_hash, points) VALUES (?,?,?,?)",
            (title, description, hashlib.sha256(answer.encode()).hexdigest(), int(points)))
    flash("已添加题目")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/update/<int:qid>", methods=["POST"])
@admin_required
def admin_update(qid):
    title = request.form.get("title","").strip()
    description = request.form.get("description","").strip()
    answer = request.form.get("answer","").strip()
    points = request.form.get("points","").strip()
    if not title or not answer or not points.isdigit():
        flash("信息不完整")
        return redirect(url_for("admin_dashboard"))
    exec_db("UPDATE questions SET title=?, description=?, answer_hash=?, points=? WHERE id=?",
            (title, description, hashlib.sha256(answer.encode()).hexdigest(), int(points), qid))
    flash("已更新题目")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete/<int:qid>", methods=["POST"])
@admin_required
def admin_delete(qid):
    exec_db("DELETE FROM questions WHERE id=?", (qid,))
    flash("已删除题目")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/notify", methods=["POST"])
@admin_required
def admin_notify():
    message = request.form.get("message","").strip()
    if not message:
        flash("公告内容不能为空")
        return redirect(url_for("admin_dashboard"))
    exec_db("INSERT INTO notifications (message, created_at) VALUES (?,?)",
            (message, datetime.now(timezone.utc).isoformat()))
    flash("公告已发布")
    return redirect(url_for("admin_dashboard"))
# 在app.py中添加以下路由
@app.route("/question/<int:qid>")
@login_required
def question_detail(qid):
    user = current_user()
    if user["is_admin"]:
        flash("管理员无法答题")
        return redirect(url_for("admin_dashboard"))
    
    qrow = query_db("SELECT id, title, description FROM questions WHERE id=?", (qid,), one=True)
    if not qrow:
        flash("题目不存在")
        return redirect(url_for("quiz"))
    
    solved = bool(query_db("SELECT 1 FROM submissions WHERE user_id=? AND question_id=? AND is_correct=1",
                          (user["id"], qid), one=True))
    
    return render_template("question_detail.html", question=qrow, solved=solved)

# -------- misc -----------
@app.template_filter("datetime_format")
def datetime_format(val):
    if not val: return ""
    return datetime.fromisoformat(val).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

@app.errorhandler(403)
def err403(e): return "403 Forbidden", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=DEBUG)