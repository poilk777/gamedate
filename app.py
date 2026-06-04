import os
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, session, jsonify
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://gamedate:gamedate@db/gamedate')


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS candidate_profiles (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
            role VARCHAR(100),
            skills TEXT[],
            portfolio_url TEXT,
            bio TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            genre VARCHAR(100),
            engine VARCHAR(100),
            status VARCHAR(50) DEFAULT 'recruiting',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS project_roles (
            id SERIAL PRIMARY KEY,
            project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
            role_name VARCHAR(100) NOT NULL,
            skills_required TEXT[],
            description TEXT,
            filled BOOLEAN DEFAULT FALSE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS swipes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            target_type VARCHAR(20) NOT NULL,
            target_id INTEGER NOT NULL,
            direction VARCHAR(10) NOT NULL,
            project_context INTEGER,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, target_type, target_id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS invitations (
            id SERIAL PRIMARY KEY,
            project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
            candidate_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            from_owner BOOLEAN NOT NULL,
            message TEXT,
            status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(project_id, candidate_id)
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    return render_template('index.html')


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    d = request.json or {}
    email = d.get('email', '').strip().lower()
    password = d.get('password', '')
    name = d.get('name', '').strip()
    if not email or not password or not name:
        return jsonify({'error': 'Заполните все поля'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Пароль минимум 6 символов'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        if cur.fetchone():
            return jsonify({'error': 'Email уже зарегистрирован'}), 400
        cur.execute('INSERT INTO users (email,password_hash,name) VALUES (%s,%s,%s) RETURNING id,name',
                    (email, hash_pw(password), name))
        user = cur.fetchone()
        conn.commit()
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        return jsonify({'ok': True, 'name': user['name']})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close(); conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    d = request.json or {}
    email = d.get('email', '').strip().lower()
    password = d.get('password', '')
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT id,name FROM users WHERE email=%s AND password_hash=%s',
                    (email, hash_pw(password)))
        user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Неверный email или пароль'}), 401
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        return jsonify({'ok': True, 'name': user['name']})
    finally:
        cur.close(); conn.close()


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False})
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT * FROM candidate_profiles WHERE user_id=%s', (session['user_id'],))
        cp = cur.fetchone()
        cur.execute('SELECT COUNT(*) as c FROM projects WHERE owner_id=%s', (session['user_id'],))
        pc = cur.fetchone()['c']
        return jsonify({
            'logged_in': True,
            'id': session['user_id'],
            'name': session['user_name'],
            'candidate': dict(cp) if cp else None,
            'projects_count': pc
        })
    finally:
        cur.close(); conn.close()


# ── Candidate Profile ─────────────────────────────────────────────────────────

@app.route('/api/profile/candidate', methods=['GET', 'POST'])
@login_required
def candidate_profile():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        if request.method == 'GET':
            cur.execute('SELECT * FROM candidate_profiles WHERE user_id=%s', (session['user_id'],))
            p = cur.fetchone()
            return jsonify(dict(p) if p else {})
        d = request.json or {}
        role = d.get('role', '')
        skills = d.get('skills', [])
        portfolio_url = d.get('portfolio_url', '')
        bio = d.get('bio', '')
        cur.execute('SELECT id FROM candidate_profiles WHERE user_id=%s', (session['user_id'],))
        if cur.fetchone():
            cur.execute("""
                UPDATE candidate_profiles
                SET role=%s, skills=%s, portfolio_url=%s, bio=%s, updated_at=NOW()
                WHERE user_id=%s RETURNING *
            """, (role, skills, portfolio_url, bio, session['user_id']))
        else:
            cur.execute("""
                INSERT INTO candidate_profiles (user_id,role,skills,portfolio_url,bio)
                VALUES (%s,%s,%s,%s,%s) RETURNING *
            """, (session['user_id'], role, skills, portfolio_url, bio))
        p = cur.fetchone()
        conn.commit()
        return jsonify({'ok': True, 'profile': dict(p)})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close(); conn.close()


# ── Projects ──────────────────────────────────────────────────────────────────

@app.route('/api/projects', methods=['GET'])
@login_required
def my_projects():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT p.*,
                   (SELECT COUNT(*) FROM project_roles WHERE project_id=p.id) as roles_count,
                   (SELECT COUNT(*) FROM invitations WHERE project_id=p.id) as invites_count
            FROM projects p WHERE p.owner_id=%s ORDER BY p.created_at DESC
        """, (session['user_id'],))
        return jsonify([dict(r) for r in cur.fetchall()])
    finally:
        cur.close(); conn.close()


@app.route('/api/projects', methods=['POST'])
@login_required
def create_project():
    d = request.json or {}
    title = d.get('title', '').strip()
    if not title:
        return jsonify({'error': 'Название обязательно'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO projects (owner_id,title,description,genre,engine)
            VALUES (%s,%s,%s,%s,%s) RETURNING *
        """, (session['user_id'], title, d.get('description',''),
               d.get('genre',''), d.get('engine','')))
        project = cur.fetchone()
        for r in d.get('roles', []):
            cur.execute("""
                INSERT INTO project_roles (project_id,role_name,skills_required,description)
                VALUES (%s,%s,%s,%s)
            """, (project['id'], r.get('role_name'), r.get('skills',[]), r.get('description','')))
        conn.commit()
        return jsonify({'ok': True, 'project': dict(project)})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close(); conn.close()


@app.route('/api/projects/<int:pid>')
@login_required
def get_project(pid):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT p.*, u.name as owner_name FROM projects p
            JOIN users u ON u.id=p.owner_id WHERE p.id=%s
        """, (pid,))
        p = cur.fetchone()
        if not p:
            return jsonify({'error': 'Не найден'}), 404
        cur.execute('SELECT * FROM project_roles WHERE project_id=%s', (pid,))
        result = dict(p)
        result['roles'] = [dict(r) for r in cur.fetchall()]
        return jsonify(result)
    finally:
        cur.close(); conn.close()


# ── Swipe ─────────────────────────────────────────────────────────────────────

@app.route('/api/swipe/candidates')
@login_required
def swipe_candidates():
    """Return one candidate card for the owner to swipe on."""
    pid = request.args.get('project_id', type=int)
    filter_role = request.args.get('role', '')
    if not pid:
        return jsonify({'error': 'project_id required'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT id FROM projects WHERE id=%s AND owner_id=%s', (pid, session['user_id']))
        if not cur.fetchone():
            return jsonify({'error': 'Нет доступа'}), 403
        cur.execute("""
            SELECT role_name FROM project_roles
            WHERE project_id=%s AND filled=FALSE
        """, (pid,))
        open_roles = [r['role_name'] for r in cur.fetchall()]
        if not open_roles:
            return jsonify({'card': None, 'message': 'Все роли уже заполнены'})
        roles_to_search = [filter_role] if filter_role in open_roles else open_roles
        cur.execute("""
            SELECT cp.*, u.name, u.id as user_id
            FROM candidate_profiles cp
            JOIN users u ON u.id=cp.user_id
            WHERE cp.role=ANY(%s)
              AND cp.is_active=TRUE
              AND cp.user_id != %s
              AND cp.user_id NOT IN (
                  SELECT target_id FROM swipes
                  WHERE user_id=%s AND target_type='candidate' AND project_context=%s
              )
              AND cp.user_id NOT IN (
                  SELECT candidate_id FROM invitations WHERE project_id=%s AND from_owner=TRUE
              )
            ORDER BY cp.updated_at DESC
            LIMIT 1
        """, (roles_to_search, session['user_id'], session['user_id'], pid, pid))
        card = cur.fetchone()
        return jsonify({'card': dict(card) if card else None,
                        'message': 'Кандидаты закончились' if not card else '',
                        'open_roles': open_roles})
    finally:
        cur.close(); conn.close()


@app.route('/api/swipe/projects')
@login_required
def swipe_projects():
    """Return one project card for the candidate to swipe on."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute('SELECT role FROM candidate_profiles WHERE user_id=%s', (session['user_id'],))
        cp = cur.fetchone()
        if not cp:
            return jsonify({'card': None, 'message': 'Сначала создайте профиль кандидата'})
        cur.execute("""
            SELECT DISTINCT ON (p.id) p.*, u.name as owner_name,
                   array_agg(pr.role_name) OVER (PARTITION BY p.id) as open_roles
            FROM projects p
            JOIN users u ON u.id=p.owner_id
            JOIN project_roles pr ON pr.project_id=p.id AND pr.filled=FALSE
            WHERE p.status='recruiting'
              AND p.owner_id != %s
              AND pr.role_name = %s
              AND p.id NOT IN (
                  SELECT target_id FROM swipes
                  WHERE user_id=%s AND target_type='project'
              )
              AND p.id NOT IN (
                  SELECT project_id FROM invitations WHERE candidate_id=%s
              )
            ORDER BY p.id, p.created_at DESC
            LIMIT 1
        """, (session['user_id'], cp['role'], session['user_id'], session['user_id']))
        card = cur.fetchone()
        return jsonify({'card': dict(card) if card else None,
                        'message': 'Проекты закончились' if not card else ''})
    finally:
        cur.close(); conn.close()


@app.route('/api/swipe', methods=['POST'])
@login_required
def record_swipe():
    d = request.json or {}
    target_type = d.get('target_type')
    target_id = d.get('target_id')
    direction = d.get('direction')
    project_id = d.get('project_id')
    if target_type not in ('candidate', 'project') or direction not in ('like', 'pass'):
        return jsonify({'error': 'Неверные параметры'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO swipes (user_id,target_type,target_id,direction,project_context)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (user_id,target_type,target_id)
            DO UPDATE SET direction=EXCLUDED.direction, project_context=EXCLUDED.project_context
        """, (session['user_id'], target_type, target_id, direction, project_id))
        match = None
        if direction == 'like':
            if target_type == 'candidate' and project_id:
                cur.execute("""
                    INSERT INTO invitations (project_id,candidate_id,from_owner,status)
                    VALUES (%s,%s,TRUE,'pending')
                    ON CONFLICT (project_id,candidate_id) DO NOTHING
                    RETURNING id
                """, (project_id, target_id))
                inv = cur.fetchone()
                if inv:
                    match = {'type': 'invite_sent'}
            elif target_type == 'project':
                cur.execute("""
                    SELECT id FROM invitations
                    WHERE project_id=%s AND candidate_id=%s AND from_owner=TRUE AND status='pending'
                """, (target_id, session['user_id']))
                existing = cur.fetchone()
                if existing:
                    cur.execute("UPDATE invitations SET status='accepted' WHERE id=%s", (existing['id'],))
                    match = {'type': 'match', 'message': '🎮 Это мэтч!'}
                else:
                    cur.execute("""
                        INSERT INTO invitations (project_id,candidate_id,from_owner,status)
                        VALUES (%s,%s,FALSE,'pending')
                        ON CONFLICT (project_id,candidate_id) DO NOTHING
                    """, (target_id, session['user_id']))
        conn.commit()
        return jsonify({'ok': True, 'match': match})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close(); conn.close()


# ── Invitations ───────────────────────────────────────────────────────────────

@app.route('/api/invitations')
@login_required
def get_invitations():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT i.*, p.title as project_title, p.genre, u.name as owner_name
            FROM invitations i
            JOIN projects p ON p.id=i.project_id
            JOIN users u ON u.id=p.owner_id
            WHERE i.candidate_id=%s
            ORDER BY i.created_at DESC
        """, (session['user_id'],))
        as_candidate = [dict(r) for r in cur.fetchall()]
        cur.execute("""
            SELECT i.*, p.title as project_title,
                   cp.role as candidate_role, cp.skills as candidate_skills,
                   cp.portfolio_url, u.name as candidate_name
            FROM invitations i
            JOIN projects p ON p.id=i.project_id
            JOIN users u ON u.id=i.candidate_id
            LEFT JOIN candidate_profiles cp ON cp.user_id=i.candidate_id
            WHERE p.owner_id=%s
            ORDER BY i.created_at DESC
        """, (session['user_id'],))
        as_owner = [dict(r) for r in cur.fetchall()]
        return jsonify({'as_candidate': as_candidate, 'as_owner': as_owner})
    finally:
        cur.close(); conn.close()


@app.route('/api/invitations/<int:iid>/respond', methods=['POST'])
@login_required
def respond_invitation(iid):
    action = (request.json or {}).get('action')
    if action not in ('accept', 'reject'):
        return jsonify({'error': 'Неверное действие'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT i.*, p.owner_id FROM invitations i
            JOIN projects p ON p.id=i.project_id WHERE i.id=%s
        """, (iid,))
        inv = cur.fetchone()
        if not inv:
            return jsonify({'error': 'Не найдено'}), 404
        allowed = (
            (inv['from_owner'] and inv['candidate_id'] == session['user_id']) or
            (not inv['from_owner'] and inv['owner_id'] == session['user_id'])
        )
        if not allowed:
            return jsonify({'error': 'Нет доступа'}), 403
        status = 'accepted' if action == 'accept' else 'rejected'
        cur.execute('UPDATE invitations SET status=%s WHERE id=%s', (status, iid))
        conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close(); conn.close()


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
