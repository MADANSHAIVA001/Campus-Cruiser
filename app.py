from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, json, secrets, time
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'campus_cruiser_multicollege_2024'
DB = 'campus_cruiser.db'

# ── DATABASE ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS colleges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            logo TEXT,
            theme TEXT DEFAULT 'dark',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','student','driver')),
            security_question TEXT,
            security_answer TEXT,
            must_change_password INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(college_id, email)
        );
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            start_point TEXT NOT NULL,
            end_point TEXT NOT NULL,
            stops TEXT DEFAULT '[]',
            distance_km REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS buses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            reg_no TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            driver_id INTEGER,
            route_id INTEGER,
            status TEXT DEFAULT 'idle',
            UNIQUE(college_id, reg_no)
        );
        CREATE TABLE IF NOT EXISTS drivers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            user_id INTEGER UNIQUE NOT NULL,
            phone TEXT,
            license_no TEXT,
            driver_id_no TEXT,
            bus_id INTEGER,
            temp_password TEXT,
            UNIQUE(college_id, driver_id_no)
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            user_id INTEGER UNIQUE NOT NULL,
            usn TEXT,
            admission_no TEXT,
            phone TEXT,
            bus_id INTEGER,
            boarding_point TEXT,
            department TEXT,
            semester TEXT,
            academic_year TEXT,
            cgpa TEXT,
            temp_password TEXT,
            UNIQUE(college_id, usn),
            UNIQUE(college_id, admission_no)
        );
        CREATE TABLE IF NOT EXISTS student_academics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            marks_obtained REAL,
            max_marks REAL DEFAULT 100,
            grade TEXT,
            semester TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS student_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            tech_stack TEXT,
            status TEXT DEFAULT 'ongoing',
            github_url TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS trip_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            bus_id INTEGER NOT NULL,
            driver_id INTEGER NOT NULL,
            route_id INTEGER,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            status TEXT DEFAULT 'active',
            lat REAL, lng REAL, speed REAL DEFAULT 0,
            last_updated TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            college_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            target_role TEXT DEFAULT 'all',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER
        );
        CREATE TABLE IF NOT EXISTS boarding_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            trip_id INTEGER NOT NULL,
            boarded INTEGER DEFAULT 0,
            boarded_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0
        );
    ''')
    conn.commit()
    conn.close()

def get_college(college_id):
    conn = get_db()
    c = conn.execute('SELECT * FROM colleges WHERE id=?', (college_id,)).fetchone()
    conn.close()
    return dict(c) if c else {'id':0,'name':'Campus Cruiser','logo':None,'theme':'dark'}

def cid():
    """Current college_id from session"""
    return session.get('college_id')

# ── AUTH HELPERS ──────────────────────────────────────────
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Access denied.', 'error')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── INDEX ─────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for(session['role'] + '_dashboard'))
    return redirect(url_for('login'))

# ── COLLEGE REGISTRATION ──────────────────────────────────
@app.route('/register-college', methods=['GET','POST'])
def register_college():
    college = {'name':'Campus Cruiser','logo':None,'theme':'dark'}
    if request.method == 'POST':
        college_name  = request.form.get('college_name','').strip()
        admin_name    = request.form.get('admin_name','').strip()
        admin_email   = request.form.get('admin_email','').strip()
        password      = request.form.get('password','')
        confirm       = request.form.get('confirm_password','')
        sec_q         = request.form.get('security_question','').strip()
        sec_a         = request.form.get('security_answer','').strip().lower()
        if not all([college_name, admin_name, admin_email, password, sec_q, sec_a]):
            flash('All fields are required.', 'error')
            return render_template('register_college.html', college=college)
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register_college.html', college=college)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register_college.html', college=college)
        logo_data = None
        if 'college_logo' in request.files:
            f = request.files['college_logo']
            if f and f.filename:
                import base64 as b64
                logo_bytes = f.read()
                ext = f.filename.rsplit('.',1)[-1].lower()
                mime = 'image/png' if ext=='png' else 'image/jpeg'
                logo_data = f'data:{mime};base64,' + b64.b64encode(logo_bytes).decode()
        conn = get_db()
        try:
            c = conn.cursor()
            # Check if this college email already has an admin
            existing = conn.execute(
                "SELECT u.id FROM users u JOIN colleges col ON u.college_id=col.id WHERE u.email=? AND u.role='admin'",
                (admin_email,)).fetchone()
            if existing:
                flash('An admin with this email already exists. Please login.', 'error')
                conn.close()
                return render_template('register_college.html', college=college)
            # Create new college entry
            c.execute('INSERT INTO colleges (name,logo) VALUES (?,?)', (college_name, logo_data))
            new_college_id = c.lastrowid
            # Create admin for this college
            hashed = generate_password_hash(password)
            c.execute('''INSERT INTO users (college_id,name,email,password,role,security_question,security_answer,must_change_password)
                         VALUES (?,?,?,?,'admin',?,?,0)''',
                      (new_college_id, admin_name, admin_email, hashed, sec_q, sec_a))
            conn.commit()
            flash(f'✅ College "{college_name}" registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            flash(f'Error: {str(e)}', 'error')
        finally:
            conn.close()
    # Show list of existing colleges
    conn = get_db()
    existing_colleges = conn.execute('SELECT id,name,created_at FROM colleges ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('register_college.html', college=college, existing_colleges=existing_colleges)

# ── LOGIN ─────────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    # Get college_id from query param for direct login
    preselect_college = request.args.get('college_id', type=int)
    conn = get_db()
    all_colleges = conn.execute('SELECT id,name,logo FROM colleges ORDER BY name').fetchall()
    conn.close()
    college = {'name':'Campus Cruiser','logo':None,'theme':'dark'}
    if preselect_college:
        conn = get_db()
        c = conn.execute('SELECT * FROM colleges WHERE id=?', (preselect_college,)).fetchone()
        conn.close()
        if c: college = dict(c)

    if request.method == 'POST':
        identifier  = request.form.get('identifier','').strip()
        password    = request.form.get('password','')
        college_id  = request.form.get('college_id', type=int)
        if not college_id:
            flash('Please select your college.', 'error')
            return render_template('login.html', college=college, all_colleges=all_colleges, preselect=preselect_college)
        conn = get_db()
        user = None
        # Try email
        user = conn.execute('SELECT * FROM users WHERE college_id=? AND email=?', (college_id, identifier)).fetchone()
        # Try USN
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN students s ON u.id=s.user_id WHERE u.college_id=? AND s.usn=?', (college_id, identifier)).fetchone()
            if row: user = row
        # Try admission_no
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN students s ON u.id=s.user_id WHERE u.college_id=? AND s.admission_no=?', (college_id, identifier)).fetchone()
            if row: user = row
        # Try driver_id_no
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN drivers d ON u.id=d.user_id WHERE u.college_id=? AND d.driver_id_no=?', (college_id, identifier)).fetchone()
            if row: user = row
        sel_college = conn.execute('SELECT * FROM colleges WHERE id=?', (college_id,)).fetchone()
        conn.close()
        if sel_college: college = dict(sel_college)
        if user and check_password_hash(user['password'], password):
            session['user_id']    = user['id']
            session['name']       = user['name']
            session['role']       = user['role']
            session['email']      = user['email']
            session['college_id'] = user['college_id']
            if user['must_change_password']:
                flash('Please set your new password and security question.', 'info')
                return redirect(url_for('first_login_setup'))
            return redirect(url_for(user['role'] + '_dashboard'))
        flash('Invalid credentials. Check your ID and password.', 'error')
    return render_template('login.html', college=college, all_colleges=all_colleges, preselect=preselect_college)

@app.route('/first-login-setup', methods=['GET','POST'])
def first_login_setup():
    if 'user_id' not in session: return redirect(url_for('login'))
    college = get_college(cid())
    if request.method == 'POST':
        new_pw  = request.form.get('new_password','')
        confirm = request.form.get('confirm_password','')
        sec_q   = request.form.get('security_question','').strip()
        sec_a   = request.form.get('security_answer','').strip().lower()
        if len(new_pw) < 6: flash('Password must be at least 6 characters.','error')
        elif new_pw != confirm: flash('Passwords do not match.','error')
        elif not sec_q or not sec_a: flash('Please set a security question and answer.','error')
        else:
            conn = get_db()
            conn.execute('UPDATE users SET password=?,security_question=?,security_answer=?,must_change_password=0 WHERE id=?',
                (generate_password_hash(new_pw), sec_q, sec_a, session['user_id']))
            conn.commit(); conn.close()
            flash('Account setup complete!', 'success')
            return redirect(url_for(session['role'] + '_dashboard'))
    return render_template('first_login_setup.html', college=college)

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    conn = get_db()
    all_colleges = conn.execute('SELECT id,name FROM colleges ORDER BY name').fetchall()
    conn.close()
    college = {'name':'Campus Cruiser','logo':None,'theme':'dark'}
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip()
        college_id = request.form.get('college_id', type=int)
        if not college_id:
            flash('Please select your college.','error')
            return render_template('forgot_password.html', college=college, all_colleges=all_colleges)
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE college_id=? AND email=?',(college_id,identifier)).fetchone()
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN students s ON u.id=s.user_id WHERE u.college_id=? AND s.usn=?',(college_id,identifier)).fetchone()
            if row: user=row
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN students s ON u.id=s.user_id WHERE u.college_id=? AND s.admission_no=?',(college_id,identifier)).fetchone()
            if row: user=row
        if not user:
            row = conn.execute('SELECT u.* FROM users u JOIN drivers d ON u.id=d.user_id WHERE u.college_id=? AND d.driver_id_no=?',(college_id,identifier)).fetchone()
            if row: user=row
        conn.close()
        if user:
            if user['security_question']:
                session['reset_user_id'] = user['id']
                session['reset_college_id'] = college_id
                return redirect(url_for('security_question_page'))
            flash('No security question set. Contact your admin.','error')
        else:
            flash('No account found.','error')
    return render_template('forgot_password.html', college=college, all_colleges=all_colleges)

@app.route('/security-question', methods=['GET','POST'])
def security_question_page():
    uid = session.get('reset_user_id')
    if not uid: return redirect(url_for('forgot_password'))
    college = get_college(session.get('reset_college_id',0))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    conn.close()
    if not user: return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        answer = request.form.get('answer','').strip().lower()
        if answer == (user['security_answer'] or '').lower():
            token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(minutes=30)
            conn = get_db()
            conn.execute('DELETE FROM password_resets WHERE user_id=?',(uid,))
            conn.execute('INSERT INTO password_resets (user_id,token,expires_at) VALUES (?,?,?)',(uid,token,expires))
            conn.commit(); conn.close()
            session['reset_token'] = token
            return redirect(url_for('reset_password'))
        flash('Incorrect answer.','error')
    return render_template('security_question.html', question=user['security_question'], college=college)

@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    token = session.get('reset_token')
    if not token: return redirect(url_for('forgot_password'))
    college = get_college(session.get('reset_college_id',0))
    conn = get_db()
    reset = conn.execute("SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at>?",(token,datetime.now())).fetchone()
    if not reset:
        conn.close()
        flash('Reset link expired.','error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_pw  = request.form.get('password','')
        confirm = request.form.get('confirm_password','')
        if len(new_pw) < 6: flash('Password must be at least 6 characters.','error')
        elif new_pw != confirm: flash('Passwords do not match.','error')
        else:
            conn.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new_pw),reset['user_id']))
            conn.execute('UPDATE password_resets SET used=1 WHERE token=?',(token,))
            conn.commit(); conn.close()
            session.pop('reset_token',None); session.pop('reset_user_id',None)
            flash('Password reset! Please log in.','success')
            return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', college=college)

@app.route('/change-password', methods=['GET','POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    college = get_college(cid())
    if request.method == 'POST':
        current = request.form.get('current_password','')
        new_pw  = request.form.get('new_password','')
        confirm = request.form.get('confirm_password','')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
        if not check_password_hash(user['password'], current): flash('Current password incorrect.','error')
        elif len(new_pw) < 6: flash('New password too short.','error')
        elif new_pw != confirm: flash('Passwords do not match.','error')
        else:
            conn.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new_pw),session['user_id']))
            conn.commit(); conn.close()
            flash('Password changed!','success')
            return redirect(url_for(session['role']+'_dashboard'))
        conn.close()
    return render_template('change_password.html', college=college)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── ADMIN ─────────────────────────────────────────────────
@app.route('/admin')
@login_required('admin')
def admin_dashboard():
    conn = get_db()
    college_id = cid()
    stats = {
        'buses':        conn.execute('SELECT COUNT(*) FROM buses WHERE college_id=?',(college_id,)).fetchone()[0],
        'drivers':      conn.execute('SELECT COUNT(*) FROM drivers WHERE college_id=?',(college_id,)).fetchone()[0],
        'students':     conn.execute('SELECT COUNT(*) FROM students WHERE college_id=?',(college_id,)).fetchone()[0],
        'routes':       conn.execute('SELECT COUNT(*) FROM routes WHERE college_id=?',(college_id,)).fetchone()[0],
        'active_trips': conn.execute("SELECT COUNT(*) FROM trip_logs WHERE college_id=? AND status='active'",(college_id,)).fetchone()[0],
    }
    active_trips = conn.execute('''
        SELECT t.*,b.reg_no,u.name as driver_name,r.name as route_name
        FROM trip_logs t JOIN buses b ON t.bus_id=b.id
        JOIN drivers d ON t.driver_id=d.id JOIN users u ON d.user_id=u.id
        LEFT JOIN routes r ON t.route_id=r.id
        WHERE t.college_id=? AND t.status='active' ''',(college_id,)).fetchall()
    notifications = conn.execute('SELECT * FROM notifications WHERE college_id=? ORDER BY created_at DESC LIMIT 5',(college_id,)).fetchall()
    conn.close()
    college = get_college(college_id)
    return render_template('admin/dashboard.html', stats=stats, active_trips=active_trips, notifications=notifications, college=college)

@app.route('/admin/settings', methods=['GET','POST'])
@login_required('admin')
def admin_settings():
    college_id = cid()
    college = get_college(college_id)
    if request.method == 'POST':
        college_name = request.form.get('college_name','').strip()
        theme = request.form.get('theme','dark')
        logo_data = college.get('logo')
        if 'college_logo' in request.files:
            f = request.files['college_logo']
            if f and f.filename:
                import base64 as b64
                logo_bytes = f.read()
                ext = f.filename.rsplit('.',1)[-1].lower()
                mime = 'image/png' if ext=='png' else 'image/jpeg'
                logo_data = f'data:{mime};base64,' + b64.b64encode(logo_bytes).decode()
        conn = get_db()
        conn.execute('UPDATE colleges SET name=?,logo=?,theme=? WHERE id=?',(college_name,logo_data,theme,college_id))
        conn.commit(); conn.close()
        flash('Settings saved!','success')
        return redirect(url_for('admin_settings'))
    return render_template('admin/settings.html', college=college)

# ── ADMIN: BUSES ──────────────────────────────────────────
@app.route('/admin/buses')
@login_required('admin')
def admin_buses():
    conn = get_db(); cid_ = cid()
    buses = conn.execute('''SELECT b.*,u.name as driver_name,r.name as route_name
        FROM buses b LEFT JOIN drivers d ON b.driver_id=d.id
        LEFT JOIN users u ON d.user_id=u.id LEFT JOIN routes r ON b.route_id=r.id
        WHERE b.college_id=?''',(cid_,)).fetchall()
    drivers = conn.execute('SELECT d.id,u.name FROM drivers d JOIN users u ON d.user_id=u.id WHERE d.college_id=?',(cid_,)).fetchall()
    routes  = conn.execute('SELECT * FROM routes WHERE college_id=?',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/buses.html', buses=buses, drivers=drivers, routes=routes, college=get_college(cid_))

@app.route('/admin/buses/add', methods=['POST'])
@login_required('admin')
def admin_add_bus():
    conn = get_db()
    try:
        conn.execute('INSERT INTO buses (college_id,reg_no,capacity,driver_id,route_id,status) VALUES (?,?,?,?,?,?)',
            (cid(), request.form['reg_no'].upper(), int(request.form['capacity']),
             request.form.get('driver_id') or None, request.form.get('route_id') or None,
             request.form.get('status','idle')))
        conn.commit(); flash('Bus added.','success')
    except sqlite3.IntegrityError: flash('Registration number already exists.','error')
    finally: conn.close()
    return redirect(url_for('admin_buses'))

@app.route('/admin/buses/edit/<int:bid>', methods=['POST'])
@login_required('admin')
def admin_edit_bus(bid):
    conn = get_db()
    conn.execute('UPDATE buses SET reg_no=?,capacity=?,driver_id=?,route_id=?,status=? WHERE id=? AND college_id=?',
        (request.form['reg_no'].upper(), int(request.form['capacity']),
         request.form.get('driver_id') or None, request.form.get('route_id') or None,
         request.form.get('status','idle'), bid, cid()))
    conn.commit(); conn.close(); flash('Bus updated.','success')
    return redirect(url_for('admin_buses'))

@app.route('/admin/buses/delete/<int:bid>', methods=['POST'])
@login_required('admin')
def admin_delete_bus(bid):
    conn = get_db()
    conn.execute('DELETE FROM buses WHERE id=? AND college_id=?',(bid,cid()))
    conn.commit(); conn.close(); flash('Bus deleted.','success')
    return redirect(url_for('admin_buses'))

# ── ADMIN: DRIVERS ────────────────────────────────────────
@app.route('/admin/drivers')
@login_required('admin')
def admin_drivers():
    conn = get_db(); cid_ = cid()
    drivers = conn.execute('''SELECT d.*,u.name,u.email,b.reg_no as bus_reg
        FROM drivers d JOIN users u ON d.user_id=u.id LEFT JOIN buses b ON d.bus_id=b.id
        WHERE d.college_id=?''',(cid_,)).fetchall()
    buses = conn.execute('SELECT * FROM buses WHERE college_id=?',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/drivers.html', drivers=drivers, buses=buses, college=get_college(cid_))

@app.route('/admin/drivers/add', methods=['POST'])
@login_required('admin')
def admin_add_driver():
    conn = get_db(); cid_ = cid()
    try:
        name = request.form['name'].strip(); email = request.form['email'].strip()
        phone = request.form.get('phone','').strip(); license_no = request.form.get('license_no','').strip()
        driver_id_no = request.form.get('driver_id_no','').strip()
        temp_password = request.form.get('temp_password','Driver@123').strip()
        hashed = generate_password_hash(temp_password)
        c = conn.cursor()
        c.execute('INSERT INTO users (college_id,name,email,password,role,must_change_password) VALUES (?,?,?,?,\'driver\',1)',
            (cid_, name, email, hashed))
        uid = c.lastrowid
        c.execute('INSERT INTO drivers (college_id,user_id,phone,license_no,driver_id_no,temp_password) VALUES (?,?,?,?,?,?)',
            (cid_, uid, phone or None, license_no or None, driver_id_no or None, temp_password))
        conn.commit()
        flash(f'Driver {name} added. Login ID: {driver_id_no or email} / Password: {temp_password}','success')
    except sqlite3.IntegrityError as e: flash(f'Error: {str(e)}','error')
    finally: conn.close()
    return redirect(url_for('admin_drivers'))

@app.route('/admin/drivers/assign_bus', methods=['POST'])
@login_required('admin')
def admin_assign_bus_driver():
    conn = get_db()
    did = request.form['driver_id']; bid = request.form.get('bus_id') or None
    conn.execute('UPDATE drivers SET bus_id=? WHERE id=? AND college_id=?',(bid,did,cid()))
    if bid: conn.execute('UPDATE buses SET driver_id=? WHERE id=? AND college_id=?',(did,bid,cid()))
    conn.commit(); conn.close(); flash('Bus assigned to driver.','success')
    return redirect(url_for('admin_drivers'))

@app.route('/admin/drivers/set-password/<int:did>', methods=['POST'])
@login_required('admin')
def admin_set_driver_password(did):
    conn = get_db()
    driver = conn.execute('SELECT user_id FROM drivers WHERE id=? AND college_id=?',(did,cid())).fetchone()
    if driver:
        tmp = request.form.get('temp_password','').strip()
        if tmp:
            conn.execute('UPDATE users SET password=?,must_change_password=1 WHERE id=?',(generate_password_hash(tmp),driver['user_id']))
            conn.execute('UPDATE drivers SET temp_password=? WHERE id=?',(tmp,did))
            conn.commit(); flash(f'Password reset to: {tmp}','success')
    conn.close()
    return redirect(url_for('admin_drivers'))

@app.route('/admin/drivers/delete/<int:did>', methods=['POST'])
@login_required('admin')
def admin_delete_driver(did):
    conn = get_db()
    driver = conn.execute('SELECT user_id FROM drivers WHERE id=? AND college_id=?',(did,cid())).fetchone()
    if driver:
        conn.execute('DELETE FROM drivers WHERE id=?',(did,))
        conn.execute('DELETE FROM users WHERE id=?',(driver['user_id'],))
        conn.commit(); flash('Driver removed.','success')
    conn.close()
    return redirect(url_for('admin_drivers'))

# ── ADMIN: STUDENTS ───────────────────────────────────────
@app.route('/admin/students')
@login_required('admin')
def admin_students():
    conn = get_db(); cid_ = cid()
    students = conn.execute('''SELECT s.*,u.name,u.email,b.reg_no as bus_reg,r.name as route_name
        FROM students s JOIN users u ON s.user_id=u.id
        LEFT JOIN buses b ON s.bus_id=b.id LEFT JOIN routes r ON b.route_id=r.id
        WHERE s.college_id=?''',(cid_,)).fetchall()
    buses = conn.execute('SELECT b.*,r.name as route_name FROM buses b LEFT JOIN routes r ON b.route_id=r.id WHERE b.college_id=?',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/students.html', students=students, buses=buses, college=get_college(cid_))

@app.route('/admin/students/add', methods=['POST'])
@login_required('admin')
def admin_add_student():
    conn = get_db(); cid_ = cid()
    try:
        name = request.form['name'].strip(); email = request.form['email'].strip()
        usn  = request.form.get('usn','').strip(); adm  = request.form.get('admission_no','').strip()
        phone = request.form.get('phone','').strip(); dept = request.form.get('department','').strip()
        sem  = request.form.get('semester','').strip(); bp  = request.form.get('boarding_point','').strip()
        tmp  = request.form.get('temp_password','Student@123').strip()
        hashed = generate_password_hash(tmp)
        c = conn.cursor()
        c.execute('INSERT INTO users (college_id,name,email,password,role,must_change_password) VALUES (?,?,?,?,\'student\',1)',
            (cid_, name, email, hashed))
        uid = c.lastrowid
        c.execute('''INSERT INTO students (college_id,user_id,usn,admission_no,phone,department,semester,boarding_point,temp_password)
                     VALUES (?,?,?,?,?,?,?,?,?)''',
            (cid_, uid, usn or None, adm or None, phone or None, dept or None, sem or None, bp or None, tmp))
        conn.commit()
        flash(f'Student {name} added. Login: {usn or adm or email} / PW: {tmp}','success')
    except sqlite3.IntegrityError as e: flash(f'Error: {str(e)}','error')
    finally: conn.close()
    return redirect(url_for('admin_students'))

@app.route('/admin/students/assign_bus', methods=['POST'])
@login_required('admin')
def admin_assign_bus_student():
    conn = get_db()
    bus_id = request.form.get('bus_id') or None
    bp = request.form.get('boarding_point','').strip() or None
    conn.execute('UPDATE students SET bus_id=?,boarding_point=? WHERE id=? AND college_id=?',
        (bus_id, bp, request.form['student_id'], cid()))
    conn.commit(); conn.close(); flash('Bus and boarding point updated.','success')
    return redirect(url_for('admin_students'))

@app.route('/admin/students/update_boarding/<int:sid>', methods=['POST'])
@login_required('admin')
def admin_update_boarding(sid):
    conn = get_db()
    conn.execute('UPDATE students SET boarding_point=? WHERE id=? AND college_id=?',
        (request.form.get('boarding_point','').strip() or None, sid, cid()))
    conn.commit(); conn.close(); flash('Boarding point updated.','success')
    return redirect(url_for('admin_students'))

@app.route('/admin/students/set-password/<int:sid>', methods=['POST'])
@login_required('admin')
def admin_set_student_password(sid):
    conn = get_db()
    s = conn.execute('SELECT user_id FROM students WHERE id=? AND college_id=?',(sid,cid())).fetchone()
    if s:
        tmp = request.form.get('temp_password','').strip()
        if tmp:
            conn.execute('UPDATE users SET password=?,must_change_password=1 WHERE id=?',(generate_password_hash(tmp),s['user_id']))
            conn.execute('UPDATE students SET temp_password=? WHERE id=?',(tmp,sid))
            conn.commit(); flash(f'Password reset to: {tmp}','success')
    conn.close()
    return redirect(url_for('admin_students'))

@app.route('/admin/students/delete/<int:sid>', methods=['POST'])
@login_required('admin')
def admin_delete_student(sid):
    conn = get_db()
    s = conn.execute('SELECT user_id FROM students WHERE id=? AND college_id=?',(sid,cid())).fetchone()
    if s:
        conn.execute('DELETE FROM student_academics WHERE student_id=?',(sid,))
        conn.execute('DELETE FROM student_projects WHERE student_id=?',(sid,))
        conn.execute('DELETE FROM students WHERE id=?',(sid,))
        conn.execute('DELETE FROM users WHERE id=?',(s['user_id'],))
        conn.commit(); flash('Student removed.','success')
    conn.close()
    return redirect(url_for('admin_students'))

@app.route('/admin/students/academics/<int:sid>', methods=['GET','POST'])
@login_required('admin')
def admin_student_academics(sid):
    conn = get_db(); cid_ = cid()
    student = conn.execute('SELECT s.*,u.name,u.email FROM students s JOIN users u ON s.user_id=u.id WHERE s.id=? AND s.college_id=?',(sid,cid_)).fetchone()
    if not student: conn.close(); flash('Student not found.','error'); return redirect(url_for('admin_students'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_subject':
            conn.execute('INSERT INTO student_academics (student_id,subject,marks_obtained,max_marks,grade,semester) VALUES (?,?,?,?,?,?)',
                (sid,request.form['subject'],request.form.get('marks_obtained'),request.form.get('max_marks',100),request.form.get('grade',''),request.form.get('semester','')))
        elif action == 'delete_subject':
            conn.execute('DELETE FROM student_academics WHERE id=?',(request.form['subject_id'],))
        elif action == 'add_project':
            conn.execute('INSERT INTO student_projects (student_id,title,description,tech_stack,status,github_url) VALUES (?,?,?,?,?,?)',
                (sid,request.form['title'],request.form.get('description',''),request.form.get('tech_stack',''),request.form.get('status','ongoing'),request.form.get('github_url','')))
        elif action == 'delete_project':
            conn.execute('DELETE FROM student_projects WHERE id=?',(request.form['project_id'],))
        elif action == 'update_info':
            conn.execute('UPDATE students SET cgpa=?,academic_year=?,semester=?,department=? WHERE id=?',
                (request.form.get('cgpa',''),request.form.get('academic_year',''),request.form.get('semester',''),request.form.get('department',''),sid))
        conn.commit(); conn.close()
        return redirect(url_for('admin_student_academics', sid=sid))
    academics = conn.execute('SELECT * FROM student_academics WHERE student_id=? ORDER BY semester',(sid,)).fetchall()
    projects  = conn.execute('SELECT * FROM student_projects WHERE student_id=? ORDER BY updated_at DESC',(sid,)).fetchall()
    conn.close()
    return render_template('admin/student_academics.html', student=student, academics=academics, projects=projects, college=get_college(cid_))

# ── ADMIN: ROUTES ─────────────────────────────────────────
@app.route('/admin/routes')
@login_required('admin')
def admin_routes():
    conn = get_db(); cid_ = cid()
    routes = conn.execute('SELECT * FROM routes WHERE college_id=?',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/routes.html', routes=routes, college=get_college(cid_))

@app.route('/admin/routes/add', methods=['POST'])
@login_required('admin')
def admin_add_route():
    conn = get_db()
    stops = json.dumps([s.strip() for s in request.form.get('stops','').split(',') if s.strip()])
    conn.execute('INSERT INTO routes (college_id,name,start_point,end_point,stops,distance_km) VALUES (?,?,?,?,?,?)',
        (cid(),request.form['name'],request.form['start_point'],request.form['end_point'],stops,float(request.form.get('distance_km') or 0)))
    conn.commit(); conn.close(); flash('Route added.','success')
    return redirect(url_for('admin_routes'))

@app.route('/admin/routes/edit/<int:rid>', methods=['POST'])
@login_required('admin')
def admin_edit_route(rid):
    conn = get_db()
    stops = json.dumps([s.strip() for s in request.form.get('stops','').split(',') if s.strip()])
    conn.execute('UPDATE routes SET name=?,start_point=?,end_point=?,stops=?,distance_km=? WHERE id=? AND college_id=?',
        (request.form['name'],request.form['start_point'],request.form['end_point'],stops,float(request.form.get('distance_km') or 0),rid,cid()))
    conn.commit(); conn.close(); flash('Route updated.','success')
    return redirect(url_for('admin_routes'))

@app.route('/admin/routes/delete/<int:rid>', methods=['POST'])
@login_required('admin')
def admin_delete_route(rid):
    conn = get_db()
    conn.execute('DELETE FROM routes WHERE id=? AND college_id=?',(rid,cid()))
    conn.commit(); conn.close(); flash('Route deleted.','success')
    return redirect(url_for('admin_routes'))

# ── ADMIN: NOTIFICATIONS ──────────────────────────────────
@app.route('/admin/notifications', methods=['GET','POST'])
@login_required('admin')
def admin_notifications():
    conn = get_db(); cid_ = cid()
    if request.method == 'POST':
        conn.execute('INSERT INTO notifications (college_id,title,message,type,target_role,created_by) VALUES (?,?,?,?,?,?)',
            (cid_,request.form['title'],request.form['message'],request.form.get('type','info'),request.form.get('target_role','all'),session['user_id']))
        conn.commit(); flash('Notification sent.','success')
    notifs = conn.execute('SELECT * FROM notifications WHERE college_id=? ORDER BY created_at DESC',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/notifications.html', notifications=notifs, college=get_college(cid_))

@app.route('/admin/notifications/delete/<int:nid>', methods=['POST'])
@login_required('admin')
def admin_delete_notif(nid):
    conn = get_db()
    conn.execute('DELETE FROM notifications WHERE id=? AND college_id=?',(nid,cid()))
    conn.commit(); conn.close(); flash('Deleted.','success')
    return redirect(url_for('admin_notifications'))

# ── ADMIN: TRACKING ───────────────────────────────────────
@app.route('/admin/tracking')
@login_required('admin')
def admin_tracking():
    conn = get_db(); cid_ = cid()
    active = conn.execute('''SELECT t.*,b.reg_no,u.name as driver_name,r.name as route_name
        FROM trip_logs t JOIN buses b ON t.bus_id=b.id
        JOIN drivers d ON t.driver_id=d.id JOIN users u ON d.user_id=u.id
        LEFT JOIN routes r ON t.route_id=r.id
        WHERE t.college_id=? AND t.status='active' ''',(cid_,)).fetchall()
    conn.close()
    return render_template('admin/tracking.html', active_trips=active, college=get_college(cid_))

# ── DRIVER ────────────────────────────────────────────────
@app.route('/driver')
@login_required('driver')
def driver_dashboard():
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    if not driver: conn.close(); flash('Driver profile not found.','error'); return redirect(url_for('logout'))
    bus = route = active_trip = None
    if driver['bus_id']:
        bus = conn.execute('SELECT b.*,r.name as route_name,r.id as rid FROM buses b LEFT JOIN routes r ON b.route_id=r.id WHERE b.id=? AND b.college_id=?',(driver['bus_id'],cid_)).fetchone()
        if bus and bus['rid']:
            route = conn.execute('SELECT * FROM routes WHERE id=?',(bus['rid'],)).fetchone()
        active_trip = conn.execute("SELECT * FROM trip_logs WHERE driver_id=? AND status='active'",(driver['id'],)).fetchone()
    student_count = conn.execute('SELECT COUNT(*) FROM students WHERE bus_id=? AND college_id=?',(driver['bus_id'] or 0,cid_)).fetchone()[0]
    students_list = conn.execute('''SELECT s.*,u.name,u.email FROM students s
        JOIN users u ON s.user_id=u.id WHERE s.bus_id=? AND s.college_id=? ORDER BY s.boarding_point,u.name''',
        (driver['bus_id'] or 0, cid_)).fetchall()
    notifs = conn.execute("SELECT * FROM notifications WHERE college_id=? AND target_role IN ('all','driver') ORDER BY created_at DESC LIMIT 5",(cid_,)).fetchall()
    conn.close()
    return render_template('driver/dashboard.html', driver=driver, bus=bus, route=route,
        active_trip=active_trip, student_count=student_count, students_list=students_list,
        notifications=notifs, college=get_college(cid_))

@app.route('/driver/location-page')
@login_required('driver')
def driver_location_page():
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    active_trip = bus = None
    if driver:
        active_trip = conn.execute("SELECT * FROM trip_logs WHERE driver_id=? AND status='active'",(driver['id'],)).fetchone()
        if driver['bus_id']:
            bus = conn.execute('SELECT b.*,r.name as route_name FROM buses b LEFT JOIN routes r ON b.route_id=r.id WHERE b.id=?',(driver['bus_id'],)).fetchone()
    conn.close()
    return render_template('driver/location.html', driver=driver, active_trip=active_trip, bus=bus, college=get_college(cid_))

@app.route('/driver/trip/start', methods=['POST'])
@login_required('driver')
def driver_start_trip():
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    if driver and driver['bus_id']:
        existing = conn.execute("SELECT id FROM trip_logs WHERE driver_id=? AND status='active'",(driver['id'],)).fetchone()
        if not existing:
            bus = conn.execute('SELECT * FROM buses WHERE id=?',(driver['bus_id'],)).fetchone()
            conn.execute('INSERT INTO trip_logs (college_id,bus_id,driver_id,route_id,start_time,status,last_updated) VALUES (?,?,?,?,?,?,?)',
                (cid_,driver['bus_id'],driver['id'],bus['route_id'] if bus else None,datetime.now(),'active',datetime.now()))
            conn.execute('UPDATE buses SET status=? WHERE id=?',('active',driver['bus_id']))
            conn.commit(); flash('Trip started! GPS sharing active.','success')
        else: flash('Trip already active.','error')
    conn.close()
    return redirect(url_for('driver_dashboard'))

@app.route('/driver/trip/end', methods=['POST'])
@login_required('driver')
def driver_end_trip():
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    if driver:
        conn.execute("UPDATE trip_logs SET status='completed',end_time=? WHERE driver_id=? AND status='active'",(datetime.now(),driver['id']))
        if driver['bus_id']:
            conn.execute('UPDATE buses SET status=? WHERE id=?',('idle',driver['bus_id']))
        conn.commit(); flash('Trip ended.','success')
    conn.close()
    return redirect(url_for('driver_dashboard'))

@app.route('/driver/location/update', methods=['POST'])
@login_required('driver')
def driver_update_location():
    data = request.get_json()
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    if driver:
        speed    = float(data.get('speed', 0) or 0)
        wx_code  = int(data.get('wx_code', -1) or -1)
        wx_temp  = data.get('wx_temp')
        wx_desc  = data.get('wx_desc', '')
        conn.execute("UPDATE trip_logs SET lat=?,lng=?,speed=?,last_updated=? WHERE driver_id=? AND status='active'",
            (data.get('lat'), data.get('lng'), speed, datetime.now(), driver['id']))
        conn.commit()

        # ── Smart alerts ──────────────────────────────────
        # Check if a similar alert was already sent in last 10 minutes
        recent = conn.execute(
            "SELECT id FROM notifications WHERE college_id=? AND created_by=? AND created_at > datetime('now','-10 minutes')",
            (cid_, session['user_id'])).fetchone()

        if not recent:
            alert_title = alert_msg = alert_type = None
            # Bus stopped (speed < 2 km/h for a running trip)
            if speed < 2:
                alert_title = f'🚌 Bus Stopped — {driver["name"]}'
                alert_msg   = f'Bus has stopped moving (0 km/h). Possible traffic, breakdown or stop pickup.'
                alert_type  = 'warning'
            # Heavy rain (WMO codes 65,55,82,95,96,99 = heavy rain / thunderstorm)
            elif wx_code in [65, 55, 82, 95, 96, 99]:
                alert_title = f'🌧 Heavy Rain Alert — {driver["name"]}'
                alert_msg   = f'Heavy rain at bus location ({wx_desc}). Delays expected. Drive safe.'
                alert_type  = 'danger'
            # Traffic proxy: slow moving but not stopped (2–10 km/h for city route)
            elif 2 < speed < 10:
                alert_title = f'🚦 Traffic Detected — {driver["name"]}'
                alert_msg   = f'Bus is moving slowly ({speed:.1f} km/h). Possible traffic jam. ETA may increase.'
                alert_type  = 'warning'

            if alert_title:
                conn.execute(
                    "INSERT INTO notifications (college_id,title,message,type,target_role,created_by) VALUES (?,?,?,?,?,?)",
                    (cid_, alert_title, alert_msg, alert_type, 'all', session['user_id']))
                conn.commit()

    conn.close()
    return jsonify({'ok': True})

@app.route('/driver/sos', methods=['POST'])
@login_required('driver')
def driver_sos():
    conn = get_db(); cid_ = cid()
    driver = conn.execute('SELECT d.*,u.name FROM drivers d JOIN users u ON d.user_id=u.id WHERE d.user_id=? AND d.college_id=?',(session['user_id'],cid_)).fetchone()
    if driver:
        conn.execute("INSERT INTO notifications (college_id,title,message,type,target_role,created_by) VALUES (?,?,?,?,?,?)",
            (cid_,f'🆘 SOS — {driver["name"]}',f'Emergency from driver {driver["name"]}. Immediate help needed.','danger','admin',session['user_id']))
        conn.commit(); flash('SOS sent to admin!','success')
    conn.close()
    return redirect(url_for('driver_dashboard'))

@app.route('/driver/student/toggle-board', methods=['POST'])
@login_required('driver')
def driver_toggle_board():
    data = request.get_json(); sid = data.get('student_id')
    conn = get_db()
    driver = conn.execute('SELECT * FROM drivers WHERE user_id=?',(session['user_id'],)).fetchone()
    if driver:
        trip = conn.execute("SELECT id FROM trip_logs WHERE driver_id=? AND status='active'",(driver['id'],)).fetchone()
        if trip:
            ex = conn.execute('SELECT * FROM boarding_status WHERE student_id=? AND trip_id=?',(sid,trip['id'])).fetchone()
            if ex:
                nv = 0 if ex['boarded'] else 1
                conn.execute('UPDATE boarding_status SET boarded=?,boarded_at=? WHERE id=?',(nv,datetime.now() if nv else None,ex['id']))
            else:
                conn.execute('INSERT INTO boarding_status (student_id,trip_id,boarded,boarded_at) VALUES (?,?,1,?)',(sid,trip['id'],datetime.now()))
            conn.commit()
            ex2 = conn.execute('SELECT boarded FROM boarding_status WHERE student_id=? AND trip_id=?',(sid,trip['id'])).fetchone()
            conn.close()
            return jsonify({'ok':True,'boarded':ex2['boarded'] if ex2 else 1})
    conn.close()
    return jsonify({'ok':False})

# ── STUDENT ───────────────────────────────────────────────
@app.route('/student')
@login_required('student')
def student_dashboard():
    conn = get_db(); cid_ = cid()
    student = conn.execute('SELECT * FROM students WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    if not student: conn.close(); flash('Profile not found.','error'); return redirect(url_for('logout'))
    bus = route = driver_info = active_trip = None
    if student['bus_id']:
        bus = conn.execute('SELECT b.*,r.name as route_name FROM buses b LEFT JOIN routes r ON b.route_id=r.id WHERE b.id=?',(student['bus_id'],)).fetchone()
        if bus:
            if bus['route_id']: route = conn.execute('SELECT * FROM routes WHERE id=?',(bus['route_id'],)).fetchone()
            if bus['driver_id']: driver_info = conn.execute('SELECT d.*,u.name FROM drivers d JOIN users u ON d.user_id=u.id WHERE d.id=?',(bus['driver_id'],)).fetchone()
            active_trip = conn.execute("SELECT * FROM trip_logs WHERE bus_id=? AND status='active'",(student['bus_id'],)).fetchone()
    notifs = conn.execute("SELECT * FROM notifications WHERE college_id=? AND target_role IN ('all','student') ORDER BY created_at DESC LIMIT 5",(cid_,)).fetchall()
    conn.close()
    return render_template('student/dashboard.html', student=student, bus=bus, route=route,
        driver_info=driver_info, active_trip=active_trip, notifications=notifs, college=get_college(cid_))

@app.route('/student/track')
@login_required('student')
def student_track():
    conn = get_db(); cid_ = cid()
    student = conn.execute('SELECT * FROM students WHERE user_id=? AND college_id=?',(session['user_id'],cid_)).fetchone()
    trip = bus = driver_info = None
    if student and student['bus_id']:
        bus = conn.execute('SELECT b.*,r.name as route_name FROM buses b LEFT JOIN routes r ON b.route_id=r.id WHERE b.id=?',(student['bus_id'],)).fetchone()
        trip = conn.execute("SELECT * FROM trip_logs WHERE bus_id=? AND status='active'",(student['bus_id'],)).fetchone()
        if bus and bus['driver_id']:
            driver_info = conn.execute('SELECT d.*,u.name FROM drivers d JOIN users u ON d.user_id=u.id WHERE d.id=?',(bus['driver_id'],)).fetchone()
    route_distance = 0
    if bus and bus['route_id']:
        r = conn.execute('SELECT distance_km FROM routes WHERE id=?', (bus['route_id'],)).fetchone()
        if r: route_distance = r['distance_km'] or 0
    conn.close()
    return render_template('student/track.html', trip=trip, bus=bus, student=student,
        driver_info=driver_info, college=get_college(cid_), route_distance=route_distance)

@app.route('/student/profile')
@login_required('student')
def student_profile():
    conn = get_db(); cid_ = cid()
    student = conn.execute('SELECT s.*,u.name,u.email FROM students s JOIN users u ON s.user_id=u.id WHERE s.user_id=? AND s.college_id=?',(session['user_id'],cid_)).fetchone()
    academics = conn.execute('SELECT * FROM student_academics WHERE student_id=? ORDER BY semester',(student['id'],)).fetchall()
    projects  = conn.execute('SELECT * FROM student_projects WHERE student_id=? ORDER BY updated_at DESC',(student['id'],)).fetchall()
    conn.close()
    return render_template('student/profile.html', student=student, academics=academics, projects=projects, college=get_college(cid_))

# ── SSE STREAMING ─────────────────────────────────────────
@app.route('/stream/bus/<int:bus_id>')
def stream_bus(bus_id):
    def generate():
        while True:
            try:
                conn = get_db()
                trip = conn.execute("SELECT lat,lng,speed,last_updated FROM trip_logs WHERE bus_id=? AND status='active'",(bus_id,)).fetchone()
                conn.close()
                if trip and trip['lat']:
                    data = json.dumps({'lat':trip['lat'],'lng':trip['lng'],'speed':round(trip['speed'] or 0,1),'updated':trip['last_updated']})
                    yield f"data: {data}\n\n"
                else:
                    yield f"data: {{\"waiting\": true}}\n\n"
            except Exception:
                yield f"data: {{\"error\": true}}\n\n"
            time.sleep(2)
    return Response(stream_with_context(generate()), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/stream/all-buses')
def stream_all_buses():
    college_id = session.get('college_id')
    def generate():
        while True:
            try:
                conn = get_db()
                q = "SELECT t.lat,t.lng,t.speed,t.last_updated,b.reg_no,b.id as bus_id,u.name as driver_name,r.name as route_name FROM trip_logs t JOIN buses b ON t.bus_id=b.id JOIN drivers d ON t.driver_id=d.id JOIN users u ON d.user_id=u.id LEFT JOIN routes r ON t.route_id=r.id WHERE t.status='active' AND t.lat IS NOT NULL"
                if college_id:
                    trips = conn.execute(q + ' AND t.college_id=?',(college_id,)).fetchall()
                else:
                    trips = conn.execute(q).fetchall()
                conn.close()
                yield f"data: {json.dumps([dict(r) for r in trips])}\n\n"
            except Exception:
                yield f"data: []\n\n"
            time.sleep(2)
    return Response(stream_with_context(generate()), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

# ── API ───────────────────────────────────────────────────
@app.route('/api/bus_location/<int:bus_id>')
def api_bus_location(bus_id):
    conn = get_db()
    trip = conn.execute("SELECT lat,lng,speed,last_updated FROM trip_logs WHERE bus_id=? AND status='active'",(bus_id,)).fetchone()
    conn.close()
    if trip and trip['lat']:
        return jsonify({'lat':trip['lat'],'lng':trip['lng'],'speed':trip['speed'],'updated':trip['last_updated']})
    return jsonify({'lat':None,'lng':None})

@app.route('/api/colleges')
def api_colleges():
    conn = get_db()
    colleges = conn.execute('SELECT id,name,logo FROM colleges ORDER BY name').fetchall()
    conn.close()
    return jsonify([dict(c) for c in colleges])

# ── TEMPLATE FILTER ───────────────────────────────────────
@app.context_processor
def inject_college():
    if 'college_id' in session:
        return dict(college=get_college(session['college_id']))
    return dict(college={'name':'Campus Cruiser','logo':None,'theme':'dark'})

@app.template_filter('fromjson')
def fromjson_filter(s):
    try: return json.loads(s) if s else []
    except: return []

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
