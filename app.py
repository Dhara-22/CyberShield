import os
import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from scanner import scan_ports
from vulnerability import check_vulnerabilities
from attack import vulnerable_login
from defense import secure_login
from sqli import simulate_sql_injection

app = Flask(__name__)
app.secret_key = "cybershield-demo-secret"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Seed default test accounts if not already present
        seed_users = [
            ("CyberShield Admin", "admin@cybershield.lab", "Admin1234"),
            ("Demo User", "demo@cybershield.lab", "Demo1234"),
            ("Admin User", "admin@example.com", "Admin1234"),
        ]
        for name, email, pwd in seed_users:
            exists = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(pwd))
                )
        conn.commit()

init_db()

def get_user_by_email(email):
    if not email:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        return dict(row) if row else None

def create_user(name, email, password_hash):
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name.strip(), email.strip().lower(), password_hash)
        )
        conn.commit()
        return cursor.lastrowid

def validate_signup(name, email, password, confirm_password):
    field_errors = {}

    if not name:
        field_errors["name"] = "Please enter your name."

    email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    if not email:
        field_errors["email"] = "Please enter your email."
    elif not re.match(email_regex, email):
        field_errors["email"] = "Please enter a valid email address."

    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not password:
        field_errors["password"] = "Please enter your password."
    elif len(password) < 8 or not has_upper or not has_digit:
        field_errors["password"] = "Password must meet the required requirements."

    if not confirm_password:
        field_errors["confirm_password"] = "Please confirm your password."
    elif password != confirm_password:
        field_errors["confirm_password"] = "Passwords do not match."

    return field_errors

@app.route("/")
def home():
    if not session.get("signed_in"):
        return redirect(url_for("signin"))

    return render_template(
        "dashboard.html",
        user_name=session.get("user_name", session.get("email")),
        user_email=session.get("email"),
        scans=session.get("scans", 0),
        vulnerabilities=session.get("vulnerabilities", 0),
        high_risk=session.get("high_risk", 0),
        fixed=session.get("fixed", 0),
        last_target=session.get("last_target", "Local Lab")
    )

@app.route("/signup", methods=["GET", "POST"])
@app.route("/register", methods=["GET", "POST"])
def signup():
    if session.get("signed_in"):
        return redirect(url_for("home"))

    if request.method == "POST":
        is_json = request.is_json
        data = request.get_json(silent=True) if is_json else request.form

        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""

        field_errors = validate_signup(name, email, password, confirm_password)

        if field_errors:
            first_err = next(iter(field_errors.values()))
            if is_json:
                return jsonify({
                    "success": False,
                    "error": first_err,
                    "field_errors": field_errors
                }), 400
            for err in field_errors.values():
                flash(err, "error")
            return render_template("signup.html", name=name, email=email)

        # Check for duplicate account
        existing_user = get_user_by_email(email)
        if existing_user:
            err_msg = "An account with this email already exists."
            if is_json:
                return jsonify({
                    "success": False,
                    "error": err_msg,
                    "field_errors": {"email": err_msg}
                }), 409
            flash(err_msg, "error")
            return render_template("signup.html", name=name, email=email)

        # Create user
        try:
            password_hash = generate_password_hash(password)
            create_user(name, email, password_hash)
            if is_json:
                return jsonify({
                    "success": True,
                    "message": "Account created successfully. You can now sign in.",
                    "redirect_url": url_for("signin")
                }), 201
            flash("Account created successfully. You can now sign in.", "success")
            return redirect(url_for("signin"))
        except Exception:
            err_msg = "Unable to create account. Please try again."
            if is_json:
                return jsonify({
                    "success": False,
                    "error": err_msg
                }), 500
            flash(err_msg, "error")
            return render_template("signup.html", name=name, email=email)

    return render_template("signup.html")

@app.route("/signin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def signin():
    if session.get("signed_in"):
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email:
            flash("Please enter your email.", "error")
            return render_template("signin.html", email=email)

        if "password" in request.form:
            if not password:
                flash("Please enter your password.", "error")
                return render_template("signin.html", email=email)

            user = get_user_by_email(email)
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "error")
                return render_template("signin.html", email=email)

            session["signed_in"] = True
            session["email"] = user["email"]
            session["user_name"] = user["name"]
            session.setdefault("scans", 0)
            session.setdefault("vulnerabilities", 0)
            session.setdefault("high_risk", 0)
            session.setdefault("fixed", 0)
            return redirect(url_for("home"))
        else:
            # Legacy email-only login support
            session["signed_in"] = True
            session["email"] = email
            user = get_user_by_email(email)
            session["user_name"] = user["name"] if user else email.split("@")[0].capitalize()
            session.setdefault("scans", 0)
            session.setdefault("vulnerabilities", 0)
            session.setdefault("high_risk", 0)
            session.setdefault("fixed", 0)
            return redirect(url_for("home"))

    return render_template("signin.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))

@app.route("/recon", methods=["GET", "POST"])
def recon():
    result = None

    if request.method == "POST":
        import socket
        target = request.form.get("target", "").strip()

        try:
            ip = socket.gethostbyname(target)
            hostname = socket.getfqdn(target)
            result = {
                "target": target,
                "ip": ip,
                "hostname": hostname,
                "status": "Target found"
            }
        except Exception:
            result = {
                "target": target,
                "status": "Target not found"
            }

    return render_template("recon.html", result=result)

@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    results = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        results = scan_ports(target)

        open_ports = sum(1 for item in results if item.get("status") == "OPEN")

        session["scans"] = session.get("scans", 0) + 1
        session["last_target"] = target

        if open_ports:
            session["high_risk"] = session.get("high_risk", 0) + (1 if open_ports >= 3 else 0)

    return render_template("scanner.html", results=results)

@app.route("/vulnerability", methods=["GET", "POST"])
def vulnerability():
    results = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        results = check_vulnerabilities(url) or []

        session["vulnerabilities"] = len(results)
        session["high_risk"] = sum(1 for item in results if item.get("risk") == "High")

    return render_template("vulnerability.html", results=results)

@app.route("/attack", methods=["GET", "POST"])
def attack():
    result = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = vulnerable_login(username, password)

    return render_template("attack.html", result=result)

@app.route("/defense", methods=["GET", "POST"])
def defense():
    result = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = secure_login(username, password)

        if result:
            session["fixed"] = session.get("fixed", 0) + 1

    return render_template("defense.html", result=result)

@app.route("/sql-injection", methods=["GET", "POST"])
def sql_injection():
    result = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = simulate_sql_injection(username, password)

        session["sql_injection_tests"] = session.get("sql_injection_tests", 0) + 1
        if result.get("injection_detected"):
            session["sql_injection_found"] = session.get("sql_injection_found", 0) + 1
        session["last_sql_injection"] = result.get("status", "BLOCKED")

    return render_template("sql_injection.html", result=result)

@app.route("/report")
def report():
    return render_template(
        "report.html",
        scans=session.get("scans", 0),
        vulnerabilities=session.get("vulnerabilities", 0),
        high_risk=session.get("high_risk", 0),
        fixed=session.get("fixed", 0),
        last_target=session.get("last_target", "Local Lab"),
        sql_injection_tests=session.get("sql_injection_tests", 0),
        sql_injection_found=session.get("sql_injection_found", 0),
        last_sql_injection=session.get("last_sql_injection", "No tests")
    )

if __name__ == "__main__":
    app.run(debug=True)
