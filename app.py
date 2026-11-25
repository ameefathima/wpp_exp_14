import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "wpp-lab15-super-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def validate_registration(username, email, password, confirm_password):
    if not username or not email or not password or not confirm_password:
        return "All fields are required."

    if not USERNAME_REGEX.match(username):
        return "Username must be 3-20 characters (letters, numbers, or underscores only)."

    if not EMAIL_REGEX.match(email):
        return "Please enter a valid email address."

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one number."

    if password != confirm_password:
        return "Passwords do not match."

    return None


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        error_msg = validate_registration(username, email, password, confirm_password)
        if error_msg:
            flash(error_msg, "error")
            return render_template("register.html", username=username, email=email)

        password_hash = generate_password_hash(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with get_db_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, email, password_hash, created_at),
                )
                conn.commit()
            flash("Registration successful! Please log in with your credentials.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("An account with that username or email already exists.", "error")
            return render_template("register.html", username=username, email=email)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both your username/email and password.", "error")
            return render_template("login.html", identifier=request.form.get("identifier", ""))

        with get_db_connection() as conn:
            user = conn.execute(
                """
                SELECT id, username, email, password_hash, created_at
                FROM users
                WHERE LOWER(username) = ? OR LOWER(email) = ?
                """,
                (identifier, identifier),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["logged_in_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials. Please check your username/email and password.", "error")
        return render_template("login.html", identifier=request.form.get("identifier", ""))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT id, username, email, created_at FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if not user:
        session.clear()
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username", "User")
    session.clear()
    flash(f"{username} has been logged out safely.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)