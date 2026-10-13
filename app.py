import os
import sqlite3
from datetime import timedelta
from pathlib import Path

try:
    import mysql.connector
except ModuleNotFoundError:  # pragma: no cover - optional dependency in local dev/test setups.
    mysql = None
from dotenv import load_dotenv
from flask import Flask, g, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "dev-secret-key"
if not os.getenv("SECRET_KEY"):
    app.logger.warning("SECRET_KEY is missing from the environment; using a development fallback.")

app.permanent_session_lifetime = timedelta(days=30)
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes"}
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_SUPPRESS_SEND"] = os.getenv("MAIL_SUPPRESS_SEND", "false").lower() in {"1", "true", "yes"}
if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
    app.config["MAIL_SUPPRESS_SEND"] = True

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)
RESET_TOKEN_SALT = "password-reset-v1"
RESET_TOKEN_MAX_AGE = 30 * 60


def _sql_for_connection(connection, query):
    if isinstance(connection, sqlite3.Connection):
        return query.replace("%s", "?")
    return query


def _create_sqlite_db():
    db_path = Path(__file__).with_name("auth.db")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def get_db_cursor(connection, *, dictionary=False):
    if isinstance(connection, sqlite3.Connection):
        connection.row_factory = sqlite3.Row
        return connection.cursor()
    if mysql is not None:
        return connection.cursor(dictionary=dictionary)
    return connection.cursor()


def get_db():
    if "db" not in g:
        if mysql is None:
            g.db = _create_sqlite_db()
            return g.db

        db_config = {
            "host": os.getenv("DB_HOST", "localhost"),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD"),
            "database": os.getenv("DB_NAME", "login_auth"),
            "autocommit": True,
            "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "2")),
            "connection_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "2")),
        }
        try:
            g.db = mysql.connector.connect(**db_config)
        except mysql.connector.Error as exc:
            app.logger.warning("Falling back to SQLite: %s", exc)
            g.db = _create_sqlite_db()
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for("index"))

    return render_template("dashboard.html", username=session.get("username"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password or not confirm_password:
            flash("Please fill in all fields.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("register"))

        connection = get_db()
        cursor = get_db_cursor(connection)
        try:
            cursor.execute(
                _sql_for_connection(connection, "SELECT id FROM users WHERE email = %s"),
                (email,),
            )
            if cursor.fetchone():
                flash("This email is already registered.")
                return redirect(url_for("register"))

            password_hash = generate_password_hash(password)
            cursor.execute(
                _sql_for_connection(
                    connection,
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                ),
                (username, email, password_hash),
            )
            connection.commit()
            flash("Account created successfully! Please log in.")
            return redirect(url_for("index"))
        except Exception:
            if hasattr(connection, "rollback"):
                connection.rollback()
            app.logger.exception("Registration database error")
            flash("Could not create your account. Please try again.")
            return redirect(url_for("register"))
        finally:
            cursor.close()

    return render_template("register.html")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form.to_dict()

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    remember = data.get("remember", False)
    if isinstance(remember, str):
        remember = remember.strip().lower() in {"1", "true", "yes", "on"}

    if not email or not password:
        return {"success": False, "message": "Please enter your email and password."}, 400

    connection = get_db()
    cursor = get_db_cursor(connection, dictionary=True)
    try:
        cursor.execute(
            _sql_for_connection(connection, "SELECT id, username, password_hash FROM users WHERE email = %s"),
            (email,),
        )
        user = cursor.fetchone()
        if isinstance(connection, sqlite3.Connection) and user is not None:
            user = dict(user)

        if user is None or not check_password_hash(user["password_hash"], password):
            return {"success": False, "message": "Invalid email or password."}, 401

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = bool(remember)

        return {"success": True, "message": "Login successful!", "redirect_url": url_for("dashboard")}, 200
    except Exception:
        app.logger.exception("Login database error")
        return {"success": False, "message": "Database error. Please try again."}, 500
    finally:
        cursor.close()


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your email address.")
            return redirect(url_for("forgot_password"))

        connection = get_db()
        cursor = get_db_cursor(connection)
        try:
            cursor.execute(
                _sql_for_connection(connection, "SELECT id FROM users WHERE email = %s"),
                (email,),
            )
            user = cursor.fetchone()
        except Exception:
            app.logger.exception("Forgot-password database error")
            flash("Unable to process your request right now.")
            return redirect(url_for("forgot_password"))
        finally:
            cursor.close()

        if user:
            try:
                if app.config.get("MAIL_SUPPRESS_SEND"):
                    app.logger.info("Password reset email suppressed for %s", email)
                else:
                    token = serializer.dumps(email, salt=RESET_TOKEN_SALT)
                    reset_url = url_for("reset_password", token=token, _external=True)
                    message = Message(
                        subject="Reset your password",
                        recipients=[email],
                        body=(
                            "We received a request to reset your password.\n\n"
                            f"Open this link to choose a new password:\n{reset_url}\n\n"
                            "This link expires in 30 minutes. If you did not request this, ignore this email."
                        ),
                    )
                    mail.send(message)
            except Exception:
                app.logger.exception("Could not send password-reset email")
                flash("We could not send the reset email right now. Please try again later.")
                return redirect(url_for("forgot_password"))

        flash("If an account uses that email address, a password-reset link will be sent.")
        return redirect(url_for("forgot_password"))

    return render_template("forgot-password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=RESET_TOKEN_SALT, max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        flash("This reset link has expired. Please request a new one.")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("This reset link is invalid. Please request a new one.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password or not confirm_password:
            flash("Please fill in both password fields.")
            return render_template("reset-password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("reset-password.html", token=token)

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("reset-password.html", token=token)

        connection = get_db()
        cursor = get_db_cursor(connection)
        try:
            cursor.execute(
                _sql_for_connection(connection, "UPDATE users SET password_hash = %s WHERE email = %s"),
                (generate_password_hash(password), email),
            )
            connection.commit()

            if cursor.rowcount == 0:
                flash("This account could not be found.")
                return redirect(url_for("forgot_password"))

            flash("Password changed successfully. Please log in.")
            return redirect(url_for("index"))
        except Exception:
            if hasattr(connection, "rollback"):
                connection.rollback()
            app.logger.exception("Password-reset database error")
            flash("Could not update your password. Please try again.")
            return render_template("reset-password.html", token=token)
        finally:
            cursor.close()

    return render_template("reset-password.html", token=token)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
