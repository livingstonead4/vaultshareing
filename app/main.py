import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_wtf.csrf import CSRFProtect
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.exc import IntegrityError

app = Flask(__name__, template_folder="templates")

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-key-change-me")

database_url = os.environ.get("DATABASE_URL", "sqlite:///vaultshare.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

password_hasher = PasswordHasher()


# USER DATABASE

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(150), nullable=False)

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(30), nullable=False)

    active = db.Column(db.Boolean, default=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# HOME PAGE

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("register"))


# REGISTRATION

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "").strip().lower()

        if not all([full_name, email, password, confirm_password, role]):
            flash("Please complete all fields.")
            return redirect(url_for("register"))

        if role not in ["sender", "recipient"]:
            flash("Invalid account type.")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Password must contain at least 10 characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("This email is already registered.")
            return redirect(url_for("register"))

        hashed_password = password_hasher.hash(password)

        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=hashed_password,
            role=role
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except IntegrityError:
            db.session.rollback()
            flash("This email is already registered.")

    return render_template("register.html")


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.active:

            try:
                password_hasher.verify(
                    user.password_hash,
                    password
                )

                login_user(user)
                return redirect(url_for("dashboard"))

            except VerifyMismatchError:
                pass

        flash("Invalid email or password.")

    return render_template("login.html")


# DASHBOARD

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        user=current_user
    )


# LOGOUT

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash("You have logged out successfully.")

    return redirect(url_for("login"))


# CREATE DATABASE TABLES

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
