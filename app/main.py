import os
import hashlib
import hmac
import base64

from io import BytesIO
from datetime import datetime, time, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, abort
)

from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text, or_
from sqlalchemy.exc import IntegrityError

from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)

from flask_wtf.csrf import CSRFProtect

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from cryptography.fernet import Fernet, InvalidToken


# =====================================
# APPLICATION SETUP
# =====================================

app = Flask(__name__, template_folder="templates")

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-key-change-me"
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# =====================================
# DATABASE CONNECTION
# =====================================

database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///vaultshare.db"
)

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =====================================
# SECURITY SETUP
# =====================================

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

password_hasher = PasswordHasher()

MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_DURATION = 15


# =====================================
# DOCUMENT ENCRYPTION
# =====================================

encryption_secret = os.environ.get(
    "DOCUMENT_ENCRYPTION_SECRET"
)

if not encryption_secret:
    raise RuntimeError(
        "DOCUMENT_ENCRYPTION_SECRET is missing from environment variables."
    )

encryption_key = base64.urlsafe_b64encode(
    hashlib.sha256(encryption_secret.encode()).digest()
)

fernet = Fernet(encryption_key)


# =====================================
# USER DATABASE
# =====================================

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(
        db.String(150),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(30),
        nullable=False
    )

    active = db.Column(
        db.Boolean,
        default=True
    )

    # LOGIN PROTECTION

    failed_login_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    locked_until = db.Column(
        db.DateTime,
        nullable=True
    )


# =====================================
# DOCUMENT DATABASE
# =====================================

class Document(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    encrypted_data = db.Column(
        db.LargeBinary,
        nullable=False
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=True
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


# =====================================
# AUDIT LOG DATABASE
# =====================================

class AuditLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=True
    )

    action = db.Column(
        db.String(100),
        nullable=False
    )

    details = db.Column(
        db.String(500),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


# =====================================
# DOCUMENT SHARING DATABASE
# =====================================

class DocumentShare(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )

    sender_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    recipient_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )


# =====================================
# AUDIT LOG HELPER
# =====================================

def record_audit(action, document_id=None, details=None):

    audit_entry = AuditLog(
        user_id=current_user.id,
        document_id=document_id,
        action=action,
        details=details
    )

    db.session.add(audit_entry)


# =====================================
# DOCUMENT ACCESS CONTROL
# =====================================

def user_can_access_document(document):

    if document.owner_id == current_user.id:
        return True

    share = DocumentShare.query.filter_by(
        document_id=document.id,
        recipient_id=current_user.id,
        is_active=True
    ).first()

    if not share:
        return False

    if share.expires_at and share.expires_at <= datetime.utcnow():
        return False

    return True


# =====================================
# USER LOGIN MANAGEMENT
# =====================================

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))


# =====================================
# HOME PAGE
# =====================================

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("register"))


# =====================================
# REGISTRATION
# =====================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        role = request.form.get(
            "role", ""
        ).strip().lower()

        if not all([
            full_name,
            email,
            password,
            confirm_password,
            role
        ]):
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

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:
            flash("This email is already registered.")
            return redirect(url_for("register"))

        hashed_password = password_hasher.hash(password)

        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=hashed_password,
            role=role,
            failed_login_attempts=0,
            locked_until=None
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


# =====================================
# LOGIN WITH ACCOUNT LOCKOUT
# =====================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if user and user.active:

            now = datetime.utcnow()

            # CHECK WHETHER ACCOUNT IS LOCKED

            if user.locked_until:

                if user.locked_until > now:

                    remaining = int(
                        (user.locked_until - now).total_seconds()
                    )

                    remaining_minutes = max(
                        1,
                        (remaining + 59) // 60
                    )

                    flash(
                        f"Your account is temporarily locked. "
                        f"Please try again in approximately "
                        f"{remaining_minutes} minute(s)."
                    )

                    return render_template("login.html")

                else:

                    # LOCK PERIOD HAS EXPIRED

                    user.locked_until = None
                    user.failed_login_attempts = 0

            # CHECK PASSWORD

            try:

                password_hasher.verify(
                    user.password_hash,
                    password
                )

                # SUCCESSFUL LOGIN

                user.failed_login_attempts = 0
                user.locked_until = None

                db.session.commit()

                login_user(user)

                flash("Login successful.")

                return redirect(url_for("dashboard"))

            except VerifyMismatchError:

                # INCORRECT PASSWORD

                user.failed_login_attempts += 1

                remaining_attempts = (
                    MAX_LOGIN_ATTEMPTS -
                    user.failed_login_attempts
                )

                if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:

                    user.locked_until = (
                        datetime.utcnow() +
                        timedelta(minutes=ACCOUNT_LOCK_DURATION)
                    )

                    db.session.commit()

                    flash(
                        "Too many incorrect login attempts. "
                        "Your account has been locked for 15 minutes."
                    )

                else:

                    db.session.commit()

                    flash(
                        "Invalid email or password. "
                        f"You have {remaining_attempts} "
                        "attempt(s) remaining."
                    )

                return render_template("login.html")

        flash("Invalid email or password.")

    return render_template("login.html")


# =====================================
# DASHBOARD
# =====================================

@app.route("/dashboard")
@login_required
def dashboard():

    documents = Document.query.filter_by(
        owner_id=current_user.id
    ).order_by(
        Document.uploaded_at.desc()
    ).all()

    return render_template(
        "dashboard.html",
        user=current_user,
        documents=documents
    )


# =====================================
# DOCUMENT UPLOAD
# =====================================

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    if request.method == "POST":

        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please select a document.")
            return redirect(url_for("upload"))

        filename = secure_filename(file.filename)

        if not filename:
            flash("Invalid filename.")
            return redirect(url_for("upload"))

        allowed_extensions = {
            "pdf", "doc", "docx", "txt",
            "xls", "xlsx", "ppt", "pptx",
            "csv", "png", "jpg", "jpeg"
        }

        extension = (
            filename.rsplit(".", 1)[-1].lower()
            if "." in filename else ""
        )

        if extension not in allowed_extensions:
            flash("This file type is not supported.")
            return redirect(url_for("upload"))

        file_data = file.read()

        if not file_data:
            flash("The selected file is empty.")
            return redirect(url_for("upload"))

        document_hash = hashlib.sha256(
            file_data
        ).hexdigest()

        encrypted_data = fernet.encrypt(file_data)

        new_document = Document(
            filename=filename,
            encrypted_data=encrypted_data,
            sha256_hash=document_hash,
            owner_id=current_user.id
        )

        try:

            db.session.add(new_document)
            db.session.flush()

            record_audit(
                action="DOCUMENT UPLOADED",
                document_id=new_document.id,
                details=f"Uploaded document: {filename}"
            )

            db.session.commit()

            flash(
                "Document uploaded, encrypted and fingerprinted successfully."
            )

            return redirect(url_for("dashboard"))

        except Exception:

            db.session.rollback()

            app.logger.exception("Document upload failed.")

            flash("Document upload failed.")

    return render_template("upload.html")


# =====================================
# SHARE DOCUMENT AND MANAGE ACCESS
# =====================================

@app.route(
    "/share/<int:document_id>",
    methods=["GET", "POST"]
)
@login_required
def share_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        abort(403)

    if request.method == "POST":

        recipient_email = request.form.get(
            "recipient_email", ""
        ).strip().lower()

        expiry_input = request.form.get(
            "expiry_date", ""
        ).strip()

        recipient = User.query.filter_by(
            email=recipient_email,
            active=True
        ).first()

        if not recipient:
            flash("No active registered user was found with that email.")
            return redirect(url_for(
                "share_document",
                document_id=document.id
            ))

        if recipient.id == current_user.id:
            flash("You cannot share a document with yourself.")
            return redirect(url_for(
                "share_document",
                document_id=document.id
            ))

        expiry_date = None

        if expiry_input:

            try:

                parsed_date = datetime.strptime(
                    expiry_input,
                    "%Y-%m-%d"
                ).date()

                expiry_date = datetime.combine(
                    parsed_date,
                    time(23, 59, 59)
                )

                if expiry_date <= datetime.utcnow():
                    flash("The expiry date must be in the future.")
                    return redirect(url_for(
                        "share_document",
                        document_id=document.id
                    ))

            except ValueError:

                flash("Invalid expiry date.")
                return redirect(url_for(
                    "share_document",
                    document_id=document.id
                ))

        existing_share = DocumentShare.query.filter_by(
            document_id=document.id,
            recipient_id=recipient.id,
            is_active=True
        ).first()

        if existing_share:

            if (
                existing_share.expires_at
                and existing_share.expires_at <= datetime.utcnow()
            ):
                existing_share.is_active = False

            else:

                existing_share.expires_at = expiry_date

                record_audit(
                    action="DOCUMENT SHARING UPDATED",
                    document_id=document.id,
                    details=f"Sharing expiry updated for {recipient.email}"
                )

                db.session.commit()

                flash("Existing sharing permission updated.")

                return redirect(url_for(
                    "share_document",
                    document_id=document.id
                ))

        new_share = DocumentShare(
            document_id=document.id,
            sender_id=current_user.id,
            recipient_id=recipient.id,
            expires_at=expiry_date
        )

        db.session.add(new_share)
        db.session.flush()

        record_audit(
            action="DOCUMENT SHARED",
            document_id=document.id,
            details=f"Shared with {recipient.email}"
        )

        db.session.add(
            AuditLog(
                user_id=recipient.id,
                document_id=document.id,
                action="DOCUMENT RECEIVED",
                details=f"Document shared by {current_user.email}"
            )
        )

        try:

            db.session.commit()

            flash("Document shared successfully.")

            return redirect(url_for(
                "share_document",
                document_id=document.id
            ))

        except Exception:

            db.session.rollback()

            app.logger.exception("Document sharing failed.")

            flash("Document sharing failed.")

    active_shares = DocumentShare.query.filter_by(
        document_id=document.id,
        sender_id=current_user.id,
        is_active=True
    ).all()

    shared_access = []

    for share in active_shares:

        recipient = db.session.get(
            User,
            share.recipient_id
        )

        if recipient:
            shared_access.append((share, recipient))

    return render_template(
        "share.html",
        document=document,
        shared_access=shared_access
    )


# =====================================
# DOCUMENTS SHARED WITH ME
# =====================================

@app.route("/shared-with-me")
@login_required
def shared_with_me():

    now = datetime.utcnow()

    shares = DocumentShare.query.filter(
        DocumentShare.recipient_id == current_user.id,
        DocumentShare.is_active.is_(True),
        or_(
            DocumentShare.expires_at.is_(None),
            DocumentShare.expires_at > now
        )
    ).order_by(
        DocumentShare.created_at.desc()
    ).all()

    shared_items = []

    for share in shares:

        document = db.session.get(
            Document,
            share.document_id
        )

        sender = db.session.get(
            User,
            share.sender_id
        )

        if document and sender:
            shared_items.append(
                (share, document, sender)
            )

    return render_template(
        "shared_documents.html",
        shared_items=shared_items
    )


# =====================================
# REVOKE DOCUMENT ACCESS
# =====================================

@app.route(
    "/shares/<int:share_id>/revoke",
    methods=["POST"]
)
@login_required
def revoke_share(share_id):

    share = db.session.get(
        DocumentShare,
        share_id
    )

    if share is None:
        abort(404)

    document = db.session.get(
        Document,
        share.document_id
    )

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        abort(403)

    if not share.is_active:
        flash("This sharing permission is already inactive.")
        return redirect(url_for(
            "share_document",
            document_id=document.id
        ))

    share.is_active = False

    recipient = db.session.get(
        User,
        share.recipient_id
    )

    recipient_email = (
        recipient.email if recipient else "Unknown recipient"
    )

    record_audit(
        action="DOCUMENT ACCESS REVOKED",
        document_id=document.id,
        details=f"Access revoked for {recipient_email}"
    )

    db.session.add(
        AuditLog(
            user_id=share.recipient_id,
            document_id=document.id,
            action="DOCUMENT ACCESS REVOKED",
            details="The document owner revoked your access."
        )
    )

    try:

        db.session.commit()

        flash("Document access revoked successfully.")

    except Exception:

        db.session.rollback()

        app.logger.exception("Access revocation failed.")

        flash("Could not revoke access. Please try again.")

    return redirect(url_for(
        "share_document",
        document_id=document.id
    ))


# =====================================
# DOCUMENT DOWNLOAD
# =====================================

@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if document is None:
        abort(404)

    if not user_can_access_document(document):
        abort(403)

    try:

        decrypted_data = fernet.decrypt(
            document.encrypted_data
        )

    except InvalidToken:

        abort(500)

    try:

        record_audit(
            action="DOCUMENT DOWNLOADED",
            document_id=document.id,
            details=f"Downloaded document: {document.filename}"
        )

        db.session.commit()

    except Exception:

        db.session.rollback()

        app.logger.exception("Download audit logging failed.")

        flash("Download could not be recorded. Please try again.")

        return redirect(url_for("dashboard"))

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=document.filename
    )


# =====================================
# DOCUMENT INTEGRITY VERIFICATION
# =====================================

@app.route(
    "/documents/<int:document_id>/verify",
    methods=["POST"]
)
@login_required
def verify_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if document is None:
        abort(404)

    if not user_can_access_document(document):
        abort(403)

    try:

        decrypted_data = fernet.decrypt(
            document.encrypted_data
        )

        current_hash = hashlib.sha256(
            decrypted_data
        ).hexdigest()

    except InvalidToken:

        record_audit(
            action="INTEGRITY VERIFICATION FAILED",
            document_id=document.id,
            details="Document encryption is invalid."
        )

        db.session.commit()

        flash(
            "Integrity check failed: document encryption is invalid."
        )

        return redirect(url_for("dashboard"))

    if not document.sha256_hash:

        document.sha256_hash = current_hash

        record_audit(
            action="DOCUMENT FINGERPRINT CREATED",
            document_id=document.id,
            details="Fingerprint created for an older document."
        )

        db.session.commit()

        flash(
            "Fingerprint created. Please verify the document again."
        )

        return redirect(url_for("dashboard"))

    if hmac.compare_digest(
        document.sha256_hash,
        current_hash
    ):

        record_audit(
            action="INTEGRITY VERIFICATION PASSED",
            document_id=document.id,
            details="Document fingerprint matches."
        )

        db.session.commit()

        flash(
            "Integrity Verified: Your document has not changed."
        )

    else:

        record_audit(
            action="INTEGRITY VERIFICATION FAILED",
            document_id=document.id,
            details="Document fingerprint does not match."
        )

        db.session.commit()

        flash(
            "Integrity Check Failed: Document may have been altered."
        )

    return redirect(url_for("dashboard"))


# =====================================
# AUDIT LOG PAGE
# =====================================

@app.route("/audit-log")
@login_required
def audit_log():

    logs = AuditLog.query.filter_by(
        user_id=current_user.id
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(200).all()

    return render_template(
        "audit_log.html",
        logs=logs
    )


# =====================================
# LOGOUT
# =====================================

@app.route("/logout")
@login_required
def logout():

    try:

        record_audit(
            action="USER LOGGED OUT",
            details="User logged out of VaultShare."
        )

        db.session.commit()

    except Exception:

        db.session.rollback()

        app.logger.exception("Logout audit logging failed.")

    logout_user()

    flash("You have logged out successfully.")

    return redirect(url_for("login"))


# =====================================
# CREATE DATABASE TABLES AND MIGRATE
# =====================================

with app.app_context():

    db.create_all()

    # Existing document migration

    document_columns = {
        column["name"]
        for column in inspect(db.engine).get_columns("document")
    }

    if "sha256_hash" not in document_columns:

        with db.engine.begin() as connection:

            connection.execute(
                text(
                    "ALTER TABLE document "
                    "ADD COLUMN sha256_hash VARCHAR(64)"
                )
            )

    # Existing user table migration

    user_columns = {
        column["name"]
        for column in inspect(db.engine).get_columns("user")
    }

    with db.engine.begin() as connection:

        if "failed_login_attempts" not in user_columns:

            connection.execute(
                text(
                    'ALTER TABLE "user" '
                    "ADD COLUMN failed_login_attempts "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            )

        if "locked_until" not in user_columns:

            connection.execute(
                text(
                    'ALTER TABLE "user" '
                    "ADD COLUMN locked_until TIMESTAMP NULL"
                )
            )


# =====================================
# RUN APPLICATION
# =====================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
        )
