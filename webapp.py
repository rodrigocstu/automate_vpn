#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask Web App — VPN SSL GlobalProtect Automation
Con autenticación y roles: admin, user, guest
Soporta entornos QA y PRD.

Ejecutar:
  python webapp.py --env qa     (puerto 5000)
  python webapp.py --env prd    (puerto 5001)
"""

import os
import sys
import logging
import argparse
import shutil
import json
import uuid
import sqlite3
import tempfile
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import date, datetime, timedelta
from functools import wraps

# Logging estructurado (sin PII ni secretos en logs)
logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","module":"%(module)s","msg":%(message)s}',
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
log = logging.getLogger("vpnapp")

from flask import (
    Flask, render_template, request, jsonify, send_file,
    session, redirect, url_for, g, flash,
)
from werkzeug.security import generate_password_hash, check_password_hash

# Importar lógica del script existente
from vpn_globalprotect import (
    normalize_minsal,
    normalize_rut,
    generate_username,
    generate_password,
    process_data,
    build_cli_int,
    build_cli_ext,
    parse_ticket,
    read_excel_row,
    create_template_excel,
    DEFAULTS,
)


# ═══════════════════════════════════════════════════════════════════════
# ENV CONFIG (QA / PRD)
# ═══════════════════════════════════════════════════════════════════════

ENV_CONFIGS = {
    "qa": {
        "name": "QA",
        "label": "ENTORNO QA",
        "emoji": "\U0001F9EA",
        "port": 5000,
        "db_file": "vpnapp_qa.db",
        "accent": "#005f9f",         # Entel Blue
        "accent_hover": "#004a7c",
        "accent_glow": "rgba(0, 95, 159, 0.3)",
        "gradient_from": "#005f9f",
        "gradient_to": "#f57917",    # Entel Orange
        "incluir_commit": True,
        "banner_bg": "rgba(0, 95, 159, 0.10)",
        "banner_border": "rgba(0, 95, 159, 0.30)",
        "banner_color": "#60a5fa",
    },
    "prd": {
        "name": "PRD",
        "label": "PRODUCCION",
        "emoji": "\U0001F3ED",
        "port": 5001,
        "db_file": "vpnapp_prd.db",
        "accent": "#005f9f",         # Entel Blue
        "accent_hover": "#004a7c",
        "accent_glow": "rgba(0, 95, 159, 0.3)",
        "gradient_from": "#005f9f",
        "gradient_to": "#0a2540",
        "incluir_commit": False,
        "banner_bg": "rgba(0, 95, 159, 0.10)",
        "banner_border": "rgba(0, 95, 159, 0.30)",
        "banner_color": "#60a5fa",
    },
}

# Parse --env arg (default: qa)
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--env", default="qa", choices=["qa", "prd"])
_args, _remaining = _parser.parse_known_args()

APP_ENV = _args.env
ENV_CFG = ENV_CONFIGS[APP_ENV]

# Módulo CMDB Sync
from cmdb_sync import CMDBSyncService
cmdb_service = CMDBSyncService(os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", ENV_CFG["db_file"]))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB max upload

# SECRET_KEY — OBLIGATORIO via env var; la app falla si no está configurado
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "SECRET_KEY env var is required. "
        "Genera uno con: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.config["SECRET_KEY"] = _secret
app.config["DATABASE"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "instance", ENV_CFG["db_file"]
)

# Seguridad de cookies de sesión
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"
app.config["SESSION_COOKIE_SECURE"]    = (APP_ENV == "prd")  # HTTPS solo en PRD
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)


@app.before_request
def attach_request_id():
    """Agrega un ID único a cada request para trazabilidad en logs."""
    g.request_id = str(uuid.uuid4())[:8]


@app.after_request
def set_security_headers(response):
    """Aplica headers HTTP de seguridad en todas las respuestas."""
    response.headers["X-Request-ID"]              = getattr(g, "request_id", "-")
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    if APP_ENV == "prd":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

import traceback
@app.errorhandler(500)
def handle_500(e):
    req_id = getattr(g, "request_id", "unknown")
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fatal_error.log")
    err_trace = traceback.format_exc()
    
    # Log técnico para el desarrollador
    print(f"\n!!! FATAL ERROR 500 (Ref: {req_id}) !!!\n{err_trace}")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n--- ERROR 500 (Ref: {req_id}) ---\n")
        f.write(err_trace)
        f.write("-" * 40 + "\n")
    
    # Log estructurado estándar
    log.error('"Internal server error, request_id=%s error=%s"', req_id, str(e))
    
    if request.is_json:
        return jsonify({"error": "Internal Server Error", "ref": req_id}), 500
    return render_template("login.html", error=f"Error interno (500). Ref: {req_id}"), 500


# ── Error handlers — evitan stack traces en producción ───────────────────────
@app.errorhandler(400)
def err_400(e):
    if request.is_json:
        return jsonify({"error": "Solicitud inválida.", "code": 400}), 400
    return render_template("login.html", error="Solicitud inválida (400)."), 400

@app.errorhandler(403)
def err_403(e):
    if request.is_json:
        return jsonify({"error": "Acceso denegado.", "code": 403}), 403
    return render_template("login.html", error="Acceso denegado (403)."), 403

@app.errorhandler(404)
def err_404(e):
    if request.is_json:
        return jsonify({"error": "Recurso no encontrado.", "code": 404}), 404
    return render_template("login.html", error="Página no encontrada (404)."), 404

@app.errorhandler(429)
def err_429(e):
    if request.is_json:
        return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde.", "code": 429}), 429
    return render_template("login.html", error="Demasiadas solicitudes. Espera unos minutos."), 429



# ═══════════════════════════════════════════════════════════════════════
# SMTP CONFIG (Gmail)
# ═══════════════════════════════════════════════════════════════════════

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "rodrigostuardos@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "")  # App Password de Google
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
OTP_EXPIRY_MINUTES = 5


# ═══════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════

def get_db():
    """Obtiene conexión a la BD (una por request)."""
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Crea tablas y seed del admin por defecto."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('super_admin','admin','user','guest')),
            must_change_pw INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK(purpose IN ('login','reset')),
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            attempted_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        -- CMDB Configuration Management (ITIL 4 / ServiceNow inspired)
        CREATE TABLE IF NOT EXISTS cmdb_ci (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ci_class TEXT NOT NULL, -- Firewall, Panorama, Interface, VPN Tunnel
            ip_address TEXT,
            status TEXT NOT NULL DEFAULT 'Operational', -- Operational, Repair, retired
            environment TEXT NOT NULL DEFAULT 'QA', -- QA, PRD
            attributes TEXT, -- JSON field for class-specific attributes
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS cmdb_rel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER NOT NULL,
            child_id INTEGER NOT NULL,
            type TEXT NOT NULL, -- Runs on, Depends on, Member of
            FOREIGN KEY (parent_id) REFERENCES cmdb_ci(id),
            FOREIGN KEY (child_id) REFERENCES cmdb_ci(id)
        );
        -- CMDB Audit History (Undo/Redo implementation)
        CREATE TABLE IF NOT EXISTS cmdb_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ci_id INTEGER,
            ci_type TEXT, -- location, hardware, network
            batch_id TEXT, -- UUID for bulk operations
            action TEXT NOT NULL, -- INSERT, UPDATE, DELETE, DEACTIVATE
            data_before TEXT, -- JSON snapshot
            data_after TEXT,  -- JSON snapshot
            undone INTEGER NOT NULL DEFAULT 0, -- 1 if undone
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        -- Normalized CMDB Tables (ITIL 4 / National Registry)
        CREATE TABLE IF NOT EXISTS cmdb_location_ci (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            region TEXT,
            comuna TEXT,
            provincia TEXT,
            macrozone TEXT,
            contratante TEXT,
            tipo_establecimiento TEXT,
            complejidad TEXT,
            casillas_correos TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            UNIQUE(name, address)
        );
        CREATE TABLE IF NOT EXISTS cmdb_hardware_ci (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location_id INTEGER NOT NULL,
            batch_id TEXT,
            model TEXT,
            machine_type TEXT,
            sw TEXT,
            vc TEXT,
            lineas_sobrevivencia TEXT,
            telefonos_satelitales TEXT,
            linea_800 TEXT,
            lineas_moviles TEXT,
            bam TEXT,
            samu_131 TEXT,
            ccm TEXT,
            fw TEXT,
            fw_sugerido TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (location_id) REFERENCES cmdb_location_ci(id)
        );
        CREATE TABLE IF NOT EXISTS cmdb_network_ci (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location_id INTEGER NOT NULL,
            batch_id TEXT,
            access_type TEXT,
            bandwidth TEXT,
            acceso_resp TEXT,
            bw_datos_resp TEXT,
            acceso_resp2 TEXT,
            bw_datos_resp2 TEXT,
            acceso_resp3 TEXT,
            bw_datos_resp3 TEXT,
            wifi TEXT,
            lineas_home TEXT,
            internet_dedicado TEXT,
            enlace_1_sugerido TEXT,
            enlace_2_sugerido TEXT,
            satelital_sugerido TEXT,
            voz TEXT,
            datos TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (location_id) REFERENCES cmdb_location_ci(id)
        );
        CREATE TABLE IF NOT EXISTS cmdb_batches (
            id TEXT PRIMARY KEY, -- UUID
            user_id INTEGER NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'completed', -- pending, completed, undone
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
        CREATE INDEX IF NOT EXISTS idx_otp_lookup      ON otp_codes(user_id, purpose, used);
        CREATE INDEX IF NOT EXISTS idx_attempts_ip     ON login_attempts(ip, endpoint, attempted_at);
        CREATE INDEX IF NOT EXISTS idx_cmdb_name       ON cmdb_ci(name);
        CREATE INDEX IF NOT EXISTS idx_cmdb_class      ON cmdb_ci(ci_class);
        CREATE INDEX IF NOT EXISTS idx_cmdb_history_ci ON cmdb_history(ci_id);
    """)

    # Agregar columna email si no existe (migración)
    try:
        db.execute("SELECT email FROM users LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        db.commit()

    # Agregar columnas a cmdb_history si no existen
    try:
        db.execute("SELECT ci_type FROM cmdb_history LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE cmdb_history ADD COLUMN ci_type TEXT")
        db.commit()
    try:
        db.execute("SELECT batch_id FROM cmdb_history LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE cmdb_history ADD COLUMN batch_id TEXT")
        db.commit()

    # Asegurar que cmdb_ci tenga columna id incremental si era antigua
    try:
        db.execute("SELECT id FROM cmdb_ci LIMIT 1")
    except sqlite3.OperationalError:
        # Migración compleja para cmdb_ci (recrear con ID)
        log.info('"Migrating cmdb_ci to include ID column"')
        db.executescript("""
            CREATE TABLE cmdb_ci_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ci_class TEXT NOT NULL,
                ip_address TEXT,
                status TEXT NOT NULL DEFAULT 'Operational',
                environment TEXT NOT NULL DEFAULT 'QA',
                attributes TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            );
            INSERT INTO cmdb_ci_new (name, ci_class, ip_address, status, environment, attributes, created_at)
            SELECT name, ci_class, ip_address, status, environment, attributes, created_at FROM cmdb_ci;
            DROP TABLE cmdb_ci;
            ALTER TABLE cmdb_ci_new RENAME TO cmdb_ci;
        """)
        db.commit()

    # Migración: Nuevas columnas CMDB (Mapeo 1:1)
    for col in ["provincia", "contratante", "tipo_establecimiento", "complejidad", "casillas_correos"]:
        try: db.execute(f"SELECT {col} FROM cmdb_location_ci LIMIT 1")
        except sqlite3.OperationalError:
            db.execute(f"ALTER TABLE cmdb_location_ci ADD COLUMN {col} TEXT")
            db.commit()

    for col in ["sw", "vc", "lineas_sobrevivencia", "telefonos_satelitales", "linea_800", 
                "lineas_moviles", "bam", "samu_131", "ccm", "fw", "fw_sugerido"]:
        try: db.execute(f"SELECT {col} FROM cmdb_hardware_ci LIMIT 1")
        except sqlite3.OperationalError:
            db.execute(f"ALTER TABLE cmdb_hardware_ci ADD COLUMN {col} TEXT")
            db.commit()

    for col in ["acceso_resp", "bw_datos_resp", "acceso_resp2", "bw_datos_resp2", 
                "acceso_resp3", "bw_datos_resp3", "wifi", "lineas_home", 
                "internet_dedicado", "enlace_1_sugerido", "enlace_2_sugerido", 
                "satelital_sugerido", "voz", "datos"]:
        try: db.execute(f"SELECT {col} FROM cmdb_network_ci LIMIT 1")
        except sqlite3.OperationalError:
            db.execute(f"ALTER TABLE cmdb_network_ci ADD COLUMN {col} TEXT")
            db.commit()

    db.executescript("""
        CREATE INDEX IF NOT EXISTS idx_cmdb_history_batch ON cmdb_history(batch_id);
        CREATE INDEX IF NOT EXISTS idx_cmdb_loc_name_addr ON cmdb_location_ci(name, address);
        CREATE INDEX IF NOT EXISTS idx_cmdb_hw_loc ON cmdb_hardware_ci(location_id);
        CREATE INDEX IF NOT EXISTS idx_cmdb_net_loc ON cmdb_network_ci(location_id);
    """)
    db.commit()

    # ── Migración segura de CHECK constraint (solo si es primera vez) ───────
    # Detectamos si la migración ya se completó chequeando el CHECK en sqlite_master
    schema = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    already_migrated = (
        schema is None
        or ("super_admin" in (schema["sql"] or ""))
    )
    if not already_migrated:
        log.info('"Running one-time schema migration for super_admin role"')
        try:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("BEGIN TRANSACTION")
            db.execute("""
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('super_admin','admin','user','guest')),
                    must_change_pw INTEGER NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
                )
            """)
            db.execute("INSERT INTO users_new SELECT * FROM users")
            db.execute("DROP TABLE users")
            db.execute("ALTER TABLE users_new RENAME TO users")
            db.execute("COMMIT")
            log.info('"Schema migration completed successfully"')
        except sqlite3.OperationalError as migrate_err:
            db.execute("ROLLBACK")
            log.error('"Schema migration failed: %s"', str(migrate_err))
        finally:
            db.execute("PRAGMA foreign_keys=ON")

    # Seed: admin / admin (Role: super_admin)
    admin_exists = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin_exists:
        must_change = 1 if APP_ENV == "prd" else 0
        db.execute(
            "INSERT INTO users (username, password_hash, display_name, email, role, must_change_pw) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", generate_password_hash("admin"), "Super Administrador", "rodrigo.cstu@gmail.com", "super_admin", must_change),
        )
    else:
        # Asegurar que admin tenga el rol super_admin y nombre correcto
        db.execute("UPDATE users SET role = 'super_admin', display_name = 'Super Administrador' WHERE username = 'admin'")

    # Seed: rodrigo_entel / entel2026 (Role: admin)
    rodrigo_exists = db.execute("SELECT id FROM users WHERE username = ?", ("rodrigo_entel",)).fetchone()
    if not rodrigo_exists:
        db.execute(
            "INSERT INTO users (username, password_hash, display_name, email, role, must_change_pw) VALUES (?, ?, ?, ?, ?, ?)",
            ("rodrigo_entel", generate_password_hash("entel2026"), "Rodrigo Entel", "rodrigo.entel@entel.cl", "admin", 0),
        )
    else:
        # Asegurar que rodrigo_entel sea admin
        db.execute("UPDATE users SET role = 'admin' WHERE username = 'rodrigo_entel'")

    # Seed: CMDB Initial CIs (ServiceNow-like baseline)
    ci_exists = db.execute("SELECT id FROM cmdb_ci LIMIT 1").fetchone()
    if not ci_exists:
        # Firewall Principal
        db.execute("""
            INSERT INTO cmdb_ci (name, ci_class, ip_address, status, environment, attributes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("FW-CORE-PRD-01", "Firewall", "10.0.1.1", "Operational", "PRD", 
             '{"model": "PA-3220", "version": "10.2.4", "vsys": "vsys1"}'))
        
        # Interface AE1
        db.execute("""
            INSERT INTO cmdb_ci (name, ci_class, ip_address, status, environment, attributes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("ae1.10 (Trust)", "Interface", "10.10.10.1", "Operational", "PRD", 
             '{"parent_if": "ae1", "zone": "trust", "vlan": 10}'))
        
        # VPN Tunnel
        db.execute("""
            INSERT INTO cmdb_ci (name, ci_class, ip_address, status, environment, attributes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("TUNNEL-S2S-AWS", "VPN Tunnel", "169.254.0.1", "Operational", "PRD", 
             '{"peer": "AWS-VGW", "protocol": "IPsec"}'))

        # Relations
        db.execute("INSERT INTO cmdb_rel (parent_id, child_id, type) VALUES (1, 2, 'Member of')")
        db.execute("INSERT INTO cmdb_rel (parent_id, child_id, type) VALUES (1, 3, 'Depends on')")

    db.commit()
    log.info('"DB initialized — seed users and CMDB configured"')


with app.app_context():
    init_db()


# ═══════════════════════════════════════════════════════════════════════
# RATE LIMITING (sin dependencias externas)
# ═══════════════════════════════════════════════════════════════════════

RATE_LIMIT_MAX     = int(os.environ.get("RATE_LIMIT_MAX", "5"))      # intentos máximos
RATE_LIMIT_WINDOW  = int(os.environ.get("RATE_LIMIT_WINDOW", "5"))   # ventana en minutos


def check_rate_limit(endpoint: str) -> bool:
    """Retorna True si la IP puede continuar; False si está bloqueada.
    Registra cada intento en login_attempts y limpia entradas antiguas.
    """
    ip = request.remote_addr or "unknown"
    db = get_db()
    cutoff = (datetime.now() - timedelta(minutes=RATE_LIMIT_WINDOW)).strftime("%Y-%m-%d %H:%M:%S")
    # Limpiar intentos viejos (mantener la tabla pequeña)
    db.execute(
        "DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,)
    )
    count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND endpoint = ? AND attempted_at >= ?",
        (ip, endpoint, cutoff),
    ).fetchone()[0]
    if count >= RATE_LIMIT_MAX:
        log.warning('"Rate limit exceeded, ip=%s endpoint=%s count=%d"', ip, endpoint, count)
        return False  # bloqueado
    db.execute(
        "INSERT INTO login_attempts (ip, endpoint) VALUES (?, ?)", (ip, endpoint)
    )
    db.commit()
    return True  # permitido


# ═══════════════════════════════════════════════════════════════════════
# CSRF PROTECTION (stateless, HMAC-based, sin dependencias externas)
# ═══════════════════════════════════════════════════════════════════════

import hmac
import hashlib


def generate_csrf_token() -> str:
    """Genera (o reutiliza) un token CSRF por sesión."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def validate_csrf(token_from_form: str) -> bool:
    """Valida el token CSRF del form contra el almacenado en sesión."""
    expected = session.get("_csrf", "")
    if not expected:
        return False
    return hmac.compare_digest(expected, token_from_form or "")


# Inyectar csrf_token() como función disponible en todos los templates Jinja2
@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf_token}


# ═══════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════════

def current_user():
    """Retorna dict del usuario en sesión (con cache en g para evitar N queries por request)."""
    if "user" in g:       # Cache hit — ya cargado en este request
        return g.user
    user_id = session.get("user_id")
    if user_id is None:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()
    if row is None:
        session.clear()
        return None
    g.user = dict(row)    # Guardar en g para este request
    return g.user


def login_required(f):
    """Decorador: requiere sesión activa."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if user is None:
            if request.is_json:
                return jsonify({"error": "No autenticado."}), 401
            return redirect(url_for("login"))
        # Forzar cambio de contraseña
        if user["must_change_pw"] and request.endpoint not in ("change_password", "logout", "static"):
            if request.is_json:
                return jsonify({"error": "Debe cambiar su contraseña.", "must_change_pw": True}), 403
            return redirect(url_for("change_password"))
        g.user = user
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorador: requiere uno de los roles especificados."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = g.get("user") or current_user()
            if user is None:
                if request.is_json:
                    return jsonify({"error": "No autenticado."}), 401
                return redirect(url_for("login"))
            # Super Admin bypass any role check
            if user["role"] == "super_admin":
                return f(*args, **kwargs)
            if user["role"] not in roles:
                if request.is_json:
                    return jsonify({"error": "Acceso denegado. Rol insuficiente."}), 403
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ═══════════════════════════════════════════════════════════════════════
# OTP / EMAIL HELPERS
# ═══════════════════════════════════════════════════════════════════════

def generate_otp(user_id, purpose, db):
    """Genera un código OTP alfanumérico de 6 caracteres (CSPRNG) y lo guarda en BD."""
    chars = string.ascii_uppercase + string.digits
    code = "".join(secrets.choice(chars) for _ in range(6))  # secrets = CSPRNG
    expires = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    # Invalidar códigos anteriores del mismo propósito
    db.execute("UPDATE otp_codes SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0", (user_id, purpose))
    db.execute(
        "INSERT INTO otp_codes (user_id, code, purpose, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, code, purpose, expires),
    )
    db.commit()
    return code


def verify_otp(user_id, code, purpose, db):
    """Verifica un código OTP. Retorna True si válido."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row = db.execute(
        "SELECT id FROM otp_codes WHERE user_id = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > ?",
        (user_id, code, purpose, now),
    ).fetchone()
    if row:
        db.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (row["id"],))
        db.commit()
        return True
    return False


def send_otp_email(to_email, code, purpose="login"):
    """Envía el código OTP por Gmail SMTP."""
    if not SMTP_PASS:
        log.warning('"SMTP_PASS not set — OTP delivery skipped, purpose=%s"', purpose)
        return True  # Modo consola si no hay password

    subject_map = {
        "login": "Código de verificación — VPN GlobalProtect",
        "reset": "Recuperar contraseña — VPN GlobalProtect",
    }
    subject = subject_map.get(purpose, "Código — VPN GlobalProtect")

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;
                background: #1a1a2e; color: #e0e0e0; padding: 30px; border-radius: 12px;">
        <h2 style="color: #fbbf24; text-align: center;">🛡️ VPN GlobalProtect</h2>
        <p style="text-align: center; font-size: 14px; color: #9ca3af;">{'Código de verificación' if purpose == 'login' else 'Recuperar contraseña'}</p>
        <div style="text-align: center; margin: 25px 0;">
            <span style="display: inline-block; font-size: 36px; font-weight: bold; letter-spacing: 8px;
                         color: #fbbf24; background: rgba(245, 158, 11, 0.1); padding: 15px 30px;
                         border-radius: 10px; border: 2px solid rgba(245, 158, 11, 0.3);">{code}</span>
        </div>
        <p style="text-align: center; font-size: 13px; color: #6b7280;">
            Este código expira en {OTP_EXPIRY_MINUTES} minutos.<br>
            Si no solicitaste este código, ignora este mensaje.
        </p>
    </div>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(f"Tu código: {code} (expira en {OTP_EXPIRY_MINUTES} min)", "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        log.info('"OTP email sent, purpose=%s"', purpose)  # NO loguear email completo ni el código
        return True
    except Exception as e:
        log.error('"OTP email failed: %s"', str(e))
        return False


# ═══════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    """Página de login estándar: usuario + contraseña."""
    if current_user():
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        # ── Rate limiting por IP ────────────────────────────────────
        if not check_rate_limit("login"):
            error = f"Demasiados intentos. Espera {RATE_LIMIT_WINDOW} minutos."
            return render_template("login.html", error=error), 429

        # ── CSRF ────────────────────────────────────────────
        if not validate_csrf(request.form.get("_csrf", "")):
            log.warning('"CSRF validation failed on /login, ip=%s"', request.remote_addr)
            error = "Token de seguridad inválido. Recarga la página."
            return render_template("login.html", error=error), 403

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # Login exitoso — rotar sesión (session fixation protection)
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            log.info('"Login successful, user_id=%d role=%s"', user["id"], user["role"])
            if user["must_change_pw"]:
                return redirect(url_for("change_password"))
            return redirect(url_for("index"))
        else:
            log.warning('"Login failed, username=%s ip=%s"', username[:20], request.remote_addr)
            error = "Usuario o contraseña incorrectos."

    return render_template("login.html", error=error)


@app.route("/login-by-code", methods=["GET", "POST"])
def login_by_code():
    """Solicitar inicio de sesión por código enviado al email (sin contraseña)."""
    error = None
    if request.method == "POST":
        # ── Rate limiting ───────────────────────────────────────
        if not check_rate_limit("login_by_code"):
            error = f"Demasiadas solicitudes. Espera {RATE_LIMIT_WINDOW} minutos."
            return render_template("forgot_password.html", error=error, is_login_by_code=True), 429
        # ── CSRF ────────────────────────────────────────────
        if not validate_csrf(request.form.get("_csrf", "")):
            error = "Token de seguridad inválido. Recarga la página."
            return render_template("forgot_password.html", error=error, is_login_by_code=True), 403

        username = request.form.get("username", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE (username = ? OR email = ?) AND active = 1", (username, username)).fetchone()
        if user and user["email"]:
            code = generate_otp(user["id"], "login", db)
            send_otp_email(user["email"], code, "login")
            session["pending_code_user"] = user["id"]
            return redirect(url_for("verify_login_code"))
        else:
            error = "Usuario no encontrado o sin email registrado."

    return render_template("forgot_password.html", error=error, is_login_by_code=True)


@app.route("/verify-login-code", methods=["GET", "POST"])
def verify_login_code():
    """Verificar código alfanumérico para login directo."""
    user_id = session.get("pending_code_user")
    if not user_id:
        return redirect(url_for("login_by_code"))

    error = None
    if request.method == "POST":
        # ── Rate limiting ───────────────────────────────────────
        if not check_rate_limit("verify_otp"):
            error = f"Demasiados intentos. Espera {RATE_LIMIT_WINDOW} minutos."
            return render_template("verify_code.html", error=error, purpose="login_by_code"), 429
        # ── CSRF ────────────────────────────────────────────
        if not validate_csrf(request.form.get("_csrf", "")):
            error = "Token de seguridad inválido. Recarga la página."
            return render_template("verify_code.html", error=error, purpose="login_by_code"), 403

        code = request.form.get("code", "").strip().upper()
        db = get_db()
        if verify_otp(user_id, code, "login", db):
            session.pop("pending_code_user", None)
            session["user_id"] = user_id
            session.permanent = True
            log.info('"OTP login successful, user_id=%d"', user_id)
            return redirect(url_for("index"))
        else:
            log.warning('"OTP verification failed, user_id=%d ip=%s"', user_id, request.remote_addr)
            error = "Código inválido o expirado."

    return render_template("verify_code.html", error=error, purpose="login_by_code")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Mantener recuperación por ahora o redirigir."""
    return redirect(url_for("login_by_code"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Cerrar sesión. POST preferido (CSRF-safe). GET funciona para compatibilidad."""
    user = current_user()
    if user:
        log.info('"Logout, user_id=%d"', user["id"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Cambio de contraseña (obligatorio o voluntario)."""
    user = g.user
    error = None
    success = None

    if request.method == "POST":
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if len(new_pw) < 8:
            error = "La contraseña debe tener al menos 8 caracteres."
        elif not any(c.isdigit() for c in new_pw):
            error = "La contraseña debe incluir al menos un número."
        elif not any(c.isalpha() for c in new_pw):
            error = "La contraseña debe incluir al menos una letra."
        elif new_pw != confirm_pw:
            error = "Las contraseñas no coinciden."
        elif user["must_change_pw"] and new_pw == "admin":
            error = "Debe elegir una contraseña diferente a la predeterminada."
        else:
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ?, must_change_pw = 0 WHERE id = ?",
                (generate_password_hash(new_pw), user["id"]),
            )
            db.commit()
            session["user_id"] = user["id"]

            if user["must_change_pw"]:
                return redirect(url_for("index"))
            success = "Contraseña actualizada correctamente."

    return render_template("change_password.html",
                           error=error, success=success,
                           must_change=user["must_change_pw"])


# ═══════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.route("/admin")
@login_required
@role_required("admin")
def admin_panel():
    """Panel de administración de usuarios."""
    return render_template("admin.html", user=g.user)


@app.route("/api/admin/users", methods=["GET"])
@login_required
@role_required("admin")
def api_list_users():
    """Lista todos los usuarios."""
    db = get_db()
    rows = db.execute(
        "SELECT id, username, display_name, email, role, active, must_change_pw, created_at FROM users ORDER BY id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/users", methods=["POST"])
@login_required
@role_required("admin")
def api_create_user():
    """Crea un nuevo usuario."""
    data = request.get_json()
    username = (data.get("username") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username:
        return jsonify({"error": "Username es requerido."}), 400
    if len(password) < 4:
        return jsonify({"error": "Contraseña mínimo 4 caracteres."}), 400
    if role not in ("admin", "user", "guest"):
        return jsonify({"error": "Rol inválido."}), 400

    db = get_db()
    exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        return jsonify({"error": f"El usuario '{username}' ya existe."}), 409

    db.execute(
        "INSERT INTO users (username, password_hash, display_name, email, role, must_change_pw) VALUES (?, ?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), display_name, email, role, 0),
    )
    db.commit()
    return jsonify({"success": True, "message": f"Usuario '{username}' creado."})


@app.route("/api/admin/users/<int:user_id>", methods=["PUT"])
@login_required
@role_required("admin")
def api_update_user(user_id):
    """Actualiza usuario (rol, nombre, estado, contraseña)."""
    data = request.get_json()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404

    # No permitir que el admin se desactive a sí mismo
    if user_id == g.user["id"] and data.get("active") == False:
        return jsonify({"error": "No puedes desactivarte a ti mismo."}), 400

    updates = []
    params = []

    if "display_name" in data:
        updates.append("display_name = ?")
        params.append(data["display_name"].strip())
    if "email" in data:
        updates.append("email = ?")
        params.append((data["email"] or "").strip().lower())
    if "role" in data and data["role"] in ("admin", "user", "guest"):
        # No permitir que el último admin pierda su rol
        if user["role"] == "admin" and data["role"] != "admin":
            admin_count = db.execute("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND active = 1").fetchone()["c"]
            if admin_count <= 1:
                return jsonify({"error": "Debe haber al menos un admin activo."}), 400
        updates.append("role = ?")
        params.append(data["role"])
    if "active" in data:
        updates.append("active = ?")
        params.append(1 if data["active"] else 0)
    if "password" in data and data["password"]:
        if len(data["password"]) < 4:
            return jsonify({"error": "Contraseña mínimo 4 caracteres."}), 400
        updates.append("password_hash = ?")
        params.append(generate_password_hash(data["password"]))
        updates.append("must_change_pw = ?")
        params.append(1 if data.get("force_change_pw") else 0)

    if updates:
        params.append(user_id)
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    return jsonify({"success": True, "message": "Usuario actualizado."})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
@role_required("admin")
def api_delete_user(user_id):
    """Desactiva (soft delete) un usuario."""
    if user_id == g.user["id"]:
        return jsonify({"error": "No puedes eliminar tu propia cuenta."}), 400

    db = get_db()
    db.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"success": True, "message": "Usuario desactivado."})


@app.route("/api/admin/migrate-to-prd", methods=["POST"])
@login_required
@role_required("super_admin")
def api_migrate_to_prd():
    """Migra configuración completa de QA a PRD usando metodología ITIL 4 (Change Enablement)."""
    # Restricción de Gobernanza: solo permitimos iniciar desde QA
    if APP_ENV != "qa":
        return jsonify({"error": "Service Configuration Management: La migración solo puede ejecutarse desde el entorno QA."}), 403

    source_db_path = os.path.join(app.instance_path, ENV_CONFIGS["qa"]["db_file"])
    target_db_path = os.path.join(app.instance_path, ENV_CONFIGS["prd"]["db_file"])
    backup_db_path = target_db_path + ".bak"

    if not os.path.exists(source_db_path):
        return jsonify({"error": "Alcance: Base de datos QA no encontrada."}), 404

    # 1. Change Assessment & Service Transition: Sincronización ITIL 4
    try:
        if os.path.exists(target_db_path):
            shutil.copy2(target_db_path, backup_db_path)
            log.info('"Pre-migration backup created: %s"', backup_db_path)

        # 2. Service Transition: Sincronización de Tablas Críticas (ITIL 4)
        dest_conn = sqlite3.connect(target_db_path)
        dest_conn.execute("ATTACH DATABASE ? AS source", (source_db_path,))
        dest_conn.execute("BEGIN TRANSACTION")

        # A. Sincronizar Usuarios (Insert or Replace)
        dest_conn.execute("""
            INSERT OR REPLACE INTO main.users (id, username, password_hash, display_name, email, role, must_change_pw, active, created_at)
            SELECT id, username, password_hash, display_name, email, role, must_change_pw, active, created_at FROM source.users
        """)

        # B. Sincronizar CMDB (Reemplazo total con mapeo explícito de columnas)
        cmdb_tables = [
            "cmdb_rel", "cmdb_history", "cmdb_network_ci", 
            "cmdb_hardware_ci", "cmdb_location_ci", "cmdb_batches", "cmdb_ci"
        ]
        
        for tbl in reversed(cmdb_tables):
            prd_cols = {row[1] for row in dest_conn.execute(f"PRAGMA table_info({tbl})").fetchall()}
            qa_cols = {row[1] for row in dest_conn.execute(f"PRAGMA source.table_info({tbl})").fetchall()}
            common = sorted(list(prd_cols.intersection(qa_cols)))
            if not common: continue

            dest_conn.execute(f"DELETE FROM main.{tbl}")
            col_list = ", ".join(common)
            safe_select = []
            for c in common:
                if c == 'created_at': safe_select.append("COALESCE(created_at, datetime('now','localtime'))")
                elif c == 'is_active': safe_select.append("COALESCE(is_active, 1)")
                else: safe_select.append(c)
            
            select_list = ", ".join(safe_select)
            dest_conn.execute(f"INSERT INTO main.{tbl} ({col_list}) SELECT {select_list} FROM source.{tbl}")

        dest_conn.commit()
        
        # 3. Post-Implementation Review
        prd_users = dest_conn.execute("SELECT COUNT(*) FROM main.users").fetchone()[0]
        prd_cis = dest_conn.execute("SELECT COUNT(*) FROM main.cmdb_location_ci").fetchone()[0]
        dest_conn.execute("DETACH DATABASE source")
        dest_conn.close()

        log.info('"Full environment migration successful: users=%d, cis=%d"', prd_users, prd_cis)

        return jsonify({
            "success": True,
            "message": (
                f"Change Enablement: Despliegue ITIL 4 Completado con Éxito\n"
                f"- Assessment: Backup '{os.path.basename(backup_db_path)}' generado.\n"
                f"- Service Transition: Usuarios sincronizados ({prd_users}) y CMDB completa migrada ({prd_cis} establecimientos).\n"
                f"- Validation: PRD ahora refleja fielmente el estado de QA."
            )
        })

    except Exception as e:
        log.error('"Migration failed, triggering rollback: %s"', str(e))
        # Rollback: Restaurar PRD a partir del backup si la transacción falló
        if os.path.exists(backup_db_path):
            try:
                shutil.copy2(backup_db_path, target_db_path)
                log.warning('"Rollback executed: PRD database restored from prior backup"')
            except Exception as restore_err:
                log.error('"Critical: Rollback failed: %s"', str(restore_err))

        return jsonify({"error": f"Fallo Crítico: Se activó protocolo de Rollback. Error original: {str(e)}"}), 500


# ═══════════════════════════════════════════════════════════════════════
# APP ROUTES (protegidas)
# ═══════════════════════════════════════════════════════════════════════

@app.context_processor
def inject_env():
    """Inyecta config de entorno en todos los templates."""
    return {"env": ENV_CFG}


@app.route("/")
@login_required
def index():
    """Página principal."""
    return render_template("index.html", defaults=DEFAULTS, user=g.user)


@app.route("/api/generate", methods=["POST"])
@login_required
@role_required("admin", "user")
def api_generate():
    """Modo 2: genera credenciales + CLI desde parámetros JSON."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No se recibieron datos JSON."}), 400

        params = process_data(data)

        if params["tipo"] == "INT":
            cli = build_cli_int(params)
        else:
            cli = build_cli_ext(params)

        return jsonify({
            "success": True,
            "datos": {
                "ritm": params["ritm"],
                "minsal_input": params["minsal_input"],
                "minsal_norm": params["minsal_norm"],
                "rut_input": params["rut_input"],
                "rut_norm": params["rut_norm"],
                "tipo": params["tipo"],
                "username": params["username"],
                "username_length": len(params["username"]),
                "password": params["password"],
                "password_length": len(params["password"]),
                "vencimiento": params["vencimiento"],
                "ips": params.get("ips", []),
                "puertos": params.get("puertos", []),
                "vsys": params["vsys"],
                "zona_origen": params["zona_origen"],
                "zona_destino": params["zona_destino"],
                "grupo": params.get("grupo_int") if params["tipo"] == "INT" else params.get("grupo_ext"),
                "ansible_playbook": params.get("ansible_playbook", "") if g.user and g.user.get("role") == "super_admin" else "",
            },
            "cli": cli,
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500


@app.route("/api/ticket", methods=["POST"])
@login_required
@role_required("admin", "user")
def api_ticket():
    """Modo 1: parsea ticket desordenado y genera resultado."""
    try:
        data = request.get_json()
        texto = data.get("texto", "")
        if not texto.strip():
            return jsonify({"error": "El texto del ticket está vacío."}), 400

        parsed = parse_ticket(texto)

        missing = [f for f in ["ritm", "minsal", "rut", "tipo"] if not parsed.get(f)]
        if parsed.get("tipo", "").upper() == "EXT" and not parsed.get("vencimiento"):
            missing.append("vencimiento")

        # Ahora process_data no lanza ValueError, genera params con placeholders
        params = process_data(parsed)
        
        if params["tipo"] == "INT":
            cli = build_cli_int(params)
        else:
            cli = build_cli_ext(params)

        res_data = {
            "success": True,
            "parsed": parsed,
            "datos": {
                "ritm": params["ritm"],
                "minsal_input": params["minsal_input"],
                "minsal_norm": params["minsal_norm"],
                "rut_input": params["rut_input"],
                "rut_norm": params["rut_norm"],
                "tipo": params["tipo"],
                "username": params["username"],
                "username_length": len(params["username"]),
                "password": params["password"],
                "password_length": len(params["password"]),
                "vencimiento": params["vencimiento"],
                "ips": params.get("ips", []),
                "puertos": params.get("puertos", []),
                "vsys": params["vsys"],
                "zona_origen": params["zona_origen"],
                "zona_destino": params["zona_destino"],
                "grupo": params.get("grupo_int") if params["tipo"] == "INT" else params.get("grupo_ext"),
                "ansible_playbook": params.get("ansible_playbook", "") if g.user and g.user.get("role") == "super_admin" else "",
            },
            "cli": cli,
        }

        if missing:
            res_data["message"] = f"⚠️ Datos faltantes: {', '.join(missing)}. Puedes completarlos manualmente en el CLI generado."
            res_data["missing"] = missing

        return jsonify(res_data)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500


@app.route("/api/excel", methods=["POST"])
@login_required
@role_required("super_admin")
def api_excel():
    """Modo 3: recibe archivo Excel, procesa una fila."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No se recibió archivo."}), 400

        file = request.files["file"]
        row = int(request.form.get("row", 3))

        if not file.filename.endswith((".xlsx", ".xlsm")):
            return jsonify({"error": "Solo se aceptan archivos .xlsx"}), 400

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
        file.save(tmp.name)
        tmp.close()

        try:
            data = read_excel_row(tmp.name, row)
        finally:
            os.unlink(tmp.name)

        if not data.get("ritm"):
            return jsonify({"error": f"La fila {row} parece estar vacía."}), 400

        params = process_data(data)
        if params["tipo"] == "INT":
            cli = build_cli_int(params)
        else:
            cli = build_cli_ext(params)

        return jsonify({
            "success": True,
            "datos": {
                "ritm": params["ritm"],
                "minsal_input": params["minsal_input"],
                "minsal_norm": params["minsal_norm"],
                "rut_input": params["rut_input"],
                "rut_norm": params["rut_norm"],
                "tipo": params["tipo"],
                "username": params["username"],
                "username_length": len(params["username"]),
                "password": params["password"],
                "password_length": len(params["password"]),
                "vencimiento": params["vencimiento"],
                "ips": params.get("ips", []),
                "puertos": params.get("puertos", []),
                "vsys": params["vsys"],
                "zona_origen": params["zona_origen"],
                "zona_destino": params["zona_destino"],
                "grupo": params.get("grupo_int") if params["tipo"] == "INT" else params.get("grupo_ext"),
                "ansible_playbook": params.get("ansible_playbook", "") if g.user and g.user.get("role") == "super_admin" else "",
            },
            "cli": cli,
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Error inesperado: {str(e)}"}), 500


@app.route("/api/s2s", methods=["POST"])
@login_required
@role_required("super_admin")
def api_s2s():
    """VPN IPsec Site-to-Site: genera CLI PAN-OS completo."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No se recibieron datos JSON."}), 400

        required = ["peer_ip", "local_subnet", "remote_subnet", "psk", "tunnel_id"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return jsonify({"error": f"Campos requeridos faltantes: {', '.join(missing)}"}), 400

        # Import and use the S2S generator
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from vpn_s2s_generator import PAN_S2S_Generator

        config = {
            "mode": "Proxy-ID",
            "peer_ip": data["peer_ip"],
            "psk": data["psk"],
            "local_subnet": data["local_subnet"],
            "remote_subnet": data["remote_subnet"],
            "local_wan_ip": data.get("local_wan_ip", ""),
            "local_if": data.get("local_if", "ethernet1/1"),
            "tunnel_id": str(data["tunnel_id"]),
            "tunnel_zone": data.get("tunnel_zone", "REMOTE_SITE"),
            "local_zone": data.get("local_zone", "Inside"),
            "vr": data.get("vr", "vr_vpn"),
            "create_policies": data.get("create_policies", True),
            # Crypto — PAN-OS 10.2.x (from frontend selectors)
            "ike_enc":       data.get("ike_enc",       "aes-256-cbc"),
            "ike_hash":      data.get("ike_hash",      "sha256"),
            "ike_dh":        data.get("ike_dh",        "group14"),
            "ike_lifetime":  str(data.get("ike_lifetime", "8")),
            "ipsec_enc":     data.get("ipsec_enc",     "aes-256-cbc"),
            "ipsec_auth":    data.get("ipsec_auth",    "sha256"),
            "ipsec_dh":      data.get("ipsec_dh",      "group14"),
            "ipsec_lifetime": str(data.get("ipsec_lifetime", "1")),
            # App-IDs for security policy
            "applications": data.get("applications", ""),
            "ritm": data.get("ritm", ""),
        }

        gen = PAN_S2S_Generator(config)
        cli_output = gen.generate()

        return jsonify({
            "success": True,
            "ritm": data.get("ritm", ""),
            "peer_ip": data["peer_ip"],
            "tunnel_if": f"tunnel.{data['tunnel_id']}",
            "tunnel_zone": f"MINSAL_TO_{config['tunnel_zone']}",
            "cli": cli_output,
        })

    except Exception as e:
        return jsonify({"error": f"Error generando configuración S2S: {str(e)}"}), 500




@app.route("/api/ansible", methods=["POST"])
@login_required
@role_required("super_admin")
def api_ansible():
    """Genera un Playbook de Ansible PAN-OS 'Elite Edition' basado en el Wizard."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data received"}), 400

        # Step 1: Access
        fw_ip = data.get("firewall_ip", "10.0.0.1")
        user  = data.get("username", "admin")
        pw    = data.get("password", "********")
        portal = data.get("portal_name", "GP-Portal")
        gateway = data.get("gateway_name", "GP-Gateway")
        
        # Step 2: Networking
        if_name = data.get("if_name", "ethernet1/1")
        if_zone = data.get("if_zone", "untrusted")
        route_dest = data.get("route_dest", "0.0.0.0/0")
        route_nexthop = data.get("route_nexthop", "")

        # Step 3: Entities (Bulk)
        bulk_objects = data.get("bulk_objects", "")

        # Step 4: NAT
        nat_name = data.get("nat_name", "VIP_NAT_RULE")
        nat_type = data.get("nat_type", "source")
        nat_src_zone = data.get("nat_src_zone", "inside")
        nat_dest_zone = data.get("nat_dest_zone", "untrusted")
        nat_translated = data.get("nat_translated", "")
        
        # Step 5: Policy
        src_zone  = data.get("src_zone", "inside")
        dest_zone = data.get("dest_zone", "outside")
        tags      = data.get("tags", "Ansible-VIP")

        # Build Playbook (YAML)
        playbook = [
            "---",
            "- name: Elite Automation Playbook - PAN-OS Logic",
            "  hosts: localhost",
            "  connection: local",
            "  gather_facts: false",
            "",
            "  vars:",
            "    provider:",
            f"      ip_address: \"{fw_ip}\"",
            f"      username: \"{user}\"",
            f"      password: \"{pw}\"",
            "",
            "  tasks:",
            "    - name: Create Security Zone (Step 2)",
            "      paloaltonetworks.panos.panos_zone:",
            "        provider: \"{{ provider }}\"",
            f"        zone: \"{if_zone}\"",
            "        mode: \"layer3\"",
            f"        interface: [\"{if_name}\"]",
            "        state: \"present\"",
            "",
            "    - name: Static Route Elite (Step 2)",
            "      paloaltonetworks.panos.panos_static_route:",
            "        provider: \"{{ provider }}\"",
            f"        name: \"Route_to_{route_dest.replace('/', '_')}\"",
            f"        destination: \"{route_dest}\"",
            f"        nexthop: \"{route_nexthop}\"",
            "        state: \"present\"",
            "" if route_nexthop else "# Next hop missing, step skipped",
            "",
            "    - name: NAT Policy Elite (Step 4)",
            "      paloaltonetworks.panos.panos_nat_rule:",
            "        provider: \"{{ provider }}\"",
            f"        rule_name: \"{nat_name}\"",
            f"        source_zone: [\"{nat_src_zone}\"]",
            f"        destination_zone: \"{nat_dest_zone}\"",
            f"        source_ip: [\"any\"]",
            f"        destination_ip: [\"any\"]",
            f"        snat_type: \"{nat_type}-translation\"",
            f"        snat_static_address: \"{nat_translated}\"",
            "        state: \"present\"",
            "" if nat_translated else "# Translation IP missing, step skipped",
            "",
            "    - name: Create Security Policy VIP (Step 5)",
            "      paloaltonetworks.panos.panos_security_rule:",
            "        provider: \"{{ provider }}\"",
            f"        rule_name: \"VIP_Access_Rule_{tags.split(',')[0].strip() if tags else 'Auto'}\"",
            f"        source_zone: [\"{src_zone}\"]",
            f"        destination_zone: [\"{dest_zone}\"]",
            "        source_ip: [\"any\"]",
            "        destination_ip: [\"any\"]",
            "        application: [\"any\"]",
            "        service: [\"application-default\"]",
            "        action: \"allow\"",
            f"        tag: [{', '.join([f'\"{t.strip()}\"' for t in tags.split(',')]) if tags else '\"Ansible-VIP\"'}]",
            "        state: \"present\"",
        ]

        # Add commit/checkpoint if requested (Step 6)
        if data.get("create_checkpoint"):
            playbook.insert(13, "    - name: Create Device Checkpoint (Step 6)")
            playbook.insert(14, "      paloaltonetworks.panos.panos_type_cmd:")
            playbook.insert(15, "        provider: \"{{ provider }}\"")
            playbook.insert(16, "        cmd: \"save config to Pre_Ansible_VIP.xml\"")
            playbook.insert(17, "")

        if data.get("auto_commit"):
            playbook.extend([
                "",
                "    - name: Commit Configuration Elite (Step 6)",
                "      paloaltonetworks.panos.panos_commit_firewall:",
                "        provider: \"{{ provider }}\"",
            ])

        return jsonify({
            "success": True,
            "playbook": "\n".join(playbook),
            "message": "Playbook Premium generado con éxito por el motor VIP Concierge."
        })

    except Exception as e:
        return jsonify({"error": f"Error en el motor Ansible VIP: {str(e)}"}), 500


@app.route("/api/cmdb", methods=["GET"])
@login_required
@role_required("super_admin")
def api_cmdb_list():
    """Lista todos los CIs con paginación y mapeo nacional 1:1 (42 columnas)."""
    db = get_db()
    
    # Parámetros de paginación
    try:
        limit = int(request.args.get('limit', 25))
        offset = int(request.args.get('offset', 0))
    except (ValueError, TypeError):
        limit, offset = 25, 0

    # Total para el frontend (contamos locations activas)
    total = db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 1").fetchone()[0]

    # Join total: 42+ columnas
    query = """
        SELECT l.*, 
               h.model as hw_model, h.machine_type as hw_type, h.sw as hw_sw, h.vc as hw_vc,
               h.lineas_sobrevivencia as hw_sop, h.telefonos_satelitales as hw_sat,
               h.linea_800 as hw_800, h.lineas_moviles as hw_mov, h.bam as hw_bam,
               h.samu_131 as hw_samu, h.ccm as hw_ccm, h.fw as hw_fw, h.fw_sugerido as hw_fw_sug,
               n.access_type as net_access, n.bandwidth as net_bw, n.acceso_resp as net_acc_r1,
               n.bw_datos_resp as net_bw_r1, n.acceso_resp2 as net_acc_r2, n.bw_datos_resp2 as net_bw_r2,
               n.acceso_resp3 as net_acc_r3, n.bw_datos_resp3 as net_bw_r3, n.wifi as net_wifi,
               n.lineas_home as net_home, n.internet_dedicado as net_dedicated,
               n.enlace_1_sugerido as net_sug1, n.enlace_2_sugerido as net_sug2,
               n.satelital_sugerido as net_sug_sat, n.voz as net_voz, n.datos as net_datos
        FROM cmdb_location_ci l
        LEFT JOIN cmdb_hardware_ci h ON l.id = h.location_id AND h.is_active = 1
        LEFT JOIN cmdb_network_ci n ON l.id = n.location_id AND n.is_active = 1
        WHERE l.is_active = 1
        ORDER BY l.name ASC
        LIMIT ? OFFSET ?
    """
    
    rows = db.execute(query, (limit, offset)).fetchall()
    
    # Convertimos a lista de dicts
    results = [dict(r) for r in rows]
    
    return jsonify({
        "results": results,
        "total": total,
        "limit": limit,
        "offset": offset
    })


@app.route("/api/cmdb", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_create():
    """Crea un nuevo Configuration Item con registro histórico."""
    data = request.json
    name = data.get("name")
    ci_class = data.get("ci_class")
    if not name or not ci_class:
        return jsonify({"error": "Nombre y Clase de CI requeridos."}), 400
    
    db = get_db()
    try:
        cur = db.execute("""
            INSERT INTO cmdb_ci (name, ci_class, ip_address, status, environment, attributes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            name, ci_class, data.get("ip_address"), 
            data.get("status", "Operational"), 
            data.get("environment", "QA"),
            json.dumps(data.get("attributes", {}))
        ))
        ci_id = cur.lastrowid
        
        # Log to history
        db.execute("""
            INSERT INTO cmdb_history (ci_id, action, data_after)
            VALUES (?, 'INSERT', ?)
        """, (ci_id, json.dumps(data)))
        
        db.commit()
        return jsonify({"success": True, "id": ci_id, "message": "CI creado en la CMDB con éxito."})
    except Exception as e:
        return jsonify({"error": f"Error al crear CI: {str(e)}"}), 500


@app.route("/api/cmdb/<int:ci_id>", methods=["PUT"])
@login_required
@role_required("super_admin")
def api_cmdb_update(ci_id):
    """Actualiza un CI existente y guarda snapshot en el historial."""
    data = request.json
    db = get_db()
    
    # Get before state
    old_ci = db.execute("SELECT * FROM cmdb_ci WHERE id = ?", (ci_id,)).fetchone()
    if not old_ci:
        return jsonify({"error": "CI no encontrado"}), 404
    
    try:
        db.execute("""
            UPDATE cmdb_ci 
            SET name=?, ci_class=?, ip_address=?, status=?, environment=?, attributes=?
            WHERE id=?
        """, (
            data.get("name", old_ci["name"]),
            data.get("ci_class", old_ci["ci_class"]),
            data.get("ip_address", old_ci["ip_address"]),
            data.get("status", old_ci["status"]),
            data.get("environment", old_ci["environment"]),
            json.dumps(data.get("attributes", json.loads(old_ci["attributes"]))),
            ci_id
        ))
        
        # Log to history
        db.execute("""
            INSERT INTO cmdb_history (ci_id, action, data_before, data_after)
            VALUES (?, 'UPDATE', ?, ?)
        """, (ci_id, json.dumps(dict(old_ci)), json.dumps(data)))
        
        db.commit()
        return jsonify({"success": True, "message": "CI actualizado con éxito."})
    except Exception as e:
        return jsonify({"error": f"Error al actualizar CI: {str(e)}"}), 500


@app.route("/api/cmdb/<int:ci_id>", methods=["DELETE"])
@login_required
@role_required("super_admin")
def api_cmdb_delete(ci_id):
    """Elimina un CI y guarda snapshot para posible restauración (undo)."""
    db = get_db()
    old_ci = db.execute("SELECT * FROM cmdb_ci WHERE id = ?", (ci_id,)).fetchone()
    if not old_ci:
        return jsonify({"error": "CI no encontrado"}), 404
        
    try:
        # Log to history before deleting
        db.execute("""
            INSERT INTO cmdb_history (ci_id, action, data_before)
            VALUES (?, 'DELETE', ?)
        """, (ci_id, json.dumps(dict(old_ci))))
        
        db.execute("DELETE FROM cmdb_ci WHERE id = ?", (ci_id,))
        db.commit()
        return jsonify({"success": True, "message": "CI eliminado con éxito."})
    except Exception as e:
        return jsonify({"error": f"Error al eliminar CI: {str(e)}"}), 500


@app.route("/api/cmdb/history/undo", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_undo():
    """Revierte el último cambio no deshecho."""
    db = get_db()
    last = db.execute("""
        SELECT * FROM cmdb_history 
        WHERE undone = 0 
        ORDER BY created_at DESC LIMIT 1
    """).fetchone()
    
    if not last:
        return jsonify({"error": "No hay más cambios para deshacer."}), 400
        
    try:
        action = last["action"]
        ci_id  = last["ci_id"]
        
        if action == "INSERT":
            db.execute("DELETE FROM cmdb_ci WHERE id = ?", (ci_id,))
        elif action == "UPDATE":
            old_data = json.loads(last["data_before"])
            db.execute("""
                UPDATE cmdb_ci SET name=?, ci_class=?, ip_address=?, status=?, environment=?, attributes=?
                WHERE id=?
            """, (old_data["name"], old_data["ci_class"], old_data["ip_address"], 
                  old_data["status"], old_data["environment"], old_data["attributes"], ci_id))
        elif action == "DELETE":
            # RESTORE CI
            old_data = json.loads(last["data_before"])
            db.execute("""
                INSERT INTO cmdb_ci (id, name, ci_class, ip_address, status, environment, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ci_id, old_data["name"], old_data["ci_class"], old_data["ip_address"], 
                  old_data["status"], old_data["environment"], old_data["attributes"]))
                  
        db.execute("UPDATE cmdb_history SET undone = 1 WHERE id = ?", (last["id"],))
        db.commit()
        return jsonify({"success": True, "message": f"Acción {action} deshecha con éxito."})
    except Exception as e:
        return jsonify({"error": f"Error al deshacer: {str(e)}"}), 500


@app.route("/api/cmdb/history/redo", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_redo():
    """Reaplica el último cambio deshecho."""
    db = get_db()
    last = db.execute("""
        SELECT * FROM cmdb_history 
        WHERE undone = 1 
        ORDER BY created_at DESC LIMIT 1
    """).fetchone()
    
    if not last:
        return jsonify({"error": "No hay cambios para rehacer."}), 400
        
    try:
        action = last["action"]
        ci_id  = last["ci_id"]
        
        if action == "INSERT":
            after_data = json.loads(last["data_after"])
            db.execute("""
                INSERT INTO cmdb_ci (id, name, ci_class, ip_address, status, environment, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ci_id, after_data["name"], after_data["ci_class"], after_data.get("ip_address"), 
                  after_data.get("status", "Operational"), after_data.get("environment", "QA"),
                  json.dumps(after_data.get("attributes", {}))))
        elif action == "UPDATE":
            after_data = json.loads(last["data_after"])
            db.execute("""
                UPDATE cmdb_ci SET name=?, ci_class=?, ip_address=?, status=?, environment=?, attributes=?
                WHERE id=?
            """, (after_data.get("name"), after_data.get("ci_class"), after_data.get("ip_address"), 
                  after_data.get("status"), after_data.get("environment"), 
                  json.dumps(after_data.get("attributes", {})), ci_id))
        elif action == "DELETE":
            db.execute("DELETE FROM cmdb_ci WHERE id = ?", (ci_id,))
            
        db.execute("UPDATE cmdb_history SET undone = 0 WHERE id = ?", (last["id"],))
        db.commit()
        return jsonify({"success": True, "message": f"Acción {action} rehecha con éxito."})
    except Exception as e:
        return jsonify({"error": f"Error al rehacer: {str(e)}"}), 500


@app.route("/api/cmdb/<int:ci_id>", methods=["GET"])
@login_required
@role_required("super_admin")
def api_cmdb_detail(ci_id):
    """Retorna detalle de un CI y sus relaciones (ServiceNow-like mapping)."""
    db = get_db()
    ci = db.execute("SELECT * FROM cmdb_ci WHERE id = ?", (ci_id,)).fetchone()
    if not ci:
        return jsonify({"error": "CI no encontrado"}), 404
    
    # Obtener relaciones (Padres e Hijos)
    parents = db.execute("""
        SELECT r.type, c.id, c.name, c.ci_class 
        FROM cmdb_rel r JOIN cmdb_ci c ON r.parent_id = c.id 
        WHERE r.child_id = ?
    """, (ci_id,)).fetchall()
    
    children = db.execute("""
        SELECT r.type, c.id, c.name, c.ci_class 
        FROM cmdb_rel r JOIN cmdb_ci c ON r.child_id = c.id 
        WHERE r.parent_id = ?
    """, (ci_id,)).fetchall()

    return jsonify({
        "ci": dict(ci),
        "parents": [dict(r) for r in parents],
        "children": [dict(r) for r in children]
    })


@app.route("/api/cmdb/search", methods=["GET"])
@login_required
def api_cmdb_search():
    """Búsqueda inteligente (type-ahead) en la base de datos de establecimientos nacionales."""
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return jsonify([])
    
    db = get_db()
    # Buscamos coincidencias en nombre o dirección, priorizando activos
    query = """
        SELECT l.*,
               h.model as hw_model, h.machine_type as hw_type, h.sw as hw_sw, h.vc as hw_vc,
               h.lineas_sobrevivencia as hw_sop, h.telefonos_satelitales as hw_sat,
               h.linea_800 as hw_800, h.lineas_moviles as hw_mov, h.bam as hw_bam,
               h.samu_131 as hw_samu, h.ccm as hw_ccm, h.fw as hw_fw, h.fw_sugerido as hw_fw_sug,
               n.access_type as net_access, n.bandwidth as net_bw, n.acceso_resp as net_acc_r1,
               n.bw_datos_resp as net_bw_r1, n.acceso_resp2 as net_acc_r2, n.bw_datos_resp2 as net_bw_r2,
               n.acceso_resp3 as net_acc_r3, n.bw_datos_resp3 as net_bw_r3, n.wifi as net_wifi,
               n.lineas_home as net_home, n.internet_dedicado as net_dedicated,
               n.enlace_1_sugerido as net_sug1, n.enlace_2_sugerido as net_sug2,
               n.satelital_sugerido as net_sug_sat, n.voz as net_voz, n.datos as net_datos
        FROM cmdb_location_ci l
        LEFT JOIN cmdb_hardware_ci h ON l.id = h.location_id AND h.is_active = 1
        LEFT JOIN cmdb_network_ci n ON l.id = n.location_id AND n.is_active = 1
        WHERE (l.name LIKE ? OR l.address LIKE ?) AND l.is_active = 1
        ORDER BY l.name ASC
        LIMIT 15
    """
    params = (f"%{q}%", f"%{q}%")
    try:
        rows = db.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        log.error('"Search error: %s"', str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/cmdb/stats", methods=["GET"])
@login_required
@role_required("super_admin")
def api_cmdb_stats():
    """Retorna estadísticas rápidas para el Dashboard CMDB usando tablas normalizadas."""
    db = get_db()
    stats = {
        "total": db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 1").fetchone()[0],
        "by_class": [
            {"ci_class": "Location", "count": db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 1").fetchone()[0]},
            {"ci_class": "Hardware", "count": db.execute("SELECT COUNT(*) FROM cmdb_hardware_ci WHERE is_active = 1").fetchone()[0]},
            {"ci_class": "Network", "count": db.execute("SELECT COUNT(*) FROM cmdb_network_ci WHERE is_active = 1").fetchone()[0]}
        ],
        "by_status": [
            {"status": "Operational", "count": db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 1").fetchone()[0]},
            {"status": "Retired", "count": db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 0").fetchone()[0]}
        ],
        "by_env": [
            {"environment": "QA", "count": db.execute("SELECT COUNT(*) FROM cmdb_location_ci WHERE is_active = 1").fetchone()[0]} # Placeholder
        ]
    }
    return jsonify(stats)


@app.route("/api/appid-search")
@login_required
@role_required("super_admin")
def api_appid_search():
    """Search the App-ID catalog for security policy generation."""
    from appid_catalog import APPID_CATALOG
    q = request.args.get('q', '').lower().strip()
    if not q:
        top = [{"id": k, **v} for k, v in list(APPID_CATALOG.items())[:20]]
        return jsonify({"results": top})
    results = []
    for app_id, meta in APPID_CATALOG.items():
        if q in app_id or q in meta["name"].lower() or q in meta.get("category", "").lower():
            results.append({"id": app_id, **meta})
    return jsonify({"results": sorted(results, key=lambda x: x["id"])[:25]})


@app.route("/api/template")
@login_required
@role_required("super_admin")
def api_template():
    """Genera y descarga la plantilla Excel (archivo único por request, sin race condition)."""
    # UUID por request evita colisiones si varios usuarios descargan simultáneamente
    tmp_dir  = tempfile.gettempdir()
    filename = f"PlantillaVPN_{uuid.uuid4().hex[:8]}.xlsx"
    filepath = os.path.join(tmp_dir, filename)
    try:
        create_template_excel(filepath)
        return send_file(filepath, as_attachment=True, download_name="PlantillaVPN.xlsx")
    finally:
        # Eliminar el temporal después de enviarlo
        try:
            os.unlink(filepath)
        except OSError:
            pass


@app.route("/api/me")
@login_required
def api_me():
    """Retorna datos del usuario actual."""
    user = g.user
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
    })


@app.route("/api/cmdb/upload", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_upload():
    """Endpoint para subir el Excel de catastro y sincronizar la CMDB en memoria."""
    if 'file' not in request.files:
        return jsonify({"error": "No se subió ningún archivo."}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nombre de archivo vacío."}), 400
    
    if not file.filename.endswith(('.xlsx', '.csv')):
        return jsonify({"error": "Formato no soportado (use .xlsx o .csv)."}), 400

    try:
        # Procesar 100% en memoria
        file_bytes = file.read()
        description = request.form.get("description", f"Carga: {file.filename}")
        
        result = cmdb_service.process_national_registry(file_bytes, g.user["id"], description)
        
        if result["success"]:
            log.info('"CMDB Sync completed, batch_id=%s stats=%s"', result["batch_id"], str(result["stats"]))
            return jsonify(result)
        else:
            return jsonify({"error": result.get("error", "Error desconocido en sincronización.")}), 500
            
    except Exception as e:
        log.error('"CMDB Upload error: %s"', str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/cmdb/batch/undo/<batch_id>", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_batch_undo(batch_id):
    """Revierte una carga masiva completa por su batch_id."""
    result = cmdb_service.undo_batch(batch_id)
    if result["success"]:
        return jsonify({"success": True, "message": f"Lote {batch_id} revertido con éxito."})
    return jsonify({"error": result.get("error")}), 500


@app.route("/api/cmdb/upload-local", methods=["POST"])
@login_required
@role_required("super_admin")
def api_cmdb_upload_local():
    """Endpoint para sincronizar desde el archivo local hardcodeado en el servidor."""
    # Ruta solicitada por el usuario
    local_path = r"C:\Users\rodri\OneDrive\Documentos\APP CIBERSEGURIDAD\Anexo_5A_Base_establecimientos_(Final).xlsx"
    
    if not os.path.exists(local_path):
        return jsonify({"error": f"Archivo local no encontrado en: {local_path}"}), 404

    try:
        with open(local_path, 'rb') as f:
            file_bytes = f.read()
        
        description = request.form.get("description", "Carga Manual: Catastro Local")
        result = cmdb_service.process_national_registry(file_bytes, g.user["id"], description)
        
        if result["success"]:
            log.info('"Local CMDB Sync completed, batch_id=%s"', result["batch_id"])
            return jsonify(result)
        else:
            return jsonify({"error": result.get("error", "Error desconocido en sincronización local.")}), 500
            
    except Exception as e:
        log.error('"Error during local CMDB sync: %s"', str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/cmdb/batches", methods=["GET"])
@login_required
@role_required("super_admin")
def api_cmdb_batches():
    """Lista los lotes de carga realizados."""
    db = get_db()
    rows = db.execute("""
        SELECT b.*, u.username as user_name 
        FROM cmdb_batches b 
        JOIN users u ON b.user_id = u.id 
        ORDER BY b.created_at DESC
    """).fetchall()
    return jsonify([dict(r) for r in rows])


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port  = ENV_CFG["port"]
    label = ENV_CFG["label"]
    emoji = ENV_CFG["emoji"]
    print("\n" + "=" * 60)
    print(f"  {emoji} VPN GlobalProtect [{label}]")
    print(f"  URL: http://localhost:{port}")
    print(f"  Entorno: {APP_ENV.upper()} | DB: {ENV_CFG['db_file']}")
    print("=" * 60 + "\n")
    _debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=_debug, host="127.0.0.1", port=port)
