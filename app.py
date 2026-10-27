from __future__ import annotations

import ipaddress
import os
import re
import secrets
from collections import defaultdict
from datetime import timedelta
import shutil
import subprocess
import threading
import time

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Domain input only; keep requests tiny.
app.config["APP_ENV"] = os.environ.get("APP_ENV", "development").lower()
AUTH_REQUIRED = app.config["APP_ENV"] == "production" or os.environ.get("AUTH_REQUIRED", "false").lower() == "true"
APP_USERNAME = os.environ.get("APP_USERNAME", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
PLACEHOLDER_VALUES = {
    "change-this-user",
    "use-a-long-unique-password-here",
    "replace-with-at-least-32-random-characters",
}
if AUTH_REQUIRED and (
    not APP_USERNAME
    or len(APP_PASSWORD) < 12
    or len(SECRET_KEY) < 32
    or APP_USERNAME.lower() in PLACEHOLDER_VALUES
    or APP_PASSWORD.lower() in PLACEHOLDER_VALUES
    or SECRET_KEY.lower() in PLACEHOLDER_VALUES
):
    raise RuntimeError(
        "Production auth requires a real APP_USERNAME, APP_PASSWORD (at least 12 characters), "
        "and SECRET_KEY (at least 32 characters). Do not use the example placeholder values."
    )
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=AUTH_REQUIRED,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
if os.environ.get("TRUST_PROXY", "false").lower() == "true":
    # Enable only behind a trusted reverse proxy that sets X-Forwarded-* headers.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Deployable wrapper for ProjectDiscovery Subfinder.
SUBFINDER_BIN = os.environ.get("SUBFINDER_BIN", "subfinder")
SCAN_TIMEOUT_SECONDS = 80
SCAN_MAX_MINUTES = "1"
MIN_SECONDS_BETWEEN_SCANS = 10
_scan_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_scan_by_ip: dict[str, float] = {}
_login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_WINDOW_SECONDS = 900
MAX_LOGIN_ATTEMPTS = 8

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$"
)


def normalize_domain(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValueError("Masukkan nama domain, misalnya example.com.")
    value = raw.strip().lower()
    if not value:
        raise ValueError("Nama domain wajib diisi.")
    if "://" in value or "/" in value or "@" in value or "*" in value or " " in value:
        raise ValueError("Masukkan domain saja, tanpa https://, path, wildcard, atau spasi.")

    # Permit a final dot and normalize international domain names to ASCII.
    value = value.rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Format domain tidak valid.") from exc

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Masukkan nama domain, bukan alamat IP.")

    if value in {"localhost", "local"} or value.endswith((".localhost", ".local", ".internal", ".test", ".example", ".invalid")):
        raise ValueError("Gunakan domain publik yang memang menjadi ruang lingkup pengujianmu.")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("Format domain tidak valid. Contoh: example.com")
    return value


def client_ip() -> str:
    return request.remote_addr or "unknown"


def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["auth_enabled"] = AUTH_REQUIRED


@app.before_request
def protect_routes():
    if request.endpoint in {"healthz", "login"} or request.path.startswith("/static/"):
        return None

    if AUTH_REQUIRED and not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Sesi berakhir. Silakan masuk kembali."}), 401
        return redirect(url_for("login"))

    if AUTH_REQUIRED and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(supplied, expected):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Permintaan ditolak karena token keamanan tidak valid. Muat ulang halaman."}), 403
            return "Permintaan ditolak: token keamanan tidak valid. Muat ulang halaman.", 403
    return None


@app.get("/healthz")
def healthz():
    # Keep health checks independent from auth and third-party provider availability.
    return jsonify({"ok": True, "service": "subscope"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if not AUTH_REQUIRED:
        return redirect(url_for("index"))
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        submitted_csrf = request.form.get("csrf_token", "")
        expected_csrf = session.get("_csrf_token", "")
        if not expected_csrf or not secrets.compare_digest(submitted_csrf, expected_csrf):
            return render_template("login.html", error="Token keamanan tidak valid. Muat ulang halaman dan coba lagi."), 403
        ip = client_ip()
        now = time.monotonic()
        with _rate_lock:
            recent = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]
            _login_attempts[ip] = recent
            if len(_login_attempts) > 5000:
                for key, attempts in list(_login_attempts.items()):
                    if not any(now - attempt < LOGIN_WINDOW_SECONDS for attempt in attempts):
                        _login_attempts.pop(key, None)
            if len(recent) >= MAX_LOGIN_ATTEMPTS:
                return render_template("login.html", error="Terlalu banyak percobaan. Coba lagi sekitar 15 menit."), 429
            _login_attempts[ip].append(now)

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user_ok = secrets.compare_digest(username.encode("utf-8"), APP_USERNAME.encode("utf-8"))
        pass_ok = secrets.compare_digest(password.encode("utf-8"), APP_PASSWORD.encode("utf-8"))
        if user_ok and pass_ok:
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            csrf_token()  # Generate a fresh token after login to avoid session fixation.
            with _rate_lock:
                _login_attempts.pop(ip, None)
            return redirect(url_for("index"))
        error = "Username atau password salah."
    return render_template("login.html", error=error)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login" if AUTH_REQUIRED else "index"))


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    binary_path = shutil.which(SUBFINDER_BIN)
    return jsonify({
        "ok": True,
        "subfinder_available": bool(binary_path),
        "binary": binary_path or SUBFINDER_BIN,
        "mode": "passive",
    })


@app.post("/api/scan")
def scan():
    global _last_scan_at
    payload = request.get_json(silent=True) or {}
    try:
        domain = normalize_domain(payload.get("domain"))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    binary_path = shutil.which(SUBFINDER_BIN)
    if not binary_path:
        return jsonify({
            "ok": False,
            "error": "Subfinder belum ditemukan. Instal Subfinder lalu pastikan perintah 'subfinder' tersedia di PATH. Lihat README.md.",
        }), 503

    now = time.monotonic()
    ip = client_ip()
    with _rate_lock:
        previous = _last_scan_by_ip.get(ip, 0.0)
        if now - previous < MIN_SECONDS_BETWEEN_SCANS:
            return jsonify({"ok": False, "error": "Tunggu 10 detik sebelum menjalankan pencarian berikutnya."}), 429
        _last_scan_by_ip[ip] = now
        # Keep the in-memory limiter bounded for long-running public deployments.
        if len(_last_scan_by_ip) > 5000:
            cutoff = now - 3600
            for key, stamp in list(_last_scan_by_ip.items()):
                if stamp < cutoff:
                    _last_scan_by_ip.pop(key, None)
    if not _scan_lock.acquire(blocking=False):
        return jsonify({"ok": False, "error": "Pencarian lain sedang berjalan. Tunggu sampai selesai."}), 429

    started = time.monotonic()
    try:
        # Argument list (not shell=True) prevents shell injection. Intentionally passive:
        # no -active, brute-force, port scanning, or exploitation flags are used.
        command = [binary_path, "-d", domain, "-silent", "-duc", "-max-time", SCAN_MAX_MINUTES]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
        elapsed = round(time.monotonic() - started, 2)
        output_lines = set()
        for line in completed.stdout.splitlines():
            host = line.strip().lower().rstrip(".")
            if host and (host == domain or host.endswith("." + domain)) and len(host) <= 253:
                output_lines.add(host)

        results = sorted(output_lines)
        if completed.returncode != 0 and not results:
            detail = completed.stderr.strip().splitlines()
            message = detail[-1][:240] if detail else "Subfinder berhenti dengan kesalahan."
            return jsonify({"ok": False, "error": f"Subfinder gagal: {message}"}), 502

        return jsonify({
            "ok": True,
            "domain": domain,
            "results": results,
            "count": len(results),
            "elapsed_seconds": elapsed,
            "note": "Hasil bergantung pada sumber pasif dan API key yang tersedia; daftar ini tidak dijamin lengkap.",
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Pencarian melewati batas waktu 80 detik. Coba lagi nanti atau periksa konfigurasi sumber Subfinder."}), 504
    except OSError as exc:
        return jsonify({"ok": False, "error": f"Tidak dapat menjalankan Subfinder: {exc}"}), 500
    finally:
        _scan_lock.release()


if __name__ == "__main__":
    # For local development only. Production uses Gunicorn via the Dockerfile.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=False)
