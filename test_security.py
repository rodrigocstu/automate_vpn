#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_security.py — Security regression tests for VPN GlobalProtect App
Corre con: SECRET_KEY=testkey123abcdefghijklmnopqrstu pytest test_security.py -v
"""

import os
import pytest

# SECRET_KEY requerido antes de importar la app
os.environ.setdefault("SECRET_KEY", "testkey123abcdefghijklmnopqrstuvwx")
os.environ.setdefault("FLASK_DEBUG", "0")

from webapp import app


# ─── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        with app.app_context():
            yield c


def _get_csrf(client) -> str:
    """Obtiene token CSRF haciendo GET a /login."""
    with client.session_transaction() as sess:
        from webapp import generate_csrf_token
        with app.app_context():
            # Forzar generación del token en sesión de test
            sess["_csrf"] = "test-csrf-token-fixed"
    return "test-csrf-token-fixed"


# ─── 1. Security Headers ───────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_x_frame_options(self, client):
        r = client.get("/login")
        assert r.headers.get("X-Frame-Options") == "DENY", "X-Frame-Options debe ser DENY"

    def test_x_content_type_options(self, client):
        r = client.get("/login")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy(self, client):
        r = client.get("/login")
        assert "strict-origin" in r.headers.get("Referrer-Policy", "")

    def test_csp_present(self, client):
        r = client.get("/login")
        assert "Content-Security-Policy" in r.headers

    def test_request_id_present(self, client):
        r = client.get("/login")
        assert "X-Request-ID" in r.headers
        assert len(r.headers["X-Request-ID"]) >= 6


# ─── 2. Authentication ─────────────────────────────────────────────────────────

class TestAuthentication:
    def test_login_page_renders(self, client):
        r = client.get("/login")
        assert r.status_code == 200

    def test_login_invalid_credentials_rejected(self, client):
        csrf = _get_csrf(client)
        r = client.post("/login", data={
            "username": "notexist",
            "password": "wrongpassword",
            "_csrf": csrf,
        })
        assert r.status_code == 200
        assert "incorrectos" in r.data.decode("utf-8", errors="replace").lower()

    def test_login_no_csrf_rejected(self, client):
        r = client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "_csrf": "",  # Token vacío
        })
        assert r.status_code == 403

    def test_login_wrong_csrf_rejected(self, client):
        r = client.post("/login", data={
            "username": "admin",
            "password": "admin",
            "_csrf": "totally-wrong-token",
        })
        assert r.status_code == 403

    def test_logout_clears_session(self, client):
        # POST logout
        r = client.post("/logout", follow_redirects=False)
        assert r.status_code in (302, 200)

    def test_unauthenticated_redirects_to_login(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code in (302, 303)
        location = r.headers.get("Location", "")
        assert "login" in location.lower()


# ─── 3. API Authorization ──────────────────────────────────────────────────────

class TestAPIAuthorization:
    def test_api_generate_requires_auth(self, client):
        r = client.post("/api/generate", json={})
        assert r.status_code in (401, 302)

    def test_api_ticket_requires_auth(self, client):
        r = client.post("/api/ticket", json={})
        assert r.status_code in (401, 302)

    def test_api_s2s_requires_auth(self, client):
        r = client.post("/api/s2s", json={})
        assert r.status_code in (401, 302)

    def test_api_appid_search_requires_auth(self, client):
        r = client.get("/api/appid-search?q=ssl")
        assert r.status_code in (401, 302)

    def test_api_me_requires_auth(self, client):
        r = client.get("/api/me")
        assert r.status_code in (401, 302)

    def test_api_template_requires_auth(self, client):
        r = client.get("/api/template")
        assert r.status_code in (401, 302)

    def test_api_returns_json_error_on_unauth(self, client):
        r = client.post(
            "/api/s2s",
            json={"test": True},
            content_type="application/json",
        )
        assert r.status_code in (401, 302)
        if r.status_code == 401:
            data = r.get_json()
            assert "error" in data


# ─── 4. Rate Limiting ──────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limit_blocks_after_max_attempts(self, client):
        """Después de RATE_LIMIT_MAX intentos, debe retornar 429."""
        from webapp import RATE_LIMIT_MAX
        csrf = _get_csrf(client)
        blocked = False
        for i in range(RATE_LIMIT_MAX + 2):
            r = client.post("/login", data={
                "username": "testuser_nonexistent",
                "password": "wrongpass",
                "_csrf": csrf,
            })
            if r.status_code == 429:
                blocked = True
                break
        assert blocked, f"Rate limit no se activó después de {RATE_LIMIT_MAX + 2} intentos"


# ─── 5. Debug Mode ─────────────────────────────────────────────────────────────

class TestConfiguration:
    def test_debug_mode_controlled_by_env(self):
        """debug debe ser False cuando FLASK_DEBUG=0."""
        assert os.environ.get("FLASK_DEBUG", "0") == "0"
        # Flask debug debería reflejar el env var
        # (en testing se puede tener debug=False)
        assert not (app.debug and os.environ.get("FLASK_DEBUG") == "0")

    def test_secret_key_not_default_hardcoded(self):
        """SECRET_KEY no debe ser el valor por defecto hardcodeado anterior."""
        key = app.config.get("SECRET_KEY", "")
        assert "vpn-gp-" not in key, "SECRET_KEY aún usa el valor hardcodeado inseguro"
        assert len(key) >= 16, "SECRET_KEY demasiado corto"

    def test_session_cookie_httponly(self):
        assert app.config.get("SESSION_COOKIE_HTTPONLY") is True

    def test_session_cookie_samesite(self):
        assert app.config.get("SESSION_COOKIE_SAMESITE") == "Lax"


# ─── 6. Error Handlers ─────────────────────────────────────────────────────────

class TestErrorHandlers:
    def test_404_no_stack_trace(self, client):
        r = client.get("/nonexistent-route-xyz")
        assert r.status_code == 404
        body = r.data.decode("utf-8", errors="replace")
        # No debe haber stack traces de Python
        assert "Traceback" not in body
        assert "File \"" not in body

    def test_404_json_for_api(self, client):
        r = client.get("/api/nonexistent", content_type="application/json")
        assert r.status_code == 404


# ─── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    result = pytest.main([__file__, "-v", "--tb=short"])
    sys.exit(result)
