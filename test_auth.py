#!/usr/bin/env python3
"""Test de verificación del sistema de autenticación."""
import requests

BASE = "http://localhost:5000"
passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name} — {detail}")

print("=" * 60)
print("  VERIFICACIÓN — Sistema de Autenticación")
print("=" * 60)

# ── 1. Redirect to login ──
s = requests.Session()
r = s.get(BASE + "/", allow_redirects=False)
check("Redirect to /login", r.status_code == 302 and "/login" in r.headers.get("Location", ""))

# ── 2. Login page renders ──
r = s.get(BASE + "/login")
check("Login page renders", r.status_code == 200 and "username" in r.text)

# ── 3. Login admin/admin ──
r = s.post(BASE + "/login", data={"username": "admin", "password": "admin"}, allow_redirects=False)
check("Login admin/admin -> redirect", r.status_code == 302)
location = r.headers.get("Location", "")
check("Redirects to change-password", "change-password" in location)

# ── 4. Change password page ──
r = s.get(BASE + "/change-password")
check("Change password page", r.status_code == 200 and "Debe cambiar" in r.text)

# ── 5. Change password ──
r = s.post(BASE + "/change-password", data={"new_password": "Admin2026!", "confirm_password": "Admin2026!"}, allow_redirects=False)
check("Password changed -> redirect", r.status_code == 302)

# ── 6. Main page (admin) ──
r = s.get(BASE + "/")
check("Main page accessible", r.status_code == 200)
check("Admin badge visible", "ADMIN" in r.text)
check("Admin button visible", "/admin" in r.text)

# ── 7. Admin panel ──
r = s.get(BASE + "/admin")
check("Admin panel accessible", r.status_code == 200 and "usersTable" in r.text)

# ── 8. List users API ──
r = s.get(BASE + "/api/admin/users")
users = r.json()
check("API list users", len(users) >= 1)
check("Admin user exists", any(u["username"] == "admin" for u in users))

# ── 9. Create guest user ──
r = s.post(BASE + "/api/admin/users", json={
    "username": "invitado",
    "display_name": "Usuario Invitado",
    "role": "guest",
    "password": "1234"
})
result = r.json()
check("Create guest user", result.get("success") == True, str(result))

# ── 10. Create regular user ──
r = s.post(BASE + "/api/admin/users", json={
    "username": "operador",
    "display_name": "Operador VPN",
    "role": "user",
    "password": "1234"
})
result = r.json()
check("Create regular user", result.get("success") == True, str(result))

# ── 11. Three users exist ──
r = s.get(BASE + "/api/admin/users")
users = r.json()
check("3 users total", len(users) == 3)
roles = {u["username"]: u["role"] for u in users}
check("Roles correct", roles.get("admin") == "admin" and roles.get("invitado") == "guest" and roles.get("operador") == "user")

# ── 12. Guest login ──
s2 = requests.Session()
r = s2.post(BASE + "/login", data={"username": "invitado", "password": "1234"}, allow_redirects=False)
check("Guest login works", r.status_code == 302)
r = s2.get(BASE + "/")
check("Guest sees banner", "Modo Invitado" in r.text)
check("Ticket tab locked", "tab-disabled" in r.text)
check("Generate blocked", "guest-action-blocked" in r.text)

# ── 13. Guest denied /api/generate ──
r = s2.post(BASE + "/api/generate", json={"test": True}, headers={"Content-Type": "application/json"})
check("Guest denied /api/generate", r.status_code == 403, f"status={r.status_code}")

# ── 14. Guest denied /api/ticket ──
r = s2.post(BASE + "/api/ticket", json={"texto": "test"}, headers={"Content-Type": "application/json"})
check("Guest denied /api/ticket", r.status_code == 403, f"status={r.status_code}")

# ── 15. Guest denied /api/excel ──
r = s2.post(BASE + "/api/excel", data={"row": 3})
check("Guest denied /api/excel", r.status_code == 403, f"status={r.status_code}")

# ── 16. Guest denied /admin ──
r = s2.get(BASE + "/admin", allow_redirects=False)
check("Guest denied /admin", r.status_code == 302)

# ── 17. User login ──
s3 = requests.Session()
r = s3.post(BASE + "/login", data={"username": "operador", "password": "1234"}, allow_redirects=False)
check("User login works", r.status_code == 302)
r = s3.get(BASE + "/")
check("User sees tabs (no lock)", "tab-disabled" not in r.text)
check("User no admin button", "Panel de Admin" not in r.text or "/admin" not in r.text)

# ── 18. User can generate ──  
r = s3.get(BASE + "/api/me")
me = r.json()
check("User role is user", me.get("role") == "user")

# ── 19. User denied /admin ──
r = s3.get(BASE + "/admin", allow_redirects=False)
check("User denied /admin", r.status_code == 302)

# ── 20. Wrong password ──
s4 = requests.Session()
r = s4.post(BASE + "/login", data={"username": "admin", "password": "wrong"})
check("Wrong password shows error", "incorrectos" in r.text)

# ── Summary ──
total = passed + failed
print()
print("=" * 60)
if failed == 0:
    print(f"  ✅ TOTAL: {total}/{total} tests pasaron")
else:
    print(f"  ❌ {passed}/{total} pasaron, {failed} fallaron")
print("=" * 60)
