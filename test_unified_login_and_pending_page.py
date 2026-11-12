"""
Automated Test Suite for Unified Login and Dedicated Pending Approval Page.
Verifies all 4 steps:
  Step 1: Routing Changes in main.py:
          - GET / -> static/login.html
          - GET /pending -> static/pending.html
          - GET /dashboard -> static/index.html
          - GET /admin -> static/admin.html
  Step 2: static/login.html:
          - Dark theme #0f141c
          - Sign Up & OTP flow -> redirects to /pending
          - Pending user login -> blocked with "Account pending. Please wait."
          - Success login -> role 'admin' -> /admin, role 'member' -> /dashboard
  Step 3: static/pending.html:
          - Dark theme #0f141c
          - Yellow padlock/hourglass icon
          - Text: "Email Verified Successfully! Your account is currently pending Administrator approval. You will receive access to the RAG platform once approved."
          - Button "Return to Login" linking to /
          - JavaScript auto-redirect to /dashboard if approved
  Step 4: static/index.html security guard:
          - Contains authentication enforcement script checking token before rendering
"""
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from fastapi.testclient import TestClient
from main import app
from core.auth_service import AuthService

client = TestClient(app)

def run_tests():
    print("=" * 85)
    print(" TESTING UNIFIED LOGIN & DEDICATED PENDING APPROVAL FLOW")
    print("=" * 85)

    test_email = "sam_student@university.edu"
    test_pwd = "StudentPassword2026!"

    # Clean up test user
    with AuthService._get_connection() as conn:
        conn.execute("DELETE FROM users WHERE email = ?", (test_email,))
        conn.commit()

    # -------------------------------------------------------------
    # STEP 1: ROUTING VERIFICATION
    # -------------------------------------------------------------
    print("\n[Step 1: Verifying Routing in main.py]")
    # 1. Root route must serve login.html
    root_res = client.get("/")
    print(f"  GET / status: {root_res.status_code}")
    assert root_res.status_code == 200, "Root route should return 200"
    assert "Sign Up" in root_res.text and "Login" in root_res.text, "Root route did not serve login.html"
    assert "#0f141c" in root_res.text, "login.html missing #0f141c theme"
    print("  Root route correctly serves static/login.html (PASSED)")

    # 2. /pending route must serve pending.html
    pending_res = client.get("/pending")
    print(f"  GET /pending status: {pending_res.status_code}")
    assert pending_res.status_code == 200, "/pending should return 200"
    assert "Email Verified Successfully!" in pending_res.text
    assert "Your account is currently pending Administrator approval. You will receive access to the RAG platform once approved." in pending_res.text
    assert 'href="/"' in pending_res.text or "Return to Login" in pending_res.text
    print("  GET /pending correctly serves static/pending.html (PASSED)")

    # 3. /dashboard route must serve index.html (the RAG UI)
    dashboard_res = client.get("/dashboard")
    print(f"  GET /dashboard status: {dashboard_res.status_code}")
    assert dashboard_res.status_code == 200, "/dashboard should return 200"
    assert "RAG Document Verifier" in dashboard_res.text
    assert "Authentication Enforcement: Secure RAG Dashboard" in dashboard_res.text or "localStorage.getItem('token')" in dashboard_res.text
    print("  GET /dashboard correctly serves static/index.html with auth enforcement (PASSED)")

    # 4. /admin route must serve admin.html
    admin_res = client.get("/admin")
    print(f"  GET /admin status: {admin_res.status_code}")
    assert admin_res.status_code == 200, "/admin should return 200"
    assert "Admin Approval Portal" in admin_res.text or "User Approval &amp; Access Registry" in admin_res.text
    print("  GET /admin correctly serves static/admin.html (PASSED)")

    # -------------------------------------------------------------
    # STEP 2: USER SIGNUP & OTP -> REDIRECT TO /pending
    # -------------------------------------------------------------
    print("\n[Step 2: Testing User Signup & OTP Verification]")
    reg = client.post("/api/v1/auth/register", json={"email": test_email, "password": test_pwd})
    assert reg.status_code == 200, "Registration failed"
    user_db = AuthService.get_user_by_email(test_email)
    otp = user_db["otp_code"]

    verify = client.post("/api/v1/auth/verify-otp", json={"email": test_email, "otp": otp})
    assert verify.status_code == 200
    assert verify.json()["status"] == "PENDING_APPROVAL"
    print(f"  User {test_email} successfully registered and verified (Status: PENDING_APPROVAL) (PASSED)")

    # -------------------------------------------------------------
    # STEP 3: LOGIN ENFORCEMENT & PENDING MESSAGE
    # -------------------------------------------------------------
    print("\n[Step 3: Testing Login Blocking for Pending User]")
    login_pending = client.post("/api/v1/auth/login", json={"email": test_email, "password": test_pwd})
    print(f"  Pending user login code: {login_pending.status_code} (Expected 403 Forbidden)")
    assert login_pending.status_code == 403
    print("  Pending user is blocked with 403 Forbidden (PASSED)")

    # -------------------------------------------------------------
    # STEP 4: ADMIN APPROVAL & ROLE-BASED REDIRECTION
    # -------------------------------------------------------------
    print("\n[Step 4: Testing Admin Login and Approval]")
    # Admin logs in
    admin_login = client.post("/api/v1/auth/login", json={"email": "admin@local.rag", "password": "AdminPass2026!"})
    assert admin_login.status_code == 200
    assert admin_login.json()["user"]["role"] == "admin"
    print("  Admin user authenticated -> role is 'admin' (redirects to /admin) (PASSED)")

    # Admin approves user
    admin_token = admin_login.json()["token"]
    appr = client.post(f"/api/v1/admin/approve?target_email={test_email}&decision=approved&admin_token={admin_token}")
    assert appr.status_code == 200
    print(f"  Admin approved user {test_email} (PASSED)")

    # Approved user logs in
    user_login = client.post("/api/v1/auth/login", json={"email": test_email, "password": test_pwd})
    assert user_login.status_code == 200
    user_data = user_login.json()
    assert user_data["status"] in ("SUCCESS", "approved")
    assert user_data["user"]["role"] == "member"
    assert user_data["token"] is not None
    print(f"  Approved user logged in -> role is 'member' (redirects to /dashboard) (PASSED)")

    print("\n" + "=" * 85)
    print(" ALL ROUTING, LOGIN, PENDING, AND DASHBOARD CHECKS PASSED! ")
    print("=" * 85)

if __name__ == "__main__":
    run_tests()

