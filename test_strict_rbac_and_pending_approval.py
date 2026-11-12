"""
Test Suite: Strict Role-Based Access Control (RBAC) and Pending Approval Logic
Validates all backend and frontend security constraints specified in the prompt:
1. Backend Security Enforcement (main.py):
   - /api/v1/auth/login returns username, role, org_id, and status
   - If status == 'pending', returns 403 with 'PENDING_APPROVAL'
   - Protects RAG routes (/query, /ingest) with JWT middleware (401 Unauthorized if missing/unapproved)
   - Protects /api/v1/admin/* routes from non-admin JWTs (403 Forbidden)
2. Frontend Session Management & Static Files:
   - login.html: shows "Email verified. Please wait for Admin approval.", stores rag_session, redirects
   - index.html & app.js: all admin features have .admin-only-feature and are hidden from members
   - index.html header displays: session-username-display, session-role-display, session-org-display
   - pending.html: contains exact text, dark theme, logout button, and redirect for approved users
   - admin.html: immediate guard redirecting non-admin members to /dashboard
"""
import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from fastapi.testclient import TestClient
from main import app, create_jwt_token
from core.auth_service import AuthService

client = TestClient(app)

def run_rbac_tests():
    print("=" * 85)
    print(" RUNNING STRICT RBAC & PENDING APPROVAL SECURITY TEST SUITE")
    print("=" * 85)

    test_member_email = "member_strict_test@secure.corp"
    test_member_pass = "MemberPass2026!Secure"
    test_pending_email = "pending_strict_test@secure.corp"
    test_pending_pass = "PendingPass2026!Secure"

    # Clean up test database records
    with AuthService._get_connection() as conn:
        conn.execute("DELETE FROM users WHERE email IN (?, ?)", (test_member_email, test_pending_email))
        conn.commit()

    # -----------------------------------------------------------------
    # STEP 1: PENDING USER REGISTRATION & 403 PENDING_APPROVAL RESPONSE
    # -----------------------------------------------------------------
    print("\n[Step 1: Testing Registration, OTP, and 403 PENDING_APPROVAL]")
    reg_res = client.post("/api/v1/auth/register", json={
        "email": test_pending_email,
        "password": test_pending_pass,
        "org_id": "default_org"
    })
    assert reg_res.status_code == 200, "Registration failed"
    user_db = AuthService.get_user_by_email(test_pending_email)
    otp = user_db["otp_code"]

    verify_res = client.post("/api/v1/auth/verify-otp", json={
        "email": test_pending_email,
        "otp": otp
    })
    assert verify_res.status_code == 200, "OTP verification failed"
    assert verify_res.json().get("status") == "PENDING_APPROVAL"

    # Now attempt login with pending user:
    # Must return 403 with message 'PENDING_APPROVAL'
    pending_login = client.post("/api/v1/auth/login", json={
        "email": test_pending_email,
        "password": test_pending_pass
    })
    print(f"  Pending user login HTTP status: {pending_login.status_code}")
    assert pending_login.status_code == 403, f"Expected 403, got {pending_login.status_code}"
    detail = pending_login.json().get("detail")
    print(f"  Pending user login detail: {detail}")
    assert detail == "PENDING_APPROVAL" or (isinstance(detail, dict) and detail.get("code") == "PENDING_APPROVAL") or "PENDING_APPROVAL" in str(detail), "Did not return PENDING_APPROVAL"
    print("  Pending user blocked with HTTP 403 PENDING_APPROVAL (PASSED)")

    # -----------------------------------------------------------------
    # STEP 2: APPROVED USER LOGIN (MUST RETURN username, role, org_id, status)
    # -----------------------------------------------------------------
    print("\n[Step 2: Testing Approved User Login Payload]")
    # Register and approve member
    client.post("/api/v1/auth/register", json={
        "email": test_member_email,
        "password": test_member_pass,
        "org_id": "org_enterprise_01"
    })
    mem_db = AuthService.get_user_by_email(test_member_email)
    client.post("/api/v1/auth/verify-otp", json={"email": test_member_email, "otp": mem_db["otp_code"]})
    AuthService.set_approval_status(test_member_email, "approved", approved_by="admin_root")

    member_login = client.post("/api/v1/auth/login", json={
        "email": test_member_email,
        "password": test_member_pass
    })
    print(f"  Approved member login status: {member_login.status_code}")
    assert member_login.status_code == 200, "Member login failed"
    login_data = member_login.json()
    print("  Login response keys:", list(login_data.keys()))
    assert "username" in login_data, "Missing 'username' in login response"
    assert "role" in login_data and login_data["role"] == "member", "Missing or invalid 'role' in login response"
    assert "org_id" in login_data and login_data["org_id"] == "org_enterprise_01", "Missing or invalid 'org_id' in login response"
    assert "status" in login_data and login_data["status"] == "approved", "Missing or invalid 'status' in login response"
    member_token = login_data["token"]
    assert member_token is not None, "Missing JWT token"
    print(f"  Verified user JSON payload: username='{login_data['username']}', role='{login_data['role']}', org_id='{login_data['org_id']}', status='{login_data['status']}' (PASSED)")

    # -----------------------------------------------------------------
    # STEP 3: RAG ROUTE PROTECTION (JWT MIDDLEWARE)
    # -----------------------------------------------------------------
    print("\n[Step 3: Testing RAG Routes Protection (/query, /ingest)]")
    # 3a. Calling /query without token -> 401 Unauthorized
    no_token_query = client.post("/query", json={
        "query_text": "Company cloud security policies",
        "user_id": "member_strict_test",
        "org_id": "org_enterprise_01"
    })
    print(f"  POST /query without token: status={no_token_query.status_code} (Expected 401)")
    assert no_token_query.status_code == 401, f"Expected 401, got {no_token_query.status_code}"

    # 3b. Calling /ingest without token -> 401 Unauthorized
    no_token_ingest = client.post("/ingest", json={
        "text": "Secret company document contents",
        "doc_id": "doc_test_sec_01",
        "user_id": "member_strict_test",
        "org_id": "org_enterprise_01"
    })
    print(f"  POST /ingest without token: status={no_token_ingest.status_code} (Expected 401)")
    assert no_token_ingest.status_code == 401, f"Expected 401, got {no_token_ingest.status_code}"

    # 3c. Calling /query with unapproved pending user's token -> 401 Unauthorized
    pending_token = create_jwt_token({
        "sub": user_db["user_id"],
        "email": test_pending_email,
        "role": "member",
        "status": "pending"
    })
    pending_token_query = client.post(
        "/query",
        headers={"Authorization": f"Bearer {pending_token}"},
        json={
            "query_text": "Company cloud security policies",
            "user_id": user_db["user_id"],
            "org_id": "default_org"
        }
    )
    print(f"  POST /query with pending user token: status={pending_token_query.status_code} (Expected 401)")
    assert pending_token_query.status_code == 401, f"Expected 401, got {pending_token_query.status_code}"
    print("  RAG routes protected: 401 Unauthorized returned for missing/unapproved tokens (PASSED)")

    # -----------------------------------------------------------------
    # STEP 4: ADMIN ROUTE PROTECTION (/api/v1/admin/*)
    # -----------------------------------------------------------------
    print("\n[Step 4: Testing Admin Route Protection from Non-Admin Users]")
    # 4a. Calling /api/v1/admin/pending with member token -> 403 Forbidden
    member_admin_access = client.get(
        "/api/v1/admin/pending",
        headers={"Authorization": f"Bearer {member_token}"}
    )
    print(f"  GET /api/v1/admin/pending with member token: status={member_admin_access.status_code} (Expected 403)")
    assert member_admin_access.status_code == 403, f"Expected 403, got {member_admin_access.status_code}"

    # 4b. Calling /api/v1/admin/users with member token -> 403 Forbidden
    member_users_access = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {member_token}"}
    )
    print(f"  GET /api/v1/admin/users with member token: status={member_users_access.status_code} (Expected 403)")
    assert member_users_access.status_code == 403, f"Expected 403, got {member_users_access.status_code}"

    # 4c. Calling /api/v1/admin/approve with member token -> 403 Forbidden
    member_approve_attempt = client.post(
        f"/api/v1/admin/approve?target_email={test_pending_email}&decision=approved",
        headers={"Authorization": f"Bearer {member_token}"}
    )
    print(f"  POST /api/v1/admin/approve with member token: status={member_approve_attempt.status_code} (Expected 403)")
    assert member_approve_attempt.status_code == 403, f"Expected 403, got {member_approve_attempt.status_code}"

    # 4d. Calling /api/v1/admin/pending with genuine admin login token -> 200 OK
    admin_login = client.post("/api/v1/auth/login", json={
        "email": "admin@local.rag",
        "password": "AdminPass2026!"
    })
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["token"]
    admin_access_ok = client.get(
        "/api/v1/admin/pending",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print(f"  GET /api/v1/admin/pending with admin token: status={admin_access_ok.status_code} (Expected 200)")
    assert admin_access_ok.status_code == 200
    print("  Admin routes protected: 403 Forbidden enforced against non-admin roles (PASSED)")

    # -----------------------------------------------------------------
    # STEP 5: STATIC FILES RBAC AUDIT (login.html, pending.html, index.html, app.js, admin.html)
    # -----------------------------------------------------------------
    print("\n[Step 5: Auditing Frontend Static Files for Strict RBAC]")

    with open("static/login.html", "r", encoding="utf-8") as f:
        login_text = f.read()
    assert "Email verified. Please wait for Admin approval." in login_text, "login.html missing required pending error message"
    assert "rag_session" in login_text, "login.html missing rag_session storage"
    assert "/admin" in login_text and "/dashboard" in login_text, "login.html missing role-based redirect logic"
    print("  static/login.html: Contains 403 pending message, rag_session storage, and role redirects (PASSED)")

    with open("static/pending.html", "r", encoding="utf-8") as f:
        pending_text = f.read()
    assert "#0f141c" in pending_text, "pending.html missing #0f141c dark theme"
    assert "Account Verified! Your access request is currently pending Administrator review. You will receive access to the RAG platform once approved." in pending_text, "pending.html missing required text"
    assert 'id="btn-logout"' in pending_text, "pending.html missing Logout button (id='btn-logout')"
    assert "localStorage.clear()" in pending_text, "pending.html logout does not clear localStorage"
    assert "/dashboard" in pending_text, "pending.html missing auto-redirect for approved accounts"
    print("  static/pending.html: Contains exact text, dark theme, Logout button, and auto-redirect (PASSED)")

    with open("static/index.html", "r", encoding="utf-8") as f:
        index_text = f.read()
    assert "admin-only-feature" in index_text, "index.html missing admin-only-feature class"
    assert 'session-username-display' in index_text, "index.html missing session-username-display"
    assert 'session-role-display' in index_text, "index.html missing session-role-display"
    assert 'session-org-display' in index_text, "index.html missing session-org-display"
    print("  static/index.html: Has .admin-only-feature on admin controls and dynamic header displays (PASSED)")

    with open("static/app.js", "r", encoding="utf-8") as f:
        app_text = f.read()
    assert "localStorage.getItem('rag_session')" in app_text, "app.js missing rag_session check"
    assert "admin-only-feature" in app_text, "app.js missing admin-only-feature hiding"
    assert "session-username-display" in app_text, "app.js missing dynamic session-username-display"
    assert "session-role-display" in app_text, "app.js missing dynamic session-role-display"
    assert "session-org-display" in app_text, "app.js missing dynamic session-org-display"
    print("  static/app.js: Contains strict session gate, admin element hiding, and dynamic header bindings (PASSED)")

    with open("static/admin.html", "r", encoding="utf-8") as f:
        admin_text = f.read()
    assert "window.location.replace('/dashboard')" in admin_text or "window.location.href = '/dashboard'" in admin_text, "admin.html missing guard redirecting non-admins"
    print("  static/admin.html: Guard present redirecting non-admins to /dashboard (PASSED)")

    print("\n" + "=" * 85)
    print(" ALL STRICT RBAC AND PENDING APPROVAL SECURITY TESTS PASSED! ")
    print("=" * 85)

if __name__ == "__main__":
    run_rbac_tests()

