"""
Comprehensive Test Suite for Self-Hosted Login, OTP Verification, Dedicated Pending Page, and Admin Approval System.
"""
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from fastapi.testclient import TestClient
from main import app
from core.auth_service import AuthService
from core.email_service import send_verification_email, send_otp_email

client = TestClient(app)

def run_all_tests():
    print("=" * 85)
    print(" COMPREHENSIVE TEST: SELF-HOSTED AUTH & ADMIN APPROVAL SYSTEM")
    print("=" * 85)

    test_user_email = "test_user_selfhosted@example.com"
    test_user_password = "Password2026!Secure"
    test_reject_email = "test_rejected_user@example.com"

    # Clean up test accounts from previous runs
    with AuthService._get_connection() as conn:
        conn.execute("DELETE FROM users WHERE email IN (?, ?)", (test_user_email, test_reject_email))
        conn.commit()

    # -------------------------------------------------------------
    # 1. TEST HTML PAGE SERVING (/, /login, /pending, /dashboard, /admin)
    # -------------------------------------------------------------
    print("\n[Step 1: Verifying HTML Page Endpoints]")
    root_page_res = client.get("/")
    print(f"  GET /: status={root_page_res.status_code}")
    assert root_page_res.status_code == 200, "Failed to serve /"
    assert "#0f141c" in root_page_res.text, "login.html missing #0f141c dark theme"

    pending_page_res = client.get("/pending")
    print(f"  GET /pending: status={pending_page_res.status_code}")
    assert pending_page_res.status_code == 200, "Failed to serve /pending"
    assert "Your account is currently pending Administrator approval. You will receive access to the RAG platform once approved." in pending_page_res.text

    dashboard_res = client.get("/dashboard")
    print(f"  GET /dashboard: status={dashboard_res.status_code}")
    assert dashboard_res.status_code == 200, "Failed to serve /dashboard"

    admin_page_res = client.get("/admin")
    print(f"  GET /admin: status={admin_page_res.status_code}")
    assert admin_page_res.status_code == 200, "Failed to serve /admin"
    assert "#0f141c" in admin_page_res.text, "admin.html missing #0f141c dark theme"
    print("  HTML pages served successfully with required theme and content (PASSED)")

    # -------------------------------------------------------------
    # 2. TEST EMAIL FUNCTION
    # -------------------------------------------------------------
    print("\n[Step 2: Testing Python Verification Email Function]")
    email_sent = send_verification_email("recipient@example.com", "123456")
    assert email_sent is True, "send_verification_email failed"
    alias_sent = send_otp_email("recipient@example.com", "654321")
    assert alias_sent is True, "send_otp_email alias failed"
    print("  Email dispatch functions executed successfully (PASSED)")

    # -------------------------------------------------------------
    # 3. USER REGISTRATION & DATABASE TRACKING
    # -------------------------------------------------------------
    print("\n[Step 3: Testing User Signup (POST /api/v1/auth/register)]")
    reg_res = client.post("/api/v1/auth/register", json={
        "email": test_user_email,
        "password": test_user_password,
        "org_id": "default_org"
    })
    print(f"  Register response code: {reg_res.status_code}")
    assert reg_res.status_code == 200
    assert reg_res.json().get("status") == "SUCCESS"

    user_db = AuthService.get_user_by_email(test_user_email)
    assert user_db is not None, "User not found in SQLite"
    assert user_db["email"] == test_user_email
    assert user_db["status"] == "unverified", f"Expected 'unverified', got {user_db['status']}"
    assert user_db["role"] in ("member", "Member"), f"Expected member role, got {user_db['role']}"
    assert user_db["otp_code"] is not None and len(user_db["otp_code"]) == 6
    assert user_db["created_at"] is not None and user_db["created_at"] > 0
    assert user_db["verified_at"] is None
    assert user_db["approved_at"] is None

    otp_code = user_db["otp_code"]
    print(f"  SQLite user record verified:")
    print(f"    - Email: {user_db['email']}")
    print(f"    - Role: {user_db['role']}")
    print(f"    - Status: {user_db['status']}")
    print(f"    - 6-digit OTP code: {otp_code}")
    print(f"    - Registered timestamp (created_at): {user_db['created_at']}")
    print("  Registration & SQLite tracking (PASSED)")

    # -------------------------------------------------------------
    # 4. UNVERIFIED LOGIN BLOCK
    # -------------------------------------------------------------
    print("\n[Step 4: Testing Login Blocking for Unverified User]")
    unverified_login = client.post("/api/v1/auth/login", json={
        "email": test_user_email,
        "password": test_user_password
    })
    print(f"  Unverified login status code: {unverified_login.status_code} (Expected 403)")
    assert unverified_login.status_code == 403
    assert unverified_login.json().get("detail", {}).get("code") == "UNVERIFIED"
    print("  Unverified user correctly blocked from login (PASSED)")

    # -------------------------------------------------------------
    # 5. OTP VERIFICATION STEP
    # -------------------------------------------------------------
    print("\n[Step 5: Testing OTP Verification Step]")
    # Bad OTP test
    bad_verify = client.post("/api/v1/auth/verify-otp", json={
        "email": test_user_email,
        "otp": "000000"
    })
    assert bad_verify.status_code == 400
    print("  Invalid OTP rejected with 400 Bad Request (PASSED)")

    # Good OTP test
    good_verify = client.post("/api/v1/auth/verify-otp", json={
        "email": test_user_email,
        "otp": otp_code
    })
    print(f"  Valid OTP verify code: {good_verify.status_code}")
    assert good_verify.status_code == 200
    assert good_verify.json().get("status") == "PENDING_APPROVAL"

    user_db = AuthService.get_user_by_email(test_user_email)
    assert user_db["status"] == "pending", f"Expected 'pending', got {user_db['status']}"
    assert user_db["verified_at"] is not None and user_db["verified_at"] > 0
    print(f"  SQLite check: status='{user_db['status']}', verified_at={user_db['verified_at']} (PASSED)")

    # -------------------------------------------------------------
    # 6. PENDING USER LOGIN BLOCKING
    # -------------------------------------------------------------
    print("\n[Step 6: Testing Login Blocking for Pending User]")
    pending_login = client.post("/api/v1/auth/login", json={
        "email": test_user_email,
        "password": test_user_password
    })
    print(f"  Pending login status code: {pending_login.status_code} (Expected 403 Forbidden)")
    assert pending_login.status_code == 403
    detail = pending_login.json().get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("code") == "PENDING_APPROVAL" or "pending" in str(detail).lower()
    else:
        assert detail == "PENDING_APPROVAL" or "pending" in str(detail).lower()
    print("  Pending user blocked from login with waiting message (PASSED)")

    # -------------------------------------------------------------
    # 7. SEPARATE ADMIN LOGIN
    # -------------------------------------------------------------
    print("\n[Step 7: Testing Separate Admin Login (POST /api/v1/admin/login)]")
    admin_login = client.post("/api/v1/admin/login", json={
        "email": "admin@local.rag",
        "password": "AdminPass2026!"
    })
    print(f"  Admin login status code: {admin_login.status_code}")
    assert admin_login.status_code == 200
    admin_token = admin_login.json().get("token")
    assert admin_token is not None, "Admin JWT token not returned"
    print("  Admin successfully authenticated and token issued (PASSED)")

    # -------------------------------------------------------------
    # 8. ADMIN DASHBOARD DATA LISTING
    # -------------------------------------------------------------
    print("\n[Step 8: Testing Admin Fetch All Users (GET /api/v1/admin/users)]")
    users_res = client.get(f"/api/v1/admin/users?admin_token={admin_token}")
    assert users_res.status_code == 200
    users_list = users_res.json().get("users", [])
    print(f"  Total users fetched by Admin: {len(users_list)}")

    found_test_user = next((u for u in users_list if u.get("email") == test_user_email), None)
    assert found_test_user is not None, "Test user not visible in Admin dashboard"
    assert found_test_user["status"] == "pending"
    assert found_test_user["created_at"] is not None
    assert found_test_user["verified_at"] is not None
    print(f"  Admin table record verified for {test_user_email}:")
    print(f"    - Email: {found_test_user['email']}")
    print(f"    - Status: {found_test_user['status']}")
    print(f"    - Registered At: {found_test_user['created_at']}")
    print(f"    - Email Verified At: {found_test_user['verified_at']}")
    print("  Admin dashboard user listing (PASSED)")

    # -------------------------------------------------------------
    # 9. ADMIN APPROVAL BUTTON (UPDATING STATUS & RECORDING TIMESTAMP)
    # -------------------------------------------------------------
    print("\n[Step 9: Testing Admin Approval (POST /api/v1/admin/approve)]")
    decision_time_before = time.time() - 1
    approve_res = client.post(
        f"/api/v1/admin/approve?target_email={test_user_email}&decision=approved&admin_token={admin_token}"
    )
    print(f"  Approve status code: {approve_res.status_code}")
    assert approve_res.status_code == 200
    assert approve_res.json().get("status") == "SUCCESS"

    user_db = AuthService.get_user_by_email(test_user_email)
    assert user_db["status"] == "approved"
    assert user_db["approved_at"] is not None and user_db["approved_at"] >= decision_time_before
    assert user_db["approved_by"] is not None
    print(f"  SQLite check after approval:")
    print(f"    - Status: {user_db['status']}")
    print(f"    - Approved By: {user_db['approved_by']}")
    print(f"    - Approved At (Timestamp): {user_db['approved_at']}")
    print("  Admin approval and decision timestamp recording (PASSED)")

    # -------------------------------------------------------------
    # 10. POST-APPROVAL USER LOGIN
    # -------------------------------------------------------------
    print("\n[Step 10: Testing Post-Approval User Login]")
    post_login = client.post("/api/v1/auth/login", json={
        "email": test_user_email,
        "password": test_user_password
    })
    print(f"  Post-approval login code: {post_login.status_code}")
    assert post_login.status_code == 200
    assert post_login.json().get("status") in ("SUCCESS", "approved")
    assert post_login.json().get("token") is not None
    print(f"  User granted access with token: {post_login.json().get('token')[:24]}... (PASSED)")

    # -------------------------------------------------------------
    # 11. ADMIN REJECTION BUTTON TEST
    # -------------------------------------------------------------
    print("\n[Step 11: Testing Admin Rejection Flow]")
    # Register another user to reject
    client.post("/api/v1/auth/register", json={
        "email": test_reject_email,
        "password": test_user_password
    })
    user_rej = AuthService.get_user_by_email(test_reject_email)
    client.post("/api/v1/auth/verify-otp", json={
        "email": test_reject_email,
        "otp": user_rej["otp_code"]
    })

    # Admin rejects user
    reject_res = client.post(
        f"/api/v1/admin/approve?target_email={test_reject_email}&decision=rejected&admin_token={admin_token}"
    )
    assert reject_res.status_code == 200

    user_rej_db = AuthService.get_user_by_email(test_reject_email)
    assert user_rej_db["status"] == "rejected"
    assert user_rej_db["approved_at"] is not None, "Decision timestamp should be recorded for rejection as well"
    print(f"  User {test_reject_email} successfully rejected at timestamp {user_rej_db['approved_at']} (PASSED)")

    # Rejected login should fail
    rej_login = client.post("/api/v1/auth/login", json={
        "email": test_reject_email,
        "password": test_user_password
    })
    assert rej_login.status_code == 403
    print("  Rejected user blocked with 403 Forbidden (PASSED)")

    print("\n" + "=" * 85)
    print(" ALL 11 VERIFICATION TESTS PASSED SUCCESSFULLY! ")
    print("=" * 85)

if __name__ == "__main__":
    run_all_tests()
