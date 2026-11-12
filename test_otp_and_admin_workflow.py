"""
Test Suite for End-to-End OTP Verification, Pending Approval, and Admin Workflow.
Covers:
  Step 1: User Signup -> status = 'unverified', 6-digit OTP generated & dispatched.
  Step 2: OTP Verification -> status upgraded to 'pending', verified_at recorded.
  Step 3: User Pending Approval -> login returns 403 Forbidden.
  Step 4: Separate Admin Login & Approval Dashboard -> admin approves user -> user can now login!
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
    print("=" * 80)
    print(" RUNNING OTP VERIFICATION & ADMIN APPROVAL WORKFLOW TESTS")
    print("=" * 80)

    test_email = "alice_researcher@company.com"
    test_password = "SecurePassword2026!"

    # Clean up test user if previously exists
    with AuthService._get_connection() as conn:
        conn.execute("DELETE FROM users WHERE email = ? OR username LIKE 'alice_%'", (test_email,))
        conn.commit()

    # -------------------------------------------------------------
    # STEP 1: Registration
    # -------------------------------------------------------------
    print("\n[Step 1: Testing User Signup / Registration (POST /api/v1/auth/register)]")
    reg_res = client.post("/api/v1/auth/register", json={
        "email": test_email,
        "password": test_password,
        "org_id": "org_enterprise_01"
    })
    print(f"  Registration Status Code: {reg_res.status_code}")
    print(f"  Response Body: {reg_res.json()}")
    assert reg_res.status_code == 200, "Registration failed"
    assert reg_res.json().get("status") == "SUCCESS"

    user_db = AuthService.get_user_by_email(test_email)
    assert user_db is not None, "User was not created in SQLite DB"
    assert user_db["status"] == "unverified", f"Expected 'unverified', got {user_db['status']}"
    assert user_db["otp_code"] is not None and len(user_db["otp_code"]) == 6, f"Invalid OTP: {user_db['otp_code']}"
    otp_code = user_db["otp_code"]
    print(f"  SQLite check: status='{user_db['status']}', otp_code='{otp_code}' (PASSED)")

    # -------------------------------------------------------------
    # STEP 2: OTP Verification
    # -------------------------------------------------------------
    print("\n[Step 2: Testing OTP Verification (POST /api/v1/auth/verify-otp)]")
    # Test invalid OTP
    bad_otp_res = client.post("/api/v1/auth/verify-otp", json={
        "email": test_email,
        "otp": "000000"
    })
    print(f"  Invalid OTP Status Code: {bad_otp_res.status_code} (Expected 400)")
    assert bad_otp_res.status_code == 400

    # Test valid OTP
    good_otp_res = client.post("/api/v1/auth/verify-otp", json={
        "email": test_email,
        "otp": otp_code
    })
    print(f"  Valid OTP Status Code: {good_otp_res.status_code}")
    print(f"  Response Body: {good_otp_res.json()}")
    assert good_otp_res.status_code == 200
    assert good_otp_res.json().get("status") == "PENDING_APPROVAL"

    user_db = AuthService.get_user_by_email(test_email)
    assert user_db["status"] == "pending", f"Expected 'pending', got {user_db['status']}"
    assert user_db["verified_at"] is not None, "verified_at timestamp was not recorded"
    assert user_db["otp_code"] is None, "otp_code should be cleared upon verification"
    print(f"  SQLite check: status='{user_db['status']}', verified_at={user_db['verified_at']} (PASSED)")

    # -------------------------------------------------------------
    # STEP 3: User "Pending Approval" Screen Flow
    # -------------------------------------------------------------
    print("\n[Step 3: Testing Login Blocking for Pending User (POST /api/v1/auth/login)]")
    login_res = client.post("/api/v1/auth/login", json={
        "email": test_email,
        "password": test_password
    })
    print(f"  Pending User Login Status Code: {login_res.status_code} (Expected 403 Forbidden)")
    print(f"  Response Body: {login_res.json()}")
    assert login_res.status_code == 403, "Pending user should be blocked from login"
    detail = login_res.json().get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("code") == "PENDING_APPROVAL" or "pending" in str(detail).lower()
    else:
        assert detail == "PENDING_APPROVAL" or "pending" in str(detail).lower()
    print("  Pending access blocked with 403 Forbidden (PASSED)")

    # -------------------------------------------------------------
    # STEP 4: Admin Login & Dashboard Approval Flow
    # -------------------------------------------------------------
    print("\n[Step 4: Testing Separate Admin Login (POST /api/v1/admin/login)]")
    admin_login_res = client.post("/api/v1/admin/login", json={
        "email": "admin@local.rag",
        "password": "AdminPass2026!"
    })
    print(f"  Admin Login Status Code: {admin_login_res.status_code}")
    print(f"  Response: {admin_login_res.json()}")
    assert admin_login_res.status_code == 200
    admin_token = admin_login_res.json().get("token")
    assert admin_token is not None, "Admin JWT token was not returned"

    print("\n[Step 4b: Testing Admin Fetch Pending Users (GET /api/v1/admin/pending)]")
    pending_res = client.get(f"/api/v1/admin/pending?admin_token={admin_token}")
    print(f"  Fetch Pending Status Code: {pending_res.status_code}")
    pending_users = pending_res.json().get("users", [])
    print(f"  Pending Users Count: {len(pending_users)}")
    assert any(u["email"] == test_email for u in pending_users), "New user should be in admin pending list"

    print("\n[Step 4c: Testing Admin Approve User (POST /api/v1/admin/approve)]")
    approve_res = client.post(f"/api/v1/admin/approve?target_email={test_email}&decision=approved&admin_token={admin_token}")
    print(f"  Approve Status Code: {approve_res.status_code}")
    print(f"  Response: {approve_res.json()}")
    assert approve_res.status_code == 200

    user_db = AuthService.get_user_by_email(test_email)
    assert user_db["status"] == "approved", f"Expected 'approved', got {user_db['status']}"
    assert user_db["approved_by"] is not None
    assert user_db["approved_at"] is not None
    print(f"  SQLite check: status='{user_db['status']}', approved_by='{user_db['approved_by']}', approved_at={user_db['approved_at']} (PASSED)")

    print("\n[Step 4d: Post-Approval User Login]")
    post_login_res = client.post("/api/v1/auth/login", json={
        "email": test_email,
        "password": test_password
    })
    print(f"  Post-Approval Login Status Code: {post_login_res.status_code}")
    print(f"  Response: {post_login_res.json().get('status')} - {post_login_res.json().get('message')}")
    assert post_login_res.status_code == 200
    assert post_login_res.json().get("status") == "SUCCESS"
    assert post_login_res.json().get("token") is not None

    print("\n" + "=" * 80)
    print(" ALL 4 STEPS PASSED SUCCESSFULLY! ")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
