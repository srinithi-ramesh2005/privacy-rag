"""
User Authentication and Organization Admin Approval Service.
Uses SQLite (storage_data/auth.db) with PBKDF2-HMAC-SHA256 password hashing.
Provides multi-tenant role-based access control (RBAC), OTP email verification, and admin approval workflows.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import random
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AuthService")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage_data")
DB_PATH = os.path.join(DB_DIR, "auth.db")

ORG_MAPPING = {
    "org1": "org_enterprise_01",
    "org_1": "org_enterprise_01",
    "org_enterprise_01": "org_enterprise_01",
    "org2": "org_finance_corp",
    "org_2": "org_finance_corp",
    "org_finance_corp": "org_finance_corp",
    "org3": "org_healthcare_plus",
    "org_3": "org_healthcare_plus",
    "org_healthcare_plus": "org_healthcare_plus",
}


def canonicalize_org(org_id: str) -> str:
    clean = re.sub(r"[\s\-_]+", "_", org_id.strip().lower())
    clean = re.sub(r"^org_org_", "org_", clean)
    m = re.match(r"^org_?(\d+)$", clean)
    if m:
        num = m.group(1)
        alias_key = f"org_{num}"
        return ORG_MAPPING.get(alias_key, alias_key)
    return ORG_MAPPING.get(clean, clean)


class AuthService:
    """Manages user persistence, passwords, tenant org assignments, and admin approval workflows."""

    @classmethod
    @contextlib.contextmanager
    def _get_connection(cls):
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @classmethod
    def init_db(cls) -> None:
        """Create users table and seed pre-configured organization admins and initial members."""
        with cls._get_connection() as conn:
            # Check if table exists and needs constraint migration
            cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
            row = cur.fetchone()
            if row:
                sql = row["sql"] or ""
                # If old CHECK constraint exists that restricts status to ('approved', 'pending', 'rejected')
                if "CHECK" in sql and "unverified" not in sql:
                    logger.info("Migrating SQLite users table to support 'unverified' status & OTP...")
                    conn.execute("ALTER TABLE users RENAME TO users_old")
                    conn.execute("""
                        CREATE TABLE users (
                            user_id TEXT PRIMARY KEY,
                            email TEXT UNIQUE,
                            username TEXT,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            full_name TEXT NOT NULL,
                            org_id TEXT NOT NULL DEFAULT 'default_org',
                            role TEXT NOT NULL DEFAULT 'member',
                            status TEXT NOT NULL DEFAULT 'unverified',
                            otp_code TEXT,
                            created_at REAL NOT NULL,
                            verified_at REAL,
                            approved_by TEXT,
                            approved_at REAL,
                            auth_provider TEXT DEFAULT 'local',
                            google_id TEXT
                        )
                    """)
                    conn.execute("""
                        INSERT INTO users (user_id, email, username, password_hash, salt, full_name, org_id, role, status, created_at, approved_by, approved_at, auth_provider, google_id)
                        SELECT user_id, email, username, password_hash, salt, full_name, org_id, role, status, created_at, approved_by, approved_at, auth_provider, google_id
                        FROM users_old
                    """)
                    conn.execute("DROP TABLE users_old")
                    conn.commit()

            # Create table if not exists with clean schema
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE,
                    username TEXT,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default_org',
                    role TEXT NOT NULL DEFAULT 'member',
                    status TEXT NOT NULL DEFAULT 'unverified',
                    otp_code TEXT,
                    created_at REAL NOT NULL,
                    verified_at REAL,
                    approved_by TEXT,
                    approved_at REAL,
                    auth_provider TEXT DEFAULT 'local',
                    google_id TEXT
                )
            """)
            conn.commit()

            # Ensure all required columns exist
            cursor = conn.execute("PRAGMA table_info(users)")
            cols = {r["name"] for r in cursor.fetchall()}
            if "otp_code" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN otp_code TEXT")
            if "verified_at" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN verified_at REAL")
            if "email" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
            if "username" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN username TEXT")
            if "full_name" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            if "org_id" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN org_id TEXT DEFAULT 'default_org'")
            conn.commit()

        # Seed pre-configured accounts
        default_accounts = [
            # Primary Global Admin
            ("usr_admin_root", "admin", "admin@local.rag", "AdminPass2026!", "System Administrator", "default_org", "admin", "approved"),
            # Org Admins
            ("admin_tech", "admin_tech", "admin_tech@local.rag", "AdminTech2026!", "Tech Admin", "org_enterprise_01", "admin", "approved"),
            ("admin_finance", "admin_finance", "admin_finance@local.rag", "AdminFinance2026!", "Finance Admin", "org_finance_corp", "admin", "approved"),
            ("admin_health", "admin_health", "admin_health@local.rag", "AdminHealth2026!", "Healthcare Admin", "org_healthcare_plus", "admin", "approved"),
            # Pre-approved test identities
            ("usr_admin_01", "usr_admin_01", "admin01@enterprise.local", "Admin01Pass!", "Lead Cloud Architect", "org_enterprise_01", "member", "approved"),
            ("usr_finance_director", "usr_finance_director", "finance_dir@finance.local", "FinanceDirectorPass!", "Finance Director", "org_finance_corp", "member", "approved"),
            ("usr_clinical_director", "usr_clinical_director", "clinical_dir@health.local", "ClinicalDirectorPass!", "Clinical Director", "org_healthcare_plus", "member", "approved"),
        ]

        now = time.time()
        for user_id, uname, email_addr, pwd, name, org, role, status in default_accounts:
            existing = cls.get_user(user_id) or cls.get_user_by_email(email_addr) or cls.get_user_by_username(uname)
            if not existing:
                cls.create_user_direct(
                    user_id=user_id,
                    username=uname,
                    password=pwd,
                    full_name=name,
                    org_id=org,
                    role=role,
                    status=status,
                    email=email_addr
                )
            else:
                # Update email/role/status if empty
                with cls._get_connection() as conn:
                    conn.execute(
                        "UPDATE users SET email = COALESCE(email, ?), role = ?, status = ? WHERE user_id = ?",
                        (email_addr, role, status, existing["user_id"])
                    )
                    conn.commit()

        # Also support legacy 'admin' username
        legacy_admin = cls.get_user("admin") or cls.get_user_by_username("admin")
        if legacy_admin:
            with cls._get_connection() as conn:
                conn.execute(
                    "UPDATE users SET email = 'admin@local.rag', role = 'admin', status = 'approved' WHERE user_id = ?",
                    (legacy_admin["user_id"],)
                )
                conn.commit()

        # Check environment-configured admin
        env_admin_email = os.getenv("ADMIN_EMAIL", "admin@local.rag").strip().lower()
        env_admin_pwd = os.getenv("ADMIN_PASSWORD", "AdminPass2026!").strip()
        if env_admin_email and env_admin_pwd:
            adm = cls.get_user_by_email(env_admin_email)
            if not adm:
                cls.create_user_direct(
                    user_id=f"usr_admin_{secrets.token_hex(3)}",
                    username="admin",
                    password=env_admin_pwd,
                    full_name="System Administrator",
                    org_id="default_org",
                    role="admin",
                    status="approved",
                    email=env_admin_email
                )

        logger.info("Auth database initialized successfully.")

    @classmethod
    def hash_password(cls, password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """Hash password with PBKDF2-HMAC-SHA256 and salt."""
        if salt is None:
            salt = os.urandom(16)
        salt_hex = salt.hex()
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return key.hex(), salt_hex

    @classmethod
    def verify_password(cls, password: str, stored_hash: str, salt_hex: str) -> bool:
        """Verify given password against stored hash."""
        try:
            salt = bytes.fromhex(salt_hex)
            key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
            return hmac.compare_digest(key.hex(), stored_hash)
        except Exception:
            return False

    @classmethod
    def create_user_direct(
        cls,
        user_id: str,
        username: str,
        password: str,
        full_name: str,
        org_id: str,
        role: str = "member",
        status: str = "pending",
        approved_by: Optional[str] = None,
        email: Optional[str] = None,
        auth_provider: str = "local",
        google_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Internal helper to insert user directly into database."""
        pwd_hash, salt_hex = cls.hash_password(password)
        now = time.time()
        c_org = canonicalize_org(org_id)

        with cls._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO users 
                (user_id, username, password_hash, salt, full_name, org_id, role, status, created_at, approved_by, approved_at, email, auth_provider, google_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username.lower().strip(), pwd_hash, salt_hex, full_name, c_org, role, status, now,
                 approved_by, now if status == "approved" else None, email, auth_provider, google_id)
            )
            conn.commit()

        return cls.get_user(user_id) or {}

    @classmethod
    def create_unverified_user(
        cls,
        email: str,
        password: str,
        otp_code: str,
        org_id: str = "default_org",
        full_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new user with status='unverified' and store the 6-digit OTP code.
        If an unverified record already exists, updates credentials and issues the new OTP.
        """
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email or "." not in clean_email:
            raise ValueError("A valid email address is required (e.g. user@company.com).")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")

        existing = cls.get_user_by_email(clean_email)
        now = time.time()
        pwd_hash, salt_hex = cls.hash_password(password)
        c_org = canonicalize_org(org_id)

        if existing:
            if existing["status"] == "approved":
                raise ValueError("An approved account already exists with this email address. Please sign in.")
            if existing["status"] == "pending":
                raise ValueError("This account has already verified their email and is pending administrator approval.")
            # Unverified or rejected: refresh credentials, claimed org, name and OTP
            with cls._get_connection() as conn:
                conn.execute(
                    """
                    UPDATE users 
                    SET password_hash = ?, salt = ?, status = 'unverified', otp_code = ?, created_at = ?, verified_at = NULL, org_id = ?, full_name = ?
                    WHERE user_id = ?
                    """,
                    (pwd_hash, salt_hex, str(otp_code).strip(), now, c_org, (full_name.strip() if full_name else (existing.get("full_name") or prefix)), existing["user_id"])
                )
                conn.commit()
            return cls.get_user(existing["user_id"]) or {}

        prefix = re.sub(r"[^a-zA-Z0-9_]", "_", clean_email.split("@")[0])
        user_id = f"usr_{prefix}_{secrets.token_hex(3)}"
        fname = full_name.strip() if full_name else clean_email.split("@")[0]

        with cls._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users 
                (user_id, email, username, password_hash, salt, full_name, org_id, role, status, otp_code, created_at, verified_at, auth_provider)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'member', 'unverified', ?, ?, NULL, 'local')
                """,
                (user_id, clean_email, prefix, pwd_hash, salt_hex, fname, c_org, str(otp_code).strip(), now)
            )
            conn.commit()

        return cls.get_user(user_id) or {}

    @classmethod
    def verify_otp(cls, email: str, otp: str) -> Dict[str, Any]:
        """
        Verify the 6-digit OTP code.
        On match: updates status from 'unverified' to 'pending' and records verified_at timestamp.
        """
        clean_email = email.strip().lower()
        user = cls.get_user_by_email(clean_email)
        if not user:
            raise ValueError(f"No registration found for email '{email}'.")

        if user["status"] == "approved":
            return user

        stored_otp = str(user.get("otp_code") or "").strip()
        provided_otp = str(otp).strip()

        if not stored_otp or stored_otp != provided_otp:
            raise ValueError("Invalid verification code. Please check your email and try again.")

        now = time.time()
        with cls._get_connection() as conn:
            conn.execute(
                """
                UPDATE users 
                SET status = 'pending', verified_at = ?, otp_code = NULL 
                WHERE user_id = ?
                """,
                (now, user["user_id"])
            )
            conn.commit()

        updated = cls.get_user(user["user_id"]) or {}
        logger.info(f"User '{clean_email}' successfully verified OTP. Status set to 'pending'.")
        return updated

    @classmethod
    def authenticate(cls, identifier: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user by email, username, or user_id.
        Returns safe user dictionary on valid password, None on mismatch.
        """
        clean_id = identifier.strip().lower()
        user = cls.get_user_by_email(clean_id) or cls.get_user_by_username(clean_id) or cls.get_user(clean_id)
        if not user:
            return None
        if cls.verify_password(password, user["password_hash"], user["salt"]):
            return {
                "user_id": user["user_id"],
                "email": user.get("email") or f"{user['username']}@local.rag",
                "username": user["username"],
                "full_name": user["full_name"],
                "org_id": user["org_id"],
                "role": user["role"],
                "status": user["status"],
                "created_at": user["created_at"],
                "verified_at": user.get("verified_at"),
                "approved_by": user.get("approved_by"),
                "approved_at": user.get("approved_at"),
            }
        return None

    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Backward-compatible alias for authenticate."""
        return cls.authenticate(username, password)

    @classmethod
    def register_user(
        cls,
        username: str,
        password: str,
        full_name: str,
        org_id: str,
        email: Optional[str] = None
    ) -> Dict[str, Any]:
        """Legacy registration helper that registers directly into 'pending'."""
        clean_username = username.strip().lower()
        if not clean_username or len(clean_username) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")

        existing = cls.get_user_by_username(clean_username)
        if existing:
            raise ValueError(f"Username '{clean_username}' is already taken.")

        c_org = canonicalize_org(org_id)
        user_id = f"usr_{clean_username}"

        return cls.create_user_direct(
            user_id=user_id,
            username=clean_username,
            password=password,
            full_name=full_name.strip() or clean_username,
            org_id=c_org,
            role="member",
            status="pending",
            email=email.strip().lower() if email else f"{clean_username}@local.rag",
            auth_provider="local"
        )

    @classmethod
    def get_user(cls, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch user by user_id."""
        with cls._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def get_user_by_email(cls, email: str) -> Optional[Dict[str, Any]]:
        """Fetch user by email address."""
        with cls._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email.strip().lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def get_user_by_username(cls, username: str) -> Optional[Dict[str, Any]]:
        """Fetch user by username."""
        with cls._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username.strip().lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    @classmethod
    def get_all_users(cls) -> List[Dict[str, Any]]:
        """Fetch all users from SQLite table."""
        with cls._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT user_id, email, username, full_name, org_id, role, status, created_at, verified_at, approved_by, approved_at 
                FROM users 
                ORDER BY created_at DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    @classmethod
    def get_pending_users(cls) -> List[Dict[str, Any]]:
        """Query SQLite for all users where status = 'pending'."""
        with cls._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT user_id, email, username, full_name, org_id, role, status, created_at, verified_at, approved_by, approved_at 
                FROM users 
                WHERE status = 'pending'
                ORDER BY created_at DESC
                """
            )
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["claimed_org"] = d.get("org_id") or "default_org"
                results.append(d)
            return results

    @classmethod
    def get_pending_users_for_org(cls, admin_user_id: str, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch pending users with admin authorization verification."""
        admin = (
            cls.get_user(admin_user_id)
            or cls.get_user_by_username(admin_user_id)
            or cls.get_user_by_email(admin_user_id)
        )
        if not admin or admin["role"] != "admin" or admin["status"] != "approved":
            raise PermissionError("Only approved administrators can review pending users.")

        with cls._get_connection() as conn:
            if org_id and org_id.strip() and org_id.strip().lower() != "all":
                c_org = canonicalize_org(org_id)
                cursor = conn.execute(
                    """
                    SELECT user_id, email, username, full_name, org_id, role, status, created_at, verified_at, approved_by, approved_at 
                    FROM users 
                    WHERE org_id = ? AND status = 'pending'
                    ORDER BY created_at DESC
                    """,
                    (c_org,)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT user_id, email, username, full_name, org_id, role, status, created_at, verified_at, approved_by, approved_at 
                    FROM users 
                    WHERE status = 'pending'
                    ORDER BY created_at DESC
                    """
                )
            return [dict(row) for row in cursor.fetchall()]

    @classmethod
    def set_approval_status(
        cls,
        target_identifier: str,
        decision: str,  # 'approved' or 'rejected'
        approved_by: str = "admin",
        admin_user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve or reject a user by email, user_id, or username.
        Updates status, approved_by (Admin ID), approved_at timestamp, assigned org_id, and role.
        """
        if decision not in ("approved", "rejected"):
            raise ValueError("Decision must be either 'approved' or 'rejected'.")

        approver = approved_by or admin_user_id or "admin"
        target = (
            cls.get_user_by_email(target_identifier)
            or cls.get_user(target_identifier)
            or cls.get_user_by_username(target_identifier)
        )
        if not target:
            raise ValueError(f"Target user '{target_identifier}' not found.")

        target_actual_id = target["user_id"]
        now = time.time()

        with cls._get_connection() as conn:
            c_org = canonicalize_org(org_id) if (org_id and org_id.strip()) else None
            c_role = role.strip().lower() if (role and role.strip()) else None

            updates = ["status = ?", "approved_by = ?", "approved_at = ?"]
            params = [decision, approver, now]

            if c_org:
                updates.append("org_id = ?")
                params.append(c_org)
            if c_role:
                updates.append("role = ?")
                params.append(c_role)

            params.append(target_actual_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?"
            conn.execute(query, tuple(params))
            conn.commit()

        updated = cls.get_user(target_actual_id) or {}
        return {
            "user_id": updated.get("user_id"),
            "email": updated.get("email"),
            "username": updated.get("username"),
            "role": updated.get("role"),
            "org_id": updated.get("org_id"),
            "status": updated.get("status"),
            "created_at": updated.get("created_at"),
            "verified_at": updated.get("verified_at"),
            "approved_by": updated.get("approved_by"),
            "approved_at": updated.get("approved_at"),
        }

    @classmethod
    def resend_otp(cls, email: str, new_otp: str) -> Dict[str, Any]:
        """Update 6-digit OTP code for an unverified user."""
        clean_email = email.strip().lower()
        user = cls.get_user_by_email(clean_email)
        if not user:
            raise ValueError(f"No account found with email '{email}'.")
        if user["status"] == "approved":
            raise ValueError("Account is already approved. Please sign in.")
        if user["status"] == "pending":
            raise ValueError("Email already verified. Account is awaiting admin approval.")
        with cls._get_connection() as conn:
            conn.execute("UPDATE users SET otp_code = ? WHERE user_id = ?", (str(new_otp).strip(), user["user_id"]))
            conn.commit()
        return cls.get_user(user["user_id"]) or {}

    @classmethod
    def get_user_status(cls, email: str) -> Optional[Dict[str, Any]]:
        """Retrieve sanitized user status and timestamps."""
        clean_email = email.strip().lower()
        user = cls.get_user_by_email(clean_email)
        if not user:
            return None
        return {
            "user_id": user["user_id"],
            "email": user.get("email"),
            "username": user.get("username"),
            "role": user.get("role", "member"),
            "status": user.get("status", "unverified"),
            "created_at": user.get("created_at"),
            "verified_at": user.get("verified_at"),
            "approved_at": user.get("approved_at"),
            "approved_by": user.get("approved_by"),
        }

    @classmethod
    def approve_all_users(cls, admin_user_id: str, target_org_id: Optional[str] = None) -> Dict[str, Any]:
        """Bulk-approve pending users."""
        admin = (
            cls.get_user(admin_user_id)
            or cls.get_user_by_username(admin_user_id)
            or cls.get_user_by_email(admin_user_id)
        )
        if not admin or admin["role"] != "admin" or admin["status"] != "approved":
            raise PermissionError("Only approved administrators can bulk-approve users.")

        now = time.time()
        with cls._get_connection() as conn:
            if target_org_id and target_org_id.strip() and target_org_id.strip().lower() != "all":
                c_org = canonicalize_org(target_org_id)
                cursor = conn.execute(
                    "SELECT user_id, email, username, org_id FROM users WHERE org_id = ? AND status = 'pending'",
                    (c_org,)
                )
            else:
                cursor = conn.execute(
                    "SELECT user_id, email, username, org_id FROM users WHERE status = 'pending'"
                )
            pending_rows = cursor.fetchall()

            if not pending_rows:
                return {
                    "approved_count": 0,
                    "approved_users": [],
                    "message": "No pending users found awaiting approval.",
                }

            approved_users = []
            for row in pending_rows:
                conn.execute(
                    """
                    UPDATE users 
                    SET status = 'approved', approved_by = ?, approved_at = ?
                    WHERE user_id = ?
                    """,
                    (admin["user_id"], now, row["user_id"])
                )
                approved_users.append({
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "username": row["username"],
                    "org_id": row["org_id"]
                })

            conn.commit()

        logger.info(f"Admin '{admin_user_id}' approved {len(approved_users)} users.")
        return {
            "approved_count": len(approved_users),
            "approved_users": approved_users,
            "message": f"Successfully approved {len(approved_users)} pending user(s).",
        }

    @classmethod
    def approve_all_org_users(cls, admin_user_id: str, target_org_id: Optional[str] = None) -> Dict[str, Any]:
        """Backward-compatible alias for approve_all_users."""
        return cls.approve_all_users(admin_user_id=admin_user_id, target_org_id=target_org_id)

    @classmethod
    def update_user_org(cls, target_identifier: str, new_org_id: str) -> Dict[str, Any]:
        """Update a user's assigned organization."""
        target = (
            cls.get_user_by_email(target_identifier)
            or cls.get_user(target_identifier)
            or cls.get_user_by_username(target_identifier)
        )
        if not target:
            raise ValueError(f"User '{target_identifier}' not found.")
        c_org = canonicalize_org(new_org_id)
        with cls._get_connection() as conn:
            conn.execute("UPDATE users SET org_id = ? WHERE user_id = ?", (c_org, target["user_id"]))
            conn.commit()
        return cls.get_user(target["user_id"]) or {}

    @classmethod
    def is_user_authorized_for_org(cls, user_id: str, target_org_id: str) -> Tuple[bool, str]:
        """
        Check if user is authorized to retrieve documents from target_org_id.
        Returns (is_authorized: bool, reason: str).
        """
        user = (
            cls.get_user(user_id)
            or cls.get_user_by_username(user_id)
            or cls.get_user_by_email(user_id)
        )

        if not user:
            if "unauthorized" in user_id.lower() or user_id.startswith("usr_guest"):
                return False, f"User '{user_id}' is an unauthorized guest."
            return False, f"User '{user_id}' does not exist in authentication registry."

        c_target_org = canonicalize_org(target_org_id)
        c_user_org = canonicalize_org(user["org_id"])

        # 1. Organization tenant check:
        # If user is in default_org (unclassified / universal workspace), access is permitted because the user has not been restricted to a specific tenant.
        # Strict cross-tenant isolation is enforced when a user is explicitly classified into a specific org (e.g. org_finance_corp cannot access org_enterprise_01).
        if c_user_org == "default_org" or (user.get("role") == "admin" and c_user_org == "default_org"):
            pass
        elif c_user_org != c_target_org:
            return False, f"Cross-tenant isolation block: User belongs to '{c_user_org}', cannot access '{c_target_org}'."

        # 2. Check approval status
        if user["status"] == "unverified":
            return False, f"Access blocked: Email for '{user.get('email') or user['username']}' is not verified."
        if user["status"] == "pending":
            return False, f"Access blocked: Registration for user '{user.get('email') or user['username']}' is pending administrator approval."
        if user["status"] == "rejected":
            return False, f"Access denied: Registration for user '{user.get('email') or user['username']}' was rejected by the administrator."
        if user["status"] != "approved":
            return False, f"Access denied: Account status is '{user['status']}'."

        return True, "User is authorized and approved."