"""
Persistent Conversation & History Management Service for Secure RAG.
Stores multi-turn conversations, messages, and security audit metadata in SQLite (storage_data/auth.db).
Enforces strict multi-tenant isolation by (user_id, org_id).
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from core.auth_service import AuthService, canonicalize_org

logger = logging.getLogger("ConversationService")

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage_data")
DB_PATH = os.path.join(DB_DIR, "auth.db")


def resolve_user_ids(identifier: str) -> List[str]:
    """Find all potential user_ids matching this user (user_id, username, email)."""
    if not identifier:
        return []
    ids = {identifier.strip()}
    try:
        u = (
            AuthService.get_user(identifier)
            or AuthService.get_user_by_username(identifier)
            or AuthService.get_user_by_email(identifier)
        )
        if u:
            if u.get("user_id"):
                ids.add(u["user_id"])
            if u.get("username"):
                ids.add(u["username"])
            if u.get("email"):
                ids.add(u["email"])
    except Exception as e:
        logger.warning(f"Error resolving user IDs for '{identifier}': {e}")
    return [i for i in ids if i]


def resolve_org_ids(org_id: str) -> List[str]:
    """Find all potential org_ids matching this org (canonical and raw)."""
    if not org_id:
        return []
    orgs = {org_id.strip()}
    try:
        c_org = canonicalize_org(org_id)
        orgs.add(c_org)
        if org_id.startswith("org_"):
            orgs.add(org_id[4:])
        else:
            orgs.add(f"org_{org_id}")
    except Exception as e:
        logger.warning(f"Error resolving org IDs for '{org_id}': {e}")
    return [o for o in orgs if o]


class ConversationService:
    """Manages persistent conversations, message history, follow-up context, and tenant isolation."""

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
        """Create conversations and conversation_messages tables with indexes."""
        with cls._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversation_messages (
                    message_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_conversations_user_org 
                ON conversations(user_id, org_id, updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_conv_created 
                ON conversation_messages(conversation_id, created_at ASC)
            """)
            conn.commit()
            logger.info("ConversationService database tables initialized successfully.")

    @classmethod
    def create_conversation(
        cls, user_id: str, org_id: str, title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new conversation session for a user within their organization."""
        cls.init_db()
        conv_id = f"conv_{uuid.uuid4().hex[:12]}"
        now = time.time()
        final_title = title.strip() if title and title.strip() else "New Conversation"

        # Canonicalize user_id and org_id for persistent consistency
        u = (
            AuthService.get_user(user_id)
            or AuthService.get_user_by_username(user_id)
            or AuthService.get_user_by_email(user_id)
        )
        canonical_user_id = u["user_id"] if (u and u.get("user_id")) else user_id
        canonical_org_id = canonicalize_org(org_id)

        with cls._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO conversations (conversation_id, user_id, org_id, title, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (conv_id, canonical_user_id, canonical_org_id, final_title, now, now),
            )
            conn.commit()

        logger.info(f"Created conversation '{conv_id}' for user='{canonical_user_id}' (orig='{user_id}'), org='{canonical_org_id}'")
        return {
            "conversation_id": conv_id,
            "user_id": canonical_user_id,
            "org_id": canonical_org_id,
            "title": final_title,
            "created_at": now,
            "updated_at": now,
            "message_count": 0,
        }

    @classmethod
    def list_conversations(
        cls, user_id: str, org_id: str, search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all conversations for a specific user and organization, optionally filtered by search."""
        cls.init_db()
        user_ids = resolve_user_ids(user_id)
        org_ids = resolve_org_ids(org_id)
        u_ph = ",".join("?" for _ in user_ids)
        o_ph = ",".join("?" for _ in org_ids)

        with cls._get_connection() as conn:
            if search_query and search_query.strip():
                term = f"%{search_query.strip().lower()}%"
                cursor = conn.execute(
                    f"""
                    SELECT c.conversation_id, c.user_id, c.org_id, c.title, c.created_at, c.updated_at,
                           COUNT(m.message_id) AS message_count
                    FROM conversations c
                    LEFT JOIN conversation_messages m ON c.conversation_id = m.conversation_id
                    WHERE c.user_id IN ({u_ph}) AND c.org_id IN ({o_ph}) AND (
                        LOWER(c.title) LIKE ? OR
                        EXISTS (
                            SELECT 1 FROM conversation_messages m2 
                            WHERE m2.conversation_id = c.conversation_id AND LOWER(m2.content) LIKE ?
                        )
                    )
                    GROUP BY c.conversation_id
                    ORDER BY c.updated_at DESC
                    """,
                    (*user_ids, *org_ids, term, term),
                )
            else:
                cursor = conn.execute(
                    f"""
                    SELECT c.conversation_id, c.user_id, c.org_id, c.title, c.created_at, c.updated_at,
                           COUNT(m.message_id) AS message_count
                    FROM conversations c
                    LEFT JOIN conversation_messages m ON c.conversation_id = m.conversation_id
                    WHERE c.user_id IN ({u_ph}) AND c.org_id IN ({o_ph})
                    GROUP BY c.conversation_id
                    ORDER BY c.updated_at DESC
                    """,
                    (*user_ids, *org_ids),
                )
            rows = cursor.fetchall()

        return [
            {
                "conversation_id": r["conversation_id"],
                "user_id": r["user_id"],
                "org_id": r["org_id"],
                "title": r["title"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "message_count": r["message_count"],
            }
            for r in rows
        ]

    @classmethod
    def get_conversation(
        cls, conversation_id: str, user_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve conversation metadata ensuring tenant & user isolation."""
        cls.init_db()
        user_ids = resolve_user_ids(user_id)
        org_ids = resolve_org_ids(org_id)
        u_ph = ",".join("?" for _ in user_ids)
        o_ph = ",".join("?" for _ in org_ids)

        with cls._get_connection() as conn:
            cur = conn.execute(
                f"""
                SELECT conversation_id, user_id, org_id, title, created_at, updated_at
                FROM conversations
                WHERE conversation_id = ? AND user_id IN ({u_ph}) AND org_id IN ({o_ph})
                """,
                (conversation_id, *user_ids, *org_ids),
            )
            row = cur.fetchone()
            if not row:
                return None

            return {
                "conversation_id": row["conversation_id"],
                "user_id": row["user_id"],
                "org_id": row["org_id"],
                "title": row["title"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    @classmethod
    def get_messages(
        cls, conversation_id: str, user_id: str, org_id: str
    ) -> List[Dict[str, Any]]:
        """Retrieve chronological message history for an authorized conversation."""
        cls.init_db()
        conv = cls.get_conversation(conversation_id, user_id, org_id)
        if not conv:
            return []

        with cls._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT message_id, conversation_id, user_id, role, content, metadata_json, created_at
                FROM conversation_messages
                WHERE conversation_id = ?
                ORDER BY created_at ASC
                """,
                (conversation_id,),
            )
            rows = cur.fetchall()

        messages = []
        for r in rows:
            meta = {}
            if r["metadata_json"]:
                try:
                    meta = json.loads(r["metadata_json"])
                except Exception:
                    pass
            messages.append({
                "message_id": r["message_id"],
                "conversation_id": r["conversation_id"],
                "user_id": r["user_id"],
                "role": r["role"],
                "content": r["content"],
                "metadata": meta,
                "created_at": r["created_at"],
            })
        return messages

    @classmethod
    def add_message(
        cls,
        conversation_id: str,
        user_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a new turn (user or assistant) to a conversation and update timestamps."""
        cls.init_db()
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        now = time.time()
        meta_str = json.dumps(metadata) if metadata else None

        with cls._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO conversation_messages (message_id, conversation_id, user_id, role, content, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (msg_id, conversation_id, user_id, role, content, meta_str, now),
            )
            conn.execute(
                """
                UPDATE conversations
                SET updated_at = ?
                WHERE conversation_id = ?
                """,
                (now, conversation_id),
            )
            conn.commit()

        return {
            "message_id": msg_id,
            "conversation_id": conversation_id,
            "user_id": user_id,
            "role": role,
            "content": content,
            "metadata": metadata or {},
            "created_at": now,
        }

    @classmethod
    def update_conversation_title(
        cls, conversation_id: str, user_id: str, org_id: str, new_title: str
    ) -> bool:
        """Rename an existing conversation."""
        cls.init_db()
        title = new_title.strip() if new_title and new_title.strip() else "Untitled Conversation"
        user_ids = resolve_user_ids(user_id)
        org_ids = resolve_org_ids(org_id)
        u_ph = ",".join("?" for _ in user_ids)
        o_ph = ",".join("?" for _ in org_ids)

        with cls._get_connection() as conn:
            cur = conn.execute(
                f"""
                UPDATE conversations
                SET title = ?, updated_at = ?
                WHERE conversation_id = ? AND user_id IN ({u_ph}) AND org_id IN ({o_ph})
                """,
                (title, time.time(), conversation_id, *user_ids, *org_ids),
            )
            conn.commit()
            return cur.rowcount > 0

    @classmethod
    def delete_conversation(
        cls, conversation_id: str, user_id: str, org_id: str
    ) -> bool:
        """Delete a conversation and its messages."""
        cls.init_db()
        user_ids = resolve_user_ids(user_id)
        org_ids = resolve_org_ids(org_id)
        u_ph = ",".join("?" for _ in user_ids)
        o_ph = ",".join("?" for _ in org_ids)

        with cls._get_connection() as conn:
            # Verify authorization first
            chk = conn.execute(
                f"SELECT 1 FROM conversations WHERE conversation_id = ? AND user_id IN ({u_ph}) AND org_id IN ({o_ph})",
                (conversation_id, *user_ids, *org_ids),
            ).fetchone()
            if not chk:
                return False

            conn.execute(
                "DELETE FROM conversation_messages WHERE conversation_id = ?",
                (conversation_id,),
            )
            cur = conn.execute(
                f"DELETE FROM conversations WHERE conversation_id = ? AND user_id IN ({u_ph}) AND org_id IN ({o_ph})",
                (conversation_id, *user_ids, *org_ids),
            )
            conn.commit()
            return cur.rowcount > 0

    @classmethod
    def auto_title_from_query(cls, query: str) -> str:
        """Generate a concise, descriptive title from the first user query."""
        clean = re.sub(r"^(?:please\s+|can\s+you\s+|give\s+me\s+a\s+|summarize\s+|explain\s+)", "", query, flags=re.I).strip()
        words = clean.split()
        if not words:
            return "Document Exploration"
        title_words = words[:6]
        title = " ".join(title_words).capitalize()
        # Remove trailing punctuation
        title = re.sub(r"[?!.,;:]+$", "", title)
        return title[:50] if len(title) > 50 else title

    @classmethod
    def auto_update_title_if_default(cls, conversation_id: str, query: str) -> Optional[str]:
        """Automatically rename conversation from 'New Conversation' if it's the first message."""
        cls.init_db()
        with cls._get_connection() as conn:
            cur = conn.execute(
                "SELECT title FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
            )
            row = cur.fetchone()
            if row and row["title"] in ("New Conversation", "Untitled Conversation"):
                new_title = cls.auto_title_from_query(query)
                conn.execute(
                    "UPDATE conversations SET title = ? WHERE conversation_id = ?",
                    (new_title, conversation_id),
                )
                conn.commit()
                return new_title
        return None

    @classmethod
    def get_conversation_history(
        cls, conversation_id: str, user_id: str, org_id: str, limit: int = 12
    ) -> List[Dict[str, str]]:
        """Returns standard role/content list suitable for LLM conversation_history."""
        messages = cls.get_messages(conversation_id, user_id, org_id)
        if not messages:
            return []
        recent = messages[-limit:]
        return [{"role": m["role"], "content": m["content"]} for m in recent]

    @classmethod
    def get_persistent_preferences(
        cls, conversation_id: str, user_id: str, org_id: str
    ) -> Dict[str, Any]:
        """
        Inspects message history for persistent instructions (language, style, formatting)
        established in earlier turns, allowing follow-ups to maintain context.
        """
        messages = cls.get_messages(conversation_id, user_id, org_id)
        prefs: Dict[str, Any] = {}
        for msg in messages:
            if msg["role"] == "user":
                q_low = msg["content"].lower()
                # Language preference
                if "in tamil" in q_low or "tamil" in q_low:
                    prefs["language"] = "Tamil"
                elif "in thanglish" in q_low or "thanglish" in q_low:
                    prefs["language"] = "Thanglish"
                elif "in hindi" in q_low:
                    prefs["language"] = "Hindi"
                elif "in english" in q_low:
                    prefs["language"] = "English"

                # Style preference
                if "simple" in q_low or "beginner" in q_low:
                    prefs["style"] = "beginner-friendly"
                elif "technical" in q_low or "deep dive" in q_low:
                    prefs["style"] = "technical"
                elif "analogy" in q_low:
                    prefs["analogy"] = True

                # Format preference
                if "table" in q_low:
                    prefs["format"] = "Markdown Table"
                elif "bullet" in q_low:
                    prefs["format"] = "Bullet Points"
                elif "numbered" in q_low or "step-by-step" in q_low:
                    prefs["format"] = "Numbered List"

            elif msg["role"] == "assistant" and msg.get("metadata"):
                meta = msg["metadata"]
                if meta.get("target_doc_id"):
                    prefs["last_doc_id"] = meta.get("target_doc_id")
                if meta.get("target_doc_name"):
                    prefs["last_doc_name"] = meta.get("target_doc_name")

        return prefs

