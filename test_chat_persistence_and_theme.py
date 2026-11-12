"""
Integration Test for:
1. Persistent Chat History Auto-Creation & Message Storage in SQLite
2. User/Org Resolution (username, user_id, email, canonical org)
3. Multi-Turn Conversation Continuity
4. Tenant Isolation Enforcement
5. Rename, Search, and Delete Operations
6. Theme Persistence and CSS Variables (Light & Dark)
"""
import unittest
import json
import os
import sqlite3
from fastapi.testclient import TestClient

from main import app
from core.conversation_service import ConversationService, resolve_user_ids, resolve_org_ids
from core.auth_service import AuthService, canonicalize_org


class TestChatPersistenceAndTheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        ConversationService.init_db()
        AuthService.init_db()

    def test_01_user_and_org_resolution(self):
        """Test username vs user_id vs email resolution."""
        # For architect_psg:
        u_ids = resolve_user_ids("architect_psg")
        self.assertIn("architect_psg", u_ids)
        self.assertIn("usr_architect_psg_655732", u_ids)

        # For org:
        o_ids = resolve_org_ids("psg")
        self.assertIn("psg", o_ids)
        self.assertIn("org_psg", o_ids)

    def test_02_auto_creation_and_persistence_on_first_query(self):
        """When query is sent without conversation_id, auto-creates persistent session in SQLite."""
        payload = {
            "query_text": "What are the primary cryptographic features in this document?",
            "user_id": "architect_psg",
            "org_id": "psg",
            "conversation_id": None,
            "simulate_missing_cluster": False,
            "simulate_integrity_failure": False,
            "conversation_history": []
        }
        res = self.client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200, f"Error: {res.text}")
        data = res.json()
        conv_id = data.get("conversation_id")
        self.assertIsNotNone(conv_id, "conversation_id must not be None")
        self.assertTrue(conv_id.startswith("conv_"), f"Invalid conv_id: {conv_id}")

        # Verify messages saved in SQLite
        messages = ConversationService.get_messages(conv_id, "architect_psg", "psg")
        self.assertGreaterEqual(len(messages), 2, "Expected at least user query and assistant answer")
        self.assertEqual(messages[0]["role"], "user")
        self.assertIn("primary cryptographic features", messages[0]["content"])
        self.assertEqual(messages[1]["role"], "assistant")
        self.assertTrue(len(messages[1]["content"]) > 0)

    def test_03_query_conversations_with_username_and_userid(self):
        """Verify list_conversations returns matching rows whether queried by username or user_id."""
        # List by username
        res_user = self.client.get("/api/v1/conversations?user_id=architect_psg&org_id=psg")
        self.assertEqual(res_user.status_code, 200)
        convs_by_username = res_user.json()["conversations"]

        # List by full user_id
        res_uid = self.client.get("/api/v1/conversations?user_id=usr_architect_psg_655732&org_id=psg")
        self.assertEqual(res_uid.status_code, 200)
        convs_by_uid = res_uid.json()["conversations"]

        self.assertGreater(len(convs_by_username), 0, "Expected conversations for architect_psg")
        self.assertEqual(len(convs_by_username), len(convs_by_uid), "Username and user_id should retrieve identical list")

    def test_04_multi_turn_continuity(self):
        """Test continuing an existing conversation turn by turn."""
        # Turn 1
        p1 = {
            "query_text": "Can you explain the MMR verification in simple bullet points?",
            "user_id": "architect_psg",
            "org_id": "psg",
            "conversation_id": None
        }
        r1 = self.client.post("/api/v1/query-verify", json=p1)
        self.assertEqual(r1.status_code, 200)
        conv_id = r1.json()["conversation_id"]

        # Turn 2: Follow-up using conv_id
        p2 = {
            "query_text": "How does it protect against injection attacks?",
            "user_id": "architect_psg",
            "org_id": "psg",
            "conversation_id": conv_id
        }
        r2 = self.client.post("/api/v1/query-verify", json=p2)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["conversation_id"], conv_id)

        # Verify message count in SQLite is now at least 4
        messages = ConversationService.get_messages(conv_id, "architect_psg", "psg")
        self.assertGreaterEqual(len(messages), 4)
        roles = [m["role"] for m in messages]
        self.assertEqual(roles[:4], ["user", "assistant", "user", "assistant"])

    def test_05_tenant_isolation(self):
        """Cross-tenant access to conversations must be strictly blocked."""
        # Create conversation in psg
        conv = ConversationService.create_conversation("usr_sam_student_d7ddc1", "default_org", title="Default Org Chat")
        cid = conv["conversation_id"]

        # Try to access from another org
        r = self.client.get(f"/api/v1/conversations/{cid}?user_id=architect_psg&org_id=psg")
        self.assertEqual(r.status_code, 404, "Cross-tenant access should return 404")

        # Try to delete from another user/org
        del_r = self.client.delete(f"/api/v1/conversations/{cid}?user_id=architect_psg&org_id=psg")
        self.assertEqual(del_r.status_code, 404, "Cross-tenant delete should return 404")

    def test_06_rename_and_delete(self):
        """Test rename and delete endpoints."""
        conv = ConversationService.create_conversation("architect_psg", "psg", title="Original Title")
        cid = conv["conversation_id"]

        # Rename
        r_ren = self.client.put(f"/api/v1/conversations/{cid}", json={
            "user_id": "architect_psg",
            "org_id": "psg",
            "title": "Renamed Title"
        })
        self.assertEqual(r_ren.status_code, 200)
        updated = ConversationService.get_conversation(cid, "architect_psg", "psg")
        self.assertEqual(updated["title"], "Renamed Title")

        # Delete
        r_del = self.client.delete(f"/api/v1/conversations/{cid}?user_id=architect_psg&org_id=psg")
        self.assertEqual(r_del.status_code, 200)
        deleted = ConversationService.get_conversation(cid, "architect_psg", "psg")
        self.assertIsNone(deleted)

    def test_07_theme_and_frontend_integrity(self):
        """Verify theme variables, dark & light rules, and persistence elements in static files."""
        # 1. Check styles.css has both dark variables and light theme definitions
        with open("static/styles.css", "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn(':root', css)
        self.assertIn('--bg-page: #0b0f17;', css, "Refined dark mode background expected")
        self.assertIn('[data-theme="light"]', css, "Light mode overrides expected")
        self.assertIn('--bg-page: #ffffff;', css, "Light mode white background expected")
        self.assertIn('[data-theme="light"] .chat-sidebar', css, "Light mode sidebar styles expected")
        self.assertIn('[data-theme="light"] .chat-workspace', css, "Light mode workspace styles expected")
        self.assertIn('[data-theme="light"] .security-verification-dialog', css, "Light mode security dialog styles expected")

        # 2. Check index.html has early inline theme restoration script in head
        with open("static/index.html", "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("rag_verifier_theme", html, "rag_verifier_theme persistence in index.html head")
        self.assertIn("btn-theme-toggle", html, "Theme toggle button in header")
        self.assertIn("btn-open-security-modal", html, "Security verification modal button in header")

        # 3. Check login.html saves user_id into rag_session
        with open("static/login.html", "r", encoding="utf-8") as f:
            login_html = f.read()
        self.assertIn("user_id: data.user_id", login_html, "login.html must persist user_id")


if __name__ == "__main__":
    unittest.main()

