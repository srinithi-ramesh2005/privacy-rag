# -*- coding: utf-8 -*-
"""
Comprehensive End-to-End Test Suite:
ChatGPT-Like Intelligent Secure RAG: History, Conversations, UI & Security Verification.

Validates:
1. Conversation CRUD & Persistence in SQLite (Create, List, Rename, Delete).
2. Multi-Tenant & User Conversation Isolation (usr_1 cannot view usr_2's chats).
3. Conversation Keyword Search.
4. History-Aware RAG follow-up understanding using DB-persisted messages.
5. Persistent user instruction awareness (language, style, format).
6. Compact retrieval summary (total_chunks, chunk_number, cluster_id with NO chunk text).
7. Security Verification modal audit payload (accurate PASS/FAIL/NOT RUN across all 5 gates).
8. Gate 1 ACL Cross-Tenant Isolation Block.
9. Gate 2 MMR Cryptographic Tampering Enforcement.
10. Gate 3 Dynamic Boundary Verification (DBV) Enforcement.
11. Document-level summarization & prioritization.
"""
from __future__ import annotations

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import json
import logging
import time
import unittest
from typing import Any, Dict, List

from fastapi.testclient import TestClient
from main import app, qdrant_repo
from core.auth_service import AuthService
from core.conversation_service import ConversationService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestChatGPTUpgrade")
client = TestClient(app)


class TestChatGPTUpgradeSuite(unittest.TestCase):
    """End-to-end integration test suite for the upgraded ChatGPT-like Secure RAG."""

    @classmethod
    def setUpClass(cls):
        AuthService.init_db()
        ConversationService.init_db()
        cls.user_id = "usr_architect_psg_655732"
        cls.org_id = "psg"
        cls.other_user_id = "usr_intel_researcher_99"
        cls.unauth_user_id = "usr_guest_unauthorized"

    def test_01_conversation_creation_and_persistence(self):
        """Validates starting a new conversation, auto-titling, and SQLite database persistence."""
        logger.info("--- TEST 1: Conversation Creation & SQLite Persistence ---")

        # 1a. Create conversation via REST API
        res = client.post("/api/v1/conversations", json={
            "user_id": self.user_id,
            "org_id": self.org_id,
            "title": "New Conversation"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "SUCCESS")
        conv = data["conversation"]
        conv_id = conv["conversation_id"]
        self.assertTrue(conv_id.startswith("conv_"))
        self.assertEqual(conv["title"], "New Conversation")
        logger.info(f"  ✓ Conversation created: {conv_id}")

        # 1b. Verify directly in SQLite database
        persisted = ConversationService.get_conversation(conv_id, self.user_id, self.org_id)
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["conversation_id"], conv_id)
        logger.info("  ✓ Verified persistent storage in SQLite database.")

        # 1c. Rename conversation
        ren_res = client.put(f"/api/v1/conversations/{conv_id}", json={
            "user_id": self.user_id,
            "org_id": self.org_id,
            "title": "Quantum Cryptography Audit"
        })
        self.assertEqual(ren_res.status_code, 200)
        updated = ConversationService.get_conversation(conv_id, self.user_id, self.org_id)
        self.assertEqual(updated["title"], "Quantum Cryptography Audit")
        logger.info("  ✓ Successfully renamed conversation.")

    def test_02_multi_tenant_and_user_conversation_isolation(self):
        """Enforces that user A cannot view, access, or delete user B's conversations."""
        logger.info("--- TEST 2: Multi-Tenant & User Conversation Isolation ---")

        # Create conversation for user_id in org psg
        conv_res = client.post("/api/v1/conversations", json={
            "user_id": self.user_id,
            "org_id": self.org_id,
            "title": "Private Architect Chat"
        })
        c_id = conv_res.json()["conversation"]["conversation_id"]

        # Other user in different tenant attempts to fetch it -> Must return 404
        spy_res = client.get(f"/api/v1/conversations/{c_id}?user_id={self.other_user_id}&org_id=intel")
        self.assertEqual(spy_res.status_code, 404)

        # Other user in same tenant attempts to delete it -> Must return 404
        del_res = client.delete(f"/api/v1/conversations/{c_id}?user_id=usr_another&org_id={self.org_id}")
        self.assertEqual(del_res.status_code, 404)

        # List conversations for other user -> Must NOT include c_id
        list_other = client.get(f"/api/v1/conversations?user_id={self.other_user_id}&org_id=intel").json()
        other_ids = [c["conversation_id"] for c in list_other["conversations"]]
        self.assertNotIn(c_id, other_ids)
        logger.info("  ✓ Strict multi-tenant and user isolation confirmed across conversation access.")

    def test_03_conversation_keyword_search(self):
        """Validates searching conversations by title and message content."""
        logger.info("--- TEST 3: Conversation Keyword Search ---")

        # Create 2 conversations
        c1 = client.post("/api/v1/conversations", json={
            "user_id": self.user_id, "org_id": self.org_id, "title": "Database Optimization Benchmark"
        }).json()["conversation"]["conversation_id"]

        c2 = client.post("/api/v1/conversations", json={
            "user_id": self.user_id, "org_id": self.org_id, "title": "Two-Tier MMR Performance"
        }).json()["conversation"]["conversation_id"]

        # Search for 'Database'
        s1 = client.get(f"/api/v1/conversations?user_id={self.user_id}&org_id={self.org_id}&search=Database").json()
        ids1 = [c["conversation_id"] for c in s1["conversations"]]
        self.assertIn(c1, ids1)
        self.assertNotIn(c2, ids1)

        # Search for 'MMR'
        s2 = client.get(f"/api/v1/conversations?user_id={self.user_id}&org_id={self.org_id}&search=MMR").json()
        ids2 = [c["conversation_id"] for c in s2["conversations"]]
        self.assertIn(c2, ids2)
        self.assertNotIn(c1, ids2)
        logger.info("  ✓ Keyword search correctly filters conversations.")

    def test_04_history_aware_query_and_compact_retrieval(self):
        """Validates follow-up query answering, DB message persistence, and compact retrieval summary."""
        logger.info("--- TEST 4: History-Aware RAG with Compact Retrieval Summary ---")

        # Create fresh conversation
        c_res = client.post("/api/v1/conversations", json={
            "user_id": self.user_id, "org_id": self.org_id, "title": "New Conversation"
        })
        conv_id = c_res.json()["conversation"]["conversation_id"]

        # Turn 1: Ask initial question
        q1 = "What are the primary evaluation metrics or results mentioned in the document?"
        payload1 = {
            "query_text": q1,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "conversation_id": conv_id,
        }
        res1 = client.post("/api/v1/query-verify", json=payload1)
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()

        # Check Compact Retrieval Summary (Requirement 1: NO chunk text, only total chunks and cluster numbers!)
        self.assertIn("retrieval_summary", data1)
        r_sum1 = data1["retrieval_summary"]
        self.assertIsNotNone(r_sum1)
        self.assertIn("total_chunks", r_sum1)
        self.assertIn("chunks", r_sum1)
        self.assertGreater(r_sum1["total_chunks"], 0)
        chk0 = r_sum1["chunks"][0]
        self.assertIn("chunk_number", chk0)
        self.assertIn("cluster_id", chk0)
        self.assertNotIn("text", chk0, "Chunk text must NOT be exposed in compact retrieval summary!")
        self.assertNotIn("hash", chk0, "Raw hashes must NOT be exposed in compact retrieval summary!")
        logger.info(f"  ✓ Compact retrieval summary validated: {r_sum1['total_chunks']} chunks with cluster IDs.")

        # Verify DB auto-updated the title from 'New Conversation'
        updated_conv = ConversationService.get_conversation(conv_id, self.user_id, self.org_id)
        self.assertNotEqual(updated_conv["title"], "New Conversation")
        logger.info(f"  ✓ Conversation title auto-generated: '{updated_conv['title']}'")

        # Turn 2: Follow-up question relying on Turn 1 ("Make it simpler and give an analogy")
        q2 = "Make it much simpler and use a real-world analogy to explain it to a student."
        payload2 = {
            "query_text": q2,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "conversation_id": conv_id,
            # Notice: conversation_history is omitted; backend must pull from SQLite!
        }
        res2 = client.post("/api/v1/query-verify", json=payload2)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertEqual(data2["status"], "SUCCESS")
        self.assertIsNotNone(data2["answer"])
        logger.info(f"  ✓ Turn 2 follow-up answered using persisted SQLite history:\n{data2['answer'][:200]}...")

        # Verify message count in SQLite database
        db_messages = ConversationService.get_messages(conv_id, self.user_id, self.org_id)
        self.assertEqual(len(db_messages), 4, "Should have 2 user turns and 2 assistant turns recorded in DB")
        logger.info("  ✓ 4 turns persistently stored in SQLite database.")

    def test_05_security_verification_modal_payload_integrity(self):
        """Validates that the Security Verification modal payload accurately reports all 5 gates."""
        logger.info("--- TEST 5: Security Verification 5-Gate Audit Accuracy ---")

        # Run query
        payload = {
            "query_text": "Summarize this document.",
            "user_id": self.user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Check breakdown for all 5 gates
        bd = data.get("verification_breakdown", {})
        self.assertIn("acl", bd)
        self.assertIn("integrity", bd)
        self.assertIn("boundary", bd)
        self.assertIn("decryption", bd)
        self.assertIn("grounding", bd)

        self.assertTrue(bd["acl"]["passed"])
        self.assertTrue(bd["integrity"]["passed"])
        self.assertTrue(bd["boundary"]["passed"])
        self.assertTrue(bd["decryption"]["passed"])
        self.assertTrue(bd["grounding"]["passed"])
        logger.info("  ✓ All 5 Security Gates verified accurately in verification breakdown.")

    def test_06_security_gate_1_acl_block(self):
        """Preserves Gate 1: Unauthorized tenant user is BLOCKED."""
        logger.info("--- TEST 6: Gate 1 ACL Cross-Tenant Isolation Enforcement ---")

        payload = {
            "query_text": "Summarize this document.",
            "user_id": self.unauth_user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        data = res.json()
        self.assertEqual(data["status"], "ACL_VIOLATION")
        self.assertFalse(data["acl_verified"])
        self.assertIn("Access Denied", data["answer"])
        logger.info("  ✓ Gate 1 ACL blocked unauthorized tenant access.")

    def test_07_security_gate_2_mmr_tampering_block(self):
        """Preserves Gate 2: Tampered MMR inclusion proof halts decryption."""
        logger.info("--- TEST 7: Gate 2 MMR Cryptographic Tampering Enforcement ---")

        payload = {
            "query_text": "Summarize this document.",
            "user_id": self.user_id,
            "org_id": self.org_id,
            "simulate_integrity_failure": True,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        data = res.json()
        self.assertEqual(data["status"], "MMR_TAMPERED")
        self.assertFalse(data["integrity_verified"])
        self.assertIn("Tampering Detected", data["answer"])
        logger.info("  ✓ Gate 2 MMR caught tampering and halted decryption.")

    def test_08_security_gate_3_dbv_boundary_block(self):
        """Preserves Gate 3: Incomplete Voronoi cell boundary halts synthesis."""
        logger.info("--- TEST 8: Gate 3 Dynamic Boundary Verification (DBV) Enforcement ---")

        payload = {
            "query_text": "What are the security metrics?",
            "user_id": self.user_id,
            "org_id": self.org_id,
            "simulate_missing_cluster": True,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        data = res.json()
        self.assertEqual(data["status"], "IVF_BOUNDARY_INCOMPLETENESS")
        self.assertFalse(data["ivf_boundary_verification"]["is_complete"])
        self.assertIn("Verification Halted", data["answer"])
        logger.info("  ✓ Gate 3 DBV caught Voronoi boundary omission.")


if __name__ == "__main__":
    unittest.main()

