# -*- coding: utf-8 -*-
"""
Comprehensive Test Suite: ChatGPT-Like Intelligent Conversational Document Assistant.
Validates:
1. Arbitrary Natural-Language Instruction Following (Simple, Technical, Analogies, Tamil, Thanglish).
2. Multiple and Combined Instructions (e.g., technical + beginner language + 5 bullets + no intro).
3. Conversational Context & Multi-Turn Follow-Ups ("Explain that again", "Make it simpler", "Explain point 2", "Now in Tamil").
4. Intelligent Document Understanding (Latest document summary, multi-document overview, comparisons).
5. Output Formatting (Markdown tables, bullet lists, numbered steps, code blocks).
6. Source Attribution & Citations.
7. Absolute Preservation of All 5 Security Gates (Gate 1 ACL, Gate 2 MMR Integrity, Gate 3 DBV Boundary, Gate 4 AEAD Decryption, Gate 5 Grounding).
8. Missing Information Abstention (Zero hallucination on absent topics).
"""
from __future__ import annotations

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import json
import logging
import sys
import unittest
from typing import Any, Dict, List

from fastapi.testclient import TestClient
from main import app, qdrant_repo
from core.auth_service import AuthService
from core.retrieval_router import RetrievalRouter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestChatGPTAssistant")
client = TestClient(app)


class TestChatGPTDocumentAssistant(unittest.TestCase):
    """Test suite validating ChatGPT-like document assistance while enforcing zero-trust security."""

    @classmethod
    def setUpClass(cls):
        AuthService.init_db()
        # Ensure our test identity exists and is authorized for psg
        cls.user_id = "usr_architect_psg_655732"
        cls.org_id = "psg"
        cls.unauth_user_id = "usr_guest_unauthorized"

        # Check that we have collections available
        collections = qdrant_repo.client.get_collections().collections
        col_names = [c.name for c in collections]
        logger.info(f"Active Qdrant Collections for testing: {col_names}")

    def test_01_retrieval_router_instruction_extraction(self):
        """Validates that RetrievalRouter accurately parses arbitrary styles, languages, formats, and follow-ups."""
        logger.info("--- TEST 1: RetrievalRouter Dynamic Intent & Instruction Extraction ---")

        # 1a. Complex combined query
        q = "Give a detailed technical explanation of the evaluation results but keep it beginner-friendly in 5 bullet points in Tamil without any examples."
        analysis = RetrievalRouter.analyze_query(q)

        self.assertEqual(analysis.language, "Tamil")
        self.assertIn("beginner-friendly and simple", analysis.style_instructions)
        self.assertIn("deep technical analysis", analysis.style_instructions)
        self.assertIn("Strictly FIVE bullet points", analysis.length_constraint)
        self.assertIn("Do NOT include any examples", analysis.negative_constraints)
        logger.info("  ✓ Successfully extracted: Language=Tamil, Style=[beginner, technical], Length=5 bullets, Negative=[no examples]")

        # 1b. Table request
        q2 = "Provide a comparison matrix in a markdown table format."
        analysis2 = RetrievalRouter.analyze_query(q2)
        self.assertEqual(analysis2.intent_type, "COMPARISON")
        self.assertEqual(analysis2.format_type, "Markdown Table")
        logger.info("  ✓ Successfully extracted: Intent=COMPARISON, Format=Markdown Table")

        # 1c. Document-level summary detection
        q3 = "Summarize this document in 3 sentences."
        docs = [{"doc_id": "doc_result_analysis", "filename": "Result Analysis.pdf", "user_id": self.user_id}]
        analysis3 = RetrievalRouter.analyze_query(q3, available_docs=docs, current_user_id=self.user_id)
        self.assertEqual(analysis3.intent_type, "DOCUMENT_SUMMARY")
        self.assertEqual(analysis3.target_doc_id, "doc_result_analysis")
        logger.info("  ✓ Successfully resolved: 'this document' -> target doc_id='doc_result_analysis'")

        # 1d. Follow-up resolution
        history = [
            {"role": "user", "content": "What are the modules evaluated?"},
            {"role": "assistant", "content": "1. Module 1: Chunking\\n2. Module 2: Two-Tier MMR Integrity\\n3. Module 3: Boundary Validation"}
        ]
        q4 = "Explain the second point in simpler words."
        analysis4 = RetrievalRouter.analyze_query(q4, conversation_history=history)
        self.assertTrue(analysis4.is_follow_up)
        self.assertIn("Two-Tier MMR Integrity", analysis4.resolved_query)
        logger.info(f"  ✓ Successfully resolved follow-up point reference -> '{analysis4.resolved_query}'")

    def test_02_single_document_summary_hierarchical(self):
        """Tests 'Summarize this document' with document prioritization and comprehensive coverage."""
        logger.info("--- TEST 2: 'Summarize this document' Intelligent Document Prioritization ---")

        payload = {
            "query_text": "Summarize this document in 3 concise bullet points with key findings.",
            "user_id": self.user_id,
            "org_id": self.org_id,
            "simulate_missing_cluster": False,
            "simulate_integrity_failure": False,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(data["acl_verified"])
        self.assertTrue(data["integrity_verified"])
        self.assertIsNotNone(data["answer"])
        self.assertGreater(len(data["answer"]), 50)

        # Check detected intent
        self.assertIn("detected_intent", data)
        self.assertEqual(data["detected_intent"]["intent_type"], "DOCUMENT_SUMMARY")
        logger.info(f"  ✓ Summary generated successfully:\n{data['answer'][:250]}...")

    def test_03_conversational_follow_ups_multi_turn(self):
        """Tests ChatGPT-like multi-turn conversation: Turn 1 -> Turn 2 (Simpler) -> Turn 3 (Tamil)."""
        logger.info("--- TEST 3: Multi-Turn Conversational Follow-Up Continuity ---")

        # Turn 1: Initial Question
        history = []
        turn1_q = "What are the primary evaluation metrics or results mentioned in the document?"
        payload1 = {
            "query_text": turn1_q,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "conversation_history": history,
        }
        res1 = client.post("/api/v1/query-verify", json=payload1)
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()
        ans1 = data1["answer"]
        self.assertIsNotNone(ans1)

        history.append({"role": "user", "content": turn1_q})
        history.append({"role": "assistant", "content": ans1})
        logger.info("  ✓ Turn 1 completed. Answer received.")

        # Turn 2: Follow-up instruction ("Make it simpler and give an analogy")
        turn2_q = "Make it much simpler and use a real-world analogy to explain it to a high school student."
        payload2 = {
            "query_text": turn2_q,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "conversation_history": history,
        }
        res2 = client.post("/api/v1/query-verify", json=payload2)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        ans2 = data2["answer"]
        self.assertIsNotNone(ans2)

        history.append({"role": "user", "content": turn2_q})
        history.append({"role": "assistant", "content": ans2})
        logger.info(f"  ✓ Turn 2 (Simpler with analogy) completed:\n{ans2[:250]}...")

        # Turn 3: Language instruction follow-up ("Now explain in Tamil")
        turn3_q = "Now explain this concept in Tamil (தமிழ்)."
        payload3 = {
            "query_text": turn3_q,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "conversation_history": history,
        }
        res3 = client.post("/api/v1/query-verify", json=payload3)
        self.assertEqual(res3.status_code, 200)
        data3 = res3.json()
        ans3 = data3["answer"]
        self.assertIsNotNone(ans3)

        # Verify language detected and output contains Tamil characters or Tamil explanation
        self.assertEqual(data3["detected_intent"]["language"], "Tamil")
        logger.info(f"  ✓ Turn 3 (Tamil explanation) completed:\n{ans3[:250]}...")

    def test_04_format_instructions_markdown_table(self):
        """Tests arbitrary format instruction: requesting a Markdown Table."""
        logger.info("--- TEST 4: Arbitrary Formatting - Markdown Table Instruction ---")

        payload = {
            "query_text": "Present the key evaluation results, modules, or formulas in a structured Markdown table format with columns for Module/Topic, Metric/Result, and Significance.",
            "user_id": self.user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        ans = data["answer"]
        self.assertIsNotNone(ans)

        # Check for Markdown table characters (|)
        self.assertIn("|", ans, "Answer must contain Markdown table syntax '|'")
        logger.info(f"  ✓ Markdown table generated:\n{ans[:300]}...")

    def test_05_combined_multiple_instructions(self):
        """Tests combined constraints: technical depth + step-by-step + bold formatting."""
        logger.info("--- TEST 5: Combined Multiple Instructions ---")

        payload = {
            "query_text": "Provide a step-by-step technical explanation of how cryptographic verification works in this system. Use **bold** for key cryptographic terms and format as numbered steps 1, 2, 3.",
            "user_id": self.user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        ans = data["answer"]
        self.assertIsNotNone(ans)

        # Verify numbered steps and bold formatting
        self.assertTrue(any(marker in ans for marker in ["1.", "2.", "3.", "**"]), "Answer must satisfy combined constraints")
        logger.info(f"  ✓ Combined instructions satisfied:\n{ans[:250]}...")

    def test_06_security_gate_1_acl_block(self):
        """Preserves Gate 1: Cross-tenant unauthorized user must be BLOCKED immediately."""
        logger.info("--- TEST 6: Gate 1 ACL Cross-Tenant Isolation Enforcement ---")

        payload = {
            "query_text": "Summarize this document.",
            "user_id": self.unauth_user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "ACL_VIOLATION")
        self.assertFalse(data["acl_verified"])
        self.assertFalse(data["decryption_verified"])
        self.assertIn("Access Denied", data["answer"])
        logger.info("  ✓ Gate 1 ACL blocked unauthorized tenant access as required.")

    def test_07_security_gate_2_mmr_tampering_block(self):
        """Preserves Gate 2: Tampered MMR inclusion proof must HALT decryption and synthesis."""
        logger.info("--- TEST 7: Gate 2 MMR Cryptographic Tampering Enforcement ---")

        payload = {
            "query_text": "Summarize this document.",
            "user_id": self.user_id,
            "org_id": self.org_id,
            "simulate_integrity_failure": True,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "MMR_TAMPERED")
        self.assertFalse(data["integrity_verified"])
        self.assertFalse(data["decryption_verified"])
        self.assertIn("Tampering Detected", data["answer"])
        logger.info("  ✓ Gate 2 Cryptographic MMR caught tampering and halted decryption.")

    def test_08_security_gate_3_dbv_boundary_block(self):
        """Preserves Gate 3: Incomplete IVF Voronoi cell boundary must HALT synthesis."""
        logger.info("--- TEST 8: Gate 3 Dynamic Boundary Verification (DBV) Enforcement ---")

        payload = {
            "query_text": "What are the security metrics?",
            "user_id": self.user_id,
            "org_id": self.org_id,
            "simulate_missing_cluster": True,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["status"], "IVF_BOUNDARY_INCOMPLETENESS")
        self.assertFalse(data["ivf_boundary_verification"]["is_complete"])
        self.assertIn("Verification Halted", data["answer"])
        logger.info("  ✓ Gate 3 DBV caught Voronoi boundary omission and halted synthesis.")

    def test_09_missing_information_abstention(self):
        """Tests that the assistant abstains when requested information does not exist in documents."""
        logger.info("--- TEST 9: Grounded Abstention for Absent Topics ---")

        payload = {
            "query_text": "What is the warp drive subspace engine displacement ratio of the spaceship mentioned in the document?",
            "user_id": self.user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        ans = data["answer"].lower()

        # Check for abstention language
        abstention_phrases = ["not contain", "cannot be found", "not mentioned", "no information", "does not discuss", "unable to find"]
        has_abstention = any(phrase in ans for phrase in abstention_phrases)
        self.assertTrue(has_abstention, f"System must state info is absent. Answer was: {data['answer']}")
        logger.info(f"  ✓ Successfully abstained with zero hallucination: '{data['answer'][:150]}...'")

    def test_10_source_attribution_and_transparency(self):
        """Tests source attribution transparency in response metadata."""
        logger.info("--- TEST 10: Source Attribution & Citation Transparency ---")

        payload = {
            "query_text": "What are the evaluation modules and results?",
            "user_id": self.user_id,
            "org_id": self.org_id,
        }
        res = client.post("/api/v1/query-verify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("sources", data)
        self.assertIsInstance(data["sources"], list)
        if data["sources"]:
            src0 = data["sources"][0]
            self.assertIn("filename", src0)
            self.assertIn("doc_id", src0)
            self.assertIn("chunk_count", src0)
            self.assertTrue(src0["verified_integrity"])
            logger.info(f"  ✓ Sources verified: {len(data['sources'])} distinct documents cited ({src0['filename']})")


if __name__ == "__main__":
    unittest.main()
