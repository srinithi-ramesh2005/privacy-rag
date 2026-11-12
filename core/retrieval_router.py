"""
Intelligent Retrieval Router and Query Intent Understanding Engine.
Transforms Secure RAG into an autonomous conversational document assistant.

Features:
1. Dynamic Intent Classification:
   - DOCUMENT_SUMMARY: User asks to summarize "this document", "the document", or a named document.
   - MULTI_DOC_SUMMARY: User asks to summarize or overview "all documents" in the organization.
   - COMPARISON: User asks to compare two or more documents or concepts.
   - PAGE_SECTION_QUERY: User asks about a specific page (e.g., "what does page 5 say?") or section.
   - FOLLOW_UP: Conversational follow-ups (e.g., "explain that again", "make it simpler", "explain the second point").
   - FOCUSED_QA: Specific natural language question about topics in the documents.
2. Context-Aware Query Resolution:
   - Resolves ambiguous follow-up pronouns and references using multi-turn conversation history.
3. Target Document Resolution:
   - Resolves "this document" -> prioritizes the most recently uploaded document by the user in the org.
   - Matches named documents (e.g., "formulas for results", "result analysis").
4. Instruction & Constraint Extraction:
   - Extracts requested styles (simple, beginner, technical, academic, analogy, step-by-step),
     languages (Tamil, Thanglish, Hindi, etc.), formats (table, bullet points, numbered steps, code),
     lengths (one word, one line, short, detailed), and negative constraints (no intro, no examples).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("RetrievalRouter")


class QueryIntentAnalysis:
    """Holds structured intent analysis and resolved query parameters."""

    def __init__(
        self,
        raw_query: str,
        resolved_query: str,
        intent_type: str,
        target_doc_id: Optional[str] = None,
        target_doc_name: Optional[str] = None,
        target_page: Optional[int] = None,
        compare_docs: Optional[List[str]] = None,
        is_summary: bool = False,
        is_all_docs: bool = False,
        is_follow_up: bool = False,
        style_instructions: Optional[List[str]] = None,
        language: Optional[str] = None,
        format_type: Optional[str] = None,
        length_constraint: Optional[str] = None,
        negative_constraints: Optional[List[str]] = None,
    ):
        self.raw_query = raw_query
        self.resolved_query = resolved_query
        self.intent_type = intent_type
        self.target_doc_id = target_doc_id
        self.target_doc_name = target_doc_name
        self.target_page = target_page
        self.compare_docs = compare_docs or []
        self.is_summary = is_summary
        self.is_all_docs = is_all_docs
        self.is_follow_up = is_follow_up
        self.style_instructions = style_instructions or []
        self.language = language or "English"
        self.format_type = format_type
        self.length_constraint = length_constraint
        self.negative_constraints = negative_constraints or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_query": self.raw_query,
            "resolved_query": self.resolved_query,
            "intent_type": self.intent_type,
            "target_doc_id": self.target_doc_id,
            "target_doc_name": self.target_doc_name,
            "target_page": self.target_page,
            "compare_docs": self.compare_docs,
            "is_summary": self.is_summary,
            "is_all_docs": self.is_all_docs,
            "is_follow_up": self.is_follow_up,
            "style_instructions": self.style_instructions,
            "language": self.language,
            "format_type": self.format_type,
            "length_constraint": self.length_constraint,
            "negative_constraints": self.negative_constraints,
        }


class RetrievalRouter:
    """Intelligent router that selects retrieval strategies and prepares context based on query intent."""

    @classmethod
    def analyze_query(
        cls,
        query: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        available_docs: Optional[List[Dict[str, Any]]] = None,
        current_user_id: Optional[str] = None,
    ) -> QueryIntentAnalysis:
        q_raw = query.strip()
        q_lower = q_raw.lower()
        history = conversation_history or []
        docs = available_docs or []

        # 1. Detect Language Request
        language = "English"
        if re.search(r"\b(in\s+tamil|tamil\s+la|tamizh|தமிழ்)\b", q_lower):
            language = "Tamil"
        elif re.search(r"\b(in\s+thanglish|tanglish|tamil-english|tamil\s+in\s+english\s+letters)\b", q_lower):
            language = "Thanglish (Tamil written in English script)"
        elif re.search(r"\b(in\s+hindi|hindi\s+mein|हिंदी)\b", q_lower):
            language = "Hindi"
        elif re.search(r"\b(in\s+french|en\s+français)\b", q_lower):
            language = "French"
        elif re.search(r"\b(in\s+spanish|en\s+español)\b", q_lower):
            language = "Spanish"
        elif re.search(r"\b(in\s+german|auf\s+deutsch)\b", q_lower):
            language = "German"

        # 2. Extract Style and Teaching Instructions
        style_instructions = []
        if re.search(r"\b(beginner[- ]friendly|simple|simple\s+words?|easy\s+to\s+understand|like\s+i'?m\s+5|eli5|for\s+kids?)\b", q_lower):
            style_instructions.append("beginner-friendly and simple")
        if re.search(r"\b(technical|in[- ]depth|deep\s+dive|expert|architectural)\b", q_lower):
            style_instructions.append("deep technical analysis")
        if re.search(r"\b(step[- ]by[- ]step|systematic|walkthrough)\b", q_lower):
            style_instructions.append("step-by-step breakdown")
        if re.search(r"\b(analog(?:y|ies)|metaphor|real[- ]world\s+example|practical\s+scenario)\b", q_lower):
            style_instructions.append("use real-world analogies and examples")
        if re.search(r"\b(from\s+scratch|basics?|fundamentals?)\b", q_lower):
            style_instructions.append("explain fundamentals from scratch")
        if re.search(r"\b(interview\s+prep|interview\s+questions?|candidate)\b", q_lower):
            style_instructions.append("tailor for interview preparation")
        if re.search(r"\b(academic|formal|scholarly|research)\b", q_lower):
            style_instructions.append("academic and rigorous tone")
        if re.search(r"\b(conversational|friendly|casual)\b", q_lower):
            style_instructions.append("conversational and engaging tone")

        # 3. Extract Format Preferences
        format_type = None
        if re.search(r"\b(in\s+a\s+table|table\s+format|tabular|matrix)\b", q_lower):
            format_type = "Markdown Table"
        elif re.search(r"\b(bullet\s+points?|bulleted|bullets?)\b", q_lower):
            format_type = "Bullet Points"
        elif re.search(r"\b(numbered\s+(?:steps?|points?|list)|step[- ]by[- ]step)\b", q_lower):
            format_type = "Numbered List"
        elif re.search(r"\b(checklist)\b", q_lower):
            format_type = "Checklist"
        elif re.search(r"\b(faq|frequently\s+asked\s+questions?)\b", q_lower):
            format_type = "FAQ"
        elif re.search(r"\b(code\s+blocks?|code\s+snippet|pseudocode)\b", q_lower):
            format_type = "Code Blocks"

        # 4. Extract Length Constraints
        length_constraint = None
        if re.search(r"\b(one|1)\s*word\b", q_lower):
            length_constraint = "Strictly exactly ONE WORD"
        elif re.search(r"\b(one|1)\s*(?:line|sentence)\b", q_lower):
            length_constraint = "Strictly exactly ONE SENTENCE on a single line"
        elif re.search(r"\b(2|two)\s*(?:lines?|sentences?)\b", q_lower):
            length_constraint = "Strictly TWO SENTENCES"
        elif re.search(r"\b(5|five)\s*(?:bullet\s+points?|points?)\b", q_lower):
            length_constraint = "Strictly FIVE bullet points"
        elif re.search(r"\b(short|brief|concise|tldr|tl;dr)\b", q_lower):
            length_constraint = "Brief and concise"
        elif re.search(r"\b(detailed|comprehensive|exhaustive|thorough)\b", q_lower):
            length_constraint = "Comprehensive and detailed"

        # 5. Extract Negative Constraints
        negative_constraints = []
        if re.search(r"\b(?:no|without)\s+(?:any\s+)?examples?\b", q_lower):
            negative_constraints.append("Do NOT include any examples")
        if re.search(r"\b(?:no|without)\s+(?:any\s+)?intro(?:duction)?\b", q_lower):
            negative_constraints.append("Do NOT include introductory phrases or greeting")
        if re.search(r"\b(only\s+formulas?|formulas?\s+only)\b", q_lower):
            negative_constraints.append("Output ONLY mathematical/technical formulas")
        if re.search(r"\b(only\s+key\s+points?|just\s+key\s+points?)\b", q_lower):
            negative_constraints.append("Output ONLY essential key points with zero fluff")

        # 6. Detect Specific Page Request
        target_page = None
        page_match = re.search(r"\bpage\s+(\d+)\b", q_lower)
        if page_match:
            target_page = int(page_match.group(1))

        # 7. Detect Intent Type & Target Documents
        intent_type = "FOCUSED_QA"
        target_doc_id = None
        target_doc_name = None
        compare_docs: List[str] = []
        is_summary = False
        is_all_docs = False
        is_follow_up = False

        # Check for Comparison
        if re.search(r"\b(compare|comparison|versus|vs\.?|difference\s+between)\b", q_lower):
            intent_type = "COMPARISON"
            # Try to identify which documents are being compared
            for d in docs:
                fname = (d.get("filename") or d.get("doc_id", "")).lower()
                did = d.get("doc_id", "").lower()
                clean_fn = re.sub(r"\.[a-z0-9]+$", "", fname)
                if clean_fn in q_lower or did in q_lower or any(word in q_lower for word in clean_fn.split() if len(word) > 4):
                    compare_docs.append(d.get("doc_id"))
            if len(compare_docs) < 2 and len(docs) >= 2:
                # Default to comparing top two available docs if user says "compare both documents"
                compare_docs = [docs[0].get("doc_id"), docs[1].get("doc_id")]

        # Check for Multi-Document Summary ("summarize all documents")
        elif re.search(r"\b(summariz\w*|overview|brief)\s+(?:of\s+)?(?:all|every|the\s+entire|each)\s+(?:documents?|docs?|files?)\b", q_lower):
            intent_type = "MULTI_DOC_SUMMARY"
            is_summary = True
            is_all_docs = True

        # Check for Single Document Summary ("summarize this document", "summarize the document", "document overview")
        elif re.search(r"\b(summariz\w*|overview|give\s+(?:a\s+)?summary|what\s+is\s+this\s+doc(?:ument)?\s+about)\b", q_lower):
            intent_type = "DOCUMENT_SUMMARY"
            is_summary = True

            # Find matching document name in query
            matched_doc = cls._find_named_document(q_lower, docs)
            if matched_doc:
                target_doc_id = matched_doc.get("doc_id")
                target_doc_name = matched_doc.get("filename")
            elif docs:
                # Rule: "Summarize this document" -> prioritize most recently uploaded doc by current user
                latest_doc = cls._find_latest_document(docs, current_user_id)
                if latest_doc:
                    target_doc_id = latest_doc.get("doc_id")
                    target_doc_name = latest_doc.get("filename")

        # Check for Page-specific query
        elif target_page is not None:
            intent_type = "PAGE_SECTION_QUERY"
            matched_doc = cls._find_named_document(q_lower, docs) or cls._find_latest_document(docs, current_user_id)
            if matched_doc:
                target_doc_id = matched_doc.get("doc_id")
                target_doc_name = matched_doc.get("filename")

        # Check for Conversational Follow-up
        follow_up_patterns = [
            r"^(?:explain\s+that\s+again|make\s+it\s+simpler|give\s+(?:another|more)\s+examples?|continue|shorten\s+(?:the\s+)?(?:previous\s+)?answer)\b",
            r"^(?:explain\s+(?:the\s+)?(?:first|second|third|fourth|fifth|\d+(?:st|nd|rd|th)?)\s+point)\b",
            r"^(?:what\s+about\s+(?:the\s+)?(?:second|third|\d+)\s+one)\b",
            r"^(?:i\s+didn'?t\s+understand|teach\s+me\s+differently|can\s+you\s+elaborate)\b",
            r"^(?:tell\s+me\s+more|why\s+is\s+that|how\s+does\s+that\s+work)\b",
            r"^(?:simplify|more\s+details?|elaborate|expand\s+on\s+that)\b",
            r"^(?:now\s+compare\s+it\s+with)\b",
            r"^(?:in\s+tamil|in\s+thanglish|in\s+hindi|in\s+french|in\s+spanish)\b",
            r"^(?:now\s+in\s+tamil|translate\s+to\s+tamil)\b",
        ]
        is_follow_up = any(re.search(pat, q_lower) for pat in follow_up_patterns) or (
            len(q_raw.split()) <= 4 and bool(history) and not is_summary
        )

        if is_follow_up and history:
            intent_type = "FOLLOW_UP"

        # Check history for persistent language preference if not explicit in query
        if history and language == "English":
            for prior in reversed(history):
                if prior.get("role") == "user":
                    p_low = prior.get("content", "").lower()
                    if re.search(r"\b(in\s+tamil|tamil\s+la|tamizh|தமிழ்)\b", p_low):
                        if not re.search(r"\b(in\s+english|english\s+mein)\b", q_lower):
                            language = "Tamil"
                        break
                    elif re.search(r"\b(in\s+thanglish|tanglish|tamil-english)\b", p_low):
                        if not re.search(r"\b(in\s+english|english\s+mein)\b", q_lower):
                            language = "Thanglish (Tamil written in English script)"
                        break

        # Check history for target doc continuity in follow-ups
        if not target_doc_id and history and is_follow_up:
            for prior in reversed(history):
                p_text = prior.get("content", "").lower()
                m_doc = cls._find_named_document(p_text, docs)
                if m_doc:
                    target_doc_id = m_doc.get("doc_id")
                    target_doc_name = m_doc.get("filename")
                    break

        # 8. Resolve Query for Retrieval (bridge pronoun & follow-up gaps)
        resolved_query = cls._resolve_conversational_query(q_raw, history, intent_type)

        return QueryIntentAnalysis(
            raw_query=q_raw,
            resolved_query=resolved_query,
            intent_type=intent_type,
            target_doc_id=target_doc_id,
            target_doc_name=target_doc_name,
            target_page=target_page,
            compare_docs=compare_docs,
            is_summary=is_summary,
            is_all_docs=is_all_docs,
            is_follow_up=is_follow_up,
            style_instructions=style_instructions,
            language=language,
            format_type=format_type,
            length_constraint=length_constraint,
            negative_constraints=negative_constraints,
        )

    @classmethod
    def _find_named_document(cls, query_lower: str, docs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Match query tokens against known document filenames or doc_ids."""
        best_doc = None
        best_overlap = 0

        for d in docs:
            fname = (d.get("filename") or "").lower()
            did = (d.get("doc_id") or "").lower()
            clean_name = re.sub(r"\.[a-z0-9]+$", "", fname)

            # Direct substring match
            if clean_name and clean_name in query_lower:
                return d
            if did and did in query_lower:
                return d

            # Token overlap
            tokens = set(re.findall(r"[a-zA-Z0-9]+", clean_name)) - {"doc", "document", "pdf", "file", "the", "and"}
            if tokens:
                matches = sum(1 for t in tokens if t in query_lower)
                if matches > best_overlap and matches >= 2:
                    best_overlap = matches
                    best_doc = d

        return best_doc

    @classmethod
    def _find_latest_document(
        cls, docs: List[Dict[str, Any]], current_user_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Finds the most recently uploaded document.
        Prioritizes documents owned by current_user_id.
        """
        if not docs:
            return None

        user_docs = [d for d in docs if current_user_id and d.get("user_id") == current_user_id]
        candidate_pool = user_docs if user_docs else docs

        # Sort by updated_at or created_at if available, else first in list (Qdrant scroll order)
        def _doc_sort_key(d: Dict[str, Any]) -> float:
            return float(d.get("created_at") or d.get("timestamp") or 0.0)

        sorted_docs = sorted(candidate_pool, key=_doc_sort_key, reverse=True)
        return sorted_docs[0] if sorted_docs else docs[0]

    @classmethod
    def _resolve_conversational_query(
        cls, query: str, history: List[Dict[str, str]], intent_type: str
    ) -> str:
        """
        Expands follow-ups like 'explain that again', 'make it simpler', 'explain point 2'
        into explicit queries using context from the last assistant/user message.
        """
        if not history:
            return query

        last_user_msg = ""
        last_assistant_msg = ""
        for msg in reversed(history):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user" and not last_user_msg:
                last_user_msg = content
            elif role == "assistant" and not last_assistant_msg:
                last_assistant_msg = content
            if last_user_msg and last_assistant_msg:
                break

        q_lower = query.lower().strip()

        # Handle numbered/ordinal point references ("explain the second point", "explain point 3", "explain the 2nd item")
        ordinal_match = re.search(
            r"\b(?:explain\s+)?(?:the\s+)?(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th|\d+)\s+(?:point|item|bullet|module)\b|\b(?:point|item|bullet|module)\s+(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th|\d+)\b",
            q_lower,
        )
        if ordinal_match and last_assistant_msg:
            num_map = {"first": 1, "1st": 1, "second": 2, "2nd": 2, "third": 3, "3rd": 3, "fourth": 4, "4th": 4, "fifth": 5, "5th": 5}
            ord_str = ordinal_match.group(1) or ordinal_match.group(2)
            target_idx = num_map.get(ord_str, int(ord_str) if (ord_str and ord_str.isdigit()) else 1)

            # Normalize literal or real newlines
            normalized_msg = last_assistant_msg.replace("\\r\\n", "\n").replace("\\n", "\n")
            lines = [l.strip() for l in normalized_msg.splitlines() if re.match(r"^(\d+[\.\)]|[-*•])\s+", l.strip())]
            if 0 < target_idx <= len(lines):
                extracted_point = re.sub(r"^(\d+[\.\)]|[-*•])\s+", "", lines[target_idx - 1])
                extracted_point = re.sub(r"[*_`]", "", extracted_point).strip()
                return f"Detailed explanation of {extracted_point} ({last_user_msg})"

        # Handle "make it simpler", "explain again", "teach me differently", "give an example"
        if any(p in q_lower for p in ["simpler", "again", "differently", "example", "continue", "shorten", "elaborate"]):
            if last_user_msg:
                return f"{query} regarding: {last_user_msg}"

        # Handle direct translation / language shift follow-up (e.g. "now in Tamil", "in Thanglish")
        if q_lower in ["in tamil", "in thanglish", "in hindi", "tamil", "thanglish", "now in tamil", "explain in tamil"]:
            if last_user_msg:
                return f"{last_user_msg} (in {query})"

        return query
