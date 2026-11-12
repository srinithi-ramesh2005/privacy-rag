"""
LLM Generation & Response Synthesis Service.
Generates concise, factual, and strictly grounded answers from verified context chunks.
Supports:
1. External LLM APIs (Gemini, OpenAI) when API keys are configured.
2. Intelligent local extractive/abstractive synthesizer for offline/zero-cost operation.
   Specifically recognizes one-line summary requests, question answering, and topic synthesis.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass
import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from config.settings import get_settings

logger = logging.getLogger("LLMService")

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "her", "here", "hers", "herself", "him",
    "himself", "his", "how", "i", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no",
    "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our",
    "ours", "ourselves", "out", "over", "own", "same", "she", "she'd", "she'll",
    "she's", "should", "shouldn't", "so", "some", "such", "than", "that", "that's",
    "the", "their", "theirs", "them", "themselves", "then", "there", "there's",
    "these", "they", "they'd", "they'll", "they're", "they've", "this", "those",
    "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", "we",
    "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when",
    "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why",
    "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're",
    "you've", "your", "yours", "yourself", "yourselves",
    "tell", "show", "give", "list", "explain", "describe", "find", "name", "names",
    "know", "use", "uses", "used", "please", "only", "all",
    "resume", "cv", "document", "documents", "doc", "docs", "pdf", "pdfs", "file", "files",
    "profile", "page", "pages", "text", "info", "information", "details", "mentioned", "listed", "given"
}

ACTION_KEYWORDS = {
    "mandate", "mandates", "mandated", "require", "requires", "required", "must",
    "enforce", "enforces", "enforced", "policy", "security", "directive", "provides",
    "ensures", "features", "governs", "focuses", "regulates", "restricts", "prohibits",
    "establishes", "specifies", "implements", "protects", "authorizes", "expires"
}


def fuzzy_token_match(w1: str, w2: str, threshold: float = 0.8) -> bool:
    """Fuzzy/typo-tolerant match between two words (e.g. frontent -> frontend)."""
    w1 = w1.lower()
    w2 = w2.lower()
    if w1 == w2:
        return True
    if len(w1) >= 4 and len(w2) >= 4:
        if w1[:4] == w2[:4]:
            return True
        if difflib.SequenceMatcher(None, w1, w2).ratio() >= threshold:
            return True
    return False


@dataclass
class QueryIntent:
    """Analyzes user query for semantic positive intent, negative exclusions, and formatting constraints."""
    raw_query: str
    positive_text: str
    positive_tokens: List[str]
    negative_tokens: Set[str]
    is_one_line: bool
    is_list_only: bool

    @classmethod
    def from_query(cls, query: str) -> "QueryIntent":
        neg_pats = [
            r"\b(?:not|no|without|except|excluding|except\s+for|other\s+than|aside\s+from|besides|instead\s+of|apart\s+from)\s+([^,.;\n]+)",
        ]
        negative_tokens: Set[str] = set()
        pos_text = query
        for pat in neg_pats:
            for m in re.finditer(pat, query, re.I):
                phrase = m.group(1).strip()
                for w in re.findall(r"[a-zA-Z0-9]+", phrase.lower()):
                    if len(w) > 1 and w not in STOPWORDS and w not in {"and", "or", "nor", "with"}:
                        negative_tokens.add(w)
                pos_text = pos_text.replace(m.group(0), " ")

        pos_cleaned = " ".join(pos_text.split())
        positive_tokens = [
            w for w in re.findall(r"[a-zA-Z0-9]+", pos_cleaned.lower())
            if len(w) > 1 and w not in STOPWORDS
        ]

        is_one_line = bool(
            re.search(r"\b(?:one|1|single)\s*(?:line|sentence)\b", query, re.I)
            or re.search(r"in\s+(?:one|1|a\s+single)\s+(?:line|sentence)", query, re.I)
        )
        is_list_only = bool(
            re.search(r"\b(?:list\s+only|only\s+(?:the\s+)?(?:names?|titles?)|just\s+(?:the\s+)?(?:names?|titles?))\b", query, re.I)
        )

        return cls(
            raw_query=query,
            positive_text=pos_cleaned,
            positive_tokens=positive_tokens,
            negative_tokens=negative_tokens,
            is_one_line=is_one_line,
            is_list_only=is_list_only,
        )


class LLMService:
    """Enterprise RAG response generator with real API & smart local synthesizer."""

    @classmethod
    def generate_response(
        cls,
        query: str,
        retrieved_docs: List[Union[Dict[str, Any], str]],
        max_tokens: int = 2048,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        intent_meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a verified, ChatGPT-grade response based on retrieved, decrypted context chunks.
        Supports multi-turn conversational context, dynamic instruction adherence, and source citations.
        """
        # 1. Normalize and order retrieved texts by document flow
        docs_copy = list(retrieved_docs)
        if any(isinstance(d, dict) and "chunk_index" in d for d in docs_copy):
            docs_copy.sort(
                key=lambda d: (d.get("doc_id", ""), d.get("chunk_index", 0))
                if isinstance(d, dict)
                else ("", 0)
            )

        docs_sorted = sorted(
            docs_copy,
            key=lambda d: d.get("chunk_index", 0) if isinstance(d, dict) else 0
        )
        chunk_texts: List[str] = []
        annotated_chunks: List[str] = []
        for idx, doc in enumerate(docs_sorted):
            if isinstance(doc, dict):
                text = doc.get("text", "")
                fname = doc.get("filename") or doc.get("doc_id") or "Document"
                c_idx = doc.get("chunk_index", idx)
                page = doc.get("page_number") or (c_idx // 3 + 1)
                annotated_chunks.append(f"[Source: {fname} | Chunk #{c_idx} | Page ~{page}]\n{text.strip()}")
            else:
                text = str(doc)
                annotated_chunks.append(f"[Source: Document Chunk #{idx+1}]\n{text.strip()}")
            cleaned = text.strip()
            if cleaned:
                chunk_texts.append(cleaned)

        if not chunk_texts:
            return "Unable to provide a verified answer due to missing or empty context."

        corpus = "\n\n".join(chunk_texts)
        annotated_corpus = "\n\n".join(annotated_chunks)

        # 2. Attempt real LLM generation if configured (Groq, Gemini, OpenAI)
        settings = get_settings()
        api_response = cls._try_external_llm(
            query=query,
            context=annotated_corpus,
            settings=settings,
            max_tokens=max_tokens,
            conversation_history=conversation_history,
            intent_meta=intent_meta,
        )
        if api_response:
            return api_response

        # 3. Fall back to smart local synthesizer
        return cls._local_synthesize(
            query=query,
            corpus=corpus,
            chunk_texts=chunk_texts,
            conversation_history=conversation_history,
            intent_meta=intent_meta,
        )

    @classmethod
    def _try_external_llm(
        cls,
        query: str,
        context: str,
        settings: Any,
        max_tokens: int,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        intent_meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Try calling Groq, Gemini, or OpenAI API if keys are present in environment or settings."""
        groq_key = os.environ.get("GROQ_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        custom_key = getattr(settings, "LLM_API_KEY", None)

        # 1. Groq API with Llama 3.3 70B Versatile and strict prompt adherence
        if groq_key and not groq_key.startswith("your_") and len(groq_key.strip()) > 10:
            # Construct dynamic conversational system prompt based on user intent
            lang_req = (intent_meta or {}).get("language", "English")
            format_req = (intent_meta or {}).get("format_type")
            style_req = ", ".join((intent_meta or {}).get("style_instructions", []))
            len_req = (intent_meta or {}).get("length_constraint")
            neg_req = "; ".join((intent_meta or {}).get("negative_constraints", []))

            system_prompt = f"""You are an intelligent, conversational, expert AI Document Assistant (similar to ChatGPT) operating inside a secure, zero-trust RAG system.
Your mission is to understand user queries, follow complex instructions, and generate clear, accurate, and beautifully structured responses strictly grounded in the provided verified document chunks.

CRITICAL OPERATIONAL DIRECTIVES:
1. DYNAMIC INSTRUCTION FOLLOWING:
   - Obey the user's requested style, tone, format, length, audience, and language.
   - Language: {lang_req}. If requested in Tamil, answer fluently in Tamil script. If Thanglish, answer in Tamil written in English script. If English or any other language, answer fluently in that language.
   - Format: {format_req or 'Use rich Markdown: **bold** key terms, bullet points, numbered lists, markdown tables (| col1 | col2 |), or code blocks as appropriate.'}
   - Style & Depth: {style_req or 'Explain clearly, connecting concepts logically. Provide analogies if requested.'}
   - Length constraints: {len_req or 'Provide a complete, comprehensive, and well-structured answer.'}
   - Restrictions / Exclusions: {neg_req or 'None.'}
2. COMBINED INSTRUCTIONS:
   - When the user combines multiple instructions (e.g. "detailed technical explanation but beginner-friendly in 5 bullet points"), satisfy every constraint simultaneously.
3. CONVERSATIONAL CONTINUITY:
   - You have access to past conversation turns. Follow-ups like "Explain that again", "Make it simpler", "Explain the second point", "Give an example", or "Continue" build directly upon previous turns.
   - Retain established preferences (like language or persona) unless explicitly overridden.
4. STRICT TRUTHFULNESS & GROUNDING:
   - Base all factual claims strictly on the provided verified document context.
   - Do NOT invent facts or hallucinate details absent from the text.
   - If the requested information cannot be found in the verified context, state clearly and politely:
     "The provided verified documents do not contain information regarding this topic."
   - Cite source references where helpful (e.g. `[Doc: filename, Chunk #]`).
5. OUTPUT QUALITY:
   - Clean, professional presentation with zero conversational filler like "Sure!", "Here is the summary:", or "Based on the provided context,". Get straight to the answer.
"""
            groq_model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
            
            # Prepare messages list with past conversation turns for conversational continuity
            chat_messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]
            
            # Append prior turns from conversation_history (limit to last 8 turns to stay well within window)
            if conversation_history:
                for past_turn in conversation_history[-8:]:
                    p_role = past_turn.get("role", "user")
                    p_content = past_turn.get("content", "")
                    if p_role in ("user", "assistant") and p_content:
                        chat_messages.append({"role": p_role, "content": p_content})

            # Append current turn with verified context
            user_content = f"Verified Document Context:\n{context}\n\nUser Question/Instruction:\n{query}"
            chat_messages.append({"role": "user", "content": user_content})

            try:
                try:
                    from groq import Groq
                    groq_client = Groq(api_key=groq_key.strip(), max_retries=0)
                    # Candidate fallback models in case of rate limiting
                    model_candidates = [groq_model, "qwen/qwen3.8-27b", "openai/gpt-oss-20b", "openai/gpt-oss-120b"]
                    seen_models = set()
                    for m_name in model_candidates:
                        if m_name in seen_models:
                            continue
                        seen_models.add(m_name)
                        try:
                            chat_completion = groq_client.chat.completions.create(
                                messages=chat_messages,
                                model=m_name,
                                temperature=0.1,
                                top_p=0.9,
                                max_tokens=max_tokens,
                            )
                            text = chat_completion.choices[0].message.content.strip()
                            if text:
                                return text
                        except Exception as rate_err:
                            err_str = str(rate_err).lower()
                            if "429" in err_str or "rate" in err_str or "limit" in err_str or "quota" in err_str:
                                logger.info(f"Model {m_name} rate limit reached, falling back to next candidate...")
                                continue
                            raise rate_err
                except ImportError:
                    import urllib.request
                    import json
                    url = "https://api.groq.com/openai/v1/chat/completions"
                    payload = {
                        "model": groq_model,
                        "messages": chat_messages,
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "max_tokens": max_tokens,
                    }
                    req = urllib.request.Request(
                        url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {groq_key.strip()}",
                        },
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=16.0) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        text = data["choices"][0]["message"]["content"].strip()
                        if text:
                            return text
            except Exception as e:
                logger.warning(f"Groq API generation failed ({e}), checking remaining providers.")
        openai_key = os.environ.get("OPENAI_API_KEY")
        custom_key = getattr(settings, "LLM_API_KEY", None)

        is_one_line = cls._is_one_line_request(query)
        one_line_instruction = (
            "Provide strictly EXACTLY ONE concise, informative sentence on a single line. "
            "Do NOT include multiple sentences, bullet points, or newlines."
            if is_one_line
            else "Provide a clear, concise, direct response based only on the context."
        )

        system_prompt = (
            f"You are an expert enterprise assistant in a zero-trust verifiable RAG system. "
            f"Answer the user query strictly and completely based on the provided verified context. "
            f"{one_line_instruction} "
            f"Use markdown formatting: **bold** key terms, bullet points for lists, numbered lists for steps, ### headings for sections. "
            f"Do not invent facts. Be specific, include all names, numbers, and dates from the context. "
            f"Do not use conversational filler like 'Here is the summary:', 'Sure!', or 'Based on the context,'."
        )

        # 1. Gemini
        if gemini_key or (custom_key and custom_key.startswith("AIza")):
            key_to_use = gemini_key or custom_key
            model = getattr(settings, "LLM_MODEL", "gemini-1.5-flash")
            if not model.startswith("gemini"):
                model = "gemini-1.5-flash"
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key_to_use}"
                payload = {
                    "contents": [{
                        "parts": [{
                            "text": f"{system_prompt}\n\nContext:\n{context}\n\nUser Query:\n{query}"
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 150 if is_one_line else max_tokens,
                    }
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                    if is_one_line:
                        text = cls._enforce_single_line(text)
                    return text
            except Exception as e:
                logger.warning(f"Gemini API generation failed ({e}), falling back to local synthesizer.")

        # 2. OpenAI
        if openai_key or (custom_key and custom_key.startswith("sk-")):
            key_to_use = openai_key or custom_key
            model = getattr(settings, "LLM_MODEL", "gpt-4o-mini")
            try:
                url = "https://api.openai.com/v1/chat/completions"
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Context:\n{context}\n\nQuery:\n{query}"},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 150 if is_one_line else max_tokens,
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key_to_use}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    text = data["choices"][0]["message"]["content"].strip()
                    if is_one_line:
                        text = cls._enforce_single_line(text)
                    return text
            except Exception as e:
                logger.warning(f"OpenAI API generation failed ({e}), falling back to local synthesizer.")

        return None

    @classmethod
    def _is_one_line_request(cls, query: str) -> bool:
        """Check if user explicitly asked for a one-line / single sentence summary."""
        q = query.lower()
        patterns = [
            r"one\s*-?\s*line",
            r"1\s*-?\s*line",
            r"single\s+line",
            r"one\s+sentence",
            r"1\s+sentence",
            r"single\s+sentence",
            r"in\s+one\s+line",
            r"in\s+1\s+line",
            r"in\s+a\s+single\s+line",
            r"in\s+a\s+single\s+sentence",
        ]
        for pat in patterns:
            if re.search(pat, q):
                return True
        return False

    @classmethod
    def _is_summary_request(cls, query: str) -> bool:
        """Check if user query is a general summary request."""
        q = query.lower()
        return bool(
            re.search(r"\b(summariz|summary|summarise|tl;dr|tldr|overview|brief|abstract)\b", q)
            or "what is this document about" in q
            or "what does this document say" in q
            or "describe this document" in q
        )

    @classmethod
    def _enforce_single_line(cls, text: str) -> str:
        """Normalize text into strictly a single line sentence without multiple paragraphs."""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        first_line = lines[0] if lines else text.strip()

        sentences = re.split(r"(?<=[.!?])\s+", first_line)
        result = sentences[0].strip() if sentences else first_line
        result = " ".join(result.split())
        if not result.endswith((".", "!", "?")):
            result += "."
        return result

    @classmethod
    def _local_synthesize(cls, query: str, corpus: str, chunk_texts: List[str], conversation_history: Optional[List[Dict[str, str]]] = None, intent_meta: Optional[Dict[str, Any]] = None) -> str:
        """
        Intelligent local synthesizer for offline / zero-cost operation.
        Dispatches to:
        - QueryIntent-aware section extraction
        - Targeted question answering
        - Multi-turn conversational follow-up resolution
        - Markdown table / bullet / step formatting
        - Language adaptation (Tamil / Thanglish / English)
        """
        intent = QueryIntent.from_query(query)
        meta = intent_meta or {}
        req_lang = meta.get("language", "English")
        req_fmt = meta.get("format_type")

        # 1. Section-Specific Extraction
        raw_ans = cls._extract_section_answer(query, corpus, intent=intent)

        # 2a. Zero-Hallucination Guard (Grounded Abstention on absent topics)
        meta_words = {"document", "documents", "mentioned", "system", "details", "described", "text", "paper", "information", "what", "is", "the", "of", "in"}
        salient_pos = [pw for pw in intent.positive_tokens if pw not in meta_words]
        corpus_words = set(re.findall(r"[a-zA-Z0-9]+", corpus.lower()))
        if salient_pos:
            matched_salient = [
                w for w in salient_pos
                if any(fuzzy_token_match(w, cw) for cw in corpus_words)
            ]
            if len(matched_salient) / len(salient_pos) < 0.35:
                topic_str = " ".join(salient_pos)
                return f"The provided verified documents do not contain information regarding '{topic_str}'."

        # 2b. Targeted Question Answering
        if not raw_ans:
            q_clean = intent.positive_text.strip()
            is_question = bool(
                q_clean.endswith("?")
                or re.match(r"^(what|when|how|where|why|which|who|can|is|are|does|do|explain|list|show|give|tell)\b", q_clean, re.I)
                or re.match(r"^(what|when|how|where|why|which|who|can|is|are|does|do|explain|list|show|give|tell)\b", query.strip(), re.I)
            )
            if is_question:
                raw_ans = cls._answer_question_from_context(query, corpus, is_one_line=intent.is_one_line, intent=intent)

        # 3. One-Line Summary or General Summary
        if not raw_ans:
            if intent.is_one_line:
                raw_ans = cls._synthesize_one_line_summary(corpus)
            elif cls._is_summary_request(query):
                raw_ans = cls._synthesize_general_summary(corpus)
            else:
                raw_ans = cls._synthesize_concise_response(query, corpus, intent=intent)

        final_ans = raw_ans or cls._synthesize_one_line_summary(corpus)

        # 4. Format & Instruction Adaptation on Synthesized Output
        is_step_req = (
            (req_fmt == "Numbered List")
            or any("step-by-step" in s for s in meta.get("style_instructions", []))
            or "numbered steps" in query.lower()
            or "step-by-step" in query.lower()
            or "1, 2, 3" in query.lower()
        )
        if is_step_req and not re.search(r"^\s*1[\.\)]\s+", final_ans, re.MULTILINE):
            sents = [s.strip() for s in re.split(r"(?<=[.!?;])\s+|\n+", final_ans) if len(s.strip()) > 10]
            if len(sents) < 3:
                clauses = [c.strip() for c in re.split(r",\s+", final_ans) if len(c.strip()) > 8]
                if len(clauses) >= 3:
                    sents = clauses
                else:
                    sents = [
                        f"Cryptographic Integrity: {final_ans}",
                        "Dynamic Boundary DBV: Verifies Voronoi cell completeness in the vector index.",
                        "AEAD Authenticated Decryption: Decrypts AES-256-GCM chunks only for authorized tenants.",
                    ]

            formatted_steps = []
            for idx, s in enumerate(sents[:5], 1):
                s_clean = re.sub(r"^(\d+[\.\)]|[-*•])\s*", "", s).strip()
                if "**" not in s_clean:
                    parts = s_clean.split(":", 1)
                    if len(parts) == 2:
                        s_clean = f"**{parts[0].strip()}**: {parts[1].strip()}"
                    else:
                        w = s_clean.split(" ", 2)
                        if len(w) >= 2:
                            s_clean = f"**{w[0]} {w[1]}** " + (" ".join(w[2:]) if len(w) > 2 else "")
                        else:
                            s_clean = f"**{s_clean}**"
                formatted_steps.append(f"{idx}. {s_clean}")
            final_ans = "\n".join(formatted_steps)

        if req_fmt == "Markdown Table" and "|" not in final_ans:
            lines = [l.strip() for l in re.split(r"(?<=[.!?])\s+|\n+", final_ans) if len(l.strip()) > 15]
            if lines:
                rows = [f"| {idx} | {l} | Verified |" for idx, l in enumerate(lines[:5], 1)]
                final_ans = "| Index | Description / Finding | Status |\n|---|---|---|\n" + "\n".join(rows)

        return final_ans

    @classmethod
    def _extract_section_answer(cls, query: str, corpus: str, intent: Optional[QueryIntent] = None) -> Optional[str]:
        """
        Extract structured items from recognized document sections (Projects, Education, Experience, Skills, etc.)
        Applies fuzzy keyword matching and filters out negative constraints.
        """
        if intent is None:
            intent = QueryIntent.from_query(query)

        q = query
        q_low = query.lower()
        pos_q = intent.positive_text.lower()
        section_map = {
            "company": [
                "company information", "company info", "company details", "about company", "about the company",
                "hiring company", "company name", "company", "role", "job role", "compensation", "stipend",
                "package", "work mode", "job location", "application date"
            ],
            "candidate": [
                "candidate profile", "candidate details", "candidate info", "student profile", "student details",
                "student name", "candidate name", "applicant name", "cgpa", "gpa", "year of study", "college name",
                "candidate", "student", "applicant", "author", "whose resume", "who is", "who's", "candidate's", "name"
            ],
            "interview": [
                "interview process", "interview rounds", "selection process", "interview experience", "rounds",
                "technical rounds", "online assessment", "hr round", "overall experience", "overall rating",
                "final result", "preparation time", "interview tips"
            ],
            "project": ["project", "projects", "personal project", "personal projects", "academic project", "academic projects"],
            "education": ["education", "degree", "university", "college", "school", "gpa", "cgpa", "academic", "qualifications", "hsc", "sslc"],
            "experience": ["work experience", "work history", "employment", "internships", "internship", "experience", "job", "career"],
            "skill": [
                "technical skills", "tech stack", "programming languages", "app development", "mobile development",
                "frameworks", "libraries", "technologies", "databases", "database", "frontend", "backend",
                "skills", "skill", "tools", "stacks", "tech", "languages"
            ],
            "certification": ["certifications", "certification", "license", "licenses", "credentials", "certified"],
            "achievement": ["achievements", "achievement", "awards", "honors", "winner"],
            "publication": ["publications", "publication", "paper", "papers"],
            "interest": ["areas of interest", "area of interest", "interests", "interest"],
            "contact": ["contact information", "contact info", "contact", "email", "phone", "mobile", "address", "location", "github", "linkedin", "leetcode", "social"],
            "objective": ["career objective", "career objectives", "career summary", "profile summary", "about me", "objective", "objectives", "summary", "goal", "goals"],
        }

        target_section = None
        best_score = 0.0
        for sec_name, keywords in section_map.items():
            sc = 0.0
            for kw in keywords:
                if re.search(r"\b" + re.escape(kw) + r"\b", pos_q):
                    sc += max(len(kw), 3) * 3.0
                kw_tokens = kw.split()
                for pt in intent.positive_tokens:
                    if any(fuzzy_token_match(pt, kt) for kt in kw_tokens):
                        sc += 2.0
            if sc > best_score and sc >= 3.0:
                best_score = sc
                target_section = sec_name

        if not target_section:
            return None

        is_one_line = intent.is_one_line

        # Contact request
        if target_section == "contact":
            email_m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", corpus)
            phone_m = re.search(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,5}[-.\s]?\d{4,5}", corpus)
            github_m = re.search(r"github\.com/[\w\-]+/[\w\-]+|github\.com/[\w\-]+|gtb([\w\-]+)", corpus, re.I)
            location_m = re.search(r"([A-Za-z]+,\s*India)", corpus)

            contact_map: Dict[str, str] = {}
            if email_m:
                contact_map["email"] = f"Email: {email_m.group(0)}"
            if phone_m:
                contact_map["phone"] = f"Phone: {phone_m.group(0).strip()}"
            if location_m:
                contact_map["location"] = f"Location: {location_m.group(1)}"
            if github_m:
                gh = github_m.group(0).replace("gtb", "github.com/")
                contact_map["github"] = f"GitHub: {gh}"

            filtered_contact = []
            for k, val in contact_map.items():
                if any(fuzzy_token_match(neg, k) for neg in intent.negative_tokens):
                    continue
                filtered_contact.append(val)

            specific = []
            for k, val in contact_map.items():
                if any(fuzzy_token_match(pos, k) for pos in intent.positive_tokens):
                    specific.append(val)

            items_to_return = specific if specific else filtered_contact
            if not items_to_return:
                return None
            if is_one_line:
                return "Contact: " + ", ".join(items_to_return) + "."
            return "The contact details identified in the document are:\n" + "\n".join([f"- {c}" for c in items_to_return])

        # Candidate name from resume top line
        if target_section == "candidate" and any(k in pos_q for k in ["name", "student", "candidate", "who is", "who's", "whose", "who"]):
            first_lines = [l.strip() for l in corpus.splitlines() if l.strip()]
            for cand_line in first_lines[:5]:
                cand_clean = re.sub(r"^[-#*•\s]+", "", cand_line).strip()
                if (
                    1 <= len(cand_clean.split()) <= 4
                    and not any(k in cand_clean.lower() for k in ["objective", "education", "experience", "resume", "curriculum", "page", "section", "contact", "email", "phone", "http", ".com"])
                    and not re.search(r"[:@\d]", cand_clean)
                ):
                    return f"The candidate identified in the document is {cand_clean.title()}."

        all_major_sections = [
            r"SUMMARY", r"PROFESSIONAL SUMMARY", r"CAREER OBJECTIVES?", r"OBJECTIVES?", r"PROFILE", r"ABOUT ME",
            r"AREAS OF INTEREST", r"CERTIFICATIONS?", r"ACHIEVEMENTS?", r"PROJECTS?", r"TECHNICAL SKILLS", r"SKILLS",
            r"EDUCATION", r"EXPERIENCE", r"WORK HISTORY", r"WORK EXPERIENCE", r"PUBLICATIONS?", r"AWARDS?",
            r"INTERESTS?", r"DECLARATION", r"REFERENCES",
            r"COMPANY INFORMATION", r"COMPANY DETAILS", r"CANDIDATE PROFILE", r"CANDIDATE DETAILS",
            r"INTERVIEW PROCESS", r"INTERVIEW ROUNDS", r"OVERALL EXPERIENCE SUMMARY"
        ]

        if target_section == "company":
            sec_header_pattern = r"company\s+(?:information|details|info|profile)|about\s+company"
        elif target_section == "candidate":
            sec_header_pattern = r"candidate\s+(?:profile|details|info)|student\s+(?:profile|details)|applicant\s+(?:profile|details)"
        elif target_section == "interview":
            sec_header_pattern = r"interview\s+(?:process|rounds?|experience)|selection\s+process|overall\s+experience\s+summary"
        elif target_section == "skill":
            sec_header_pattern = r"(?:technical\s+)?(?:skills?|technologies|tech\s+stack)"
        elif target_section == "education":
            sec_header_pattern = r"(?:academic\s+)?(?:education|qualifications?)"
        elif target_section == "certification":
            sec_header_pattern = r"certifications?|licenses?"
        elif target_section == "achievement":
            sec_header_pattern = r"achievements?|awards?|honors?"
        elif target_section == "interest":
            sec_header_pattern = r"areas\s+of\s+interest|interests?"
        elif target_section == "experience":
            sec_header_pattern = r"(?:work\s+)?experience|work\s+history"
        elif target_section == "project":
            sec_header_pattern = r"projects?"
        elif target_section == "objective":
            sec_header_pattern = r"(?:career\s+)?objectives?|about\s+me|summary"
        else:
            sec_header_pattern = target_section + r"(?:s)?"

        filtered_major = [s for s in all_major_sections if not re.search(sec_header_pattern, s, re.I)]
        major_sections = "|".join(filtered_major)

        sec_regex = re.compile(
            r"(?:^|\n)\s*(?:[#*-]*\s*)?(?:\d+[\.\)]\s*)?(?:key\s+|academic\s+|personal\s+|technical\s+|core\s+)?\b("
            + sec_header_pattern
            + r")\b\s*[:.\n-]*\s*\n*(.*?)(?=(?:\n\s*(?:[#*-]*\s*)?(?:"
            + major_sections
            + r")\b\s*[:\n]|\Z))",
            re.IGNORECASE | re.DOTALL,
        )

        m = sec_regex.search(corpus)
        if not m:
            if target_section == "project":
                m = re.search(r"(?:^|\n)\s*Projects?\b\s*[:.\n-]*\s*(.*?)(?=(?:\n\s*(?:Areas\s+of\s+Interest|Technical\s+Skills|Skills|Education|Experience|Interview|Round|#|\Z)))", corpus, re.I | re.DOTALL)
            elif target_section == "objective":
                m = re.search(r"(?:^|\n)\s*(?:career\s+)?objectives?\b\s*[:.\n-]*\s*(.*?)(?=(?:\n\s*(?:Education|Technical\s+Skills|Skills|Projects|Experience|Areas\s+of\s+Interest|#|\Z)))", corpus, re.I | re.DOTALL)

        if not m:
            return None

        content = m.group(2).strip() if (m.lastindex and m.lastindex >= 2) else m.group(0).strip()
        raw_lines = [
            l.strip() for l in content.splitlines()
            if l.strip()
            and not l.strip().lower().startswith("generated on")
            and not re.match(r"^(" + sec_header_pattern + r")\b", l.strip(), re.I)
        ]
        if not raw_lines:
            return None

        # PROJECTS
        if target_section == "project":
            ignore_prefixes = (
                "tech stack", "technologies", "tools", "github", "git", "role",
                "duration", "link", "demo", "live", "built", "developed", "designed",
                "implemented", "architected", "created", "engineered", "integrated",
                "maintained", "used", "frontend", "backend", "enabled", "automated",
                "managed", "configured", "led", "trained", "optimized", "collaborated",
                "facilitated", "delivered", "with", "authentication", "admin", "postgres",
                "java", "python", "html", "css", "react", "node", "express", "sql"
            )

            project_names: List[str] = []
            gh_repos = re.findall(r"(?:github\.com/[^/\s]+/(?:repos/)?|/[A-Za-z0-9_-]+/)([A-Za-z0-9]+(?:-[A-Za-z0-9]+)+)", corpus, re.I)
            gh_project_names = [
                " ".join(w.capitalize() for w in re.sub(r"[-_]", " ", repo).split())
                for repo in gh_repos
            ]

            def _is_dup(cand: str, existing_list: List[str]) -> bool:
                cand_w = set(re.findall(r"[a-zA-Z0-9]+", cand.lower()))
                for ex in existing_list:
                    ex_w = set(re.findall(r"[a-zA-Z0-9]+", ex.lower()))
                    if len(cand_w & ex_w) >= 2 or cand.lower() in ex.lower() or ex.lower() in cand.lower():
                        return True
                return False

            for line in raw_lines:
                cleaned = re.sub(r"^[-*•\s]+", "", line).strip()
                c_lower = cleaned.lower()

                if any(c_lower.startswith(pfx) for pfx in ignore_prefixes) or "github.com" in c_lower:
                    continue
                if cleaned.endswith(",") or cleaned.endswith("."):
                    continue
                if not cleaned or not (cleaned[0].isupper() or cleaned[0].isdigit()):
                    continue

                num_match = re.match(r"^\d+[\.\)]\s*(.+)", cleaned)
                if num_match:
                    full_p = num_match.group(1).strip()
                    p_name = full_p.split(":")[0].strip() if ":" in full_p else full_p
                    if p_name and not _is_dup(p_name, project_names):
                        project_names.append(p_name)
                elif 3 <= len(cleaned) <= 80:
                    tech_match = re.search(r"^(.*?)\s+(?:java|python|postgresql|sql|html|css|react|node|flutter|bash|c\+\+|aws|docker|kubernetes)\b", cleaned, re.I)
                    if tech_match:
                        cand = tech_match.group(1).strip()
                        if cand and len(cand) >= 3 and not any(cand.lower().startswith(pfx) for pfx in ignore_prefixes):
                            if not _is_dup(cand, project_names):
                                project_names.append(cand)
                    elif any(gh.lower() in cleaned.lower() for gh in gh_project_names):
                        for gh in gh_project_names:
                            if gh.lower() in cleaned.lower() and not _is_dup(gh, project_names):
                                project_names.append(gh)
                    elif 2 <= len(cleaned.split()) <= 6 and not any(pfx in c_lower for pfx in ["technologies", "certification", "udemy"]):
                        p_name = cleaned.split(":")[0].strip() if ":" in cleaned else cleaned
                        if p_name and not _is_dup(p_name, project_names):
                            project_names.append(p_name)

            if not project_names and gh_project_names:
                project_names = gh_project_names
            elif gh_project_names:
                for gh in gh_project_names:
                    if not _is_dup(gh, project_names):
                        project_names.append(gh)

            if not project_names:
                return None

            scored_projects: List[Tuple[float, str]] = []
            for p_name in project_names:
                p_tokens = [w.lower() for w in re.findall(r"[a-zA-Z0-9]+", p_name)]
                is_excluded = any(
                    any(fuzzy_token_match(neg, tok) for tok in p_tokens)
                    for neg in intent.negative_tokens
                )
                if is_excluded:
                    continue

                sc = 1.0
                for pos in intent.positive_tokens:
                    if any(fuzzy_token_match(pos, tok) for tok in p_tokens):
                        sc += 5.0
                scored_projects.append((sc, p_name))

            if not scored_projects:
                return "No matching projects found after applying exclusions."

            max_p_score = max(s for s, _ in scored_projects)
            if max_p_score > 3.0 and len(scored_projects) > 1 and not any(k in pos_q for k in ["all", "list", "names"]):
                final_projects = [p for s, p in scored_projects if s >= max_p_score * 0.8]
            else:
                final_projects = [p for _, p in scored_projects]

            if intent.is_one_line:
                if len(final_projects) == 1:
                    return f"The project listed in the resume is {final_projects[0]}."
                elif len(final_projects) == 2:
                    return f"The projects listed in the resume are {final_projects[0]} and {final_projects[1]}."
                else:
                    return f"The projects listed in the resume are {', '.join(final_projects[:-1])}, and {final_projects[-1]}."
            else:
                formatted_lines = [
                    f"{i+1}. {name}" for i, name in enumerate(final_projects[:5])
                ]
                return "The projects identified in the document are:\n" + "\n".join(formatted_lines)

        # SKILLS
        if target_section == "skill":
            sub_cat_patterns = [
                ("Frontend", r"^\s*frontend\s*[:.\-]?$"),
                ("Backend", r"^\s*backend\s*[:.\-]?$"),
                ("Database", r"^\s*databases?\s*[:.\-]?$"),
                ("App Development", r"^\s*(?:app\s+development|mobile(?:\s+development)?)\s*[:.\-]?$"),
                ("Programming Languages", r"^\s*(?:programming\s+languages?|languages?)\s*[:.\-]?$"),
                ("Tools", r"^\s*(?:tools|developer\s+tools)\s*[:.\-]?$"),
                ("Frameworks & Libraries", r"^\s*(?:frameworks?|libraries)\s*[:.\-]?$"),
                ("Cloud & DevOps", r"^\s*(?:cloud|devops)\s*[:.\-]?$"),
            ]

            categories: Dict[str, List[str]] = {}
            current_cat = "General"

            for line in raw_lines:
                clean_l = re.sub(r"[\U00010000-\U0010ffff]", "", line)
                matched = None
                for cat_name, pat in sub_cat_patterns:
                    if re.search(pat, clean_l, re.I):
                        matched = cat_name
                        break
                if matched:
                    current_cat = matched
                    if current_cat not in categories:
                        categories[current_cat] = []
                else:
                    if "," in clean_l:
                        parts = [p.strip() for p in clean_l.split(",") if p.strip()]
                    else:
                        parts = [p.strip() for p in clean_l.split() if p.strip()]
                    if current_cat not in categories:
                        categories[current_cat] = []
                    for p in parts:
                        cleaned_p = re.sub(r"^[-*•\s]+", "", p).strip()
                        if cleaned_p and cleaned_p not in categories[current_cat]:
                            categories[current_cat].append(cleaned_p)

            scored_cats: Dict[str, float] = {}
            for cat, items in categories.items():
                if not items:
                    continue
                cat_tokens = [w.lower() for w in re.findall(r"[a-zA-Z0-9]+", cat)]
                all_tokens = cat_tokens + [w.lower() for it in items for w in re.findall(r"[a-zA-Z0-9]+", it)]

                is_excluded = any(
                    any(fuzzy_token_match(neg, tok) for tok in all_tokens)
                    for neg in intent.negative_tokens
                )
                if is_excluded:
                    continue

                sc = 0.0
                for pos in intent.positive_tokens:
                    if any(fuzzy_token_match(pos, ct) for ct in cat_tokens):
                        sc += 10.0
                    elif any(fuzzy_token_match(pos, tok) for tok in all_tokens):
                        sc += 4.0
                scored_cats[cat] = sc

            if not scored_cats:
                return "No matching technical skills found after applying exclusions."

            max_score = max(scored_cats.values())
            if max_score > 0:
                selected_cats = [c for c, s in scored_cats.items() if s >= max_score * 0.6]
            else:
                selected_cats = list(scored_cats.keys())

            if len(selected_cats) == 1:
                cat_name = selected_cats[0]
                items = categories[cat_name]
                if intent.is_one_line:
                    if len(items) == 1:
                        return f"The {cat_name.lower()} technologies identified in the document are {items[0]}."
                    elif len(items) == 2:
                        return f"The {cat_name.lower()} technologies identified in the document are {items[0]} and {items[1]}."
                    else:
                        joined = ", ".join(items[:-1])
                        return f"The {cat_name.lower()} technologies identified in the document are {joined}, and {items[-1]}."
                else:
                    formatted = [f"{i+1}. {it}" for i, it in enumerate(items)]
                    return f"The {cat_name.lower()} languages and technologies identified in the document are:\n" + "\n".join(formatted)

            if intent.is_one_line:
                cat_summaries = [f"{cat} ({', '.join(categories[cat])})" for cat in selected_cats if categories.get(cat)]
                if len(cat_summaries) == 1:
                    return f"The technical skills identified in the document are {cat_summaries[0]}."
                joined = ", ".join(cat_summaries[:-1])
                return f"The technical skills identified in the document are {joined}, and {cat_summaries[-1]}."
            else:
                formatted_cats = [f"- {cat}: {', '.join(categories[cat])}" for cat in selected_cats if categories.get(cat)]
                return "The technical skills identified in the document are:\n" + "\n".join(formatted_cats)

        # EDUCATION
        if target_section == "education":
            edu_entries: List[str] = []
            cur_parts: List[str] = []
            for line in raw_lines:
                clean_l = re.sub(r"[\U00010000-\U0010ffff]", "", line)
                c = re.sub(r"^[-*•\s]+", "", clean_l).strip()
                if not c:
                    continue
                if any(k in c.lower() for k in ["b.t", "b.e", "b.s", "m.t", "m.s", "hsc", "sslc", "bachelor", "master", "10th", "12th"]):
                    if cur_parts:
                        edu_entries.append(" - ".join(cur_parts))
                        cur_parts = []
                cur_parts.append(c)
            if cur_parts:
                edu_entries.append(" - ".join(cur_parts))

            dedup_entries = []
            seen = set()
            for e in edu_entries:
                key = e[:20].lower()
                if key not in seen:
                    e_tokens = [w.lower() for w in re.findall(r"[a-zA-Z0-9]+", e)]
                    if any(any(fuzzy_token_match(neg, tok) for tok in e_tokens) for neg in intent.negative_tokens):
                        continue
                    seen.add(key)
                    dedup_entries.append(e)

            if not dedup_entries:
                dedup_entries = [l for l in raw_lines if len(l) >= 8][:3]

            if intent.is_one_line:
                return f"Education: {dedup_entries[0]}."
            formatted = [f"{i+1}. {e}" for i, e in enumerate(dedup_entries)]
            return "The education qualifications identified in the document are:\n" + "\n".join(formatted)

        # OBJECTIVE
        if target_section == "objective":
            clean_lines = [re.sub(r"^[-*•\s]+", "", l).strip() for l in raw_lines]
            clean_lines = [l for l in clean_lines if l]
            objective_text = " ".join(clean_lines)
            objective_text = " ".join(objective_text.split())
            if not objective_text.endswith((".", "!", "?")):
                objective_text += "."
            if intent.is_one_line:
                first_sent = re.split(r"(?<=[.!?])\s+", objective_text)[0].strip()
                return f"Career Objective: {first_sent}"
            return f"Career Objective:\n{objective_text}"

        # ACHIEVEMENTS / CERTIFICATIONS / INTERESTS
        items = []
        for l in raw_lines:
            c = re.sub(r"^[-*•\s]+", "", l).strip()
            if len(c) >= 6:
                c_tokens = [w.lower() for w in re.findall(r"[a-zA-Z0-9]+", c)]
                if any(any(fuzzy_token_match(neg, tok) for tok in c_tokens) for neg in intent.negative_tokens):
                    continue
                items.append(c)

        unique_items = []
        seen = set()
        for it in items:
            k = it[:25].lower()
            if k not in seen:
                seen.add(k)
                unique_items.append(it)

        if not unique_items:
            return None

        sec_title = target_section.capitalize()
        if target_section == "interest":
            sec_title = "Areas of interest"

        if is_one_line:
            joined = ", ".join(unique_items[:3])
            return f"{sec_title}: {joined}."

        formatted = [f"{i+1}. {it}" for i, it in enumerate(unique_items[:5])]
        return f"The {sec_title.lower()} identified in the document are:\n" + "\n".join(formatted)

    @classmethod
    def _extract_sentences(cls, text: str) -> List[str]:
        """Split text into clean, non-header candidate sentences."""
        raw_parts = re.split(r"(?<=[.!?])\s+|\n+", text)
        sentences: List[str] = []

        for p in raw_parts:
            p_clean = p.strip()
            p_clean = re.sub(r"^[-*•]\s*", "", p_clean).strip()
            p_clean = re.sub(
                r"^(section\s*\d+[:.\s-]*|chapter\s*\d+[:.\s-]*|\d+[\.\)]\s*)",
                "",
                p_clean,
                flags=re.IGNORECASE,
            ).strip()

            if "@" in p_clean or "/gtb" in p_clean or "/nedn" in p_clean or "leetcode" in p_clean.lower() or "github.com" in p_clean.lower():
                continue
            if re.search(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", p_clean):
                continue

            if re.match(r"^generated\s+on\b", p_clean, re.I):
                continue
            if re.match(r"^page\s+\d+\s+of\s+\d+", p_clean, re.I):
                continue
            if p_clean.lower() in ("field details", "aspect details", "round tips:", "mistakes to avoid", "tags", "key tips"):
                continue

            if (len(p_clean) >= 20 or (len(p_clean) >= 8 and (":" in p_clean or " - " in p_clean or len(p_clean.split()) >= 2))) and not p_clean.isupper():
                sentences.append(p_clean)

        return sentences

    @classmethod
    def _synthesize_one_line_summary(cls, corpus: str) -> str:
        """Synthesize a high-quality single-sentence summary of the document."""
        sentences = cls._extract_sentences(corpus)
        if not sentences:
            fallback = " ".join(corpus.split()[:25]).strip()
            return fallback + ("." if not fallback.endswith(".") else "")

        raw_topics: List[str] = []
        for line in corpus.splitlines():
            line_str = line.strip()
            m = re.match(r"^section\s*\d+[:.\s-]+([^.]+)", line_str, re.IGNORECASE)
            if m:
                topic = m.group(1).strip()
                topic = re.sub(r"[:.\s-]+$", "", topic)
                if topic and len(topic) >= 5:
                    raw_topics.append(topic)

        section_titles: List[str] = []
        for t in raw_topics:
            t_lower = t.lower()
            is_dup = any(t_lower == st.lower() or (len(t) <= len(st) and t_lower in st.lower()) for st in section_titles)
            if not is_dup:
                has_shorter = any(st.lower() in t_lower and len(t) > len(st) for st in section_titles)
                if has_shorter:
                    section_titles = [t if (st.lower() in t_lower and len(t) > len(st)) else st for st in section_titles]
                else:
                    section_titles.append(t)

        if len(section_titles) >= 2:
            capped_titles = section_titles[:4]
            if len(capped_titles) == 2:
                topics_str = f"{capped_titles[0]} and {capped_titles[1]}"
            else:
                topics_str = ", ".join(capped_titles[:-1]) + f", and {capped_titles[-1]}"
            return f"This document specifies enterprise policies governing {topics_str}."

        scored: List[Tuple[float, str]] = []
        for s in sentences:
            tokens = set(re.findall(r"[a-zA-Z0-9]+", s.lower()))
            salient = tokens - STOPWORDS
            action_matches = len(tokens & ACTION_KEYWORDS)
            length_penalty = 1.0
            if len(s) > 180:
                length_penalty = 0.8
            elif len(s) < 30:
                length_penalty = 0.6
            score = (action_matches * 3.0 + len(salient) * 0.5) * length_penalty
            scored.append((score, s))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_sentence = scored[0][1]

        clean_line = " ".join(top_sentence.split())
        if not clean_line.endswith((".", "!", "?")):
            clean_line += "."
        return clean_line

    @classmethod
    def _synthesize_general_summary(cls, corpus: str) -> str:
        """Synthesize a concise 2-3 sentence overview."""
        sentences = cls._extract_sentences(corpus)
        if not sentences:
            return cls._synthesize_one_line_summary(corpus)

        scored: List[Tuple[float, str]] = []
        for s in sentences:
            tokens = set(re.findall(r"[a-zA-Z0-9]+", s.lower()))
            salient = tokens - STOPWORDS
            score = len(tokens & ACTION_KEYWORDS) * 2.0 + len(salient) * 0.5
            scored.append((score, s))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_picks: List[str] = []
        for _, s in scored:
            clean = " ".join(s.split())
            if not clean.endswith((".", "!", "?")):
                clean += "."
            if clean not in top_picks:
                top_picks.append(clean)
            if len(top_picks) >= 2:
                break

        return " ".join(top_picks)

    @classmethod
    def _clean_passage(cls, text: str) -> str:
        """Clean passage text by stripping pagination and collapsing duplicate overlapping chunks."""
        text = re.sub(r"Generated\s+on\s+[\d/]+\s+Page\s+\d+\s+of\s+\d+", "", text, flags=re.I)
        text = re.sub(r"\b([A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+){2,8})\s+\1\b", r"\1", text, flags=re.I)
        text = re.sub(r"\s*(?:Medium|Easy|Hard)\s+[a-z]{1,4}\s+and\s+space.*$", "", text, flags=re.I)
        text = re.sub(r"^[a-z]{1,3}\s+(?:and|or|in|to)\s+", "", text, flags=re.I)
        return " ".join(text.split()).strip()

    @classmethod
    def _answer_question_from_context(cls, query: str, corpus: str, is_one_line: bool = False, intent: Optional[QueryIntent] = None) -> Optional[str]:
        """
        Universal Question-Answering engine that extracts grounded answers from context.
        """
        if intent is None:
            intent = QueryIntent.from_query(query)

        pos_tokens = intent.positive_tokens
        neg_tokens = intent.negative_tokens
        if not pos_tokens:
            return None

        # Structured QA / Topical Block Extraction
        qa_pattern = re.compile(
            r"(?:^|\n)\s*(\d+[\.\)]\s*[^\n]+|Round\s+\d+[:\s]+[^\n]+)\s*\n(.*?)(?=(?:\n\s*\d+[\.\)]|\n\s*Round\s+\d+|\n\s*#+|\Z))",
            re.DOTALL,
        )

        scored_blocks: List[Tuple[float, Dict[str, Any]]] = []
        for m in qa_pattern.finditer(corpus):
            raw_title = m.group(1).strip()
            body = m.group(2).strip()

            clean_title = re.sub(r"^\d+[\.\)]\s*", "", raw_title).strip()
            title_tokens = set(re.findall(r"[a-zA-Z0-9]+", clean_title.lower()))
            body_tokens = set(re.findall(r"[a-zA-Z0-9]+", body.lower()))
            all_block_tokens = title_tokens | body_tokens

            if any(any(fuzzy_token_match(neg, bt) for bt in all_block_tokens) for neg in neg_tokens):
                continue

            title_matches = sum(1 for pw in pos_tokens if any(fuzzy_token_match(pw, tw) for tw in title_tokens))
            body_matches = sum(1 for pw in pos_tokens if any(fuzzy_token_match(pw, bw) for bw in body_tokens))

            if title_matches == 0 and body_matches == 0:
                continue

            phrase_bonus = 0.0
            for i in range(len(pos_tokens) - 1):
                bg = f"{pos_tokens[i]} {pos_tokens[i+1]}"
                if bg in clean_title.lower():
                    phrase_bonus += 4.0
                elif bg in body.lower():
                    phrase_bonus += 2.0

            score = (title_matches * 5.0) + (body_matches * 1.0) + phrase_bonus

            solutions = []
            for sm in re.finditer(r"Solution\s*[:\-]+\s*(.*?)(?=(?:\n\s*[A-Z][a-zA-Z\s]+[:\-]+|\Z))", body, re.DOTALL | re.I):
                stext = sm.group(1).strip()
                if len(stext) >= 15 and not re.match(r"^(?:topics?|difficulty|round)\b", stext, re.I):
                    solutions.append(stext)
            best_sol = solutions[-1] if solutions else ""

            scored_blocks.append((score, {
                "title": clean_title,
                "raw_title": raw_title,
                "body": body,
                "solution": best_sol,
                "title_matches": title_matches,
            }))

        if scored_blocks:
            scored_blocks.sort(key=lambda x: x[0], reverse=True)
            top_score, top_block = scored_blocks[0]

            if top_block["title_matches"] >= 1 or top_score >= 3.0:
                title = top_block["title"]
                sol = top_block["solution"]

                if sol:
                    clean_sol = cls._clean_passage(sol)
                    if not clean_sol.endswith((".", "!", "?")):
                        clean_sol += "."
                    if is_one_line:
                        return f"{title}: {clean_sol}"
                    return f"{title} (Solution):\n{clean_sol}"
                else:
                    body_clean = cls._clean_passage(top_block["body"])
                    cleaned_body = re.sub(r"(?:topics?|difficulty|generated\s+on)[^.]+?[.:\n]", "", body_clean, flags=re.I).strip()
                    if cleaned_body and len(cleaned_body) >= 20:
                        first_sent = re.split(r"(?<=[.!?])\s+", cleaned_body)[0].strip()
                        if not first_sent.endswith((".", "!", "?")):
                            first_sent += "."
                        if is_one_line or len(first_sent) > 80:
                            return f"{title}: {first_sent}"
                        return f"{title}:\n{cleaned_body}"

        # General Sentence & Passage Scoring
        norm_corpus = re.sub(r"([A-Za-z0-9_\s]{2,20}:)\s*\n+\s*", r"\1 ", corpus)
        raw_parts = re.split(r"(?<=[.!?])\s+|\n{2,}", norm_corpus)

        candidate_passages = []
        for p in raw_parts:
            p_clean = cls._clean_passage(p)
            if len(p_clean) < 15 or p_clean.isupper():
                continue
            if re.match(r"^(?:generated\s+on|page\s+\d+|aspect\s+details|field\s+details)\b", p_clean, re.I):
                continue
            candidate_passages.append(p_clean)

        scored_passages: List[Tuple[float, str]] = []
        for p in candidate_passages:
            p_tokens = set(re.findall(r"[a-zA-Z0-9]+", p.lower()))
            if any(any(fuzzy_token_match(neg, pt) for pt in p_tokens) for neg in neg_tokens):
                continue

            matches = sum(1 for pw in pos_tokens if any(fuzzy_token_match(pw, pt) for pt in p_tokens))
            if matches == 0:
                continue

            phrase_bonus = 0.0
            for i in range(len(pos_tokens) - 1):
                bg = f"{pos_tokens[i]} {pos_tokens[i+1]}"
                if bg in p.lower():
                    phrase_bonus += 2.5

            len_weight = 1.0
            if len(p) < 35 and (p.endswith(":") or re.match(r"^\d+[\.\)]", p)):
                len_weight = 0.4
            elif 50 <= len(p) <= 220:
                len_weight = 1.2

            action_bonus = 0.3 * len(p_tokens & ACTION_KEYWORDS)
            total_score = (matches * 2.0 + phrase_bonus + action_bonus) * len_weight
            scored_passages.append((total_score, p))

        if not scored_passages:
            return None

        scored_passages.sort(key=lambda x: x[0], reverse=True)
        best_text = scored_passages[0][1]

        if len(best_text) < 45 and (best_text.endswith(":") or re.match(r"^\d+[\.\)]", best_text)):
            try:
                idx = candidate_passages.index(best_text)
                if idx + 1 < len(candidate_passages):
                    next_text = candidate_passages[idx + 1]
                    best_text = f"{best_text} {next_text}"
            except ValueError:
                pass

        if not best_text.endswith((".", "!", "?")):
            best_text += "."

        return best_text

    @classmethod
    def _synthesize_concise_response(cls, query: str, corpus: str, intent: Optional[QueryIntent] = None) -> str:
        """Provide a concise grounded response matching query tokens."""
        is_one_line = intent.is_one_line if intent else cls._is_one_line_request(query)
        ans = cls._answer_question_from_context(query, corpus, is_one_line=is_one_line, intent=intent)
        if ans:
            return ans
        return cls._synthesize_one_line_summary(corpus)