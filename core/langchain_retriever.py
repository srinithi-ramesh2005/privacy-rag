"""
Modular LangChain RAG Retrieval Pipeline.
Upgraded to BAAI/bge-small-en-v1.5 (384-dimensional) and Groq Llama 3.3 70B / local FlashRank reranking.

Implements:
1. Qdrant Vector Store connection (Docker at localhost:6333).
2. HuggingFace Embeddings (BAAI/bge-small-en-v1.5, 384-dimensional).
3. Fast MultiQueryRetriever expansion via Groq (llama-3.3-70b-versatile) or direct base vector retrieval.
4. Local FlashRank cross-encoder reranking (Top 10 -> Top 3).
"""
from __future__ import annotations

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import logging
import warnings
from functools import lru_cache
from typing import Any, List, Optional

from qdrant_client import QdrantClient

warnings.filterwarnings("ignore", category=DeprecationWarning)
logger = logging.getLogger("LangChainRetriever")


@lru_cache(maxsize=1)
def _get_qdrant_client(qdrant_url: str = "http://localhost:6333") -> QdrantClient:
    return QdrantClient(url=qdrant_url)


from langchain_core.embeddings import Embeddings

class LocalEmbeddingAdapter(Embeddings):
    """Zero-overhead LangChain embedding interface reusing pre-warmed EmbeddingService."""
    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        from core.embedding_service import EmbeddingService
        vecs = EmbeddingService.embed_batch(texts)
        return vecs.tolist()

    def embed_query(self, text: str) -> List[float]:
        from core.embedding_service import EmbeddingService
        vec = EmbeddingService.embed(text)
        return vec.tolist()


@lru_cache(maxsize=1)
def _get_embeddings():
    return LocalEmbeddingAdapter()


@lru_cache(maxsize=1)
def _get_compressor():
    try:
        from langchain.retrievers.document_compressors import FlashrankRerank
    except ImportError:
        from langchain_community.document_compressors.flashrank_rerank import FlashrankRerank

    return FlashrankRerank(
        model="ms-marco-TinyBERT-L-2-v2",
        top_n=7,
    )


def _resolve_document_text(
    doc: Any,
    client: Optional[QdrantClient] = None,
    collection_name: str = "org_1_collection",
) -> str:
    """Extract raw plaintext from Document, supporting decrypted payloads if present."""
    if hasattr(doc, "page_content") and doc.page_content:
        return doc.page_content.strip()

    metadata = getattr(doc, "metadata", {})
    if isinstance(metadata, dict):
        if "text" in metadata and metadata["text"]:
            return str(metadata["text"]).strip()

        # Prioritize in-memory metadata payload before making HTTP retrieve requests
        ciphertext = metadata.get("encrypted_content")
        nonce = metadata.get("nonce")
        if ciphertext and nonce:
            try:
                from crypto.encryption import decrypt_aes_gcm
                from config.settings import get_settings
                return decrypt_aes_gcm(
                    ciphertext,
                    nonce,
                    get_settings().DEFAULT_ENCRYPTION_KEY,
                ).strip()
            except Exception as e:
                logger.debug(f"Direct payload decrypt note: {e}")

        point_id = metadata.get("_id")
        if point_id and client:
            try:
                from crypto.encryption import decrypt_aes_gcm
                from config.settings import get_settings

                pts = client.retrieve(
                    collection_name=collection_name,
                    ids=[point_id],
                    with_payload=True,
                )
                if pts and pts[0].payload:
                    payload = pts[0].payload
                    if "text" in payload and payload["text"]:
                        return str(payload["text"]).strip()
                    ciphertext = payload.get("encrypted_content")
                    nonce = payload.get("nonce")
                    if ciphertext and nonce:
                        return decrypt_aes_gcm(
                            ciphertext,
                            nonce,
                            get_settings().DEFAULT_ENCRYPTION_KEY,
                        ).strip()
            except Exception as e:
                logger.debug(f"Payload extraction note: {e}")

    return str(getattr(doc, "page_content", "")).strip()


def retrieve_optimized_chunks(
    user_query: str,
    collection_name: str = "org_1_collection",
    qdrant_url: str = "http://localhost:6333",
    groq_model: str = "llama-3.3-70b-versatile",
) -> List[str]:
    """
    Executes high-accuracy multi-query expansion, Qdrant retrieval, and FlashRank
    reranking. Returns the raw text of the top 3 chunks.

    Args:
        user_query: The incoming natural language question or search query.
        collection_name: Name of the target Qdrant collection (default: "org_1_collection").
        qdrant_url: URL for the local Qdrant instance.
        groq_model: Model name for LLM query expansion.

    Returns:
        List of up to 3 raw text strings [chunk1, chunk2, chunk3].
    """
    try:
        from langchain.retrievers.multi_query import MultiQueryRetriever
    except ImportError:
        try:
            from langchain_classic.retrievers import MultiQueryRetriever
        except ImportError:
            MultiQueryRetriever = None

    from langchain_qdrant import QdrantVectorStore

    client = _get_qdrant_client(qdrant_url)
    embeddings = _get_embeddings()

    # 1. Connect to existing Qdrant collection
    vector_store = QdrantVectorStore(
        client=client,
        collection_name=collection_name,
        embedding=embeddings,
        content_payload_key="text",
    )
    base_retriever = vector_store.as_retriever(search_kwargs={"k": 20})

    # 2. Base Vector Retrieval & Local FlashRank Cross-Encoder
    # Uses local vector retrieval directly to preserve 100% of LLM API quota for conversational synthesis
    try:
        candidate_docs = base_retriever.invoke(user_query)
    except Exception as bre:
        logger.debug(f"Base vector retriever fallback note: {bre}")
        candidate_docs = []

    # 3. Ensure document page_content is populated before reranking
    for doc in candidate_docs:
        if not getattr(doc, "page_content", None):
            doc.page_content = _resolve_document_text(
                doc, client=client, collection_name=collection_name
            )

    # 4. Local FlashRank Cross-Encoder Reranking (top 10 -> top 3)
    compressor = _get_compressor()
    ranked_documents = compressor.compress_documents(
        documents=candidate_docs,
        query=user_query,
    )

    # 5. Extract raw string texts
    final_chunks = [
        _resolve_document_text(doc, client=client, collection_name=collection_name)
        for doc in ranked_documents
    ]

    return [chunk for chunk in final_chunks if chunk][:7]
