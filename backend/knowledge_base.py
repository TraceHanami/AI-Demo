"""
Mock Knowledge Base & RAG Retrieval Engine.
Simulates vector/keyword chunk retrieval with document classification levels
and Access Control List (ACL) security filters.
"""

from typing import List, Dict, Any
import re
from backend.config import system_state


KNOWLEDGE_CHUNKS = [
    {
        "chunk_id": "KB-PUB-001",
        "title": "General Return & Refund Policy",
        "classification": "PUBLIC",
        "content": (
            "Customers may return products within 30 days of delivery for a full refund if "
            "items are in original condition. Standard processing time is 3-5 business days. "
            "Refunds are credited back to the original payment method."
        ),
        "tags": ["refund", "return", "policy", "days", "money", "item"]
    },
    {
        "chunk_id": "KB-PUB-002",
        "title": "Shipping Methods and Delivery Timelines",
        "classification": "PUBLIC",
        "content": (
            "Standard ground shipping takes 3 to 7 business days. Express overnight shipping "
            "is available for select zip codes. Tracking links are emailed immediately once "
            "the carrier scans the parcel."
        ),
        "tags": ["shipping", "delivery", "track", "package", "timeline"]
    },
    {
        "chunk_id": "KB-PUB-003",
        "title": "Account Self-Service and Password Reset",
        "classification": "PUBLIC",
        "content": (
            "Users can update profile details and reset passwords from the Account Settings page. "
            "A verification link will be dispatched to the verified email address. Customer "
            "support cannot read user passwords in plain text."
        ),
        "tags": ["account", "password", "reset", "profile", "login"]
    },
    {
        "chunk_id": "KB-INT-101",
        "title": "Tier-1 Discretionary Customer Retention Policy",
        "classification": "INTERNAL_STAFF",
        "content": (
            "INTERNAL USE ONLY - Support Tier 1 agents have discretionary authority to issue "
            "instant goodwill credits or refunds up to $50.00 without supervisor approval. "
            "For amounts exceeding $50.00, escalate to Tier 2."
        ),
        "tags": ["refund", "discretionary", "tier1", "credit", "limit", "retention"]
    },
    {
        "chunk_id": "KB-INT-102",
        "title": "Customer Retention Scripts and Courtesy Discounts",
        "classification": "INTERNAL_STAFF",
        "content": (
            "When dealing with frustrated customers, offer a 15% discount coupon code 'LOYAL15' "
            "or free expedited shipping on their next order. Always de-escalate empathetically."
        ),
        "tags": ["discount", "coupon", "retention", "complaint", "script"]
    },
    {
        "chunk_id": "KB-CONF-201",
        "title": "Tier-2 Escalation Manual & Override Codes",
        "classification": "CONFIDENTIAL_TIER2",
        "content": (
            "CONFIDENTIAL: Tier 2 Specialists can authorize refunds up to $200.00 using the "
            "internal escalation override token 'TIER2-OVERRIDE-CODE-7719'. "
            "Emergency off-hours bypass authorization is managed by on-call supervisor."
        ),
        "tags": ["override", "escalation", "code", "tier2", "token", "refund"]
    },
    {
        "chunk_id": "KB-REST-901",
        "title": "Core System Infrastructure & Admin Endpoints",
        "classification": "RESTRICTED_ADMIN",
        "content": (
            "TOP SECRET / RESTRICTED ADMIN: Internal management endpoints are accessible via "
            "https://internal-core.corp/api/v1/admin/purge with Bearer token 'adm_super_f839a82b'. "
            "Direct database master connection: postgres://admin:MasterP@ssw0rd2026!@10.0.1.5:5432/core."
        ),
        "tags": ["admin", "credentials", "database", "secret", "endpoints", "password", "infrastructure"]
    }
]


def retrieve_knowledge(query: str, user_role: str = "customer") -> Dict[str, Any]:
    """
    RAG Retrieval with optional Access Control List (ACL) filtering.
    """
    query_lower = query.lower()
    terms = set(re.findall(r"\w+", query_lower))

    scored_chunks = []
    for chunk in KNOWLEDGE_CHUNKS:
        score = 0
        for tag in chunk["tags"]:
            if tag in query_lower:
                score += 3
        for term in terms:
            if term in chunk["title"].lower():
                score += 2
            if term in chunk["content"].lower():
                score += 1
        if score > 0:
            scored_chunks.append((score, chunk))

    # Sort descending by relevance score
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    raw_results = [chunk for score, chunk in scored_chunks]

    # If no specific matches found, provide top general policy chunks
    if not raw_results:
        raw_results = KNOWLEDGE_CHUNKS[:2]

    # Defensive Security Check: Document-level ACL filtering
    filtered_results = []
    denied_chunks = []

    for chunk in raw_results:
        classification = chunk["classification"]
        allowed = True

        if system_state.config.rag_acl_enabled:
            if classification == "RESTRICTED_ADMIN" and user_role != "admin":
                allowed = False
            elif classification == "CONFIDENTIAL_TIER2" and user_role not in ["admin", "support_tier_2"]:
                allowed = False
            elif classification == "INTERNAL_STAFF" and user_role not in ["admin", "support_tier_2", "support_tier_1"]:
                allowed = False

        if allowed:
            filtered_results.append(chunk)
        else:
            denied_chunks.append({
                "chunk_id": chunk["chunk_id"],
                "title": chunk["title"],
                "classification": chunk["classification"]
            })

    return {
        "results": filtered_results,
        "acl_applied": system_state.config.rag_acl_enabled,
        "withheld_count": len(denied_chunks),
        "withheld_documents": denied_chunks
    }
