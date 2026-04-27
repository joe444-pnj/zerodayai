"""
agents/llm/rag.py — CVE Knowledge Retrieval (RAG)

Lightweight retrieval system for NVD CVE data.
Uses TF-IDF style keyword scoring without heavy ML dependencies.
Falls back to keyword search if chromadb is unavailable.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console

console = Console()

# Optional: chromadb for semantic search
try:
    import chromadb
    try:
        from chromadb.config import Settings
    except ImportError:
        # Some versions of chromadb use different import paths or don't have Settings
        Settings = None
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    chromadb = None
    Settings = None


class CVEKnowledgeBase:
    """
    CVE knowledge retrieval. Supports two backends:
    1. ChromaDB (semantic similarity) — if installed
    2. TF-IDF keyword search (always available)
    """

    def __init__(self, cache_path: str = "knowledge/cve_cache.json"):
        self.cache_path = Path(cache_path)
        self.cve_data: List[Dict] = []
        self._tfidf_index: Dict[str, Dict[str, float]] = {}  # term -> {cve_id: score}
        self._chroma_client = None
        self._chroma_collection = None
        self._loaded = False

    def load(self) -> bool:
        """Load CVE data from local cache."""
        if not self.cache_path.exists():
            console.print(
                f"[yellow]CVE cache not found at {self.cache_path}[/yellow]\n"
                "[dim]Run: python -m knowledge.cve_loader to download CVE data[/dim]"
            )
            return False

        with open(self.cache_path, "r", encoding="utf-8") as f:
            self.cve_data = json.load(f)

        console.print(f"[green]✓ Loaded {len(self.cve_data):,} CVEs from knowledge base[/green]")
        self._build_tfidf_index()

        if CHROMADB_AVAILABLE:
            self._init_chromadb()

        self._loaded = True
        return True

    def _build_tfidf_index(self) -> None:
        """Build a simple TF-IDF inverted index over CVE descriptions."""
        # Count document frequencies
        df: Counter = Counter()
        doc_terms: List[Counter] = []

        for cve in self.cve_data:
            text = f"{cve.get('id', '')} {cve.get('description', '')}".lower()
            terms = self._tokenize(text)
            term_counts = Counter(terms)
            doc_terms.append(term_counts)
            for term in term_counts:
                df[term] += 1

        N = len(self.cve_data)
        if N == 0:
            return

        # Compute TF-IDF scores
        self._tfidf_index = defaultdict(dict)
        for idx, (cve, term_counts) in enumerate(zip(self.cve_data, doc_terms)):
            cve_id = cve.get("id", str(idx))
            total_terms = sum(term_counts.values()) or 1
            for term, count in term_counts.items():
                tf = count / total_terms
                idf = math.log((N + 1) / (df[term] + 1)) + 1
                self._tfidf_index[term][cve_id] = tf * idf

    def _init_chromadb(self) -> None:
        """Initialize ChromaDB for semantic search."""
        try:
            chroma_path = self.cache_path.parent / "chroma_db"
            self._chroma_client = chromadb.PersistentClient(
                path=str(chroma_path),
                settings=Settings(anonymized_telemetry=False) if Settings else None,
            )
            self._chroma_collection = self._chroma_client.get_or_create_collection(
                name="cve_knowledge",
                metadata={"hnsw:space": "cosine"},
            )

            # Only index if collection is empty
            if self._chroma_collection.count() == 0:
                self._index_to_chromadb()
        except Exception as e:
            console.print(f"[dim]ChromaDB init failed ({e}), falling back to TF-IDF[/dim]")
            self._chroma_collection = None

    def _index_to_chromadb(self) -> None:
        """Index CVEs into ChromaDB in batches."""
        if not self._chroma_collection or not self.cve_data:
            return

        BATCH = 500
        console.print("[dim]Building semantic search index (first run only)...[/dim]")
        for i in range(0, len(self.cve_data), BATCH):
            batch = self.cve_data[i : i + BATCH]
            ids = [c.get("id", str(i + j)) for j, c in enumerate(batch)]
            documents = [c.get("description", "") for c in batch]
            metadatas = [
                {
                    "cvss": str(c.get("cvss_score", 0.0)),
                    "cwe": c.get("cwe_id", ""),
                    "published": c.get("published", ""),
                }
                for c in batch
            ]
            self._chroma_collection.add(
                ids=ids, documents=documents, metadatas=metadatas
            )

    def search(
        self, query: str, top_k: int = 10
    ) -> List[Dict]:
        """
        Search CVEs by query text.
        Uses ChromaDB if available, otherwise TF-IDF.
        """
        if not self._loaded:
            self.load()

        if not self.cve_data:
            return []

        if self._chroma_collection:
            return self._chroma_search(query, top_k)
        return self._tfidf_search(query, top_k)

    def _tfidf_search(self, query: str, top_k: int) -> List[Dict]:
        """Score CVEs by TF-IDF relevance to query."""
        terms = self._tokenize(query.lower())
        scores: Dict[str, float] = defaultdict(float)

        for term in terms:
            if term in self._tfidf_index:
                for cve_id, score in self._tfidf_index[term].items():
                    scores[cve_id] += score

        # Build CVE lookup
        cve_map = {c.get("id"): c for c in self.cve_data}

        sorted_ids = sorted(scores, key=lambda x: scores[x], reverse=True)[:top_k]
        return [cve_map[cve_id] for cve_id in sorted_ids if cve_id in cve_map]

    def _chroma_search(self, query: str, top_k: int) -> List[Dict]:
        """Semantic similarity search via ChromaDB."""
        results = self._chroma_collection.query(
            query_texts=[query], n_results=min(top_k, self._chroma_collection.count())
        )
        cve_map = {c.get("id"): c for c in self.cve_data}
        found = []
        for cve_id in results.get("ids", [[]])[0]:
            if cve_id in cve_map:
                found.append(cve_map[cve_id])
        return found

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get a specific CVE by ID."""
        for cve in self.cve_data:
            if cve.get("id", "").upper() == cve_id.upper():
                return cve
        return None

    def search_by_cwe(self, cwe_id: str, top_k: int = 20) -> List[Dict]:
        """Find CVEs by CWE weakness type."""
        results = [
            c for c in self.cve_data
            if cwe_id.upper() in c.get("cwe_id", "").upper()
        ]
        # Sort by CVSS score
        results.sort(key=lambda x: x.get("cvss_score", 0.0), reverse=True)
        return results[:top_k]

    def search_for_finding(
        self, finding_title: str, finding_description: str, top_k: int = 5
    ) -> List[Dict]:
        """Search CVEs most relevant to a specific finding."""
        query = f"{finding_title} {finding_description}"
        return self.search(query, top_k=top_k)

    def search_by_package(
        self, package: str, version: str = "", top_k: int = 10
    ) -> List[Dict]:
        """Search CVEs by package/library name and optional version."""
        query = f"{package} {version}" if version else package
        results = self.search(query, top_k=top_k * 2)
        
        # Filter to only CVEs that mention the package name
        filtered = []
        for cve in results:
            desc = cve.get("description", "").lower()
            if package.lower() in desc:
                filtered.append(cve)
        
        return filtered[:top_k]

    def enrich_finding(self, finding) -> None:
        """Auto-populate cve_ids and cvss_score on a Finding object."""
        title = getattr(finding, "title", "")
        desc = getattr(finding, "description", "")
        
        if not title and not desc:
            return
        
        related_cves = self.search_for_finding(title, desc, top_k=5)
        
        if related_cves:
            cve_ids = [c.get("id", "") for c in related_cves if c.get("id")]
            cvss_scores = [c.get("cvss_score", 0) for c in related_cves if c.get("cvss_score")]
            
            if cve_ids:
                existing = getattr(finding, "cve_ids", "") or ""
                new_ids = ",".join(cve_ids[:5])
                finding.cve_ids = f"{existing},{new_ids}".strip(",") if existing else new_ids
            
            if cvss_scores:
                finding.cvss_score = max(cvss_scores)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Simple whitespace + punctuation tokenizer."""
        return re.findall(r"\b[a-z0-9_\-]{2,}\b", text.lower())

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def cve_count(self) -> int:
        return len(self.cve_data)


# ─── Singleton ────────────────────────────────────────────────────────

_kb_instance: Optional[CVEKnowledgeBase] = None


def get_knowledge_base(cache_path: str = "knowledge/cve_cache.json") -> CVEKnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = CVEKnowledgeBase(cache_path)
        _kb_instance.load()
    return _kb_instance


class LearningKnowledgeBase:
    """Retrieves past scan experiences from the local DB for the AI to learn from."""

    def __init__(self, cache_path: str = "knowledge/learning_cache.json"):
        self.cache_path = Path(cache_path)
        self.learnings = []
        self._loaded = False
        self._chroma_client = None
        self._chroma_collection = None

    def load(self) -> bool:
        from core.database import run_sync
        try:
            self.learnings = run_sync(self._fetch_learnings())
            if self.learnings:
                console.print(f"[green]✓ Loaded {len(self.learnings):,} past experiences from memory[/green]")
        except Exception as e:
            console.print(f"[dim]Failed to load learnings ({e})[/dim]")
            return False

        if CHROMADB_AVAILABLE and self.learnings:
            self._init_chromadb()

        self._loaded = True
        return True

    async def _fetch_learnings(self):
        from core.database import get_session
        from core.models import AgentLearning
        from sqlalchemy import select
        async with get_session() as session:
            # Only fetch learnings that have actual notes
            res = await session.execute(
                select(AgentLearning).where(AgentLearning.outcome_notes.is_not(None))
            )
            return res.scalars().all()

    def _init_chromadb(self) -> None:
        try:
            chroma_path = self.cache_path.parent / "chroma_db_learnings"
            self._chroma_client = chromadb.PersistentClient(
                path=str(chroma_path),
                settings=Settings(anonymized_telemetry=False) if Settings else None,
            )
            self._chroma_collection = self._chroma_client.get_or_create_collection(
                name="ai_learnings",
                metadata={"hnsw:space": "cosine"},
            )

            # Upsert all learnings
            if self.learnings:
                ids = [str(l.id) for l in self.learnings]
                documents = [str(l.pattern_context) for l in self.learnings]
                metadatas = [
                    {
                        "fp": str(l.is_false_positive),
                        "outcome": str(l.outcome_notes or "")
                    }
                    for l in self.learnings
                ]
                self._chroma_collection.upsert(
                    ids=ids, documents=documents, metadatas=metadatas
                )
        except Exception as e:
            console.print(f"[dim]ChromaDB init failed for learnings ({e}), falling back to text search[/dim]")
            self._chroma_collection = None

    def search_past_experiences(self, query: str, top_k: int = 5) -> str:
        if not self._loaded:
            self.load()

        if not self.learnings:
            return ""

        found = []
        if self._chroma_collection:
            count = self._chroma_collection.count()
            if count > 0:
                results = self._chroma_collection.query(
                    query_texts=[query], n_results=min(top_k, count)
                )
                found_ids = results.get("ids", [[]])[0]
                lb_map = {str(l.id): l for l in self.learnings}
                for lid in found_ids:
                    if lid in lb_map:
                        found.append(lb_map[lid])
        else:
            # Fallback keyword match
            q = query.lower()
            words = set(q.split())
            scored = []
            for l in self.learnings:
                ctx_lower = (l.pattern_context or "").lower()
                score = sum(1 for w in words if w in ctx_lower)
                if score > 0:
                    scored.append((score, l))
            scored.sort(key=lambda x: x[0], reverse=True)
            found = [l for _, l in scored[:top_k]]

        if not found:
            return ""

        exploits = []
        failed = []

        for l in found:
            block = (
                f"[PATTERN]: {l.pattern_context}\n"
                f"[OUTCOME]: {l.outcome_notes}\n"
            )
            if l.is_false_positive:
                failed.append(block)
            else:
                exploits.append(block)

        result = ""
        if exploits:
            result += f"<similar_exploits>\n" + "\n".join(exploits) + "\n</similar_exploits>\n"
        if failed:
            result += f"<failed_attempts>\n" + "\n".join(failed) + "\n</failed_attempts>\n"
        
        return result

    def search_for_endpoint(
        self, endpoint: str, params: list = None, top_k: int = 5
    ) -> str:
        """Search learnings specifically relevant to an endpoint being scanned.
        
        This is the key RAG feedback loop method — called before scanning
        each endpoint to inject past intelligence into LLM prompts.
        """
        params = params or []
        query = f"{endpoint} {' '.join(params)}"
        
        result = self.search_past_experiences(query, top_k=top_k)
        
        if result:
            return (
                f"<past_scan_intelligence>\n"
                f"In previous scans of similar endpoints, the following was discovered:\n"
                f"{result}"
                f"Use this intelligence to prioritize your analysis. "
                f"Avoid repeating known false positives.\n"
                f"</past_scan_intelligence>"
            )
        return ""


_lb_instance: Optional[LearningKnowledgeBase] = None

def get_learning_base() -> LearningKnowledgeBase:
    global _lb_instance
    if _lb_instance is None:
        _lb_instance = LearningKnowledgeBase()
        _lb_instance.load()
    return _lb_instance
