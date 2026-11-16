"""Retrieval-Augmented Generation: ransomware response playbook retrieval.

Knowledge base = markdown playbooks in knowledge_base/ (front matter with id,
title, sources). Documents are chunked by '## ' sections. Two interchangeable
embedding backends:
  * tfidf (default) - scikit-learn TF-IDF, zero downloads, deterministic
  * sbert           - sentence-transformers model (e.g. BAAI/bge-small-en-v1.5)
Vectors are L2-normalised and searched with cosine similarity (numpy). For a
few hundred chunks this is as fast as FAISS/Chroma and has no extra deps.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from . import config


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    section: str
    text: str
    sources: str

    def citation(self) -> str:
        return f"[{self.chunk_id}]"


def _parse(path) -> list[Chunk]:
    raw = path.read_text(encoding="utf-8")
    meta = {}
    m = re.match(r"^---\n(.*?)\n---\n", raw, re.S)
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        raw = raw[m.end():]
    doc_id = meta.get("id", path.stem.split("_")[0])
    title = meta.get("title", path.stem)
    chunks, n = [], 0
    for part in re.split(r"\n(?=## )", raw):
        part = part.strip()
        if not part.startswith("## "):
            continue
        n += 1
        head, _, body = part.partition("\n")
        chunks.append(Chunk(f"{doc_id}-{n}", doc_id, title, head.lstrip("# ").strip(), body.strip(), meta.get("sources", "")))
    return chunks


class PlaybookRetriever:
    def __init__(self, kb_dir=None, backend: str | None = None):
        self.kb_dir = kb_dir or config.KB_DIR
        self.chunks: list[Chunk] = []
        for p in sorted(self.kb_dir.glob("*.md")):
            self.chunks.extend(_parse(p))
        if not self.chunks:
            raise RuntimeError(f"No knowledge-base documents found in {self.kb_dir}")
        self.backend = backend or config.EMBEDDING_BACKEND
        texts = [f"{c.title}. {c.section}. {c.text}" for c in self.chunks]
        if self.backend == "sbert":
            try:
                from sentence_transformers import SentenceTransformer  # optional dependency

                self._model = SentenceTransformer(config.EMBEDDING_MODEL)
                self._mat = self._model.encode(texts, normalize_embeddings=True)
            except Exception:  # missing package / no model download -> safe fallback
                self.backend = "tfidf"
        if self.backend == "tfidf":
            from sklearn.feature_extraction.text import TfidfVectorizer

            self._vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
            m = self._vec.fit_transform(texts).toarray()
            self._mat = m / np.clip(np.linalg.norm(m, axis=1, keepdims=True), 1e-9, None)

    def _embed(self, q: str) -> np.ndarray:
        if self.backend == "sbert":
            return self._model.encode([q], normalize_embeddings=True)[0]
        v = self._vec.transform([q]).toarray()[0]
        return v / max(np.linalg.norm(v), 1e-9)

    def search(self, query: str, k: int | None = None, min_score: float = 0.02) -> list[dict]:
        k = k or config.RAG_TOP_K
        query = (query or "").strip()[:1000]
        if not query:
            return []
        sims = self._mat @ self._embed(query)
        order = np.argsort(-sims)
        out, seen_docs = [], {}
        for i in order:
            if sims[i] < min_score or len(out) >= k:
                break
            c = self.chunks[i]
            if seen_docs.get(c.doc_id, 0) >= 2:  # diversity: max 2 chunks per document
                continue
            seen_docs[c.doc_id] = seen_docs.get(c.doc_id, 0) + 1
            out.append({"chunk_id": c.chunk_id, "doc_id": c.doc_id, "title": c.title, "section": c.section,
                        "score": round(float(sims[i]), 4), "text": c.text, "sources": c.sources})
        return out


@lru_cache(maxsize=2)
def get_retriever(backend: str | None = None) -> PlaybookRetriever:
    return PlaybookRetriever(backend=backend)


# Query templates the agent uses per indicator (also used for retrieval eval)
INDICATOR_QUERIES = {
    "I1": "mass file rename encryption impact isolate host containment",
    "I2": "files encrypted high entropy overwrite data encrypted for impact containment",
    "I3": "ransom note created encryption response reporting do not pay",
    "I4": "shadow copy deletion vssadmin wbadmin backup deletion inhibit system recovery",
    "I5": "bcdedit recoveryenabled no boot recovery inhibition backups",
    "I6": "security service stopped antivirus EDR backup agent tampering net stop",
    "I7": "privilege escalation SeDebugPrivilege credential reset privileged accounts",
    "I8": "office spawned powershell encoded command discovery phishing initial execution",
}
