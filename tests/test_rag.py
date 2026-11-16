import pytest

from rewa.rag import INDICATOR_QUERIES, get_retriever


@pytest.mark.parametrize("q,doc", [("vssadmin delete shadows", "KB03"), ("isolate the infected host", "KB02"),
                                   ("winword spawned powershell encoded", "KB06"), ("net stop WinDefend antivirus stopped", "KB04"),
                                   ("report ransomware Canada Cyber Centre", "KB08")])
def test_expected_doc_in_top3(q, doc):
    assert doc in [h["doc_id"] for h in get_retriever().search(q, k=3)]


def test_empty_query_returns_nothing():
    assert get_retriever().search("   ") == []


def test_every_indicator_query_retrieves_something():
    r = get_retriever()
    for q in INDICATOR_QUERIES.values():
        assert r.search(q, k=2)


def test_chunks_have_sources():
    assert all(c.sources for c in get_retriever().chunks)
