from rewa.generator import generate_dataset


def test_deterministic_and_labelled():
    e1, l1 = generate_dataset(10, seed=3)
    e2, l2 = generate_dataset(10, seed=3)
    assert e1.equals(e2) and l1.equals(l2)
    assert set(l1.host) == set(e1.host) and l1.is_ransomware.sum() == 4


def test_ransomware_hosts_have_malicious_phases():
    e, l = generate_dataset(10, seed=5)
    for h in l[l.is_ransomware == 1].host:
        assert (e[e.host == h].phase != "benign").any()
    for h in l[l.is_ransomware == 0].host:
        assert (e[e.host == h].phase == "benign").all()
