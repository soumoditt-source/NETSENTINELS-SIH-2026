from netsentinel.coverage import get_coverage


def test_coverage_contract_has_explicit_boundary_and_states():
    coverage = get_coverage()

    assert coverage["as_of"] == "2026-08-30"
    assert coverage["counts"]["active"] > 0
    assert coverage["counts"]["partial"] > 0
    assert coverage["counts"]["out_of_scope"] > 0
    assert len(coverage["items"]) == sum(coverage["counts"].values())
    assert all(item["limitation"] for item in coverage["items"])


def test_coverage_includes_sih_core_network_families():
    names = {item["name"] for item in get_coverage()["items"]}

    assert "Direct TCP SYN and UDP flood" in names
    assert "Horizontal and vertical port scanning" in names
    assert "DNS-based C2 and DNS tunneling" in names
    assert "Large outbound transfer and asymmetric flow volume" in names
    assert "Living-off-the-land, process injection, fileless execution, and persistence" in names
