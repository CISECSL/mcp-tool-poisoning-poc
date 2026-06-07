from aisac_proxy.atlas import ATLAS_BY_RULE


def test_every_implemented_rule_has_atlas_mapping():
    expected_rule_ids = {
        "R-DESC-01",
        "R-DESC-02",
        "R-DESC-03",
        "R-TOOL-04",
        "R-CALL-05",
        "R-CALL-06",
        "R-CALL-07",
    }
    assert expected_rule_ids.issubset(ATLAS_BY_RULE.keys())


def test_atlas_entries_have_id_and_name():
    for rule_id, entry in ATLAS_BY_RULE.items():
        assert entry.id.startswith("AML."), rule_id
        assert entry.name, rule_id
