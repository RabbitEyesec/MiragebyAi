from mirage_common.acceptance import acceptance_specification


def test_profile_a_uses_the_same_immutable_targets() -> None:
    value = acceptance_specification()
    assert len(value["numeric_targets"]) == 25
    assert value["repeat_rule"]
