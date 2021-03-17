import pytest
import saltext.vcenter.states.fnord as vcenter_module


@pytest.fixture
def configure_loader_modules():
    module_globals = {"__salt__": {"this_does_not_exist.please_replace_it": lambda: True}}
    return {vcenter_module: module_globals}


def test_replace_this_this_with_something_meaningful():
    assert "this_does_not_exist.please_replace_it" in vcenter_module.__salt__
    assert vcenter_module.__salt__["this_does_not_exist.please_replace_it"]() is True
