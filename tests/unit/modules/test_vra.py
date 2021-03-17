import pytest
import salt.modules.cmdmod as cmdmod
import saltext.vcenter.modules.fnord as vcenter_module


@pytest.fixture
def configure_loader_modules():
    module_globals = {"__salt__": {"cmd.run_stdout": cmdmod.run_stdout}}
    return {vcenter_module: module_globals, cmdmod: {}}


def test_echo():
    assert vcenter_module.echo("echoed") == "echoed"


def test_echo_cli():
    assert vcenter_module.cli_echo("echoed") == "echoed"
