import os
from pathlib import Path

import pytest


@pytest.fixture(scope="package")
def master(master):
    with master.started():
        yield master


@pytest.fixture(scope="package")
def minion(minion):
    with minion.started():
        yield minion


@pytest.fixture
def salt_run_cli(master):
    return master.get_salt_run_cli()


@pytest.fixture
def salt_cli(master):
    return master.get_salt_cli()


@pytest.fixture
def salt_call_cli(minion):
    return minion.get_salt_call_cli()


@pytest.fixture(scope="session")
def service_instance():
    default_path = Path().parent.parent / "local" / "vcenter.conf"
    config_path = os.environ.get("VCENTER_CONFIG", default_path)
    return str(config_path)
