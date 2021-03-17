"""
Salt execution module
"""
import logging

import saltext.vcenter.utils.bloop as bloop

log = logging.getLogger(__name__)

__virtualname__ = "vcenter"


def __virtual__():
    # To force a module not to load return something like:
    #   return (False, "The vra execution module is not implemented yet")
    return __virtualname__


def echo(text):
    return text


def boop():
    return bloop.voom()


def cli_echo(text):
    return __salt__["cmd.run_stdout"](["echo", text])
