"""
Salt state module
"""
import logging

log = logging.getLogger(__name__)

__virtualname__ = "vcenter"


def __virtual__():
    # To force a module not to load return something like:
    #   return (False, "The vra state module is not implemented yet")
    return __virtualname__
