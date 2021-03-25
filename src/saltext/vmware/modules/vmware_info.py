import logging
import sys

import saltext.vmware.utils.vmware

from salt.utils.decorators import depends, ignores_kwargs

log = logging.getLogger(__name__)

try:
    # pylint: disable=no-name-in-module
    from pyVmomi import (
        vim,
        vmodl,
        pbm,
        VmomiSupport,
    )

    # pylint: enable=no-name-in-module

    # We check the supported vim versions to infer the pyVmomi version
    if (
        "vim25/6.0" in VmomiSupport.versionMap
        and sys.version_info > (2, 7)
        and sys.version_info < (2, 7, 9)
    ):

        log.debug(
            "pyVmomi not loaded: Incompatible versions " "of Python. See Issue #29537."
        )
        raise ImportError()
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False


__virtualname__ = "vmware_info"


def __virtual__():
    return __virtualname__


def get_proxy_type():
    """
    Returns the proxy type retrieved either from the pillar of from the proxy
    minion's config.  Returns ``<undefined>`` otherwise.

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.get_proxy_type
    """
    if __pillar__.get("proxy", {}).get("proxytype"):
        return __pillar__["proxy"]["proxytype"]
    if __opts__.get("proxy", {}).get("proxytype"):
        return __opts__["proxy"]["proxytype"]
    return "<undefined>"


def get_proxy_connection_details():
    """
    Returns the connection details of the following proxies: esxi
    """
    proxytype = get_proxy_type()
    if proxytype == "esxi":
        details = __salt__["esxi.get_details"]()
    elif proxytype == "esxcluster":
        details = __salt__["esxcluster.get_details"]()
    elif proxytype == "esxdatacenter":
        details = __salt__["esxdatacenter.get_details"]()
    elif proxytype == "vcenter":
        details = __salt__["vcenter.get_details"]()
    elif proxytype == "esxvm":
        details = __salt__["esxvm.get_details"]()
    else:
        raise CommandExecutionError("'{}' proxy is not supported" "".format(proxytype))

    proxy_details = {
        "username": details.get("username"),
        "password": details.get("password"),
        "protocol": details.get("protocol"),
        "port": details.get("port"),
        "mechanism": details.get("mechanism", "userpass"), 
        "principal": details.get("principal"),
        "domain": details.get("domain"),
        "verify_ssl": details.get("verify_ssl", True),
    }
    if "vcenter" in details:
        proxy_details["vcenter"] = vcenter

    if "host" in details:
        proxy_details["host"] = host 

    return proxy_details


def get_connection_details(host=None,
                           vcenter=None,
                           username=None,
                           password=None,
                           protocol=None,
                           port=None,
                           mechanism=None,
                           principal=None,
                           domain=None,
                           verify_ssl=None):
    """
    Returns the connection details of the following proxies: esxi
    """
    if not host:
        host = (
            __salt__["config.get"]("vmware.host")
            or __salt__["config.get"]("vmware:host")
            or __salt__["pillar.get"]("vmware.host")
            or None
        )

    if not vcenter:
        vcenter = (
            __salt__["config.get"]("vmware.vcenter")
            or __salt__["config.get"]("vmware:vcenter")
            or __salt__["pillar.get"]("vmware.vcenter")
            or None
        )

    if not username:
        username = (
            __salt__["config.get"]("vmware.username")
            or __salt__["config.get"]("vmware:username")
            or __salt__["pillar.get"]("vmware.username")
            or None
        )

    if not password:
        password = (
            __salt__["config.get"]("vmware.password")
            or __salt__["config.get"]("vmware:password")
            or __salt__["pillar.get"]("vmware.password")
            or None
        )

    if not protocol:
        protocol = (
            __salt__["config.get"]("vmware.protocol")
            or __salt__["config.get"]("vmware:protocol")
            or __salt__["pillar.get"]("vmware.protocol")
            or None
        )

    if not port:
        port = (
            __salt__["config.get"]("vmware.port")
            or __salt__["config.get"]("vmware:port")
            or __salt__["pillar.get"]("vmware.port")
            or None
        )

    if not mechanism:
        mechanism = (
            __salt__["config.get"]("vmware.mechanism")
            or __salt__["config.get"]("vmware:mechanism")
            or __salt__["pillar.get"]("vmware.mechanism")
            or "userpass"
        )

    if not principal:
        principal = (
            __salt__["config.get"]("vmware.principal")
            or __salt__["config.get"]("vmware:principal")
            or __salt__["pillar.get"]("vmware.principal")
            or None
        )

    if not domain:
        domain = (
            __salt__["config.get"]("vmware.domain")
            or __salt__["config.get"]("vmware:domain")
            or __salt__["pillar.get"]("vmware.domain")
            or None
        )

    if verify_ssl == None:
        verify_ssl = (
            __salt__["config.get"]("vmware.verify_ssl")
            or __salt__["config.get"]("vmware:verify_ssl")
            or __salt__["pillar.get"]("vmware.verify_ssl")
            or True
        )

    proxy_details = {
        "username": username,
        "password": password,
        "protocol": protocol,
        "port": port,
        "mechanism": mechanism, 
        "principal": principal,
        "domain": domain,
        "verify_ssl": verify_ssl,
    }
    if vcenter:
        proxy_details["vcenter"] = vcenter

    if host:
        proxy_details["host"] = host 

    return proxy_details


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def system_info(
    host=None,
    vcenter=None,
    username=None,
    password=None,
    protocol=None,
    port=None,
    verify_ssl=True,
):
    """
    Return system information about a VMware environment.

    host
        The location of the host.

    username
        The username used to login to the host, such as ``root``.

    password
        The password used to login to the host.

    protocol
        Optionally set to alternate protocol if the host is not using the default
        protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the host is not using the default
        port. Default port is ``443``.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.system_info 1.2.3.4 root bad-password
    """
    if salt.utils.platform.is_proxy():
        details = __salt__["vmware_info.get_proxy_connection_details"]()
    else:
        details = __salt__["vmware_info.get_connection_details"](host=host,
                                                                 vcenter=vcenter,
                                                                 username=username,
                                                                 password=password,
                                                                 protocol=protocol,
                                                                 port=port,
                                                                 verify_ssl=verify_ssl)
    service_instance = saltext.vmware.utils.vmware.get_service_instance(**details)

    ret = salt.utils.vmware.get_inventory(service_instance).about.__dict__
    if "apiType" in ret:
        if ret["apiType"] == "HostAgent":
            ret = dictupdate.update(
                ret, salt.utils.vmware.get_hardware_grains(service_instance)
            )
    return ret
