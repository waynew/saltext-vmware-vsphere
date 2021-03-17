import logging
import sys

import salt.utils.platform
import saltext.vmware_vsphere.utils.vmware_vsphere

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


__virtualname__ = "vmware_vsphere"


def __virtual__():
    return __virtualname__


def _get_proxy_connection_details():
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
    proxy_details = [
        details.get("vcenter") if "vcenter" in details else details.get("host"),
        details.get("username"),
        details.get("password"),
        details.get("protocol"),
        details.get("port"),
        details.get("mechanism"),
        details.get("principal"),
        details.get("domain"),
    ]
    if "verify_ssl" in details:
        proxy_details.append(details.get("verify_ssl"))
    return tuple(proxy_details)


@depends(HAS_PYVMOMI)
def _get_service_instance_via_proxy():
    """
    Returns a service instance to the proxied endpoint (vCenter/ESXi host).

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    Note:
        Should be used by state functions not invoked directly.

    CLI Example:

        See note above
    """
    connection_details = _get_proxy_connection_details()
    return saltext.vmware_vsphere.utils.vmware_vsphere.get_service_instance(  # pylint: disable=no-value-for-parameter
        *connection_details
    )


@depends(HAS_PYVMOMI)
def _get_service_instance():
    """
    Get the service instance using credentials from configuration or pillar.
    """
    vsphere_host = (
        __salt__["config.get"]("vsphere.host")
        or __salt__["config.get"]("vsphere:host")
        or __salt__["pillar.get"]("vsphere.host")
    )

    vsphere_username = (
        __salt__["config.get"]("vsphere.username")
        or __salt__["config.get"]("vsphere:username")
        or __salt__["pillar.get"]("vsphere.username")
    )

    vsphere_password = (
        __salt__["config.get"]("vsphere.password")
        or __salt__["config.get"]("vsphere:password")
        or __salt__["pillar.get"]("vsphere.password")
    )

    vsphere_protocol = (
        __salt__["config.get"]("vsphere.protocol")
        or __salt__["config.get"]("vsphere:protocol")
        or __salt__["pillar.get"]("vsphere.protocol")
    )

    vsphere_port = (
        __salt__["config.get"]("vsphere.port")
        or __salt__["config.get"]("vsphere:port")
        or __salt__["pillar.get"]("vsphere.port")
    )

    verify_ssl = (
        __salt__["config.get"]("vsphere.verify_ssl")
        or __salt__["config.get"]("vsphere:verify_ssl")
        or __salt__["pillar.get"]("vsphere.verify_ssl")
    )

    return saltext.vmware_vsphere.utils.vmware_vsphere.get_service_instance(
        host=vsphere_host,
        username=vsphere_username,
        password=vsphere_password,
        protocol=vsphere_protocol,
        port=vsphere_port,
        verify_ssl=verify_ssl,
    )

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

@depends(HAS_PYVMOMI)
def power_on_vm(name, datacenter=None, **kwargs):
    """
    Powers on a virtual machine specified by its name.

    name
        Name of the virtual machine

    datacenter
        Datacenter of the virtual machine

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.power_on_vm name=my_vm

    """
    if salt.utils.platform.is_proxy():
        service_instance = _get_service_instance_via_proxy()
    else:
        service_instance = _get_service_instance()

    log.trace("Powering on virtual machine {}".format(name))
    vm_properties = ["name", "summary.runtime.powerState"]
    virtual_machine = saltext.vmware_vsphere.utils.vmware_vsphere_vsphere.get_vm_by_property(
        service_instance, 
        name,
        datacenter=datacenter,
        vm_properties=vm_properties
    )
    if virtual_machine["summary.runtime.powerState"] == "poweredOn":
        result = {
            "comment": "Virtual machine is already powered on",
            "changes": {"power_on": True},
        }
        return result
    saltext.vmware_vsphere.utils.vmware_vsphere_vsphere.power_cycle_vm(virtual_machine["object"], action="on")
    result = {
        "comment": "Virtual machine power on action succeeded",
        "changes": {"power_on": True},
    }
    return result


@depends(HAS_PYVMOMI)
def power_off_vm(name, datacenter=None):
    """
    Powers off a virtual machine specified by its name.

    name
        Name of the virtual machine

    datacenter
        Datacenter of the virtual machine

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.power_off_vm name=my_vm

    """
    if salt.utils.platform.is_proxy():
        service_instance = _get_service_instance_via_proxy()
    else:
        service_instance = _get_service_instance()

    log.trace("Powering off virtual machine {}".format(name))
    vm_properties = ["name", "summary.runtime.powerState"]
    virtual_machine = saltext.vmware_vsphere.utils.vmware_vsphere_vsphere.get_vm_by_property(
        service_instance, 
        name,
        datacenter=datacenter,
        vm_properties=vm_properties
    )
    if virtual_machine["summary.runtime.powerState"] == "poweredOff":
        result = {
            "comment": "Virtual machine is already powered off",
            "changes": {"power_off": True},
        }
        return result
    saltext.vmware_vsphere.utils.vmware_vsphere_vsphere.power_cycle_vm(virtual_machine["object"], action="off")
    result = {
        "comment": "Virtual machine power off action succeeded",
        "changes": {"power_off": True},
    }
    return result

@depends(HAS_PYVMOMI)
def list_vms():
    """
    Returns a list of VMs for the specified host.

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

        salt '*' vsphere.list_vms 1.2.3.4 root bad-password
    """
    if salt.utils.platform.is_proxy():
        service_instance = _get_service_instance_via_proxy()
    else:
        service_instance = _get_service_instance()

    return saltext.vmware_vsphere.utils.vmware_vsphere.list_vms(service_instance)

@depends(HAS_PYVMOMI)
def delete_vm(name, datacenter, placement=None, power_off=False):
    """
    Deletes a virtual machine defined by name and placement

    name
        Name of the virtual machine

    datacenter
        Datacenter of the virtual machine

    placement
        Placement information of the virtual machine

    service_instance
        vCenter service instance for connection and configuration

    .. code-block:: bash

        salt '*' vsphere.delete_vm name=my_vm datacenter=my_datacenter

    """
    if salt.utils.platform.is_proxy():
        service_instance = _get_service_instance_via_proxy()
    else:
        service_instance = _get_service_instance()

    results = {}
    schema = ESXVirtualMachineDeleteSchema.serialize()
    try:
        jsonschema.validate(
            {"name": name, "datacenter": datacenter, "placement": placement}, schema
        )
    except jsonschema.exceptions.ValidationError as exc:
        raise InvalidConfigError(exc)
    (results, vm_ref) = _remove_vm(
        name,
        datacenter,
        service_instance=service_instance,
        placement=placement,
        power_off=power_off,
    )
    saltext.vmware_vsphere.utils.vmware_vsphere.delete_vm(vm_ref)
    results["deleted_vm"] = True
    return results

@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_datacenters():
    """
    Returns a list of datacenters for the specified host.
    """
    if salt.utils.platform.is_proxy():
        service_instance = _get_service_instance_via_proxy()
    else:
        service_instance = _get_service_instance()

    return saltext.vmware_vsphere.utils.vmware_vsphere.list_datacenters(service_instance)
