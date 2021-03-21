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


__virtualname__ = "vmware_datastore"


def __virtual__():
    return __virtualname__


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_datastore_clusters(
    host, username, password, protocol=None, port=None, verify_ssl=True
):
    """
    Returns a list of datastore clusters for the specified host.

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

        salt '*' vsphere.list_datastore_clusters 1.2.3.4 root bad-password
    """
    service_instance = saltext.vmware.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return saltext.vmware.utils.vmware.list_datastore_clusters(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_datastores(
    host, username, password, protocol=None, port=None, verify_ssl=True
):
    """
    Returns a list of datastores for the specified host.

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

        salt '*' vsphere.list_datastores 1.2.3.4 root bad-password
    """
    service_instance = saltext.vmware.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return saltext.vmware.utils.vmware.list_datastores(service_instance)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_default_storage_policy_of_datastore(datastore, service_instance=None):
    """
    Returns a list of datastores assign the storage policies.

    datastore
        Name of the datastore to assign.
        The datastore needs to be visible to the VMware entity the proxy
        points to.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_default_storage_policy_of_datastore datastore=ds1
    """
    log.trace(
        "Listing the default storage policy of datastore '{}'" "".format(datastore)
    )
    # Find datastore
    target_ref = _get_proxy_target(service_instance)
    ds_refs = salt.utils.vmware.get_datastores(
        service_instance, target_ref, datastore_names=[datastore]
    )
    if not ds_refs:
        raise VMwareObjectRetrievalError(
            "Datastore '{}' was not " "found".format(datastore)
        )
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policy = salt.utils.pbm.get_default_storage_policy_of_datastore(
        profile_manager, ds_refs[0]
    )
    return _get_policy_dict(policy)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def assign_default_storage_policy_to_datastore(
    policy, datastore, service_instance=None
):
    """
    Assigns a storage policy as the default policy to a datastore.

    policy
        Name of the policy to assign.

    datastore
        Name of the datastore to assign.
        The datastore needs to be visible to the VMware entity the proxy
        points to.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.assign_storage_policy_to_datastore
            policy='policy name' datastore=ds1
    """
    log.trace("Assigning policy {} to datastore {}" "".format(policy, datastore))
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    # Find policy
    policies = salt.utils.pbm.get_storage_policies(profile_manager, [policy])
    if not policies:
        raise VMwareObjectRetrievalError("Policy '{}' was not found" "".format(policy))
    policy_ref = policies[0]
    # Find datastore
    target_ref = _get_proxy_target(service_instance)
    ds_refs = salt.utils.vmware.get_datastores(
        service_instance, target_ref, datastore_names=[datastore]
    )
    if not ds_refs:
        raise VMwareObjectRetrievalError(
            "Datastore '{}' was not " "found".format(datastore)
        )
    ds_ref = ds_refs[0]
    salt.utils.pbm.assign_default_storage_policy_to_datastore(
        profile_manager, policy_ref, ds_ref
    )
    return True


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "esxcluster", "vcenter", "esxvm")
@_gets_service_instance_via_proxy
def list_datacenters_via_proxy(datacenter_names=None, service_instance=None):
    """
    Returns a list of dict representations of VMware datacenters.
    Connection is done via the proxy details.

    Supported proxies: esxdatacenter

    datacenter_names
        List of datacenter names.
        Default is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_datacenters_via_proxy

        salt '*' vsphere.list_datacenters_via_proxy dc1

        salt '*' vsphere.list_datacenters_via_proxy dc1,dc2

        salt '*' vsphere.list_datacenters_via_proxy datacenter_names=[dc1, dc2]
    """
    if not datacenter_names:
        dc_refs = salt.utils.vmware.get_datacenters(
            service_instance, get_all_datacenters=True
        )
    else:
        dc_refs = salt.utils.vmware.get_datacenters(service_instance, datacenter_names)

    return [
        {"name": salt.utils.vmware.get_managed_object_name(dc_ref)}
        for dc_ref in dc_refs
    ]


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxi")
@_gets_service_instance_via_proxy
def create_vmfs_datastore(
    datastore_name,
    disk_id,
    vmfs_major_version,
    safety_checks=True,
    service_instance=None,
):
    """
    Creates a ESXi host disk group with the specified cache and capacity disks.

    datastore_name
        The name of the datastore to be created.

    disk_id
        The disk id (canonical name) on which the datastore is created.

    vmfs_major_version
        The VMFS major version.

    safety_checks
        Specify whether to perform safety check or to skip the checks and try
        performing the required task. Default is True.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.create_vmfs_datastore datastore_name=ds1 disk_id=
            vmfs_major_version=5
    """


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_default_storage_policy_of_datastore(datastore, service_instance=None):
    """
    Returns a list of datastores assign the storage policies.

    datastore
        Name of the datastore to assign.
        The datastore needs to be visible to the VMware entity the proxy
        points to.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_default_storage_policy_of_datastore datastore=ds1
    """
    log.trace(
        "Listing the default storage policy of datastore '{}'" "".format(datastore)
    )
    # Find datastore
    target_ref = _get_proxy_target(service_instance)
    ds_refs = salt.utils.vmware.get_datastores(
        service_instance, target_ref, datastore_names=[datastore]
    )
    if not ds_refs:
        raise VMwareObjectRetrievalError(
            "Datastore '{}' was not " "found".format(datastore)
        )
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policy = salt.utils.pbm.get_default_storage_policy_of_datastore(
        profile_manager, ds_refs[0]
    )
    return _get_policy_dict(policy)

    log.debug("Validating vmfs datastore input")
    schema = VmfsDatastoreSchema.serialize()
    try:
        jsonschema.validate(
            {
                "datastore": {
                    "name": datastore_name,
                    "backing_disk_id": disk_id,
                    "vmfs_version": vmfs_major_version,
                }
            },
            schema,
        )
    except jsonschema.exceptions.ValidationError as exc:
        raise ArgumentValueError(exc)
    host_ref = _get_proxy_target(service_instance)
    hostname = __proxy__["esxi.get_details"]()["esxi_host"]
    if safety_checks:
        disks = salt.utils.vmware.get_disks(host_ref, disk_ids=[disk_id])
        if not disks:
            raise VMwareObjectRetrievalError(
                "Disk '{}' was not found in host '{}'".format(disk_id, hostname)
            )
    ds_ref = salt.utils.vmware.create_vmfs_datastore(
        host_ref, datastore_name, disks[0], vmfs_major_version
    )
    return True


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def rename_datastore(datastore_name, new_datastore_name, service_instance=None):
    """
    Renames a datastore. The datastore needs to be visible to the proxy.

    datastore_name
        Current datastore name.

    new_datastore_name
        New datastore name.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.rename_datastore old_name new_name
    """
    # Argument validation
    log.trace(
        "Renaming datastore {} to {}" "".format(datastore_name, new_datastore_name)
    )
    target = _get_proxy_target(service_instance)
    datastores = salt.utils.vmware.get_datastores(
        service_instance, target, datastore_names=[datastore_name]
    )
    if not datastores:
        raise VMwareObjectRetrievalError(
            "Datastore '{}' was not found" "".format(datastore_name)
        )
    ds = datastores[0]
    salt.utils.vmware.rename_datastore(ds, new_datastore_name)
    return True


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def remove_datastore(datastore, service_instance=None):
    """
    Removes a datastore. If multiple datastores an error is raised.

    datastore
        Datastore name

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.remove_datastore ds_name
    """
    log.trace("Removing datastore '{}'".format(datastore))
    target = _get_proxy_target(service_instance)
    datastores = salt.utils.vmware.get_datastores(
        service_instance, reference=target, datastore_names=[datastore]
    )
    if not datastores:
        raise VMwareObjectRetrievalError(
            "Datastore '{}' was not found".format(datastore)
        )
    if len(datastores) > 1:
        raise VMwareObjectRetrievalError(
            "Multiple datastores '{}' were found".format(datastore)
        )
    salt.utils.vmware.remove_datastore(service_instance, datastores[0])
    return True
