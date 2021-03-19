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


__virtualname__ = "vmware_cluster"


def __virtual__():
    return __virtualname__


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_clusters(host, username, password, protocol=None, port=None, verify_ssl=True):
    """
    Returns a list of clusters for the specified host.

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

        salt '*' vsphere.list_clusters 1.2.3.4 root bad-password

    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_clusters(service_instance)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def list_cluster(datacenter=None, cluster=None, service_instance=None):
    """
    Returns a dict representation of an ESX cluster.

    datacenter
        Name of datacenter containing the cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    cluster
        Name of cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        # vcenter proxy
        salt '*' vsphere.list_cluster datacenter=dc1 cluster=cl1

        # esxdatacenter proxy
        salt '*' vsphere.list_cluster cluster=cl1

        # esxcluster proxy
        salt '*' vsphere.list_cluster
    """
    proxy_type = get_proxy_type()
    if proxy_type == "esxdatacenter":
        dc_ref = _get_proxy_target(service_instance)
        if not cluster:
            raise ArgumentValueError("'cluster' needs to be specified")
        cluster_ref = salt.utils.vmware.get_cluster(dc_ref, cluster)
    elif proxy_type == "esxcluster":
        cluster_ref = _get_proxy_target(service_instance)
        cluster = __salt__["esxcluster.get_details"]()["cluster"]
    log.trace(
        "Retrieving representation of cluster '{}' in a "
        "{} proxy".format(cluster, proxy_type)
    )
    return _get_cluster_dict(cluster, cluster_ref)


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def create_cluster(cluster_dict, datacenter=None, cluster=None, service_instance=None):
    """
    Creates a cluster.

    Note: cluster_dict['name'] will be overridden by the cluster param value

    config_dict
        Dictionary with the config values of the new cluster.

    datacenter
        Name of datacenter containing the cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    cluster
        Name of cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        # esxdatacenter proxy
        salt '*' vsphere.create_cluster cluster_dict=$cluster_dict cluster=cl1

        # esxcluster proxy
        salt '*' vsphere.create_cluster cluster_dict=$cluster_dict
    """
    # Validate cluster dictionary
    schema = ESXClusterConfigSchema.serialize()
    try:
        jsonschema.validate(cluster_dict, schema)
    except jsonschema.exceptions.ValidationError as exc:
        raise InvalidConfigError(exc)
    # Get required details from the proxy
    proxy_type = get_proxy_type()
    if proxy_type == "esxdatacenter":
        datacenter = __salt__["esxdatacenter.get_details"]()["datacenter"]
        dc_ref = _get_proxy_target(service_instance)
        if not cluster:
            raise ArgumentValueError("'cluster' needs to be specified")
    elif proxy_type == "esxcluster":
        datacenter = __salt__["esxcluster.get_details"]()["datacenter"]
        dc_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
        cluster = __salt__["esxcluster.get_details"]()["cluster"]

    if cluster_dict.get("vsan") and not salt.utils.vsan.vsan_supported(
        service_instance
    ):

        raise VMwareApiError("VSAN operations are not supported")
    si = service_instance
    cluster_spec = vim.ClusterConfigSpecEx()
    vsan_spec = None
    ha_config = None
    vsan_61 = None
    if cluster_dict.get("vsan"):
        # XXX The correct way of retrieving the VSAN data (on the if branch)
        #  is not supported before 60u2 vcenter
        vcenter_info = salt.utils.vmware.get_service_info(si)
        if (
            float(vcenter_info.apiVersion) >= 6.0 and int(vcenter_info.build) >= 3634794
        ):  # 60u2
            vsan_spec = vim.vsan.ReconfigSpec(modify=True)
            vsan_61 = False
            # We need to keep HA disabled and enable it afterwards
            if cluster_dict.get("ha", {}).get("enabled"):
                enable_ha = True
                ha_config = cluster_dict["ha"]
                del cluster_dict["ha"]
        else:
            vsan_61 = True
    # If VSAN is 6.1 the configuration of VSAN happens when configuring the
    # cluster via the regular endpoint
    _apply_cluster_dict(cluster_spec, cluster_dict, vsan_spec, vsan_61)
    salt.utils.vmware.create_cluster(dc_ref, cluster, cluster_spec)
    if not vsan_61:
        # Only available after VSAN 61
        if vsan_spec:
            cluster_ref = salt.utils.vmware.get_cluster(dc_ref, cluster)
            salt.utils.vsan.reconfigure_cluster_vsan(cluster_ref, vsan_spec)
        if enable_ha:
            # Set HA after VSAN has been configured
            _apply_cluster_dict(cluster_spec, {"ha": ha_config})
            salt.utils.vmware.update_cluster(cluster_ref, cluster_spec)
            # Set HA back on the object
            cluster_dict["ha"] = ha_config
    return {"create_cluster": True}


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def update_cluster(cluster_dict, datacenter=None, cluster=None, service_instance=None):
    """
    Updates a cluster.

    config_dict
        Dictionary with the config values of the new cluster.

    datacenter
        Name of datacenter containing the cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    cluster
        Name of cluster.
        Ignored if already contained by proxy details.
        Default value is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        # esxdatacenter proxy
        salt '*' vsphere.update_cluster cluster_dict=$cluster_dict cluster=cl1

        # esxcluster proxy
        salt '*' vsphere.update_cluster cluster_dict=$cluster_dict

    """
    # Validate cluster dictionary
    schema = ESXClusterConfigSchema.serialize()
    try:
        jsonschema.validate(cluster_dict, schema)
    except jsonschema.exceptions.ValidationError as exc:
        raise InvalidConfigError(exc)
    # Get required details from the proxy
    proxy_type = get_proxy_type()
    if proxy_type == "esxdatacenter":
        datacenter = __salt__["esxdatacenter.get_details"]()["datacenter"]
        dc_ref = _get_proxy_target(service_instance)
        if not cluster:
            raise ArgumentValueError("'cluster' needs to be specified")
    elif proxy_type == "esxcluster":
        datacenter = __salt__["esxcluster.get_details"]()["datacenter"]
        dc_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
        cluster = __salt__["esxcluster.get_details"]()["cluster"]

    if cluster_dict.get("vsan") and not salt.utils.vsan.vsan_supported(
        service_instance
    ):

        raise VMwareApiError("VSAN operations are not supported")

    cluster_ref = salt.utils.vmware.get_cluster(dc_ref, cluster)
    cluster_spec = vim.ClusterConfigSpecEx()
    props = salt.utils.vmware.get_properties_of_managed_object(
        cluster_ref, properties=["configurationEx"]
    )
    # Copy elements we want to update to spec
    for p in ["dasConfig", "drsConfig"]:
        setattr(cluster_spec, p, getattr(props["configurationEx"], p))
    if props["configurationEx"].vsanConfigInfo:
        cluster_spec.vsanConfig = props["configurationEx"].vsanConfigInfo
    vsan_spec = None
    vsan_61 = None
    if cluster_dict.get("vsan"):
        # XXX The correct way of retrieving the VSAN data (on the if branch)
        #  is not supported before 60u2 vcenter
        vcenter_info = salt.utils.vmware.get_service_info(service_instance)
        if (
            float(vcenter_info.apiVersion) >= 6.0 and int(vcenter_info.build) >= 3634794
        ):  # 60u2
            vsan_61 = False
            vsan_info = salt.utils.vsan.get_cluster_vsan_info(cluster_ref)
            vsan_spec = vim.vsan.ReconfigSpec(modify=True)
            # Only interested in the vsanClusterConfig and the
            # dataEfficiencyConfig
            # vsan_spec.vsanClusterConfig = vsan_info
            vsan_spec.dataEfficiencyConfig = vsan_info.dataEfficiencyConfig
            vsan_info.dataEfficiencyConfig = None
        else:
            vsan_61 = True

    _apply_cluster_dict(cluster_spec, cluster_dict, vsan_spec, vsan_61)
    # We try to reconfigure vsan first as it fails if HA is enabled so the
    # command will abort not having any side-effects
    # also if HA was previously disabled it can be enabled automatically if
    # desired
    if vsan_spec:
        log.trace("vsan_spec = {}".format(vsan_spec))
        salt.utils.vsan.reconfigure_cluster_vsan(cluster_ref, vsan_spec)

        # We need to retrieve again the properties and reapply them
        # As the VSAN configuration has changed
        cluster_spec = vim.ClusterConfigSpecEx()
        props = salt.utils.vmware.get_properties_of_managed_object(
            cluster_ref, properties=["configurationEx"]
        )
        # Copy elements we want to update to spec
        for p in ["dasConfig", "drsConfig"]:
            setattr(cluster_spec, p, getattr(props["configurationEx"], p))
        if props["configurationEx"].vsanConfigInfo:
            cluster_spec.vsanConfig = props["configurationEx"].vsanConfigInfo
        # We only need to configure the cluster_spec, as if it were a vsan_61
        # cluster
        _apply_cluster_dict(cluster_spec, cluster_dict)
    salt.utils.vmware.update_cluster(cluster_ref, cluster_spec)
    return {"update_cluster": True}
