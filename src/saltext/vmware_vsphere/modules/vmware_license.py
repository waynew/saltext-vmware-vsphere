@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def list_licenses(service_instance=None):
    """
    Lists all licenses on a vCenter.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_licenses
    """
    log.trace("Retrieving all licenses")
    licenses = salt.utils.vmware.get_licenses(service_instance)
    ret_dict = [
        {
            "key": l.licenseKey,
            "name": l.name,
            "description": l.labels[0].value if l.labels else None,
            # VMware handles unlimited capacity as 0
            "capacity": l.total if l.total > 0 else sys.maxsize,
            "used": l.used if l.used else 0,
        }
        for l in licenses
    ]
    return ret_dict


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def add_license(key, description, safety_checks=True, service_instance=None):
    """
    Adds a license to the vCenter or ESXi host

    key
        License key.

    description
        License description added in as a label.

    safety_checks
        Specify whether to perform safety check or to skip the checks and try
        performing the required task

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.add_license key=<license_key> desc='License desc'
    """
    log.trace("Adding license '{}'".format(key))
    salt.utils.vmware.add_license(service_instance, key, description)
    return True


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def list_assigned_licenses(
    entity, entity_display_name, license_keys=None, service_instance=None
):
    """
    Lists the licenses assigned to an entity

    entity
        Dictionary representation of an entity.
        See ``_get_entity`` docstrings for format.

    entity_display_name
        Entity name used in logging

    license_keys:
        List of license keys to be retrieved. Default is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_assigned_licenses
            entity={type:cluster,datacenter:dc,cluster:cl}
            entiy_display_name=cl
    """
    log.trace("Listing assigned licenses of entity {}" "".format(entity))
    _validate_entity(entity)

    assigned_licenses = salt.utils.vmware.get_assigned_licenses(
        service_instance,
        entity_ref=_get_entity(service_instance, entity),
        entity_name=entity_display_name,
    )

    return [
        {
            "key": l.licenseKey,
            "name": l.name,
            "description": l.labels[0].value if l.labels else None,
            # VMware handles unlimited capacity as 0
            "capacity": l.total if l.total > 0 else sys.maxsize,
        }
        for l in assigned_licenses
        if (license_keys is None) or (l.licenseKey in license_keys)
    ]


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def assign_license(
    license_key,
    license_name,
    entity,
    entity_display_name,
    safety_checks=True,
    service_instance=None,
):
    """
    Assigns a license to an entity

    license_key
        Key of the license to assign
        See ``_get_entity`` docstrings for format.

    license_name
        Display name of license

    entity
        Dictionary representation of an entity

    entity_display_name
        Entity name used in logging

    safety_checks
        Specify whether to perform safety check or to skip the checks and try
        performing the required task. Default is False.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.assign_license license_key=00000:00000
            license name=test entity={type:cluster,datacenter:dc,cluster:cl}
    """
    log.trace("Assigning license {} to entity {}" "".format(license_key, entity))
    _validate_entity(entity)
    if safety_checks:
        licenses = salt.utils.vmware.get_licenses(service_instance)
        if not [l for l in licenses if l.licenseKey == license_key]:
            raise VMwareObjectRetrievalError(
                "License '{}' wasn't found" "".format(license_name)
            )
    salt.utils.vmware.assign_license(
        service_instance,
        license_key,
        license_name,
        entity_ref=_get_entity(service_instance, entity),
        entity_name=entity_display_name,
    )
