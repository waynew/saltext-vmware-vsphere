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


__virtualname__ = "vmware_vm"


def __virtual__():
    return __virtualname__


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
    virtual_machine = saltext.vmware.utils.vmware.get_vm_by_property(
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
    saltext.vmware.utils.vmware.power_cycle_vm(virtual_machine["object"], action="on")
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
    virtual_machine = saltext.vmware.utils.vmware.get_vm_by_property(
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
    saltext.vmware.utils.vmware.power_cycle_vm(virtual_machine["object"], action="off")
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

    return saltext.vmware.utils.vmware.list_vms(service_instance)

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
    saltext.vmware.utils.vmware.delete_vm(vm_ref)
    results["deleted_vm"] = True
    return results


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def create_vm(
    vm_name,
    cpu,
    memory,
    image,
    version,
    datacenter,
    datastore,
    placement,
    interfaces,
    disks,
    scsi_devices,
    serial_ports=None,
    ide_controllers=None,
    sata_controllers=None,
    cd_drives=None,
    advanced_configs=None,
    service_instance=None,
):
    """
    Creates a virtual machine container.

    CLI Example:

    .. code-block:: bash

        salt vm_minion vsphere.create_vm vm_name=vmname cpu='{count: 2, nested: True}' ...

    vm_name
        Name of the virtual machine

    cpu
        Properties of CPUs for freshly created machines

    memory
        Memory size for freshly created machines

    image
        Virtual machine guest OS version identifier
        VirtualMachineGuestOsIdentifier

    version
        Virtual machine container hardware version

    datacenter
        Datacenter where the virtual machine will be deployed (mandatory)

    datastore
        Datastore where the virtual machine files will be placed

    placement
        Resource pool or cluster or host or folder where the virtual machine
        will be deployed

    devices
        interfaces

        .. code-block:: bash

            interfaces:
              adapter: 'Network adapter 1'
              name: vlan100
              switch_type: distributed or standard
              adapter_type: vmxnet3 or vmxnet, vmxnet2, vmxnet3, e1000, e1000e
              mac: '00:11:22:33:44:55'
              connectable:
                allow_guest_control: True
                connected: True
                start_connected: True

        disks

        .. code-block:: bash

            disks:
              adapter: 'Hard disk 1'
              size: 16
              unit: GB
              address: '0:0'
              controller: 'SCSI controller 0'
              thin_provision: False
              eagerly_scrub: False
              datastore: 'myshare'
              filename: 'vm/mydisk.vmdk'

        scsi_devices

        .. code-block:: bash

            scsi_devices:
              controller: 'SCSI controller 0'
              type: paravirtual
              bus_sharing: no_sharing

        serial_ports

        .. code-block:: bash

            serial_ports:
              adapter: 'Serial port 1'
              type: network
              backing:
                uri: 'telnet://something:port'
                direction: <client|server>
                filename: 'service_uri'
              connectable:
                allow_guest_control: True
                connected: True
                start_connected: True
              yield: False

        cd_drives

        .. code-block:: bash

            cd_drives:
              adapter: 'CD/DVD drive 0'
              controller: 'IDE 0'
              device_type: datastore_iso_file
              datastore_iso_file:
                path: path_to_iso
              connectable:
                allow_guest_control: True
                connected: True
                start_connected: True

    advanced_config
        Advanced config parameters to be set for the virtual machine
    """
    # If datacenter is specified, set the container reference to start search
    # from it instead
    container_object = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    (resourcepool_object, placement_object) = salt.utils.vmware.get_placement(
        service_instance, datacenter, placement=placement
    )
    folder_object = salt.utils.vmware.get_folder(
        service_instance, datacenter, placement
    )
    # Create the config specs
    config_spec = vim.vm.ConfigSpec()
    config_spec.name = vm_name
    config_spec.guestId = image
    config_spec.files = vim.vm.FileInfo()

    # For VSAN disks we need to specify a different vm path name, the vm file
    # full path cannot be used
    datastore_object = salt.utils.vmware.get_datastores(
        service_instance, placement_object, datastore_names=[datastore]
    )[0]
    if not datastore_object:
        raise salt.exceptions.ArgumentValueError(
            "Specified datastore: '{}' does not exist.".format(datastore)
        )
    try:
        ds_summary = salt.utils.vmware.get_properties_of_managed_object(
            datastore_object, "summary.type"
        )
        if "summary.type" in ds_summary and ds_summary["summary.type"] == "vsan":
            log.trace(
                "The vmPathName should be the datastore "
                "name if the datastore type is vsan"
            )
            config_spec.files.vmPathName = "[{}]".format(datastore)
        else:
            config_spec.files.vmPathName = "[{0}] {1}/{1}.vmx".format(
                datastore, vm_name
            )
    except salt.exceptions.VMwareApiError:
        config_spec.files.vmPathName = "[{0}] {1}/{1}.vmx".format(datastore, vm_name)

    cd_controllers = []
    if version:
        _apply_hardware_version(version, config_spec, "add")
    if cpu:
        _apply_cpu_config(config_spec, cpu)
    if memory:
        _apply_memory_config(config_spec, memory)
    if scsi_devices:
        scsi_specs = _create_scsi_devices(scsi_devices)
        config_spec.deviceChange.extend(scsi_specs)
    if disks:
        scsi_controllers = [spec.device for spec in scsi_specs]
        disk_specs = _create_disks(
            service_instance,
            disks,
            scsi_controllers=scsi_controllers,
            parent=container_object,
        )
        config_spec.deviceChange.extend(disk_specs)
    if interfaces:
        (interface_specs, nic_settings) = _create_network_adapters(
            interfaces, parent=container_object
        )
        config_spec.deviceChange.extend(interface_specs)
    if serial_ports:
        serial_port_specs = _create_serial_ports(serial_ports)
        config_spec.deviceChange.extend(serial_port_specs)
    if ide_controllers:
        ide_specs = _create_ide_controllers(ide_controllers)
        config_spec.deviceChange.extend(ide_specs)
        cd_controllers.extend(ide_specs)
    if sata_controllers:
        sata_specs = _create_sata_controllers(sata_controllers)
        config_spec.deviceChange.extend(sata_specs)
        cd_controllers.extend(sata_specs)
    if cd_drives:
        cd_drive_specs = _create_cd_drives(
            cd_drives, controllers=cd_controllers, parent_ref=container_object
        )
        config_spec.deviceChange.extend(cd_drive_specs)
    if advanced_configs:
        _apply_advanced_config(config_spec, advanced_configs)
    salt.utils.vmware.create_vm(
        vm_name, config_spec, folder_object, resourcepool_object, placement_object
    )

    return {"create_vm": True}


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def update_vm(
    vm_name,
    cpu=None,
    memory=None,
    image=None,
    version=None,
    interfaces=None,
    disks=None,
    scsi_devices=None,
    serial_ports=None,
    datacenter=None,
    datastore=None,
    cd_dvd_drives=None,
    sata_controllers=None,
    advanced_configs=None,
    service_instance=None,
):
    """
    Updates the configuration of the virtual machine if the config differs

    vm_name
        Virtual Machine name to be updated

    cpu
        CPU configuration options

    memory
        Memory configuration options

    version
        Virtual machine container hardware version

    image
        Virtual machine guest OS version identifier
        VirtualMachineGuestOsIdentifier

    interfaces
        Network interfaces configuration options

    disks
        Disks configuration options

    scsi_devices
        SCSI devices configuration options

    serial_ports
        Serial ports configuration options

    datacenter
        Datacenter where the virtual machine is available

    datastore
        Datastore where the virtual machine config files are available

    cd_dvd_drives
        CD/DVD drives configuration options

    advanced_config
        Advanced config parameters to be set for the virtual machine

    service_instance
        vCenter service instance for connection and configuration
    """
    current_config = get_vm_config(
        vm_name, datacenter=datacenter, objects=True, service_instance=service_instance
    )
    diffs = compare_vm_configs(
        {
            "name": vm_name,
            "cpu": cpu,
            "memory": memory,
            "image": image,
            "version": version,
            "interfaces": interfaces,
            "disks": disks,
            "scsi_devices": scsi_devices,
            "serial_ports": serial_ports,
            "datacenter": datacenter,
            "datastore": datastore,
            "cd_drives": cd_dvd_drives,
            "sata_controllers": sata_controllers,
            "advanced_configs": advanced_configs,
        },
        current_config,
    )
    config_spec = vim.vm.ConfigSpec()
    datacenter_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    vm_ref = salt.utils.vmware.get_mor_by_property(
        service_instance,
        vim.VirtualMachine,
        vm_name,
        property_name="name",
        container_ref=datacenter_ref,
    )

    difference_keys = diffs.keys()
    if "cpu" in difference_keys:
        if diffs["cpu"].changed() != set():
            _apply_cpu_config(config_spec, diffs["cpu"].current_dict)
    if "memory" in difference_keys:
        if diffs["memory"].changed() != set():
            _apply_memory_config(config_spec, diffs["memory"].current_dict)
    if "advanced_configs" in difference_keys:
        _apply_advanced_config(
            config_spec, diffs["advanced_configs"].new_values, vm_ref.config.extraConfig
        )
    if "version" in difference_keys:
        _apply_hardware_version(version, config_spec, "edit")
    if "image" in difference_keys:
        config_spec.guestId = image
    new_scsi_devices = []
    if "scsi_devices" in difference_keys and "disks" in current_config:
        scsi_changes = []
        scsi_changes.extend(
            _update_scsi_devices(
                diffs["scsi_devices"].intersect, current_config["disks"]
            )
        )
        for item in diffs["scsi_devices"].removed:
            scsi_changes.append(_delete_device(item["object"]))
        new_scsi_devices = _create_scsi_devices(diffs["scsi_devices"].added)
        scsi_changes.extend(new_scsi_devices)
        config_spec.deviceChange.extend(scsi_changes)
    if "disks" in difference_keys:
        disk_changes = []
        disk_changes.extend(_update_disks(diffs["disks"].intersect))
        for item in diffs["disks"].removed:
            disk_changes.append(_delete_device(item["object"]))
        # We will need the existing and new controllers as well
        scsi_controllers = [dev["object"] for dev in current_config["scsi_devices"]]
        scsi_controllers.extend(
            [device_spec.device for device_spec in new_scsi_devices]
        )
        disk_changes.extend(
            _create_disks(
                service_instance,
                diffs["disks"].added,
                scsi_controllers=scsi_controllers,
                parent=datacenter_ref,
            )
        )
        config_spec.deviceChange.extend(disk_changes)
    if "interfaces" in difference_keys:
        network_changes = []
        network_changes.extend(
            _update_network_adapters(diffs["interfaces"].intersect, datacenter_ref)
        )
        for item in diffs["interfaces"].removed:
            network_changes.append(_delete_device(item["object"]))
        (adapters, nics) = _create_network_adapters(
            diffs["interfaces"].added, datacenter_ref
        )
        network_changes.extend(adapters)
        config_spec.deviceChange.extend(network_changes)
    if "serial_ports" in difference_keys:
        serial_changes = []
        serial_changes.extend(_update_serial_ports(diffs["serial_ports"].intersect))
        for item in diffs["serial_ports"].removed:
            serial_changes.append(_delete_device(item["object"]))
        serial_changes.extend(_create_serial_ports(diffs["serial_ports"].added))
        config_spec.deviceChange.extend(serial_changes)
    new_controllers = []
    if "sata_controllers" in difference_keys:
        # SATA controllers don't have many properties, it does not make sense
        # to update them
        sata_specs = _create_sata_controllers(diffs["sata_controllers"].added)
        for item in diffs["sata_controllers"].removed:
            sata_specs.append(_delete_device(item["object"]))
        new_controllers.extend(sata_specs)
        config_spec.deviceChange.extend(sata_specs)
    if "cd_drives" in difference_keys:
        cd_changes = []
        controllers = [dev["object"] for dev in current_config["sata_controllers"]]
        controllers.extend([device_spec.device for device_spec in new_controllers])
        cd_changes.extend(
            _update_cd_drives(
                diffs["cd_drives"].intersect,
                controllers=controllers,
                parent=datacenter_ref,
            )
        )
        for item in diffs["cd_drives"].removed:
            cd_changes.append(_delete_device(item["object"]))
        cd_changes.extend(
            _create_cd_drives(
                diffs["cd_drives"].added,
                controllers=controllers,
                parent_ref=datacenter_ref,
            )
        )
        config_spec.deviceChange.extend(cd_changes)

    if difference_keys:
        salt.utils.vmware.update_vm(vm_ref, config_spec)
    changes = {}
    for key, properties in diffs.items():
        # We can't display object, although we will need them for delete
        # and update actions, we will need to delete these before we summarize
        # the changes for the users
        if isinstance(properties, salt.utils.listdiffer.ListDictDiffer):
            properties.remove_diff(diff_key="object", diff_list="intersect")
            properties.remove_diff(diff_key="key", diff_list="intersect")
            properties.remove_diff(diff_key="object", diff_list="removed")
            properties.remove_diff(diff_key="key", diff_list="removed")
        changes[key] = properties.diffs

    return changes


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def register_vm(name, datacenter, placement, vmx_path, service_instance=None):
    """
    Registers a virtual machine to the inventory with the given vmx file.
    Returns comments and change list

    name
        Name of the virtual machine

    datacenter
        Datacenter of the virtual machine

    placement
        Placement dictionary of the virtual machine, host or cluster

    vmx_path:
        Full path to the vmx file, datastore name should be included

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.
    """
    log.trace(
        "Registering virtual machine with properties "
        "datacenter={}, placement={}, "
        "vmx_path={}".format(datacenter, placement, vmx_path)
    )
    datacenter_object = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    if "cluster" in placement:
        cluster_obj = salt.utils.vmware.get_cluster(
            datacenter_object, placement["cluster"]
        )
        cluster_props = salt.utils.vmware.get_properties_of_managed_object(
            cluster_obj, properties=["resourcePool"]
        )
        if "resourcePool" in cluster_props:
            resourcepool = cluster_props["resourcePool"]
        else:
            raise salt.exceptions.VMwareObjectRetrievalError(
                "The cluster's resource pool object could not be retrieved."
            )
        salt.utils.vmware.register_vm(datacenter_object, name, vmx_path, resourcepool)
    elif "host" in placement:
        hosts = salt.utils.vmware.get_hosts(
            service_instance, datacenter_name=datacenter, host_names=[placement["host"]]
        )
        if not hosts:
            raise salt.exceptions.VMwareObjectRetrievalError(
                "ESXi host named '{}' wasn't found.".format(placement["host"])
            )
        host_obj = hosts[0]
        host_props = salt.utils.vmware.get_properties_of_managed_object(
            host_obj, properties=["parent"]
        )
        if "parent" in host_props:
            host_parent = host_props["parent"]
            parent = salt.utils.vmware.get_properties_of_managed_object(
                host_parent, properties=["parent"]
            )
            if "parent" in parent:
                resourcepool = parent["parent"]
            else:
                raise salt.exceptions.VMwareObjectRetrievalError(
                    "The host parent's parent object could not be retrieved."
                )
        else:
            raise salt.exceptions.VMwareObjectRetrievalError(
                "The host's parent object could not be retrieved."
            )
        salt.utils.vmware.register_vm(
            datacenter_object, name, vmx_path, resourcepool, host_object=host_obj
        )
    result = {
        "comment": "Virtual machine registration action succeeded",
        "changes": {"register_vm": True},
    }
    return result


def _remove_vm(name, datacenter, service_instance, placement=None, power_off=None):
    """
    Helper function to remove a virtual machine

    name
        Name of the virtual machine

    service_instance
        vCenter service instance for connection and configuration

    datacenter
        Datacenter of the virtual machine

    placement
        Placement information of the virtual machine
    """
    results = {}
    if placement:
        (resourcepool_object, placement_object) = salt.utils.vmware.get_placement(
            service_instance, datacenter, placement
        )
    else:
        placement_object = salt.utils.vmware.get_datacenter(
            service_instance, datacenter
        )
    if power_off:
        power_off_vm(name, datacenter, service_instance)
        results["powered_off"] = True
    vm_ref = salt.utils.vmware.get_mor_by_property(
        service_instance,
        vim.VirtualMachine,
        name,
        property_name="name",
        container_ref=placement_object,
    )
    if not vm_ref:
        raise salt.exceptions.VMwareObjectRetrievalError(
            "The virtual machine object {} in datacenter "
            "{} was not found".format(name, datacenter)
        )
    return results, vm_ref


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def delete_vm(name, datacenter, placement=None, power_off=False, service_instance=None):
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
    salt.utils.vmware.delete_vm(vm_ref)
    results["deleted_vm"] = True
    return results


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def unregister_vm(
    name, datacenter, placement=None, power_off=False, service_instance=None
):
    """
    Unregisters a virtual machine defined by name and placement

    name
        Name of the virtual machine

    datacenter
        Datacenter of the virtual machine

    placement
        Placement information of the virtual machine

    service_instance
        vCenter service instance for connection and configuration

    .. code-block:: bash

        salt '*' vsphere.unregister_vm name=my_vm datacenter=my_datacenter

    """
    results = {}
    schema = ESXVirtualMachineUnregisterSchema.serialize()
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
    salt.utils.vmware.unregister_vm(vm_ref)
    results["unregistered_vm"] = True
    return results


@depends(HAS_PYVMOMI)
@_gets_service_instance_via_proxy
def get_vm(
    name,
    datacenter=None,
    vm_properties=None,
    traversal_spec=None,
    parent_ref=None,
    service_instance=None,
):
    """
    Returns vm object properties.

    name
        Name of the virtual machine.

    datacenter
        Datacenter name

    vm_properties
        List of vm properties.

    traversal_spec
        Traversal Spec object(s) for searching.

    parent_ref
        Container Reference object for searching under a given object.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.
    """
    virtual_machine = salt.utils.vmware.get_vm_by_property(
        service_instance,
        name,
        datacenter=datacenter,
        vm_properties=vm_properties,
        traversal_spec=traversal_spec,
        parent_ref=parent_ref,
    )
    return virtual_machine


@depends(HAS_PYVMOMI)
@_gets_service_instance_via_proxy
def get_vm_config_file(name, datacenter, placement, datastore, service_instance=None):
    """
    Queries the virtual machine config file and returns
    vim.host.DatastoreBrowser.SearchResults object on success None on failure

    name
        Name of the virtual machine

    datacenter
        Datacenter name

    datastore
        Datastore where the virtual machine files are stored

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.
    """

    browser_spec = vim.host.DatastoreBrowser.SearchSpec()
    directory = name
    browser_spec.query = [vim.host.DatastoreBrowser.VmConfigQuery()]
    datacenter_object = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    if "cluster" in placement:
        container_object = salt.utils.vmware.get_cluster(
            datacenter_object, placement["cluster"]
        )
    else:
        container_objects = salt.utils.vmware.get_hosts(
            service_instance, datacenter_name=datacenter, host_names=[placement["host"]]
        )
        if not container_objects:
            raise salt.exceptions.VMwareObjectRetrievalError(
                "ESXi host named '{}' wasn't " "found.".format(placement["host"])
            )
        container_object = container_objects[0]

    # list of vim.host.DatastoreBrowser.SearchResults objects
    files = salt.utils.vmware.get_datastore_files(
        service_instance, directory, [datastore], container_object, browser_spec
    )
    if files and len(files[0].file) > 1:
        raise salt.exceptions.VMwareMultipleObjectsError(
            "Multiple configuration files found in " "the same virtual machine folder"
        )
    elif files and files[0].file:
        return files[0]
    else:
        return None


@_gets_service_instance_via_proxy
def get_vm_config(name, datacenter=None, objects=True, service_instance=None):
    """
    Queries and converts the virtual machine properties to the available format
    from the schema. If the objects attribute is True the config objects will
    have extra properties, like 'object' which will include the
    vim.vm.device.VirtualDevice, this is necessary for deletion and update
    actions.

    name
        Name of the virtual machine

    datacenter
        Datacenter's name where the virtual machine is available

    objects
        Indicates whether to return the vmware object properties
        (eg. object, key) or just the properties which can be set

    service_instance
        vCenter service instance for connection and configuration
    """
    properties = [
        "config.hardware.device",
        "config.hardware.numCPU",
        "config.hardware.numCoresPerSocket",
        "config.nestedHVEnabled",
        "config.cpuHotAddEnabled",
        "config.cpuHotRemoveEnabled",
        "config.hardware.memoryMB",
        "config.memoryReservationLockedToMax",
        "config.memoryHotAddEnabled",
        "config.version",
        "config.guestId",
        "config.extraConfig",
        "name",
    ]
    virtual_machine = salt.utils.vmware.get_vm_by_property(
        service_instance, name, vm_properties=properties, datacenter=datacenter
    )
    parent_ref = salt.utils.vmware.get_datacenter(
        service_instance=service_instance, datacenter_name=datacenter
    )
    current_config = {"name": name}
    current_config["cpu"] = {
        "count": virtual_machine["config.hardware.numCPU"],
        "cores_per_socket": virtual_machine["config.hardware.numCoresPerSocket"],
        "nested": virtual_machine["config.nestedHVEnabled"],
        "hotadd": virtual_machine["config.cpuHotAddEnabled"],
        "hotremove": virtual_machine["config.cpuHotRemoveEnabled"],
    }

    current_config["memory"] = {
        "size": virtual_machine["config.hardware.memoryMB"],
        "unit": "MB",
        "reservation_max": virtual_machine["config.memoryReservationLockedToMax"],
        "hotadd": virtual_machine["config.memoryHotAddEnabled"],
    }
    current_config["image"] = virtual_machine["config.guestId"]
    current_config["version"] = virtual_machine["config.version"]
    current_config["advanced_configs"] = {}
    for extra_conf in virtual_machine["config.extraConfig"]:
        try:
            current_config["advanced_configs"][extra_conf.key] = int(extra_conf.value)
        except ValueError:
            current_config["advanced_configs"][extra_conf.key] = extra_conf.value

    current_config["disks"] = []
    current_config["scsi_devices"] = []
    current_config["interfaces"] = []
    current_config["serial_ports"] = []
    current_config["cd_drives"] = []
    current_config["sata_controllers"] = []

    for device in virtual_machine["config.hardware.device"]:
        if isinstance(device, vim.vm.device.VirtualSCSIController):
            controller = {}
            controller["adapter"] = device.deviceInfo.label
            controller["bus_number"] = device.busNumber
            bus_sharing = device.sharedBus
            if bus_sharing == "noSharing":
                controller["bus_sharing"] = "no_sharing"
            elif bus_sharing == "virtualSharing":
                controller["bus_sharing"] = "virtual_sharing"
            elif bus_sharing == "physicalSharing":
                controller["bus_sharing"] = "physical_sharing"
            if isinstance(device, vim.vm.device.ParaVirtualSCSIController):
                controller["type"] = "paravirtual"
            elif isinstance(device, vim.vm.device.VirtualBusLogicController):
                controller["type"] = "buslogic"
            elif isinstance(device, vim.vm.device.VirtualLsiLogicController):
                controller["type"] = "lsilogic"
            elif isinstance(device, vim.vm.device.VirtualLsiLogicSASController):
                controller["type"] = "lsilogic_sas"
            if objects:
                # int list, stores the keys of the disks which are attached
                # to this controller
                controller["device"] = device.device
                controller["key"] = device.key
                controller["object"] = device
            current_config["scsi_devices"].append(controller)
        if isinstance(device, vim.vm.device.VirtualDisk):
            disk = {}
            disk["adapter"] = device.deviceInfo.label
            disk["size"] = device.capacityInKB
            disk["unit"] = "KB"
            controller = _get_device_by_key(
                virtual_machine["config.hardware.device"], device.controllerKey
            )
            disk["controller"] = controller.deviceInfo.label
            disk["address"] = str(controller.busNumber) + ":" + str(device.unitNumber)
            disk["datastore"] = salt.utils.vmware.get_managed_object_name(
                device.backing.datastore
            )
            disk["thin_provision"] = device.backing.thinProvisioned
            disk["eagerly_scrub"] = device.backing.eagerlyScrub
            if objects:
                disk["key"] = device.key
                disk["unit_number"] = device.unitNumber
                disk["bus_number"] = controller.busNumber
                disk["controller_key"] = device.controllerKey
                disk["object"] = device
            current_config["disks"].append(disk)
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            interface = {}
            interface["adapter"] = device.deviceInfo.label
            interface[
                "adapter_type"
            ] = salt.utils.vmware.get_network_adapter_object_type(device)
            interface["connectable"] = {
                "allow_guest_control": device.connectable.allowGuestControl,
                "connected": device.connectable.connected,
                "start_connected": device.connectable.startConnected,
            }
            interface["mac"] = device.macAddress
            if isinstance(
                device.backing,
                vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo,
            ):
                interface["switch_type"] = "distributed"
                pg_key = device.backing.port.portgroupKey
                network_ref = salt.utils.vmware.get_mor_by_property(
                    service_instance,
                    vim.DistributedVirtualPortgroup,
                    pg_key,
                    property_name="key",
                    container_ref=parent_ref,
                )
            elif isinstance(
                device.backing, vim.vm.device.VirtualEthernetCard.NetworkBackingInfo
            ):
                interface["switch_type"] = "standard"
                network_ref = device.backing.network
            interface["name"] = salt.utils.vmware.get_managed_object_name(network_ref)
            if objects:
                interface["key"] = device.key
                interface["object"] = device
            current_config["interfaces"].append(interface)
        if isinstance(device, vim.vm.device.VirtualCdrom):
            drive = {}
            drive["adapter"] = device.deviceInfo.label
            controller = _get_device_by_key(
                virtual_machine["config.hardware.device"], device.controllerKey
            )
            drive["controller"] = controller.deviceInfo.label
            if isinstance(
                device.backing, vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo
            ):
                drive["device_type"] = "client_device"
                drive["client_device"] = {"mode": "passthrough"}
            if isinstance(
                device.backing, vim.vm.device.VirtualCdrom.RemoteAtapiBackingInfo
            ):
                drive["device_type"] = "client_device"
                drive["client_device"] = {"mode": "atapi"}
            if isinstance(device.backing, vim.vm.device.VirtualCdrom.IsoBackingInfo):
                drive["device_type"] = "datastore_iso_file"
                drive["datastore_iso_file"] = {"path": device.backing.fileName}
            drive["connectable"] = {
                "allow_guest_control": device.connectable.allowGuestControl,
                "connected": device.connectable.connected,
                "start_connected": device.connectable.startConnected,
            }
            if objects:
                drive["key"] = device.key
                drive["controller_key"] = device.controllerKey
                drive["object"] = device
            current_config["cd_drives"].append(drive)
        if isinstance(device, vim.vm.device.VirtualSerialPort):
            port = {}
            port["adapter"] = device.deviceInfo.label
            if isinstance(
                device.backing, vim.vm.device.VirtualSerialPort.URIBackingInfo
            ):
                port["type"] = "network"
                port["backing"] = {
                    "uri": device.backing.proxyURI,
                    "direction": device.backing.direction,
                    "filename": device.backing.serviceURI,
                }
            if isinstance(
                device.backing, vim.vm.device.VirtualSerialPort.PipeBackingInfo
            ):
                port["type"] = "pipe"
            if isinstance(
                device.backing, vim.vm.device.VirtualSerialPort.FileBackingInfo
            ):
                port["type"] = "file"
            if isinstance(
                device.backing, vim.vm.device.VirtualSerialPort.DeviceBackingInfo
            ):
                port["type"] = "device"
            port["yield"] = device.yieldOnPoll
            port["connectable"] = {
                "allow_guest_control": device.connectable.allowGuestControl,
                "connected": device.connectable.connected,
                "start_connected": device.connectable.startConnected,
            }
            if objects:
                port["key"] = device.key
                port["object"] = device
            current_config["serial_ports"].append(port)
        if isinstance(device, vim.vm.device.VirtualSATAController):
            sata = {}
            sata["adapter"] = device.deviceInfo.label
            sata["bus_number"] = device.busNumber
            if objects:
                sata["device"] = device.device  # keys of the connected devices
                sata["key"] = device.key
                sata["object"] = device
            current_config["sata_controllers"].append(sata)

    return current_config
