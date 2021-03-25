# pylint: disable=C0302
"""
Manage VMware vCenter servers and ESXi hosts.

.. versionadded:: 2015.8.4

:codeauthor: Alexandru Bleotu <alexandru.bleotu@morganstaley.com>

Dependencies
============

- pyVmomi Python Module
- ESXCLI

pyVmomi
-------

PyVmomi can be installed via pip:

.. code-block:: bash

    pip install pyVmomi

.. note::

    Version 6.0 of pyVmomi has some problems with SSL error handling on certain
    versions of Python. If using version 6.0 of pyVmomi, Python 2.7.9,
    or newer must be present. This is due to an upstream dependency
    in pyVmomi 6.0 that is not supported in Python versions 2.7 to 2.7.8. If the
    version of Python is not in the supported range, you will need to install an
    earlier version of pyVmomi. See `Issue #29537`_ for more information.

.. _Issue #29537: https://github.com/saltstack/salt/issues/29537

Based on the note above, to install an earlier version of pyVmomi than the
version currently listed in PyPi, run the following:

.. code-block:: bash

    pip install pyVmomi==5.5.0.2014.1.1

The 5.5.0.2014.1.1 is a known stable version that this original vSphere Execution
Module was developed against.

vSphere Automation SDK
----------------------

vSphere Automation SDK can be installed via pip:

.. code-block:: bash

    pip install --upgrade pip setuptools
    pip install --upgrade git+https://github.com/vmware/vsphere-automation-sdk-python.git

.. note::

    The SDK also requires OpenSSL 1.0.1+ if you want to connect to vSphere 6.5+ in order to support
    TLS1.1 & 1.2.

    In order to use the tagging functions in this module, vSphere Automation SDK is necessary to
    install.

The module is currently in version 1.0.3
(as of 8/26/2019)

ESXCLI
------

Currently, about a third of the functions used in the vSphere Execution Module require
the ESXCLI package be installed on the machine running the Proxy Minion process.

The ESXCLI package is also referred to as the VMware vSphere CLI, or vCLI. VMware
provides vCLI package installation instructions for `vSphere 5.5`_ and
`vSphere 6.0`_.

.. _vSphere 5.5: http://pubs.vmware.com/vsphere-55/index.jsp#com.vmware.vcli.getstart.doc/cli_install.4.2.html
.. _vSphere 6.0: http://pubs.vmware.com/vsphere-60/index.jsp#com.vmware.vcli.getstart.doc/cli_install.4.2.html

Once all of the required dependencies are in place and the vCLI package is
installed, you can check to see if you can connect to your ESXi host or vCenter
server by running the following command:

.. code-block:: bash

    esxcli -s <host-location> -u <username> -p <password> system syslog config get

If the connection was successful, ESXCLI was successfully installed on your system.
You should see output related to the ESXi host's syslog configuration.

.. note::

    Be aware that some functionality in this execution module may depend on the
    type of license attached to a vCenter Server or ESXi host(s).

    For example, certain services are only available to manipulate service state
    or policies with a VMware vSphere Enterprise or Enterprise Plus license, while
    others are available with a Standard license. The ``ntpd`` service is restricted
    to an Enterprise Plus license, while ``ssh`` is available via the Standard
    license.

    Please see the `vSphere Comparison`_ page for more information.

.. _vSphere Comparison: https://www.vmware.com/products/vsphere/compare


About
=====

This execution module was designed to be able to handle connections both to a
vCenter Server, as well as to an ESXi host. It utilizes the pyVmomi Python
library and the ESXCLI package to run remote execution functions against either
the defined vCenter server or the ESXi host.

Whether or not the function runs against a vCenter Server or an ESXi host depends
entirely upon the arguments passed into the function. Each function requires a
``host`` location, ``username``, and ``password``. If the credentials provided
apply to a vCenter Server, then the function will be run against the vCenter
Server. For example, when listing hosts using vCenter credentials, you'll get a
list of hosts associated with that vCenter Server:

.. code-block:: bash

    # salt my-minion vsphere.list_hosts <vcenter-ip> <vcenter-user> <vcenter-password>
    my-minion:
    - esxi-1.example.com
    - esxi-2.example.com

However, some functions should be used against ESXi hosts, not vCenter Servers.
Functionality such as getting a host's coredump network configuration should be
performed against a host and not a vCenter server. If the authentication
information you're using is against a vCenter server and not an ESXi host, you
can provide the host name that is associated with the vCenter server in the
command, as a list, using the ``host_names`` or ``esxi_host`` kwarg. For
example:

.. code-block:: bash

    # salt my-minion vsphere.get_coredump_network_config <vcenter-ip> <vcenter-user> \
        <vcenter-password> esxi_hosts='[esxi-1.example.com, esxi-2.example.com]'
    my-minion:
    ----------
        esxi-1.example.com:
            ----------
            Coredump Config:
                ----------
                enabled:
                    False
        esxi-2.example.com:
            ----------
            Coredump Config:
                ----------
                enabled:
                    True
                host_vnic:
                    vmk0
                ip:
                    coredump-location.example.com
                port:
                    6500

You can also use these functions against an ESXi host directly by establishing a
connection to an ESXi host using the host's location, username, and password. If ESXi
connection credentials are used instead of vCenter credentials, the ``host_names`` and
``esxi_hosts`` arguments are not needed.

.. code-block:: bash

    # salt my-minion vsphere.get_coredump_network_config esxi-1.example.com root <host-password>
    local:
    ----------
        10.4.28.150:
            ----------
            Coredump Config:
                ----------
                enabled:
                    True
                host_vnic:
                    vmk0
                ip:
                    coredump-location.example.com
                port:
                    6500
"""
import logging
import sys

import salt.utils.platform
import saltext.vmware.utils.vmware
from salt.exceptions import InvalidConfigError
from salt.utils.decorators import depends
from salt.utils.dictdiffer import recursive_diff
from salt.utils.listdiffer import list_diff
from saltext.vmware.config.schemas.esxvm import ESXVirtualMachineDeleteSchema
from saltext.vmware.config.schemas.esxvm import ESXVirtualMachineUnregisterSchema

log = logging.getLogger(__name__)

try:
    import jsonschema

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

try:
    # pylint: disable=no-name-in-module
    from pyVmomi import (
        vim,
        VmomiSupport,
    )

    # pylint: enable=no-name-in-module

    # We check the supported vim versions to infer the pyVmomi version
    if (
        "vim25/6.0" in VmomiSupport.versionMap
        and sys.version_info > (2, 7)
        and sys.version_info < (2, 7, 9)
    ):

        log.debug("pyVmomi not loaded: Incompatible versions " "of Python. See Issue #29537.")
        raise ImportError()
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False

__virtualname__ = "vmware_extra"


def __virtual__():
    return __virtualname__


@ignores_kwargs("credstore")
def upload_ssh_key(
    host,
    username,
    password,
    ssh_key=None,
    ssh_key_file=None,
    protocol=None,
    port=None,
    certificate_verify=None,
):
    """
    Upload an ssh key for root to an ESXi host via http PUT.
    This function only works for ESXi, not vCenter.
    Only one ssh key can be uploaded for root.  Uploading a second key will
    replace any existing key.

    :param host: The location of the ESXi Host
    :param username: Username to connect as
    :param password: Password for the ESXi web endpoint
    :param ssh_key: Public SSH key, will be added to authorized_keys on ESXi
    :param ssh_key_file: File containing the SSH key.  Use 'ssh_key' or
                         ssh_key_file, but not both.
    :param protocol: defaults to https, can be http if ssl is disabled on ESXi
    :param port: defaults to 443 for https
    :param certificate_verify: If true require that the SSL connection present
                               a valid certificate. Default: True
    :return: Dictionary with a 'status' key, True if upload is successful.
             If upload is unsuccessful, 'status' key will be False and
             an 'Error' key will have an informative message.

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.upload_ssh_key my.esxi.host root bad-password ssh_key_file='/etc/salt/my_keys/my_key.pub'

    """
    if protocol is None:
        protocol = "https"
    if port is None:
        port = 443
    if certificate_verify is None:
        certificate_verify = True

    url = "{}://{}:{}/host/ssh_root_authorized_keys".format(protocol, host, port)
    ret = {}
    result = None
    try:
        if ssh_key:
            result = salt.utils.http.query(
                url,
                status=True,
                text=True,
                method="PUT",
                username=username,
                password=password,
                data=ssh_key,
                verify_ssl=certificate_verify,
            )
        elif ssh_key_file:
            result = salt.utils.http.query(
                url,
                status=True,
                text=True,
                method="PUT",
                username=username,
                password=password,
                data_file=ssh_key_file,
                data_render=False,
                verify_ssl=certificate_verify,
            )
        if result.get("status") == 200:
            ret["status"] = True
        else:
            ret["status"] = False
            ret["Error"] = result["error"]
    except Exception as msg:  # pylint: disable=broad-except
        ret["status"] = False
        ret["Error"] = msg

    return ret


@ignores_kwargs("credstore")
def get_ssh_key(
    host, username, password, protocol=None, port=None, certificate_verify=None
):
    """
    Retrieve the authorized_keys entry for root.
    This function only works for ESXi, not vCenter.

    :param host: The location of the ESXi Host
    :param username: Username to connect as
    :param password: Password for the ESXi web endpoint
    :param protocol: defaults to https, can be http if ssl is disabled on ESXi
    :param port: defaults to 443 for https
    :param certificate_verify: If true require that the SSL connection present
                               a valid certificate. Default: True
    :return: True if upload is successful

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.get_ssh_key my.esxi.host root bad-password certificate_verify=True

    """
    if protocol is None:
        protocol = "https"
    if port is None:
        port = 443
    if certificate_verify is None:
        certificate_verify = True

    url = "{}://{}:{}/host/ssh_root_authorized_keys".format(protocol, host, port)
    ret = {}
    try:
        result = salt.utils.http.query(
            url,
            status=True,
            text=True,
            method="GET",
            username=username,
            password=password,
            verify_ssl=certificate_verify,
        )
        if result.get("status") == 200:
            ret["status"] = True
            ret["key"] = result["text"]
        else:
            ret["status"] = False
            ret["Error"] = result["error"]
    except Exception as msg:  # pylint: disable=broad-except
        ret["status"] = False
        ret["Error"] = msg

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def get_host_datetime(
    host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True
):
    """
    Get the date/time information for a given host or list of host_names.

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

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to tell
        vCenter the hosts for which to get date/time information.

        If host_names is not provided, the date/time information will be retrieved for the
        ``host`` location instead. This is useful for when service instance connection
        information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.get_host_datetime my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.get_host_datetime my.vcenter.location root bad-password \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        date_time_manager = _get_date_time_mgr(host_ref)
        date_time = date_time_manager.QueryDateTime()
        ret.update({host_name: date_time})

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def get_ntp_config(
    host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True
):
    """
    Get the NTP configuration information for a given host or list of host_names.

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

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to tell
        vCenter the hosts for which to get ntp configuration information.

        If host_names is not provided, the NTP configuration will be retrieved for the
        ``host`` location instead. This is useful for when service instance connection
        information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.get_ntp_config my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.get_ntp_config my.vcenter.location root bad-password \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        ntp_config = host_ref.configManager.dateTimeSystem.dateTimeInfo.ntpConfig.server
        ret.update({host_name: ntp_config})

    return ret


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter", "vcenter", "esxvm")
@_gets_service_instance_via_proxy
def test_vcenter_connection(service_instance=None):
    """
    Checks if a connection is to a vCenter

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.test_vcenter_connection
    """
    try:
        if salt.utils.vmware.is_connection_to_a_vcenter(service_instance):
            return True
    except VMwareSaltError:
        return False
    return False


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def system_info(
    host, username, password, protocol=None, port=None, verify_ssl=True,
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
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    ret = salt.utils.vmware.get_inventory(service_instance).about.__dict__
    if "apiType" in ret:
        if ret["apiType"] == "HostAgent":
            ret = dictupdate.update(
                ret, salt.utils.vmware.get_hardware_grains(service_instance)
            )
    return ret




@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_hosts(host, username, password, protocol=None, port=None, verify_ssl=True):
    """
    Returns a list of hosts for the specified VMware environment.

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

        salt '*' vsphere.list_hosts 1.2.3.4 root bad-password
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_hosts(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_resourcepools(
    host, username, password, protocol=None, port=None, verify_ssl=True
):
    """
    Returns a list of resource pools for the specified host.

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

        salt '*' vsphere.list_resourcepools 1.2.3.4 root bad-password
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_resourcepools(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_networks(host, username, password, protocol=None, port=None, verify_ssl=True):
    """
    Returns a list of networks for the specified host.

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

        salt '*' vsphere.list_networks 1.2.3.4 root bad-password
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_networks(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_folders(host, username, password, protocol=None, port=None, verify_ssl=True):
    """
    Returns a list of folders for the specified host.

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

        salt '*' vsphere.list_folders 1.2.3.4 root bad-password
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_folders(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_vapps(host, username, password, protocol=None, port=None, verify_ssl=True):
    """
    Returns a list of vApps for the specified host.

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

        # List vapps from all minions
        salt '*' vsphere.list_vapps 1.2.3.4 root bad-password
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_vapps(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_ssds(
    host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True
):
    """
    Returns a list of SSDs for the given host or list of host_names.

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

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to
        tell vCenter the hosts for which to retrieve SSDs.

        If host_names is not provided, SSDs will be retrieved for the
        ``host`` location instead. This is useful for when service instance
        connection information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.list_ssds my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.list_ssds my.vcenter.location root bad-password \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    names = []
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        disks = _get_host_ssds(host_ref)
        for disk in disks:
            names.append(disk.canonicalName)
        ret.update({host_name: names})

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_non_ssds(
    host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True
):
    """
    Returns a list of Non-SSD disks for the given host or list of host_names.

    .. note::

        In the pyVmomi StorageSystem, ScsiDisks may, or may not have an ``ssd`` attribute.
        This attribute indicates if the ScsiDisk is SSD backed. As this option is optional,
        if a relevant disk in the StorageSystem does not have ``ssd = true``, it will end
        up in the ``non_ssds`` list here.

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

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to
        tell vCenter the hosts for which to retrieve Non-SSD disks.

        If host_names is not provided, Non-SSD disks will be retrieved for the
        ``host`` location instead. This is useful for when service instance
        connection information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.list_non_ssds my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.list_non_ssds my.vcenter.location root bad-password \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    names = []
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        disks = _get_host_non_ssds(host_ref)
        for disk in disks:
            names.append(disk.canonicalName)
        ret.update({host_name: names})

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def set_ntp_config(
    host,
    username,
    password,
    ntp_servers,
    protocol=None,
    port=None,
    host_names=None,
    verify_ssl=True,
):
    """
    Set NTP configuration for a given host of list of host_names.

    host
        The location of the host.

    username
        The username used to login to the host, such as ``root``.

    password
        The password used to login to the host.

    ntp_servers
        A list of servers that should be added to and configured for the specified
        host's NTP configuration.

    protocol
        Optionally set to alternate protocol if the host is not using the default
        protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the host is not using the default
        port. Default port is ``443``.

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to tell
        vCenter which hosts to configure ntp servers.

        If host_names is not provided, the NTP servers will be configured for the
        ``host`` location instead. This is useful for when service instance connection
        information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.ntp_configure my.esxi.host root bad-password '[192.174.1.100, 192.174.1.200]'

        # Used for connecting to a vCenter Server
        salt '*' vsphere.ntp_configure my.vcenter.location root bad-password '[192.174.1.100, 192.174.1.200]' \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    if not isinstance(ntp_servers, list):
        raise CommandExecutionError("'ntp_servers' must be a list.")

    # Get NTP Config Object from ntp_servers
    ntp_config = vim.HostNtpConfig(server=ntp_servers)

    # Get DateTimeConfig object from ntp_config
    date_config = vim.HostDateTimeConfig(ntpConfig=ntp_config)

    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        date_time_manager = _get_date_time_mgr(host_ref)
        log.debug(
            "Configuring NTP Servers '{}' for host '{}'.".format(ntp_servers, host_name)
        )

        try:
            date_time_manager.UpdateDateTimeConfig(config=date_config)
        except vim.fault.HostConfigFault as err:
            msg = "vsphere.ntp_configure_servers failed: {}".format(err)
            log.debug(msg)
            ret.update({host_name: {"Error": msg}})
            continue

        ret.update({host_name: {"NTP Servers": ntp_config}})
    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def update_host_datetime(
    host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True
):
    """
    Update the date/time on the given host or list of host_names. This function should be
    used with caution since network delays and execution delays can result in time skews.

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

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to
        tell vCenter which hosts should update their date/time.

        If host_names is not provided, the date/time will be updated for the ``host``
        location instead. This is useful for when service instance connection
        information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.update_date_time my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.update_date_time my.vcenter.location root bad-password \
        host_names='[esxi-1.host.com, esxi-2.host.com]'
    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    host_names = _check_hosts(service_instance, host, host_names)
    ret = {}
    for host_name in host_names:
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        date_time_manager = _get_date_time_mgr(host_ref)
        try:
            date_time_manager.UpdateDateTime(datetime.datetime.utcnow())
        except vim.fault.HostConfigFault as err:
            msg = "'vsphere.update_date_time' failed for host {}: {}".format(
                host_name, err
            )
            log.debug(msg)
            ret.update({host_name: {"Error": msg}})
            continue

        ret.update({host_name: {"Datetime Updated": True}})

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def update_host_password(
    host, username, password, new_password, protocol=None, port=None, verify_ssl=True
):
    """
    Update the password for a given host.

    .. note:: Currently only works with connections to ESXi hosts. Does not work with vCenter servers.

    host
        The location of the ESXi host.

    username
        The username used to login to the ESXi host, such as ``root``.

    password
        The password used to login to the ESXi host.

    new_password
        The new password that will be updated for the provided username on the ESXi host.

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

        salt '*' vsphere.update_host_password my.esxi.host root original-bad-password new-bad-password

    """
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    # Get LocalAccountManager object
    account_manager = salt.utils.vmware.get_inventory(service_instance).accountManager

    # Create user account specification object and assign id and password attributes
    user_account = vim.host.LocalAccountManager.AccountSpecification()
    user_account.id = username
    user_account.password = new_password

    # Update the password
    try:
        account_manager.UpdateUser(user_account)
    except vmodl.fault.SystemError as err:
        raise CommandExecutionError(err.msg)
    except vim.fault.UserNotFound:
        raise CommandExecutionError(
            "'vsphere.update_host_password' failed for host {}: "
            "User was not found.".format(host)
        )
    # If the username and password already exist, we don't need to do anything.
    except vim.fault.AlreadyExists:
        pass

    return True


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_storage_policies(policy_names=None, service_instance=None):
    """
    Returns a list of storage policies.

    policy_names
        Names of policies to list. If None, all policies are listed.
        Default is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_storage_policies

        salt '*' vsphere.list_storage_policy policy_names=[policy_name]
    """
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    if not policy_names:
        policies = salt.utils.pbm.get_storage_policies(
            profile_manager, get_all_policies=True
        )
    else:
        policies = salt.utils.pbm.get_storage_policies(profile_manager, policy_names)
    return [_get_policy_dict(p) for p in policies]


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_default_vsan_policy(service_instance=None):
    """
    Returns the default vsan storage policy.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_storage_policies

        salt '*' vsphere.list_storage_policy policy_names=[policy_name]
    """
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policies = salt.utils.pbm.get_storage_policies(
        profile_manager, get_all_policies=True
    )
    def_policies = [
        p for p in policies if p.systemCreatedProfileType == "VsanDefaultProfile"
    ]
    if not def_policies:
        raise VMwareObjectRetrievalError("Default VSAN policy was not " "retrieved")
    return _get_policy_dict(def_policies[0])


def _get_capability_definition_dict(cap_metadata):
    # We assume each capability definition has one property with the same id
    # as the capability so we display its type as belonging to the capability
    # The object model permits multiple properties
    return {
        "namespace": cap_metadata.id.namespace,
        "id": cap_metadata.id.id,
        "mandatory": cap_metadata.mandatory,
        "description": cap_metadata.summary.summary,
        "type": cap_metadata.propertyMetadata[0].type.typeName,
    }


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_capability_definitions(service_instance=None):
    """
    Returns a list of the metadata of all capabilities in the vCenter.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_capabilities
    """
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    ret_list = [
        _get_capability_definition_dict(c)
        for c in salt.utils.pbm.get_capability_definitions(profile_manager)
    ]
    return ret_list


def _apply_policy_config(policy_spec, policy_dict):
    """Applies a policy dictionary to a policy spec"""
    log.trace("policy_dict = {}".format(policy_dict))
    if policy_dict.get("name"):
        policy_spec.name = policy_dict["name"]
    if policy_dict.get("description"):
        policy_spec.description = policy_dict["description"]
    if policy_dict.get("subprofiles"):
        # Incremental changes to subprofiles and capabilities are not
        # supported because they would complicate updates too much
        # The whole configuration of all sub-profiles is expected and applied
        policy_spec.constraints = pbm.profile.SubProfileCapabilityConstraints()
        subprofiles = []
        for subprofile_dict in policy_dict["subprofiles"]:
            subprofile_spec = pbm.profile.SubProfileCapabilityConstraints.SubProfile(
                name=subprofile_dict["name"]
            )
            cap_specs = []
            if subprofile_dict.get("force_provision"):
                subprofile_spec.forceProvision = subprofile_dict["force_provision"]
            for cap_dict in subprofile_dict["capabilities"]:
                prop_inst_spec = pbm.capability.PropertyInstance(id=cap_dict["id"])
                setting_type = cap_dict["setting"]["type"]
                if setting_type == "set":
                    prop_inst_spec.value = pbm.capability.types.DiscreteSet()
                    prop_inst_spec.value.values = cap_dict["setting"]["values"]
                elif setting_type == "range":
                    prop_inst_spec.value = pbm.capability.types.Range()
                    prop_inst_spec.value.max = cap_dict["setting"]["max"]
                    prop_inst_spec.value.min = cap_dict["setting"]["min"]
                elif setting_type == "scalar":
                    prop_inst_spec.value = cap_dict["setting"]["value"]
                cap_spec = pbm.capability.CapabilityInstance(
                    id=pbm.capability.CapabilityMetadata.UniqueId(
                        id=cap_dict["id"], namespace=cap_dict["namespace"]
                    ),
                    constraint=[
                        pbm.capability.ConstraintInstance(
                            propertyInstance=[prop_inst_spec]
                        )
                    ],
                )
                cap_specs.append(cap_spec)
            subprofile_spec.capability = cap_specs
            subprofiles.append(subprofile_spec)
        policy_spec.constraints.subProfiles = subprofiles
    log.trace("updated policy_spec = {}".format(policy_spec))
    return policy_spec


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def create_storage_policy(policy_name, policy_dict, service_instance=None):
    """
    Creates a storage policy.

    Supported capability types: scalar, set, range.

    policy_name
        Name of the policy to create.
        The value of the argument will override any existing name in
        ``policy_dict``.

    policy_dict
        Dictionary containing the changes to apply to the policy.
        (example in salt.states.pbm)

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.create_storage_policy policy_name='policy name'
            policy_dict="$policy_dict"
    """
    log.trace(
        "create storage policy '{}', dict = {}" "".format(policy_name, policy_dict)
    )
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policy_create_spec = pbm.profile.CapabilityBasedProfileCreateSpec()
    # Hardcode the storage profile resource type
    policy_create_spec.resourceType = pbm.profile.ResourceType(
        resourceType=pbm.profile.ResourceTypeEnum.STORAGE
    )
    # Set name argument
    policy_dict["name"] = policy_name
    log.trace("Setting policy values in policy_update_spec")
    _apply_policy_config(policy_create_spec, policy_dict)
    salt.utils.pbm.create_storage_policy(profile_manager, policy_create_spec)
    return {"create_storage_policy": True}


@depends(HAS_PYVMOMI)
@_supports_proxies("esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def update_storage_policy(policy, policy_dict, service_instance=None):
    """
    Updates a storage policy.

    Supported capability types: scalar, set, range.

    policy
        Name of the policy to update.

    policy_dict
        Dictionary containing the changes to apply to the policy.
        (example in salt.states.pbm)

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.update_storage_policy policy='policy name'
            policy_dict="$policy_dict"
    """
    log.trace("updating storage policy, dict = {}".format(policy_dict))
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policies = salt.utils.pbm.get_storage_policies(profile_manager, [policy])
    if not policies:
        raise VMwareObjectRetrievalError("Policy '{}' was not found" "".format(policy))
    policy_ref = policies[0]
    policy_update_spec = pbm.profile.CapabilityBasedProfileUpdateSpec()
    log.trace("Setting policy values in policy_update_spec")
    for prop in ["description", "constraints"]:
        setattr(policy_update_spec, prop, getattr(policy_ref, prop))
    _apply_policy_config(policy_update_spec, policy_dict)
    salt.utils.pbm.update_storage_policy(
        profile_manager, policy_ref, policy_update_spec
    )
    return {"update_storage_policy": True}


def _get_cluster_dict(cluster_name, cluster_ref):
    """
    Returns a cluster dict representation from
    a vim.ClusterComputeResource object.

    cluster_name
        Name of the cluster

    cluster_ref
        Reference to the cluster
    """

    log.trace(
        "Building a dictionary representation of cluster " "'{}'".format(cluster_name)
    )
    props = salt.utils.vmware.get_properties_of_managed_object(
        cluster_ref, properties=["configurationEx"]
    )
    res = {
        "ha": {"enabled": props["configurationEx"].dasConfig.enabled},
        "drs": {"enabled": props["configurationEx"].drsConfig.enabled},
    }
    # Convert HA properties of interest
    ha_conf = props["configurationEx"].dasConfig
    log.trace("ha_conf = {}".format(ha_conf))
    res["ha"]["admission_control_enabled"] = ha_conf.admissionControlEnabled
    if ha_conf.admissionControlPolicy and isinstance(
        ha_conf.admissionControlPolicy,
        vim.ClusterFailoverResourcesAdmissionControlPolicy,
    ):
        pol = ha_conf.admissionControlPolicy
        res["ha"]["admission_control_policy"] = {
            "cpu_failover_percent": pol.cpuFailoverResourcesPercent,
            "memory_failover_percent": pol.memoryFailoverResourcesPercent,
        }
    if ha_conf.defaultVmSettings:
        def_vm_set = ha_conf.defaultVmSettings
        res["ha"]["default_vm_settings"] = {
            "isolation_response": def_vm_set.isolationResponse,
            "restart_priority": def_vm_set.restartPriority,
        }
    res["ha"]["hb_ds_candidate_policy"] = ha_conf.hBDatastoreCandidatePolicy
    if ha_conf.hostMonitoring:
        res["ha"]["host_monitoring"] = ha_conf.hostMonitoring
    if ha_conf.option:
        res["ha"]["options"] = [
            {"key": o.key, "value": o.value} for o in ha_conf.option
        ]
    res["ha"]["vm_monitoring"] = ha_conf.vmMonitoring
    # Convert DRS properties
    drs_conf = props["configurationEx"].drsConfig
    log.trace("drs_conf = {}".format(drs_conf))
    res["drs"]["vmotion_rate"] = 6 - drs_conf.vmotionRate
    res["drs"]["default_vm_behavior"] = drs_conf.defaultVmBehavior
    # vm_swap_placement
    res["vm_swap_placement"] = props["configurationEx"].vmSwapPlacement
    # Convert VSAN properties
    si = salt.utils.vmware.get_service_instance_from_managed_object(cluster_ref)

    if salt.utils.vsan.vsan_supported(si):
        # XXX The correct way of retrieving the VSAN data (on the if branch)
        #  is not supported before 60u2 vcenter
        vcenter_info = salt.utils.vmware.get_service_info(si)
        if int(vcenter_info.build) >= 3634794:  # 60u2
            # VSAN API is fully supported by the VC starting with 60u2
            vsan_conf = salt.utils.vsan.get_cluster_vsan_info(cluster_ref)
            log.trace("vsan_conf = {}".format(vsan_conf))
            res["vsan"] = {
                "enabled": vsan_conf.enabled,
                "auto_claim_storage": vsan_conf.defaultConfig.autoClaimStorage,
            }
            if vsan_conf.dataEfficiencyConfig:
                data_eff = vsan_conf.dataEfficiencyConfig
                res["vsan"].update(
                    {
                        # We force compression_enabled to be True/False
                        "compression_enabled": data_eff.compressionEnabled or False,
                        "dedup_enabled": data_eff.dedupEnabled,
                    }
                )
        else:  # before 60u2 (no advanced vsan info)
            if props["configurationEx"].vsanConfigInfo:
                default_config = props["configurationEx"].vsanConfigInfo.defaultConfig
                res["vsan"] = {
                    "enabled": props["configurationEx"].vsanConfigInfo.enabled,
                    "auto_claim_storage": default_config.autoClaimStorage,
                }
    return res



def _apply_cluster_dict(cluster_spec, cluster_dict, vsan_spec=None, vsan_61=True):
    """
    Applies the values of cluster_dict dictionary to a cluster spec
    (vim.ClusterConfigSpecEx).

    All vsan values (cluster_dict['vsan']) will be applied to
    vsan_spec (vim.vsan.cluster.ConfigInfoEx). Can be not omitted
    if not required.

    VSAN 6.1 config needs to be applied differently than the post VSAN 6.1 way.
    The type of configuration desired is dictated by the flag vsan_61.
    """
    log.trace("Applying cluster dict {}".format(cluster_dict))
    if cluster_dict.get("ha"):
        ha_dict = cluster_dict["ha"]
        if not cluster_spec.dasConfig:
            cluster_spec.dasConfig = vim.ClusterDasConfigInfo()
        das_config = cluster_spec.dasConfig
        if "enabled" in ha_dict:
            das_config.enabled = ha_dict["enabled"]
            if ha_dict["enabled"]:
                # Default values when ha is enabled
                das_config.failoverLevel = 1
        if "admission_control_enabled" in ha_dict:
            das_config.admissionControlEnabled = ha_dict["admission_control_enabled"]
        if "admission_control_policy" in ha_dict:
            adm_pol_dict = ha_dict["admission_control_policy"]
            if not das_config.admissionControlPolicy or not isinstance(
                das_config.admissionControlPolicy,
                vim.ClusterFailoverResourcesAdmissionControlPolicy,
            ):

                das_config.admissionControlPolicy = vim.ClusterFailoverResourcesAdmissionControlPolicy(
                    cpuFailoverResourcesPercent=adm_pol_dict["cpu_failover_percent"],
                    memoryFailoverResourcesPercent=adm_pol_dict[
                        "memory_failover_percent"
                    ],
                )
        if "default_vm_settings" in ha_dict:
            vm_set_dict = ha_dict["default_vm_settings"]
            if not das_config.defaultVmSettings:
                das_config.defaultVmSettings = vim.ClusterDasVmSettings()
            if "isolation_response" in vm_set_dict:
                das_config.defaultVmSettings.isolationResponse = vm_set_dict[
                    "isolation_response"
                ]
            if "restart_priority" in vm_set_dict:
                das_config.defaultVmSettings.restartPriority = vm_set_dict[
                    "restart_priority"
                ]
        if "hb_ds_candidate_policy" in ha_dict:
            das_config.hBDatastoreCandidatePolicy = ha_dict["hb_ds_candidate_policy"]
        if "host_monitoring" in ha_dict:
            das_config.hostMonitoring = ha_dict["host_monitoring"]
        if "options" in ha_dict:
            das_config.option = []
            for opt_dict in ha_dict["options"]:
                das_config.option.append(vim.OptionValue(key=opt_dict["key"]))
                if "value" in opt_dict:
                    das_config.option[-1].value = opt_dict["value"]
        if "vm_monitoring" in ha_dict:
            das_config.vmMonitoring = ha_dict["vm_monitoring"]
        cluster_spec.dasConfig = das_config
    if cluster_dict.get("drs"):
        drs_dict = cluster_dict["drs"]
        drs_config = vim.ClusterDrsConfigInfo()
        if "enabled" in drs_dict:
            drs_config.enabled = drs_dict["enabled"]
        if "vmotion_rate" in drs_dict:
            drs_config.vmotionRate = 6 - drs_dict["vmotion_rate"]
        if "default_vm_behavior" in drs_dict:
            drs_config.defaultVmBehavior = vim.DrsBehavior(
                drs_dict["default_vm_behavior"]
            )
        cluster_spec.drsConfig = drs_config
    if cluster_dict.get("vm_swap_placement"):
        cluster_spec.vmSwapPlacement = cluster_dict["vm_swap_placement"]
    if cluster_dict.get("vsan"):
        vsan_dict = cluster_dict["vsan"]
        if not vsan_61:  # VSAN is 6.2 and above
            if "enabled" in vsan_dict:
                if not vsan_spec.vsanClusterConfig:
                    vsan_spec.vsanClusterConfig = vim.vsan.cluster.ConfigInfo()
                vsan_spec.vsanClusterConfig.enabled = vsan_dict["enabled"]
            if "auto_claim_storage" in vsan_dict:
                if not vsan_spec.vsanClusterConfig:
                    vsan_spec.vsanClusterConfig = vim.vsan.cluster.ConfigInfo()
                if not vsan_spec.vsanClusterConfig.defaultConfig:
                    vsan_spec.vsanClusterConfig.defaultConfig = (
                        vim.VsanClusterConfigInfoHostDefaultInfo()
                    )
                elif vsan_spec.vsanClusterConfig.defaultConfig.uuid:
                    # If this remains set it caused an error
                    vsan_spec.vsanClusterConfig.defaultConfig.uuid = None
                vsan_spec.vsanClusterConfig.defaultConfig.autoClaimStorage = vsan_dict[
                    "auto_claim_storage"
                ]
            if "compression_enabled" in vsan_dict:
                if not vsan_spec.dataEfficiencyConfig:
                    vsan_spec.dataEfficiencyConfig = vim.vsan.DataEfficiencyConfig()
                vsan_spec.dataEfficiencyConfig.compressionEnabled = vsan_dict[
                    "compression_enabled"
                ]
            if "dedup_enabled" in vsan_dict:
                if not vsan_spec.dataEfficiencyConfig:
                    vsan_spec.dataEfficiencyConfig = vim.vsan.DataEfficiencyConfig()
                vsan_spec.dataEfficiencyConfig.dedupEnabled = vsan_dict["dedup_enabled"]
        # In all cases we need to configure the vsan on the cluster
        # directly so not to have a mismatch between vsan_spec and
        # cluster_spec
        if not cluster_spec.vsanConfig:
            cluster_spec.vsanConfig = vim.VsanClusterConfigInfo()
        vsan_config = cluster_spec.vsanConfig
        if "enabled" in vsan_dict:
            vsan_config.enabled = vsan_dict["enabled"]
        if "auto_claim_storage" in vsan_dict:
            if not vsan_config.defaultConfig:
                vsan_config.defaultConfig = vim.VsanClusterConfigInfoHostDefaultInfo()
            elif vsan_config.defaultConfig.uuid:
                # If this remains set it caused an error
                vsan_config.defaultConfig.uuid = None
            vsan_config.defaultConfig.autoClaimStorage = vsan_dict["auto_claim_storage"]
    log.trace("cluster_spec = {}".format(cluster_spec))


def _get_entity(service_instance, entity):
    """
    Returns the entity associated with the entity dict representation

    Supported entities: cluster, vcenter

    Expected entity format:

    .. code-block:: python

        cluster:
            {'type': 'cluster',
             'datacenter': <datacenter_name>,
             'cluster': <cluster_name>}
        vcenter:
            {'type': 'vcenter'}

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.

    entity
        Entity dict in the format above
    """

    log.trace("Retrieving entity: {}".format(entity))
    if entity["type"] == "cluster":
        dc_ref = salt.utils.vmware.get_datacenter(
            service_instance, entity["datacenter"]
        )
        return salt.utils.vmware.get_cluster(dc_ref, entity["cluster"])
    elif entity["type"] == "vcenter":
        return None
    raise ArgumentValueError("Unsupported entity type '{}'" "".format(entity["type"]))


def _validate_entity(entity):
    """
    Validates the entity dict representation

    entity
        Dictionary representation of an entity.
        See ``_get_entity`` docstrings for format.
    """

    # Validate entity:
    if entity["type"] == "cluster":
        schema = ESXClusterEntitySchema.serialize()
    elif entity["type"] == "vcenter":
        schema = VCenterEntitySchema.serialize()
    else:
        raise ArgumentValueError(
            "Unsupported entity type '{}'" "".format(entity["type"])
        )
    try:
        jsonschema.validate(entity, schema)
    except jsonschema.exceptions.ValidationError as exc:
        raise InvalidEntityError(exc)



@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_hosts_via_proxy(
    hostnames=None, datacenter=None, cluster=None, service_instance=None
):
    """
    Returns a list of hosts for the specified VMware environment. The list
    of hosts can be filtered by datacenter name and/or cluster name

    hostnames
        Hostnames to filter on.

    datacenter_name
        Name of datacenter. Only hosts in this datacenter will be retrieved.
        Default is None.

    cluster_name
        Name of cluster. Only hosts in this cluster will be retrieved. If a
        datacenter is not specified the first cluster with this name will be
        considerred. Default is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    CLI Example:

    .. code-block:: bash

        salt '*' vsphere.list_hosts_via_proxy

        salt '*' vsphere.list_hosts_via_proxy hostnames=[esxi1.example.com]

        salt '*' vsphere.list_hosts_via_proxy datacenter=dc1 cluster=cluster1
    """
    if cluster:
        if not datacenter:
            raise salt.exceptions.ArgumentValueError(
                "Datacenter is required when cluster is specified"
            )
    get_all_hosts = False
    if not hostnames:
        get_all_hosts = True
    hosts = salt.utils.vmware.get_hosts(
        service_instance,
        datacenter_name=datacenter,
        host_names=hostnames,
        cluster_name=cluster,
        get_all_hosts=get_all_hosts,
    )
    return [salt.utils.vmware.get_managed_object_name(h) for h in hosts]


@depends(HAS_PYVMOMI)
@depends(HAS_JSONSCHEMA)
@_supports_proxies("esxi")
@_gets_service_instance_via_proxy
def configure_host_cache(
    enabled, datastore=None, swap_size_MiB=None, service_instance=None
):
    """
    Configures the host cache on the selected host.

    enabled
        Boolean flag specifying whether the host cache is enabled.

    datastore
        Name of the datastore that contains the host cache. Must be set if
        enabled is ``true``.

    swap_size_MiB
        Swap size in Mibibytes. Needs to be set if enabled is ``true``. Must be
        smaller than the datastore size.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.configure_host_cache enabled=False

        salt '*' vsphere.configure_host_cache enabled=True datastore=ds1
            swap_size_MiB=1024
    """
    log.debug("Validating host cache input")
    schema = SimpleHostCacheSchema.serialize()
    try:
        jsonschema.validate(
            {
                "enabled": enabled,
                "datastore_name": datastore,
                "swap_size_MiB": swap_size_MiB,
            },
            schema,
        )
    except jsonschema.exceptions.ValidationError as exc:
        raise ArgumentValueError(exc)
    if not enabled:
        raise ArgumentValueError("Disabling the host cache is not supported")
    ret_dict = {"enabled": False}

    host_ref = _get_proxy_target(service_instance)
    hostname = __proxy__["esxi.get_details"]()["esxi_host"]
    if datastore:
        ds_refs = salt.utils.vmware.get_datastores(
            service_instance, host_ref, datastore_names=[datastore]
        )
        if not ds_refs:
            raise VMwareObjectRetrievalError(
                "Datastore '{}' was not found on host "
                "'{}'".format(datastore, hostname)
            )
        ds_ref = ds_refs[0]
    salt.utils.vmware.configure_host_cache(host_ref, ds_ref, swap_size_MiB)
    return True


def _check_hosts(service_instance, host, host_names):
    """
    Helper function that checks to see if the host provided is a vCenter Server or
    an ESXi host. If it's an ESXi host, returns a list of a single host_name.

    If a host reference isn't found, we're trying to find a host object for a vCenter
    server. Raises a CommandExecutionError in this case, as we need host references to
    check against.
    """
    if not host_names:
        host_name = _get_host_ref(service_instance, host)
        if host_name:
            host_names = [host]
        else:
            raise CommandExecutionError(
                "No host reference found. If connecting to a "
                "vCenter Server, a list of 'host_names' must be "
                "provided."
            )
    elif not isinstance(host_names, list):
        raise CommandExecutionError("'host_names' must be a list.")

    return host_names


def _get_date_time_mgr(host_reference):
    """
    Helper function that returns a dateTimeManager object
    """
    return host_reference.configManager.dateTimeSystem


def _get_host_ref(service_instance, host, host_name=None):
    """
    Helper function that returns a host object either from the host location or the host_name.
    If host_name is provided, that is the host_object that will be returned.

    The function will first search for hosts by DNS Name. If no hosts are found, it will
    try searching by IP Address.
    """
    search_index = salt.utils.vmware.get_inventory(service_instance).searchIndex

    # First, try to find the host reference by DNS Name.
    if host_name:
        host_ref = search_index.FindByDnsName(dnsName=host_name, vmSearch=False)
    else:
        host_ref = search_index.FindByDnsName(dnsName=host, vmSearch=False)

    # If we couldn't find the host by DNS Name, then try the IP Address.
    if host_ref is None:
        host_ref = search_index.FindByIp(ip=host, vmSearch=False)

    return host_ref


def _get_host_ssds(host_reference):
    """
    Helper function that returns a list of ssd objects for a given host.
    """
    return _get_host_disks(host_reference).get("SSDs")


def _get_host_non_ssds(host_reference):
    """
    Helper function that returns a list of Non-SSD objects for a given host.
    """
    return _get_host_disks(host_reference).get("Non-SSDs")


def _get_host_disks(host_reference):
    """
    Helper function that returns a dictionary containing a list of SSD and Non-SSD disks.
    """
    storage_system = host_reference.configManager.storageSystem
    disks = storage_system.storageDeviceInfo.scsiLun
    ssds = []
    non_ssds = []

    for disk in disks:
        try:
            has_ssd_attr = disk.ssd
        except AttributeError:
            has_ssd_attr = False
        if has_ssd_attr:
            ssds.append(disk)
        else:
            non_ssds.append(disk)

    return {"SSDs": ssds, "Non-SSDs": non_ssds}


def _get_service_manager(host_reference):
    """
    Helper function that returns a service manager object from a given host object.
    """
    return host_reference.configManager.serviceSystem


def _get_vsan_eligible_disks(service_instance, host, host_names):
    """
    Helper function that returns a dictionary of host_name keys with either a list of eligible
    disks that can be added to VSAN or either an 'Error' message or a message saying no
    eligible disks were found. Possible keys/values look like:

    return = {'host_1': {'Error': 'VSAN System Config Manager is unset ...'},
              'host_2': {'Eligible': 'The host xxx does not have any VSAN eligible disks.'},
              'host_3': {'Eligible': [disk1, disk2, disk3, disk4],
              'host_4': {'Eligible': []}}
    """
    ret = {}
    for host_name in host_names:

        # Get VSAN System Config Manager, if available.
        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        vsan_system = host_ref.configManager.vsanSystem
        if vsan_system is None:
            msg = (
                "VSAN System Config Manager is unset for host '{}'. "
                "VSAN configuration cannot be changed without a configured "
                "VSAN System.".format(host_name)
            )
            log.debug(msg)
            ret.update({host_name: {"Error": msg}})
            continue

        # Get all VSAN suitable disks for this host.
        suitable_disks = []
        query = vsan_system.QueryDisksForVsan()
        for item in query:
            if item.state == "eligible":
                suitable_disks.append(item)

        # No suitable disks were found to add. Warn and move on.
        # This isn't an error as the state may run repeatedly after all eligible disks are added.
        if not suitable_disks:
            msg = "The host '{}' does not have any VSAN eligible disks.".format(
                host_name
            )
            log.warning(msg)
            ret.update({host_name: {"Eligible": msg}})
            continue

        # Get disks for host and combine into one list of Disk Objects
        disks = _get_host_ssds(host_ref) + _get_host_non_ssds(host_ref)

        # Get disks that are in both the disks list and suitable_disks lists.
        matching = []
        for disk in disks:
            for suitable_disk in suitable_disks:
                if disk.canonicalName == suitable_disk.disk.canonicalName:
                    matching.append(disk)

        ret.update({host_name: {"Eligible": matching}})

    return ret


def _reset_syslog_config_params(
    host,
    username,
    password,
    cmd,
    resets,
    valid_resets,
    protocol=None,
    port=None,
    esxi_host=None,
    credstore=None,
):
    """
    Helper function for reset_syslog_config that resets the config and populates the return dictionary.
    """
    ret_dict = {}
    all_success = True

    if not isinstance(resets, list):
        resets = [resets]

    for reset_param in resets:
        if reset_param in valid_resets:
            ret = salt.utils.vmware.esxcli(
                host,
                username,
                password,
                cmd + reset_param,
                protocol=protocol,
                port=port,
                esxi_host=esxi_host,
                credstore=credstore,
            )
            ret_dict[reset_param] = {}
            ret_dict[reset_param]["success"] = ret["retcode"] == 0
            if ret["retcode"] != 0:
                all_success = False
                ret_dict[reset_param]["message"] = ret["stdout"]
        else:
            all_success = False
            ret_dict[reset_param] = {}
            ret_dict[reset_param]["success"] = False
            ret_dict[reset_param]["message"] = (
                "Invalid syslog " "configuration parameter"
            )

    ret_dict["success"] = all_success

    return ret_dict


def _set_syslog_config_helper(
    host,
    username,
    password,
    syslog_config,
    config_value,
    protocol=None,
    port=None,
    reset_service=None,
    esxi_host=None,
    credstore=None,
):
    """
    Helper function for set_syslog_config that sets the config and populates the return dictionary.
    """
    cmd = "system syslog config set --{} {}".format(syslog_config, config_value)
    ret_dict = {}

    valid_resets = [
        "logdir",
        "loghost",
        "default-rotate",
        "default-size",
        "default-timeout",
        "logdir-unique",
    ]
    if syslog_config not in valid_resets:
        ret_dict.update(
            {
                "success": False,
                "message": "'{}' is not a valid config variable.".format(syslog_config),
            }
        )
        return ret_dict

    response = salt.utils.vmware.esxcli(
        host,
        username,
        password,
        cmd,
        protocol=protocol,
        port=port,
        esxi_host=esxi_host,
        credstore=credstore,
    )

    # Update the return dictionary for success or error messages.
    if response["retcode"] != 0:
        ret_dict.update(
            {syslog_config: {"success": False, "message": response["stdout"]}}
        )
    else:
        ret_dict.update({syslog_config: {"success": True}})

    # Restart syslog for each host, if desired.
    if reset_service:
        if esxi_host:
            host_name = esxi_host
            esxi_host = [esxi_host]
        else:
            host_name = host
        response = syslog_service_reload(
            host,
            username,
            password,
            protocol=protocol,
            port=port,
            esxi_hosts=esxi_host,
            credstore=credstore,
        ).get(host_name)
        ret_dict.update({"syslog_restart": {"success": response["retcode"] == 0}})

    return ret_dict


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter", "vcenter")
def _get_proxy_target(service_instance):
    """
    Returns the target object of a proxy.

    If the object doesn't exist a VMwareObjectRetrievalError is raised

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
    """
    proxy_type = get_proxy_type()
    if not salt.utils.vmware.is_connection_to_a_vcenter(service_instance):
        raise CommandExecutionError(
            "'_get_proxy_target' not supported " "when connected via the ESXi host"
        )
    reference = None
    if proxy_type == "esxcluster":
        (
            host,
            username,
            password,
            protocol,
            port,
            mechanism,
            principal,
            domain,
            datacenter,
            cluster,
        ) = _get_esxcluster_proxy_details()

        dc_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
        reference = salt.utils.vmware.get_cluster(dc_ref, cluster)
    elif proxy_type == "esxdatacenter":
        # esxdatacenter proxy
        (
            host,
            username,
            password,
            protocol,
            port,
            mechanism,
            principal,
            domain,
            datacenter,
        ) = _get_esxdatacenter_proxy_details()

        reference = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    elif proxy_type == "vcenter":
        # vcenter proxy - the target is the root folder
        reference = salt.utils.vmware.get_root_folder(service_instance)
    elif proxy_type == "esxi":
        # esxi proxy
        details = __proxy__["esxi.get_details"]()
        if "vcenter" not in details:
            raise InvalidEntityError(
                "Proxies connected directly to ESXi " "hosts are not supported"
            )
        references = salt.utils.vmware.get_hosts(
            service_instance, host_names=details["esxi_host"]
        )
        if not references:
            raise VMwareObjectRetrievalError(
                "ESXi host '{}' was not found".format(details["esxi_host"])
            )
        reference = references[0]
    log.trace("reference = {}".format(reference))
    return reference


def _get_esxdatacenter_proxy_details():
    """
    Returns the running esxdatacenter's proxy details
    """
    det = __salt__["esxdatacenter.get_details"]()
    return (
        det.get("vcenter"),
        det.get("username"),
        det.get("password"),
        det.get("protocol"),
        det.get("port"),
        det.get("mechanism"),
        det.get("principal"),
        det.get("domain"),
        det.get("datacenter"),
    )


def _get_esxcluster_proxy_details():
    """
    Returns the running esxcluster's proxy details
    """
    det = __salt__["esxcluster.get_details"]()
    return (
        det.get("vcenter"),
        det.get("username"),
        det.get("password"),
        det.get("protocol"),
        det.get("port"),
        det.get("mechanism"),
        det.get("principal"),
        det.get("domain"),
        det.get("datacenter"),
        det.get("cluster"),
    )


def _get_esxi_proxy_details():
    """
    Returns the running esxi's proxy details
    """
    det = __proxy__["esxi.get_details"]()
    host = det.get("host")
    if det.get("vcenter"):
        host = det["vcenter"]
    esxi_hosts = None
    if det.get("esxi_host"):
        esxi_hosts = [det["esxi_host"]]
    return (
        host,
        det.get("username"),
        det.get("password"),
        det.get("protocol"),
        det.get("port"),
        det.get("mechanism"),
        det.get("principal"),
        det.get("domain"),
        esxi_hosts,
    )


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def get_advanced_configs(vm_name, datacenter, service_instance=None):
    """
    Returns extra config parameters from a virtual machine advanced config list

    vm_name
        Virtual machine name

    datacenter
        Datacenter name where the virtual machine is available

    service_instance
        vCenter service instance for connection and configuration
    """
    current_config = get_vm_config(
        vm_name, datacenter=datacenter, objects=True, service_instance=service_instance
    )
    return current_config["advanced_configs"]


def _apply_advanced_config(config_spec, advanced_config, vm_extra_config=None):
    """
    Sets configuration parameters for the vm

    config_spec
        vm.ConfigSpec object

    advanced_config
        config key value pairs

    vm_extra_config
        Virtual machine vm_ref.config.extraConfig object
    """
    log.trace(
        "Configuring advanced configuration " "parameters {}".format(advanced_config)
    )
    if isinstance(advanced_config, str):
        raise salt.exceptions.ArgumentValueError(
            "The specified 'advanced_configs' configuration "
            "option cannot be parsed, please check the parameters"
        )
    for key, value in advanced_config.items():
        if vm_extra_config:
            for option in vm_extra_config:
                if option.key == key and option.value == str(value):
                    continue
        else:
            option = vim.option.OptionValue(key=key, value=value)
            config_spec.extraConfig.append(option)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def set_advanced_configs(vm_name, datacenter, advanced_configs, service_instance=None):
    """
    Appends extra config parameters to a virtual machine advanced config list

    vm_name
        Virtual machine name

    datacenter
        Datacenter name where the virtual machine is available

    advanced_configs
        Dictionary with advanced parameter key value pairs

    service_instance
        vCenter service instance for connection and configuration
    """
    current_config = get_vm_config(
        vm_name, datacenter=datacenter, objects=True, service_instance=service_instance
    )
    diffs = compare_vm_configs(
        {"name": vm_name, "advanced_configs": advanced_configs}, current_config
    )
    datacenter_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    vm_ref = salt.utils.vmware.get_mor_by_property(
        service_instance,
        vim.VirtualMachine,
        vm_name,
        property_name="name",
        container_ref=datacenter_ref,
    )
    config_spec = vim.vm.ConfigSpec()
    changes = diffs["advanced_configs"].diffs
    _apply_advanced_config(
        config_spec, diffs["advanced_configs"].new_values, vm_ref.config.extraConfig
    )
    if changes:
        salt.utils.vmware.update_vm(vm_ref, config_spec)
    return {"advanced_config_changes": changes}


def _delete_advanced_config(config_spec, advanced_config, vm_extra_config):
    """
    Removes configuration parameters for the vm

    config_spec
        vm.ConfigSpec object

    advanced_config
        List of advanced config keys to be deleted

    vm_extra_config
        Virtual machine vm_ref.config.extraConfig object
    """
    log.trace(
        "Removing advanced configuration " "parameters {}".format(advanced_config)
    )
    if isinstance(advanced_config, str):
        raise salt.exceptions.ArgumentValueError(
            "The specified 'advanced_configs' configuration "
            "option cannot be parsed, please check the parameters"
        )
    removed_configs = []
    for key in advanced_config:
        for option in vm_extra_config:
            if option.key == key:
                option = vim.option.OptionValue(key=key, value="")
                config_spec.extraConfig.append(option)
                removed_configs.append(key)
    return removed_configs


@depends(HAS_PYVMOMI)
@_supports_proxies("esxvm", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def delete_advanced_configs(
    vm_name, datacenter, advanced_configs, service_instance=None
):
    """
    Removes extra config parameters from a virtual machine

    vm_name
        Virtual machine name

    datacenter
        Datacenter name where the virtual machine is available

    advanced_configs
        List of advanced config values to be removed

    service_instance
        vCenter service instance for connection and configuration
    """
    datacenter_ref = salt.utils.vmware.get_datacenter(service_instance, datacenter)
    vm_ref = salt.utils.vmware.get_mor_by_property(
        service_instance,
        vim.VirtualMachine,
        vm_name,
        property_name="name",
        container_ref=datacenter_ref,
    )
    config_spec = vim.vm.ConfigSpec()
    removed_configs = _delete_advanced_config(
        config_spec, advanced_configs, vm_ref.config.extraConfig
    )
    if removed_configs:
        salt.utils.vmware.update_vm(vm_ref, config_spec)
    return {"removed_configs": removed_configs}
