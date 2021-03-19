from salt.utils.decorators import _supports_proxies
from salt.utils.decorators import depends
from salt.utils.decorators import ignores_kwargs

HAS_PYVMOMI = False
HAS_ESX_CLI = False


@depends(HAS_PYVMOMI)
def _get_service_instance():
    """
    Returns a service instance to the proxied endpoint (vCenter/ESXi host).

    Note:
        Should be used by state functions not invoked directly.

    CLI Example:

        See note above
    """
    if salt.utils.platform.is_proxy():
        return _get_service_instance_via_proxy
    else:
        return _get_service_instance_via_config


@depends(HAS_PYVMOMI)
def _get_service_instance_via_proxy():
    """
    Returns a service instance to the proxied endpoint (vCenter/ESXi host).

    Note:
        Should be used by state functions not invoked directly.

    CLI Example:

        See note above
    """
    connection_details = _get_proxy_connection_details()
    return (
        saltext.vmware.utils.vmware.get_service_instance(  # pylint: disable=no-value-for-parameter
            *connection_details
        )
    )


@depends(HAS_PYVMOMI)
def _get_service_instance_via_config():
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

    return saltext.vmware.utils.vmware.get_service_instance(
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


@depends(HAS_ESX_CLI)
def syslog_service_reload(
    host, username, password, protocol=None, port=None, esxi_hosts=None, credstore=None
):
    """
    Reload the syslog service so it will pick up any changes.

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

    esxi_hosts
        If ``host`` is a vCenter host, then use esxi_hosts to execute this function
        on a list of one or more ESXi machines.

    credstore
        Optionally set to path to the credential store file.

    :return: A standard cmd.run_all dictionary.  This dictionary will at least
             have a `retcode` key.  If `retcode` is 0 the command was successful.

    CLI Example:

    .. code-block:: bash

        # Used for ESXi host connection information
        salt '*' vsphere.syslog_service_reload my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.syslog_service_reload my.vcenter.location root bad-password \
            esxi_hosts='[esxi-1.host.com, esxi-2.host.com]'
    """
    cmd = "system syslog reload"

    ret = {}
    if esxi_hosts:
        if not isinstance(esxi_hosts, list):
            raise CommandExecutionError("'esxi_hosts' must be a list.")

        for esxi_host in esxi_hosts:
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
            ret.update({esxi_host: response})
    else:
        # Handles a single host or a vCenter connection when no esxi_hosts are provided.
        response = salt.utils.vmware.esxcli(
            host,
            username,
            password,
            cmd,
            protocol=protocol,
            port=port,
            credstore=credstore,
        )
        ret.update({host: response})

    return ret


@depends(HAS_ESX_CLI)
def set_syslog_config(
    host,
    username,
    password,
    syslog_config,
    config_value,
    protocol=None,
    port=None,
    firewall=True,
    reset_service=True,
    esxi_hosts=None,
    credstore=None,
):
    """
    Set the specified syslog configuration parameter. By default, this function will
    reset the syslog service after the configuration is set.

    host
        ESXi or vCenter host to connect to.

    username
        User to connect as, usually root.

    password
        Password to connect with.

    syslog_config
        Name of parameter to set (corresponds to the command line switch for
        esxcli without the double dashes (--))

        Valid syslog_config values are ``logdir``, ``loghost``, ``default-rotate`,
        ``default-size``, ``default-timeout``, and ``logdir-unique``.

    config_value
        Value for the above parameter. For ``loghost``, URLs or IP addresses to
        use for logging. Multiple log servers can be specified by listing them,
        comma-separated, but without spaces before or after commas.

        (reference: https://blogs.vmware.com/vsphere/2012/04/configuring-multiple-syslog-servers-for-esxi-5.html)

    protocol
        Optionally set to alternate protocol if the host is not using the default
        protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the host is not using the default
        port. Default port is ``443``.

    firewall
        Enable the firewall rule set for syslog. Defaults to ``True``.

    reset_service
        After a successful parameter set, reset the service. Defaults to ``True``.

    esxi_hosts
        If ``host`` is a vCenter host, then use esxi_hosts to execute this function
        on a list of one or more ESXi machines.

    credstore
        Optionally set to path to the credential store file.

    :return: Dictionary with a top-level key of 'success' which indicates
             if all the parameters were reset, and individual keys
             for each parameter indicating which succeeded or failed, per host.

    CLI Example:

    .. code-block:: bash

        # Used for ESXi host connection information
        salt '*' vsphere.set_syslog_config my.esxi.host root bad-password \
            loghost ssl://localhost:5432,tcp://10.1.0.1:1514

        # Used for connecting to a vCenter Server
        salt '*' vsphere.set_syslog_config my.vcenter.location root bad-password \
            loghost ssl://localhost:5432,tcp://10.1.0.1:1514 \
            esxi_hosts='[esxi-1.host.com, esxi-2.host.com]'

    """
    ret = {}

    # First, enable the syslog firewall ruleset, for each host, if needed.
    if firewall and syslog_config == "loghost":
        if esxi_hosts:
            if not isinstance(esxi_hosts, list):
                raise CommandExecutionError("'esxi_hosts' must be a list.")

            for esxi_host in esxi_hosts:
                response = enable_firewall_ruleset(
                    host,
                    username,
                    password,
                    ruleset_enable=True,
                    ruleset_name="syslog",
                    protocol=protocol,
                    port=port,
                    esxi_hosts=[esxi_host],
                    credstore=credstore,
                ).get(esxi_host)
                if response["retcode"] != 0:
                    ret.update(
                        {
                            esxi_host: {
                                "enable_firewall": {
                                    "message": response["stdout"],
                                    "success": False,
                                }
                            }
                        }
                    )
                else:
                    ret.update({esxi_host: {"enable_firewall": {"success": True}}})
        else:
            # Handles a single host or a vCenter connection when no esxi_hosts are provided.
            response = enable_firewall_ruleset(
                host,
                username,
                password,
                ruleset_enable=True,
                ruleset_name="syslog",
                protocol=protocol,
                port=port,
                credstore=credstore,
            ).get(host)
            if response["retcode"] != 0:
                ret.update(
                    {
                        host: {
                            "enable_firewall": {
                                "message": response["stdout"],
                                "success": False,
                            }
                        }
                    }
                )
            else:
                ret.update({host: {"enable_firewall": {"success": True}}})

    # Set the config value on each esxi_host, if provided.
    if esxi_hosts:
        if not isinstance(esxi_hosts, list):
            raise CommandExecutionError("'esxi_hosts' must be a list.")

        for esxi_host in esxi_hosts:
            response = _set_syslog_config_helper(
                host,
                username,
                password,
                syslog_config,
                config_value,
                protocol=protocol,
                port=port,
                reset_service=reset_service,
                esxi_host=esxi_host,
                credstore=credstore,
            )
            # Ensure we don't overwrite any dictionary data already set
            # By updating the esxi_host directly.
            if ret.get(esxi_host) is None:
                ret.update({esxi_host: {}})
            ret[esxi_host].update(response)

    else:
        # Handles a single host or a vCenter connection when no esxi_hosts are provided.
        response = _set_syslog_config_helper(
            host,
            username,
            password,
            syslog_config,
            config_value,
            protocol=protocol,
            port=port,
            reset_service=reset_service,
            credstore=credstore,
        )
        # Ensure we don't overwrite any dictionary data already set
        # By updating the host directly.
        if ret.get(host) is None:
            ret.update({host: {}})
        ret[host].update(response)

    return ret


@depends(HAS_ESX_CLI)
def get_syslog_config(
    host, username, password, protocol=None, port=None, esxi_hosts=None, credstore=None
):
    """
    Retrieve the syslog configuration.

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

    esxi_hosts
        If ``host`` is a vCenter host, then use esxi_hosts to execute this function
        on a list of one or more ESXi machines.

    credstore
        Optionally set to path to the credential store file.

    :return: Dictionary with keys and values corresponding to the
             syslog configuration, per host.

    CLI Example:

    .. code-block:: bash

        # Used for ESXi host connection information
        salt '*' vsphere.get_syslog_config my.esxi.host root bad-password

        # Used for connecting to a vCenter Server
        salt '*' vsphere.get_syslog_config my.vcenter.location root bad-password \
            esxi_hosts='[esxi-1.host.com, esxi-2.host.com]'
    """
    cmd = "system syslog config get"

    ret = {}
    if esxi_hosts:
        if not isinstance(esxi_hosts, list):
            raise CommandExecutionError("'esxi_hosts' must be a list.")

        for esxi_host in esxi_hosts:
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
            # format the response stdout into something useful
            ret.update({esxi_host: _format_syslog_config(response)})
    else:
        # Handles a single host or a vCenter connection when no esxi_hosts are provided.
        response = salt.utils.vmware.esxcli(
            host,
            username,
            password,
            cmd,
            protocol=protocol,
            port=port,
            credstore=credstore,
        )
        # format the response stdout into something useful
        ret.update({host: _format_syslog_config(response)})

    return ret


@depends(HAS_ESX_CLI)
def reset_syslog_config(
    host,
    username,
    password,
    protocol=None,
    port=None,
    syslog_config=None,
    esxi_hosts=None,
    credstore=None,
):
    """
    Reset the syslog service to its default settings.

    Valid syslog_config values are ``logdir``, ``loghost``, ``logdir-unique``,
    ``default-rotate``, ``default-size``, ``default-timeout``,
    or ``all`` for all of these.

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

    syslog_config
        List of parameters to reset, provided as a comma-delimited string, or 'all' to
        reset all syslog configuration parameters. Required.

    esxi_hosts
        If ``host`` is a vCenter host, then use esxi_hosts to execute this function
        on a list of one or more ESXi machines.

    credstore
        Optionally set to path to the credential store file.

    :return: Dictionary with a top-level key of 'success' which indicates
             if all the parameters were reset, and individual keys
             for each parameter indicating which succeeded or failed, per host.

    CLI Example:

    ``syslog_config`` can be passed as a quoted, comma-separated string, e.g.

    .. code-block:: bash

        # Used for ESXi host connection information
        salt '*' vsphere.reset_syslog_config my.esxi.host root bad-password \
            syslog_config='logdir,loghost'

        # Used for connecting to a vCenter Server
        salt '*' vsphere.reset_syslog_config my.vcenter.location root bad-password \
            syslog_config='logdir,loghost' esxi_hosts='[esxi-1.host.com, esxi-2.host.com]'
    """
    if not syslog_config:
        raise CommandExecutionError(
            "The 'reset_syslog_config' function requires a " "'syslog_config' setting."
        )

    valid_resets = [
        "logdir",
        "loghost",
        "default-rotate",
        "default-size",
        "default-timeout",
        "logdir-unique",
    ]
    cmd = "system syslog config set --reset="
    if "," in syslog_config:
        resets = [ind_reset.strip() for ind_reset in syslog_config.split(",")]
    elif syslog_config == "all":
        resets = valid_resets
    else:
        resets = [syslog_config]

    ret = {}
    if esxi_hosts:
        if not isinstance(esxi_hosts, list):
            raise CommandExecutionError("'esxi_hosts' must be a list.")

        for esxi_host in esxi_hosts:
            response_dict = _reset_syslog_config_params(
                host,
                username,
                password,
                cmd,
                resets,
                valid_resets,
                protocol=protocol,
                port=port,
                esxi_host=esxi_host,
                credstore=credstore,
            )
            ret.update({esxi_host: response_dict})
    else:
        # Handles a single host or a vCenter connection when no esxi_hosts are provided.
        response_dict = _reset_syslog_config_params(
            host,
            username,
            password,
            cmd,
            resets,
            valid_resets,
            protocol=protocol,
            port=port,
            credstore=credstore,
        )
        ret.update({host: response_dict})

    return ret


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
def get_ssh_key(host, username, password, protocol=None, port=None, certificate_verify=None):
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
@ignores_kwargs("credstore")
def get_service_policy(
    host,
    username,
    password,
    service_name,
    protocol=None,
    port=None,
    host_names=None,
    verify_ssl=True,
):
    """
    Get the service name's policy for a given host or list of hosts.

    host
        The location of the host.

    username
        The username used to login to the host, such as ``root``.

    password
        The password used to login to the host.

    service_name
        The name of the service for which to retrieve the policy. Supported service names are:
          - DCUI
          - TSM
          - SSH
          - lbtd
          - lsassd
          - lwiod
          - netlogond
          - ntpd
          - sfcbd-watchdog
          - snmpd
          - vprobed
          - vpxa
          - xorg

    protocol
        Optionally set to alternate protocol if the host is not using the default
        protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the host is not using the default
        port. Default port is ``443``.

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to tell
        vCenter the hosts for which to get service policy information.

        If host_names is not provided, the service policy information will be retrieved
        for the ``host`` location instead. This is useful for when service instance
        connection information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.get_service_policy my.esxi.host root bad-password 'ssh'

        # Used for connecting to a vCenter Server
        salt '*' vsphere.get_service_policy my.vcenter.location root bad-password 'ntpd' \
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
    valid_services = [
        "DCUI",
        "TSM",
        "SSH",
        "ssh",
        "lbtd",
        "lsassd",
        "lwiod",
        "netlogond",
        "ntpd",
        "sfcbd-watchdog",
        "snmpd",
        "vprobed",
        "vpxa",
        "xorg",
    ]
    host_names = _check_hosts(service_instance, host, host_names)

    ret = {}
    for host_name in host_names:
        # Check if the service_name provided is a valid one.
        # If we don't have a valid service, return. The service will be invalid for all hosts.
        if service_name not in valid_services:
            ret.update(
                {host_name: {"Error": "{} is not a valid service name.".format(service_name)}}
            )
            return ret

        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        services = host_ref.configManager.serviceSystem.serviceInfo.service

        # Don't require users to know that VMware lists the ssh service as TSM-SSH
        if service_name == "SSH" or service_name == "ssh":
            temp_service_name = "TSM-SSH"
        else:
            temp_service_name = service_name

        # Loop through services until we find a matching name
        for service in services:
            if service.key == temp_service_name:
                ret.update({host_name: {service_name: service.policy}})
                # We've found a match - break out of the loop so we don't overwrite the
                # Updated host_name value with an error message.
                break
            else:
                msg = "Could not find service '{}' for host '{}'.".format(service_name, host_name)
                ret.update({host_name: {"Error": msg}})

        # If we made it this far, something else has gone wrong.
        if ret.get(host_name) is None:
            msg = "'vsphere.get_service_policy' failed for host {}.".format(host_name)
            log.debug(msg)
            ret.update({host_name: {"Error": msg}})

    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def get_service_running(
    host,
    username,
    password,
    service_name,
    protocol=None,
    port=None,
    host_names=None,
    verify_ssl=True,
):
    """
    Get the service name's running state for a given host or list of hosts.

    host
        The location of the host.

    username
        The username used to login to the host, such as ``root``.

    password
        The password used to login to the host.

    service_name
        The name of the service for which to retrieve the policy. Supported service names are:
          - DCUI
          - TSM
          - SSH
          - lbtd
          - lsassd
          - lwiod
          - netlogond
          - ntpd
          - sfcbd-watchdog
          - snmpd
          - vprobed
          - vpxa
          - xorg

    protocol
        Optionally set to alternate protocol if the host is not using the default
        protocol. Default protocol is ``https``.

    port
        Optionally set to alternate port if the host is not using the default
        port. Default port is ``443``.

    host_names
        List of ESXi host names. When the host, username, and password credentials
        are provided for a vCenter Server, the host_names argument is required to tell
        vCenter the hosts for which to get the service's running state.

        If host_names is not provided, the service's running state will be retrieved
        for the ``host`` location instead. This is useful for when service instance
        connection information is used for a single ESXi host.

    verify_ssl
        Verify the SSL certificate. Default: True

    CLI Example:

    .. code-block:: bash

        # Used for single ESXi host connection information
        salt '*' vsphere.get_service_running my.esxi.host root bad-password 'ssh'

        # Used for connecting to a vCenter Server
        salt '*' vsphere.get_service_running my.vcenter.location root bad-password 'ntpd' \
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
    valid_services = [
        "DCUI",
        "TSM",
        "SSH",
        "ssh",
        "lbtd",
        "lsassd",
        "lwiod",
        "netlogond",
        "ntpd",
        "sfcbd-watchdog",
        "snmpd",
        "vprobed",
        "vpxa",
        "xorg",
    ]
    host_names = _check_hosts(service_instance, host, host_names)

    ret = {}
    for host_name in host_names:
        # Check if the service_name provided is a valid one.
        # If we don't have a valid service, return. The service will be invalid for all hosts.
        if service_name not in valid_services:
            ret.update(
                {host_name: {"Error": "{} is not a valid service name.".format(service_name)}}
            )
            return ret

        host_ref = _get_host_ref(service_instance, host, host_name=host_name)
        services = host_ref.configManager.serviceSystem.serviceInfo.service

        # Don't require users to know that VMware lists the ssh service as TSM-SSH
        if service_name == "SSH" or service_name == "ssh":
            temp_service_name = "TSM-SSH"
        else:
            temp_service_name = service_name

        # Loop through services until we find a matching name
        for service in services:
            if service.key == temp_service_name:
                ret.update({host_name: {service_name: service.running}})
                # We've found a match - break out of the loop so we don't overwrite the
                # Updated host_name value with an error message.
                break
            else:
                msg = "Could not find service '{}' for host '{}'.".format(service_name, host_name)
                ret.update({host_name: {"Error": msg}})

        # If we made it this far, something else has gone wrong.
        if ret.get(host_name) is None:
            msg = "'vsphere.get_service_running' failed for host {}.".format(host_name)
            log.debug(msg)
            ret.update({host_name: {"Error": msg}})

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
    host,
    username,
    password,
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
            ret = dictupdate.update(ret, salt.utils.vmware.get_hardware_grains(service_instance))
    return ret


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_datastore_clusters(host, username, password, protocol=None, port=None, verify_ssl=True):
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
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_datastore_clusters(service_instance)


@depends(HAS_PYVMOMI)
@ignores_kwargs("credstore")
def list_datastores(host, username, password, protocol=None, port=None, verify_ssl=True):
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
    service_instance = salt.utils.vmware.get_service_instance(
        host=host,
        username=username,
        password=password,
        protocol=protocol,
        port=port,
        verify_ssl=verify_ssl,
    )
    return salt.utils.vmware.list_datastores(service_instance)


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
def list_resourcepools(host, username, password, protocol=None, port=None, verify_ssl=True):
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
def list_ssds(host, username, password, protocol=None, port=None, host_names=None, verify_ssl=True):
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
        log.debug("Configuring NTP Servers '{}' for host '{}'.".format(ntp_servers, host_name))

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
            msg = "'vsphere.update_date_time' failed for host {}: {}".format(host_name, err)
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
            "'vsphere.update_host_password' failed for host {}: " "User was not found.".format(host)
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
        policies = salt.utils.pbm.get_storage_policies(profile_manager, get_all_policies=True)
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
    policies = salt.utils.pbm.get_storage_policies(profile_manager, get_all_policies=True)
    def_policies = [p for p in policies if p.systemCreatedProfileType == "VsanDefaultProfile"]
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
                        pbm.capability.ConstraintInstance(propertyInstance=[prop_inst_spec])
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
    log.trace("create storage policy '{}', dict = {}" "".format(policy_name, policy_dict))
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
    salt.utils.pbm.update_storage_policy(profile_manager, policy_ref, policy_update_spec)
    return {"update_storage_policy": True}


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
    log.trace("Listing the default storage policy of datastore '{}'" "".format(datastore))
    # Find datastore
    target_ref = _get_proxy_target(service_instance)
    ds_refs = salt.utils.vmware.get_datastores(
        service_instance, target_ref, datastore_names=[datastore]
    )
    if not ds_refs:
        raise VMwareObjectRetrievalError("Datastore '{}' was not " "found".format(datastore))
    profile_manager = salt.utils.pbm.get_profile_manager(service_instance)
    policy = salt.utils.pbm.get_default_storage_policy_of_datastore(profile_manager, ds_refs[0])
    return _get_policy_dict(policy)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def assign_default_storage_policy_to_datastore(policy, datastore, service_instance=None):
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
        raise VMwareObjectRetrievalError("Datastore '{}' was not " "found".format(datastore))
    ds_ref = ds_refs[0]
    salt.utils.pbm.assign_default_storage_policy_to_datastore(profile_manager, policy_ref, ds_ref)
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
        dc_refs = salt.utils.vmware.get_datacenters(service_instance, get_all_datacenters=True)
    else:
        dc_refs = salt.utils.vmware.get_datacenters(service_instance, datacenter_names)

    return [{"name": salt.utils.vmware.get_managed_object_name(dc_ref)} for dc_ref in dc_refs]


def _get_cluster_dict(cluster_name, cluster_ref):
    """
    Returns a cluster dict representation from
    a vim.ClusterComputeResource object.

    cluster_name
        Name of the cluster

    cluster_ref
        Reference to the cluster
    """

    log.trace("Building a dictionary representation of cluster " "'{}'".format(cluster_name))
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
        res["ha"]["options"] = [{"key": o.key, "value": o.value} for o in ha_conf.option]
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

                das_config.admissionControlPolicy = (
                    vim.ClusterFailoverResourcesAdmissionControlPolicy(
                        cpuFailoverResourcesPercent=adm_pol_dict["cpu_failover_percent"],
                        memoryFailoverResourcesPercent=adm_pol_dict["memory_failover_percent"],
                    )
                )
        if "default_vm_settings" in ha_dict:
            vm_set_dict = ha_dict["default_vm_settings"]
            if not das_config.defaultVmSettings:
                das_config.defaultVmSettings = vim.ClusterDasVmSettings()
            if "isolation_response" in vm_set_dict:
                das_config.defaultVmSettings.isolationResponse = vm_set_dict["isolation_response"]
            if "restart_priority" in vm_set_dict:
                das_config.defaultVmSettings.restartPriority = vm_set_dict["restart_priority"]
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
            drs_config.defaultVmBehavior = vim.DrsBehavior(drs_dict["default_vm_behavior"])
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
                vsan_spec.dataEfficiencyConfig.compressionEnabled = vsan_dict["compression_enabled"]
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


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter")
@_gets_service_instance_via_proxy
def list_datastores_via_proxy(
    datastore_names=None,
    backing_disk_ids=None,
    backing_disk_scsi_addresses=None,
    service_instance=None,
):
    """
    Returns a list of dict representations of the datastores visible to the
    proxy object. The list of datastores can be filtered by datastore names,
    backing disk ids (canonical names) or backing disk scsi addresses.

    Supported proxy types: esxi, esxcluster, esxdatacenter

    datastore_names
        List of the names of datastores to filter on

    backing_disk_ids
        List of canonical names of the backing disks of the datastores to filer.
        Default is None.

    backing_disk_scsi_addresses
        List of scsi addresses of the backing disks of the datastores to filter.
        Default is None.

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter/ESXi host.
        Default is None.

    .. code-block:: bash

        salt '*' vsphere.list_datastores_via_proxy

        salt '*' vsphere.list_datastores_via_proxy datastore_names=[ds1, ds2]
    """
    target = _get_proxy_target(service_instance)
    target_name = salt.utils.vmware.get_managed_object_name(target)
    log.trace("target name = {}".format(target_name))

    # Default to getting all disks if no filtering is done
    get_all_datastores = (
        True if not (datastore_names or backing_disk_ids or backing_disk_scsi_addresses) else False
    )
    # Get the ids of the disks with the scsi addresses
    if backing_disk_scsi_addresses:
        log.debug(
            "Retrieving disk ids for scsi addresses " "'{}'".format(backing_disk_scsi_addresses)
        )
        disk_ids = [
            d.canonicalName
            for d in salt.utils.vmware.get_disks(target, scsi_addresses=backing_disk_scsi_addresses)
        ]
        log.debug("Found disk ids '{}'".format(disk_ids))
        backing_disk_ids = backing_disk_ids.extend(disk_ids) if backing_disk_ids else disk_ids
    datastores = salt.utils.vmware.get_datastores(
        service_instance, target, datastore_names, backing_disk_ids, get_all_datastores
    )

    # Search for disk backed datastores if target is host
    # to be able to add the backing_disk_ids
    mount_infos = []
    if isinstance(target, vim.HostSystem):
        storage_system = salt.utils.vmware.get_storage_system(service_instance, target, target_name)
        props = salt.utils.vmware.get_properties_of_managed_object(
            storage_system, ["fileSystemVolumeInfo.mountInfo"]
        )
        mount_infos = props.get("fileSystemVolumeInfo.mountInfo", [])
    ret_dict = []
    for ds in datastores:
        ds_dict = {
            "name": ds.name,
            "type": ds.summary.type,
            "free_space": ds.summary.freeSpace,
            "capacity": ds.summary.capacity,
        }
        backing_disk_ids = []
        for vol in [
            i.volume
            for i in mount_infos
            if i.volume.name == ds.name and isinstance(i.volume, vim.HostVmfsVolume)
        ]:

            backing_disk_ids.extend([e.diskName for e in vol.extent])
        if backing_disk_ids:
            ds_dict["backing_disk_ids"] = backing_disk_ids
        ret_dict.append(ds_dict)
    return ret_dict


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
    log.trace("Renaming datastore {} to {}" "".format(datastore_name, new_datastore_name))
    target = _get_proxy_target(service_instance)
    datastores = salt.utils.vmware.get_datastores(
        service_instance, target, datastore_names=[datastore_name]
    )
    if not datastores:
        raise VMwareObjectRetrievalError("Datastore '{}' was not found" "".format(datastore_name))
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
        raise VMwareObjectRetrievalError("Datastore '{}' was not found".format(datastore))
    if len(datastores) > 1:
        raise VMwareObjectRetrievalError("Multiple datastores '{}' were found".format(datastore))
    salt.utils.vmware.remove_datastore(service_instance, datastores[0])
    return True


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
        dc_ref = salt.utils.vmware.get_datacenter(service_instance, entity["datacenter"])
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
        raise ArgumentValueError("Unsupported entity type '{}'" "".format(entity["type"]))
    try:
        jsonschema.validate(entity, schema)
    except jsonschema.exceptions.ValidationError as exc:
        raise InvalidEntityError(exc)


@depends(HAS_PYVMOMI)
@_supports_proxies("esxi", "esxcluster", "esxdatacenter", "vcenter")
@_gets_service_instance_via_proxy
def list_hosts_via_proxy(hostnames=None, datacenter=None, cluster=None, service_instance=None):
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
def configure_host_cache(enabled, datastore=None, swap_size_MiB=None, service_instance=None):
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
                "Datastore '{}' was not found on host " "'{}'".format(datastore, hostname)
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


def _format_coredump_stdout(cmd_ret):
    """
    Helper function to format the stdout from the get_coredump_network_config function.

    cmd_ret
        The return dictionary that comes from a cmd.run_all call.
    """
    ret_dict = {}
    for line in cmd_ret["stdout"].splitlines():
        line = line.strip().lower()
        if line.startswith("enabled:"):
            enabled = line.split(":")
            if "true" in enabled[1]:
                ret_dict["enabled"] = True
            else:
                ret_dict["enabled"] = False
                break
        if line.startswith("host vnic:"):
            host_vnic = line.split(":")
            ret_dict["host_vnic"] = host_vnic[1].strip()
        if line.startswith("network server ip:"):
            ip = line.split(":")
            ret_dict["ip"] = ip[1].strip()
        if line.startswith("network server port:"):
            ip_port = line.split(":")
            ret_dict["port"] = ip_port[1].strip()

    return ret_dict


def _format_firewall_stdout(cmd_ret):
    """
    Helper function to format the stdout from the get_firewall_status function.

    cmd_ret
        The return dictionary that comes from a cmd.run_all call.
    """
    ret_dict = {"success": True, "rulesets": {}}
    for line in cmd_ret["stdout"].splitlines():
        if line.startswith("Name"):
            continue
        if line.startswith("---"):
            continue
        ruleset_status = line.split()
        ret_dict["rulesets"][ruleset_status[0]] = bool(ruleset_status[1])

    return ret_dict


def _format_syslog_config(cmd_ret):
    """
    Helper function to format the stdout from the get_syslog_config function.

    cmd_ret
        The return dictionary that comes from a cmd.run_all call.
    """
    ret_dict = {"success": cmd_ret["retcode"] == 0}

    if cmd_ret["retcode"] != 0:
        ret_dict["message"] = cmd_ret["stdout"]
    else:
        for line in cmd_ret["stdout"].splitlines():
            line = line.strip()
            cfgvars = line.split(": ")
            key = cfgvars[0].strip()
            value = cfgvars[1].strip()
            ret_dict[key] = value

    return ret_dict


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
            msg = "The host '{}' does not have any VSAN eligible disks.".format(host_name)
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
            ret_dict[reset_param]["message"] = "Invalid syslog " "configuration parameter"

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
        ret_dict.update({syslog_config: {"success": False, "message": response["stdout"]}})
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
        references = salt.utils.vmware.get_hosts(service_instance, host_names=details["esxi_host"])
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


def _apply_hardware_version(hardware_version, config_spec, operation="add"):
    """
    Specifies vm container version or schedules upgrade,
    returns True on change and False if nothing have been changed.

    hardware_version
        Hardware version string eg. vmx-08

    config_spec
        Configuration spec object

    operation
        Defines the operation which should be used,
        the possibles values: 'add' and 'edit', the default value is 'add'
    """
    log.trace("Configuring virtual machine hardware " "version version={}".format(hardware_version))
    if operation == "edit":
        log.trace("Scheduling hardware version " "upgrade to {}".format(hardware_version))
        scheduled_hardware_upgrade = vim.vm.ScheduledHardwareUpgradeInfo()
        scheduled_hardware_upgrade.upgradePolicy = "always"
        scheduled_hardware_upgrade.versionKey = hardware_version
        config_spec.scheduledHardwareUpgradeInfo = scheduled_hardware_upgrade
    elif operation == "add":
        config_spec.version = str(hardware_version)


def _apply_cpu_config(config_spec, cpu_props):
    """
    Sets CPU core count to the given value

    config_spec
        vm.ConfigSpec object

    cpu_props
        CPU properties dict
    """
    log.trace("Configuring virtual machine CPU " "settings cpu_props={}".format(cpu_props))
    if "count" in cpu_props:
        config_spec.numCPUs = int(cpu_props["count"])
    if "cores_per_socket" in cpu_props:
        config_spec.numCoresPerSocket = int(cpu_props["cores_per_socket"])
    if "nested" in cpu_props and cpu_props["nested"]:
        config_spec.nestedHVEnabled = cpu_props["nested"]  # True
    if "hotadd" in cpu_props and cpu_props["hotadd"]:
        config_spec.cpuHotAddEnabled = cpu_props["hotadd"]  # True
    if "hotremove" in cpu_props and cpu_props["hotremove"]:
        config_spec.cpuHotRemoveEnabled = cpu_props["hotremove"]  # True


def _apply_memory_config(config_spec, memory):
    """
    Sets memory size to the given value

    config_spec
        vm.ConfigSpec object

    memory
        Memory size and unit
    """
    log.trace("Configuring virtual machine memory " "settings memory={}".format(memory))
    if "size" in memory and "unit" in memory:
        try:
            if memory["unit"].lower() == "kb":
                memory_mb = memory["size"] / 1024
            elif memory["unit"].lower() == "mb":
                memory_mb = memory["size"]
            elif memory["unit"].lower() == "gb":
                memory_mb = int(float(memory["size"]) * 1024)
        except (TypeError, ValueError):
            memory_mb = int(memory["size"])
        config_spec.memoryMB = memory_mb
    if "reservation_max" in memory:
        config_spec.memoryReservationLockedToMax = memory["reservation_max"]
    if "hotadd" in memory:
        config_spec.memoryHotAddEnabled = memory["hotadd"]


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
    log.trace("Configuring advanced configuration " "parameters {}".format(advanced_config))
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
    log.trace("Removing advanced configuration " "parameters {}".format(advanced_config))
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
def delete_advanced_configs(vm_name, datacenter, advanced_configs, service_instance=None):
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


def _get_scsi_controller_key(bus_number, scsi_ctrls):
    """
    Returns key number of the SCSI controller keys

    bus_number
        Controller bus number from the adapter

    scsi_ctrls
        List of SCSI Controller objects (old+newly created)
    """
    # list of new/old VirtualSCSIController objects, both new and old objects
    # should contain a key attribute key should be a negative integer in case
    # of a new object
    keys = [ctrl.key for ctrl in scsi_ctrls if scsi_ctrls and ctrl.busNumber == bus_number]
    if not keys:
        raise salt.exceptions.VMwareVmCreationError(
            "SCSI controller number {} doesn't exist".format(bus_number)
        )
    return keys[0]


def _apply_hard_disk(
    unit_number,
    key,
    operation,
    disk_label=None,
    size=None,
    unit="GB",
    controller_key=None,
    thin_provision=None,
    eagerly_scrub=None,
    datastore=None,
    filename=None,
):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to add/edit
    a virtual disk device

    unit_number
        Add network adapter to this address

    key
        Device key number

    operation
        Action which should be done on the device add or edit

    disk_label
        Label of the new disk, can be overridden

    size
        Size of the disk

    unit
        Unit of the size, can be GB, MB, KB

    controller_key
        Unique umber of the controller key

    thin_provision
        Boolean for thin provision

    eagerly_scrub
        Boolean for eagerly scrubbing

    datastore
        Datastore name where the disk will be located

    filename
        Full file name of the vm disk
    """
    log.trace(
        "Configuring hard disk {} size={}, unit={}, "
        "controller_key={}, thin_provision={}, "
        "eagerly_scrub={}, datastore={}, "
        "filename={}".format(
            disk_label,
            size,
            unit,
            controller_key,
            thin_provision,
            eagerly_scrub,
            datastore,
            filename,
        )
    )
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.device = vim.vm.device.VirtualDisk()
    disk_spec.device.key = key
    disk_spec.device.unitNumber = unit_number
    disk_spec.device.deviceInfo = vim.Description()
    if size:
        convert_size = salt.utils.vmware.convert_to_kb(unit, size)
        disk_spec.device.capacityInKB = convert_size["size"]
    if disk_label:
        disk_spec.device.deviceInfo.label = disk_label
    if thin_provision is not None or eagerly_scrub is not None:
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_spec.device.backing.diskMode = "persistent"
    if thin_provision is not None:
        disk_spec.device.backing.thinProvisioned = thin_provision
    if eagerly_scrub is not None and eagerly_scrub != "None":
        disk_spec.device.backing.eagerlyScrub = eagerly_scrub
    if controller_key:
        disk_spec.device.controllerKey = controller_key
    if operation == "add":
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.device.backing.fileName = "[{}] {}".format(
            salt.utils.vmware.get_managed_object_name(datastore), filename
        )
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
    elif operation == "edit":
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    return disk_spec


def _create_adapter_type(network_adapter, adapter_type, network_adapter_label=""):
    """
    Returns a vim.vm.device.VirtualEthernetCard object specifying a virtual
    ethernet card information

    network_adapter
        None or VirtualEthernet object

    adapter_type
        String, type of adapter

    network_adapter_label
        string, network adapter name
    """
    log.trace("Configuring virtual machine network " "adapter adapter_type={}".format(adapter_type))
    if adapter_type in ["vmxnet", "vmxnet2", "vmxnet3", "e1000", "e1000e"]:
        edited_network_adapter = salt.utils.vmware.get_network_adapter_type(adapter_type)
        if isinstance(network_adapter, type(edited_network_adapter)):
            edited_network_adapter = network_adapter
        else:
            if network_adapter:
                log.trace(
                    "Changing type of '{}' from"
                    " '{}' to '{}'".format(
                        network_adapter.deviceInfo.label,
                        type(network_adapter).__name__.rsplit(".", 1)[1][7:].lower(),
                        adapter_type,
                    )
                )
    else:
        # If device is edited and type not specified or does not match,
        # don't change adapter type
        if network_adapter:
            if adapter_type:
                log.error(
                    "Cannot change type of '{}' to '{}'. "
                    "Not changing type".format(network_adapter.deviceInfo.label, adapter_type)
                )
            edited_network_adapter = network_adapter
        else:
            if not adapter_type:
                log.trace(
                    "The type of '{}' has not been specified. "
                    "Creating of default type 'vmxnet3'".format(network_adapter_label)
                )
            edited_network_adapter = vim.vm.device.VirtualVmxnet3()
    return edited_network_adapter


def _create_network_backing(network_name, switch_type, parent_ref):
    """
    Returns a vim.vm.device.VirtualDevice.BackingInfo object specifying a
    virtual ethernet card backing information

    network_name
        string, network name

    switch_type
        string, type of switch

    parent_ref
        Parent reference to search for network
    """
    log.trace(
        "Configuring virtual machine network backing network_name={} "
        "switch_type={} parent={}".format(
            network_name,
            switch_type,
            salt.utils.vmware.get_managed_object_name(parent_ref),
        )
    )
    backing = {}
    if network_name:
        if switch_type == "standard":
            networks = salt.utils.vmware.get_networks(parent_ref, network_names=[network_name])
            if not networks:
                raise salt.exceptions.VMwareObjectRetrievalError(
                    "The network '{}' could not be " "retrieved.".format(network_name)
                )
            network_ref = networks[0]
            backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
            backing.deviceName = network_name
            backing.network = network_ref
        elif switch_type == "distributed":
            networks = salt.utils.vmware.get_dvportgroups(
                parent_ref, portgroup_names=[network_name]
            )
            if not networks:
                raise salt.exceptions.VMwareObjectRetrievalError(
                    "The port group '{}' could not be " "retrieved.".format(network_name)
                )
            network_ref = networks[0]
            dvs_port_connection = vim.dvs.PortConnection(
                portgroupKey=network_ref.key,
                switchUuid=network_ref.config.distributedVirtualSwitch.uuid,
            )
            backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
            backing.port = dvs_port_connection
    return backing


def _apply_network_adapter_config(
    key,
    network_name,
    adapter_type,
    switch_type,
    network_adapter_label=None,
    operation="add",
    connectable=None,
    mac=None,
    parent=None,
):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to add/edit a
    network device

    network_adapter_label
        Network adapter label

    key
        Unique key for device creation

    network_name
        Network or port group name

    adapter_type
        Type of the adapter eg. vmxnet3

    switch_type
        Type of the switch: standard or distributed

    operation
        Type of operation: add or edit

    connectable
        Dictionary with the device connection properties

    mac
        MAC address of the network adapter

    parent
        Parent object reference
    """
    adapter_type.strip().lower()
    switch_type.strip().lower()
    log.trace(
        "Configuring virtual machine network adapter "
        "network_adapter_label={} network_name={} "
        "adapter_type={} switch_type={} mac={}".format(
            network_adapter_label, network_name, adapter_type, switch_type, mac
        )
    )
    network_spec = vim.vm.device.VirtualDeviceSpec()
    network_spec.device = _create_adapter_type(
        network_spec.device, adapter_type, network_adapter_label=network_adapter_label
    )
    network_spec.device.deviceInfo = vim.Description()
    if operation == "add":
        network_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    elif operation == "edit":
        network_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    if switch_type and network_name:
        network_spec.device.backing = _create_network_backing(network_name, switch_type, parent)
        network_spec.device.deviceInfo.summary = network_name
    if key:
        # random negative integer for creations, concrete device key
        # for updates
        network_spec.device.key = key
    if network_adapter_label:
        network_spec.device.deviceInfo.label = network_adapter_label
    if mac:
        network_spec.device.macAddress = mac
        network_spec.device.addressType = "Manual"
    network_spec.device.wakeOnLanEnabled = True
    if connectable:
        network_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        network_spec.device.connectable.startConnected = connectable["start_connected"]
        network_spec.device.connectable.allowGuestControl = connectable["allow_guest_control"]
    return network_spec


def _apply_scsi_controller(adapter, adapter_type, bus_sharing, key, bus_number, operation):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to
    add/edit a SCSI controller

    adapter
        SCSI controller adapter name

    adapter_type
        SCSI controller adapter type eg. paravirtual

    bus_sharing
         SCSI controller bus sharing eg. virtual_sharing

    key
        SCSI controller unique key

    bus_number
        Device bus number property

    operation
        Describes the operation which should be done on the object,
        the possibles values: 'add' and 'edit', the default value is 'add'

    .. code-block:: bash

        scsi:
          adapter: 'SCSI controller 0'
          type: paravirtual or lsilogic or lsilogic_sas
          bus_sharing: 'no_sharing' or 'virtual_sharing' or 'physical_sharing'
    """
    log.trace(
        "Configuring scsi controller adapter={} adapter_type={} "
        "bus_sharing={} key={} bus_number={}".format(
            adapter, adapter_type, bus_sharing, key, bus_number
        )
    )
    scsi_spec = vim.vm.device.VirtualDeviceSpec()
    if adapter_type == "lsilogic":
        summary = "LSI Logic"
        scsi_spec.device = vim.vm.device.VirtualLsiLogicController()
    elif adapter_type == "lsilogic_sas":
        summary = "LSI Logic Sas"
        scsi_spec.device = vim.vm.device.VirtualLsiLogicSASController()
    elif adapter_type == "paravirtual":
        summary = "VMware paravirtual SCSI"
        scsi_spec.device = vim.vm.device.ParaVirtualSCSIController()
    elif adapter_type == "buslogic":
        summary = "Bus Logic"
        scsi_spec.device = vim.vm.device.VirtualBusLogicController()
    if operation == "add":
        scsi_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    elif operation == "edit":
        scsi_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    scsi_spec.device.key = key
    scsi_spec.device.busNumber = bus_number
    scsi_spec.device.deviceInfo = vim.Description()
    scsi_spec.device.deviceInfo.label = adapter
    scsi_spec.device.deviceInfo.summary = summary
    if bus_sharing == "virtual_sharing":
        # Virtual disks can be shared between virtual machines on
        # the same server
        scsi_spec.device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.virtualSharing
    elif bus_sharing == "physical_sharing":
        # Virtual disks can be shared between virtual machines on any server
        scsi_spec.device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.physicalSharing
    elif bus_sharing == "no_sharing":
        # Virtual disks cannot be shared between virtual machines
        scsi_spec.device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
    return scsi_spec


def _create_ide_controllers(ide_controllers):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing
    IDE controllers

    ide_controllers
        IDE properties
    """
    ide_ctrls = []
    keys = range(-200, -250, -1)
    if ide_controllers:
        devs = [ide["adapter"] for ide in ide_controllers]
        log.trace("Creating IDE controllers {}".format(devs))
        for ide, key in zip(ide_controllers, keys):
            ide_ctrls.append(
                _apply_ide_controller_config(ide["adapter"], "add", key, abs(key + 200))
            )
    return ide_ctrls


def _apply_ide_controller_config(ide_controller_label, operation, key, bus_number=0):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to add/edit an
    IDE controller

    ide_controller_label
        Controller label of the IDE adapter

    operation
        Type of operation: add or edit

    key
        Unique key of the device

    bus_number
        Device bus number property
    """
    log.trace("Configuring IDE controller " "ide_controller_label={}".format(ide_controller_label))
    ide_spec = vim.vm.device.VirtualDeviceSpec()
    ide_spec.device = vim.vm.device.VirtualIDEController()
    if operation == "add":
        ide_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    if operation == "edit":
        ide_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    ide_spec.device.key = key
    ide_spec.device.busNumber = bus_number
    if ide_controller_label:
        ide_spec.device.deviceInfo = vim.Description()
        ide_spec.device.deviceInfo.label = ide_controller_label
        ide_spec.device.deviceInfo.summary = ide_controller_label
    return ide_spec


def _create_sata_controllers(sata_controllers):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing
    SATA controllers

    sata_controllers
        SATA properties
    """
    sata_ctrls = []
    keys = range(-15000, -15050, -1)
    if sata_controllers:
        devs = [sata["adapter"] for sata in sata_controllers]
        log.trace("Creating SATA controllers {}".format(devs))
        for sata, key in zip(sata_controllers, keys):
            sata_ctrls.append(
                _apply_sata_controller_config(sata["adapter"], "add", key, sata["bus_number"])
            )
    return sata_ctrls


def _apply_sata_controller_config(sata_controller_label, operation, key, bus_number=0):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to add/edit a
    SATA controller

    sata_controller_label
        Controller label of the SATA adapter

    operation
        Type of operation: add or edit

    key
        Unique key of the device

    bus_number
        Device bus number property
    """
    log.trace(
        "Configuring SATA controller " "sata_controller_label={}".format(sata_controller_label)
    )
    sata_spec = vim.vm.device.VirtualDeviceSpec()
    sata_spec.device = vim.vm.device.VirtualAHCIController()
    if operation == "add":
        sata_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    elif operation == "edit":
        sata_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    sata_spec.device.key = key
    sata_spec.device.controllerKey = 100
    sata_spec.device.busNumber = bus_number
    if sata_controller_label:
        sata_spec.device.deviceInfo = vim.Description()
        sata_spec.device.deviceInfo.label = sata_controller_label
        sata_spec.device.deviceInfo.summary = sata_controller_label
    return sata_spec


def _apply_cd_drive(
    drive_label,
    key,
    device_type,
    operation,
    client_device=None,
    datastore_iso_file=None,
    connectable=None,
    controller_key=200,
    parent_ref=None,
):
    """
    Returns a vim.vm.device.VirtualDeviceSpec object specifying to add/edit a
    CD/DVD drive

    drive_label
        Leble of the CD/DVD drive

    key
        Unique key of the device

    device_type
        Type of the device: client or iso

    operation
        Type of operation: add or edit

    client_device
        Client device properties

    datastore_iso_file
        ISO properties

    connectable
        Connection info for the device

    controller_key
        Controller unique identifier to which we will attach this device

    parent_ref
        Parent object

    .. code-block:: bash

        cd:
            adapter: "CD/DVD drive 1"
            device_type: datastore_iso_file or client_device
            client_device:
              mode: atapi or passthrough
            datastore_iso_file:
              path: "[share] iso/disk.iso"
            connectable:
              start_connected: True
              allow_guest_control:
    """
    log.trace(
        "Configuring CD/DVD drive drive_label={} "
        "device_type={} client_device={} "
        "datastore_iso_file={}".format(drive_label, device_type, client_device, datastore_iso_file)
    )
    drive_spec = vim.vm.device.VirtualDeviceSpec()
    drive_spec.device = vim.vm.device.VirtualCdrom()
    drive_spec.device.deviceInfo = vim.Description()
    if operation == "add":
        drive_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    elif operation == "edit":
        drive_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    if device_type == "datastore_iso_file":
        drive_spec.device.backing = vim.vm.device.VirtualCdrom.IsoBackingInfo()
        drive_spec.device.backing.fileName = datastore_iso_file["path"]
        datastore = datastore_iso_file["path"].partition("[")[-1].rpartition("]")[0]
        datastore_object = salt.utils.vmware.get_datastores(
            salt.utils.vmware.get_service_instance_from_managed_object(parent_ref),
            parent_ref,
            datastore_names=[datastore],
        )[0]
        if datastore_object:
            drive_spec.device.backing.datastore = datastore_object
        drive_spec.device.deviceInfo.summary = "{}".format(datastore_iso_file["path"])
    elif device_type == "client_device":
        if client_device["mode"] == "passthrough":
            drive_spec.device.backing = vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo()
        elif client_device["mode"] == "atapi":
            drive_spec.device.backing = vim.vm.device.VirtualCdrom.RemoteAtapiBackingInfo()
    drive_spec.device.key = key
    drive_spec.device.deviceInfo.label = drive_label
    drive_spec.device.controllerKey = controller_key
    drive_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    if connectable:
        drive_spec.device.connectable.startConnected = connectable["start_connected"]
        drive_spec.device.connectable.allowGuestControl = connectable["allow_guest_control"]
    return drive_spec


def _set_network_adapter_mapping(domain, gateway, ip_addr, subnet_mask, mac):
    """
    Returns a vim.vm.customization.AdapterMapping object containing the IP
    properties of a network adapter card

    domain
        Domain of the host

    gateway
        Gateway address

    ip_addr
        IP address

    subnet_mask
        Subnet mask

    mac
        MAC address of the guest
    """
    adapter_mapping = vim.vm.customization.AdapterMapping()
    adapter_mapping.macAddress = mac
    adapter_mapping.adapter = vim.vm.customization.IPSettings()
    if domain:
        adapter_mapping.adapter.dnsDomain = domain
    if gateway:
        adapter_mapping.adapter.gateway = gateway
    if ip_addr:
        adapter_mapping.adapter.ip = vim.vm.customization.FixedIp(ipAddress=ip_addr)
        adapter_mapping.adapter.subnetMask = subnet_mask
    else:
        adapter_mapping.adapter.ip = vim.vm.customization.DhcpIpGenerator()
    return adapter_mapping


def _apply_serial_port(serial_device_spec, key, operation="add"):
    """
    Returns a vim.vm.device.VirtualSerialPort representing a serial port
    component

    serial_device_spec
        Serial device properties

    key
        Unique key of the device

    operation
        Add or edit the given device

    .. code-block:: bash

        serial_ports:
            adapter: 'Serial port 1'
            backing:
              type: uri
              uri: 'telnet://something:port'
              direction: <client|server>
              filename: 'service_uri'
            connectable:
              allow_guest_control: True
              start_connected: True
            yield: False
    """
    log.trace(
        "Creating serial port adapter={} type={} connectable={} "
        "yield={}".format(
            serial_device_spec["adapter"],
            serial_device_spec["type"],
            serial_device_spec["connectable"],
            serial_device_spec["yield"],
        )
    )
    device_spec = vim.vm.device.VirtualDeviceSpec()
    device_spec.device = vim.vm.device.VirtualSerialPort()
    if operation == "add":
        device_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    elif operation == "edit":
        device_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
    connect_info = vim.vm.device.VirtualDevice.ConnectInfo()
    type_backing = None

    if serial_device_spec["type"] == "network":
        type_backing = vim.vm.device.VirtualSerialPort.URIBackingInfo()
        if "uri" not in serial_device_spec["backing"].keys():
            raise ValueError("vSPC proxy URI not specified in config")
        if "uri" not in serial_device_spec["backing"].keys():
            raise ValueError("vSPC Direction not specified in config")
        if "filename" not in serial_device_spec["backing"].keys():
            raise ValueError("vSPC Filename not specified in config")
        type_backing.proxyURI = serial_device_spec["backing"]["uri"]
        type_backing.direction = serial_device_spec["backing"]["direction"]
        type_backing.serviceURI = serial_device_spec["backing"]["filename"]
    if serial_device_spec["type"] == "pipe":
        type_backing = vim.vm.device.VirtualSerialPort.PipeBackingInfo()
    if serial_device_spec["type"] == "file":
        type_backing = vim.vm.device.VirtualSerialPort.FileBackingInfo()
    if serial_device_spec["type"] == "device":
        type_backing = vim.vm.device.VirtualSerialPort.DeviceBackingInfo()
    connect_info.allowGuestControl = serial_device_spec["connectable"]["allow_guest_control"]
    connect_info.startConnected = serial_device_spec["connectable"]["start_connected"]
    device_spec.device.backing = type_backing
    device_spec.device.connectable = connect_info
    device_spec.device.unitNumber = 1
    device_spec.device.key = key
    device_spec.device.yieldOnPoll = serial_device_spec["yield"]

    return device_spec


def _create_disks(service_instance, disks, scsi_controllers=None, parent=None):
    """
    Returns a list of disk specs representing the disks to be created for a
    virtual machine

    service_instance
        Service instance (vim.ServiceInstance) of the vCenter.
        Default is None.

    disks
        List of disks with properties

    scsi_controllers
        List of SCSI controllers

    parent
        Parent object reference

    .. code-block:: bash

        disk:
          adapter: 'Hard disk 1'
          size: 16
          unit: GB
          address: '0:0'
          controller: 'SCSI controller 0'
          thin_provision: False
          eagerly_scrub: False
          datastore: 'myshare'
          filename: 'vm/mydisk.vmdk'
    """
    disk_specs = []
    keys = range(-2000, -2050, -1)
    if disks:
        devs = [disk["adapter"] for disk in disks]
        log.trace("Creating disks {}".format(devs))
    for disk, key in zip(disks, keys):
        # create the disk
        filename, datastore, datastore_ref = None, None, None
        size = float(disk["size"])
        # when creating both SCSI controller and Hard disk at the same time
        # we need the randomly assigned (temporary) key of the newly created
        # SCSI controller
        controller_key = 1000  # Default is the first SCSI controller
        if "address" in disk:  # 0:0
            controller_bus_number, unit_number = disk["address"].split(":")
            controller_bus_number = int(controller_bus_number)
            unit_number = int(unit_number)
            controller_key = _get_scsi_controller_key(
                controller_bus_number, scsi_ctrls=scsi_controllers
            )
        elif "controller" in disk:
            for contr in scsi_controllers:
                if contr["label"] == disk["controller"]:
                    controller_key = contr["key"]
                    break
            else:
                raise salt.exceptions.VMwareObjectNotFoundError(
                    "The given controller does not exist: " "{}".format(disk["controller"])
                )
        if "datastore" in disk:
            datastore_ref = salt.utils.vmware.get_datastores(
                service_instance, parent, datastore_names=[disk["datastore"]]
            )[0]
            datastore = disk["datastore"]
        if "filename" in disk:
            filename = disk["filename"]
        # XOR filename, datastore
        if (not filename and datastore) or (filename and not datastore):
            raise salt.exceptions.ArgumentValueError(
                "You must specify both filename and datastore attributes"
                " to place your disk to a specific datastore "
                "{}, {}".format(datastore, filename)
            )
        disk_spec = _apply_hard_disk(
            unit_number,
            key,
            disk_label=disk["adapter"],
            size=size,
            unit=disk["unit"],
            controller_key=controller_key,
            operation="add",
            thin_provision=disk["thin_provision"],
            eagerly_scrub=disk["eagerly_scrub"] if "eagerly_scrub" in disk else None,
            datastore=datastore_ref,
            filename=filename,
        )
        disk_specs.append(disk_spec)
        unit_number += 1
    return disk_specs


def _create_scsi_devices(scsi_devices):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing
    SCSI controllers

    scsi_devices:
        List of SCSI device properties
    """
    keys = range(-1000, -1050, -1)
    scsi_specs = []
    if scsi_devices:
        devs = [scsi["adapter"] for scsi in scsi_devices]
        log.trace("Creating SCSI devices {}".format(devs))
        # unitNumber for disk attachment, 0:0 1st 0 is the controller busNumber,
        # 2nd is the unitNumber
        for (key, scsi_controller) in zip(keys, scsi_devices):
            # create the SCSI controller
            scsi_spec = _apply_scsi_controller(
                scsi_controller["adapter"],
                scsi_controller["type"],
                scsi_controller["bus_sharing"],
                key,
                scsi_controller["bus_number"],
                "add",
            )
            scsi_specs.append(scsi_spec)
    return scsi_specs


def _create_network_adapters(network_interfaces, parent=None):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing
    the interfaces to be created for a virtual machine

    network_interfaces
        List of network interfaces and properties

    parent
        Parent object reference

    .. code-block:: bash

        interfaces:
          adapter: 'Network adapter 1'
          name: vlan100
          switch_type: distributed or standard
          adapter_type: vmxnet3 or vmxnet, vmxnet2, vmxnet3, e1000, e1000e
          mac: '00:11:22:33:44:55'
    """
    network_specs = []
    nics_settings = []
    keys = range(-4000, -4050, -1)
    if network_interfaces:
        devs = [inter["adapter"] for inter in network_interfaces]
        log.trace("Creating network interfaces {}".format(devs))
        for interface, key in zip(network_interfaces, keys):
            network_spec = _apply_network_adapter_config(
                key,
                interface["name"],
                interface["adapter_type"],
                interface["switch_type"],
                network_adapter_label=interface["adapter"],
                operation="add",
                connectable=interface["connectable"] if "connectable" in interface else None,
                mac=interface["mac"],
                parent=parent,
            )
            network_specs.append(network_spec)
            if "mapping" in interface:
                adapter_mapping = _set_network_adapter_mapping(
                    interface["mapping"]["domain"],
                    interface["mapping"]["gateway"],
                    interface["mapping"]["ip_addr"],
                    interface["mapping"]["subnet_mask"],
                    interface["mac"],
                )
                nics_settings.append(adapter_mapping)
    return (network_specs, nics_settings)


def _create_serial_ports(serial_ports):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing the
    serial ports to be created for a virtual machine

    serial_ports
        Serial port properties
    """
    ports = []
    keys = range(-9000, -9050, -1)
    if serial_ports:
        devs = [serial["adapter"] for serial in serial_ports]
        log.trace("Creating serial ports {}".format(devs))
        for port, key in zip(serial_ports, keys):
            serial_port_device = _apply_serial_port(port, key, "add")
            ports.append(serial_port_device)
    return ports


def _create_cd_drives(cd_drives, controllers=None, parent_ref=None):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec objects representing the
    CD/DVD drives to be created for a virtual machine

    cd_drives
        CD/DVD drive properties

    controllers
        CD/DVD drive controllers (IDE, SATA)

    parent_ref
        Parent object reference
    """
    cd_drive_specs = []
    keys = range(-3000, -3050, -1)
    if cd_drives:
        devs = [dvd["adapter"] for dvd in cd_drives]
        log.trace("Creating cd/dvd drives {}".format(devs))
        for drive, key in zip(cd_drives, keys):
            # if a controller is not available/cannot be created we should use the
            #  one which is available by default, this is 'IDE 0'
            controller_key = 200
            if controllers:
                controller = _get_device_by_label(controllers, drive["controller"])
                controller_key = controller.key
            cd_drive_specs.append(
                _apply_cd_drive(
                    drive["adapter"],
                    key,
                    drive["device_type"],
                    "add",
                    client_device=drive["client_device"] if "client_device" in drive else None,
                    datastore_iso_file=drive["datastore_iso_file"]
                    if "datastore_iso_file" in drive
                    else None,
                    connectable=drive["connectable"] if "connectable" in drive else None,
                    controller_key=controller_key,
                    parent_ref=parent_ref,
                )
            )

    return cd_drive_specs


def _get_device_by_key(devices, key):
    """
    Returns the device with the given key, raises error if the device is
    not found.

    devices
        list of vim.vm.device.VirtualDevice objects

    key
        Unique key of device
    """
    device_keys = [d for d in devices if d.key == key]
    if device_keys:
        return device_keys[0]
    else:
        raise salt.exceptions.VMwareObjectNotFoundError(
            "Virtual machine device with unique key " "{} does not exist".format(key)
        )


def _get_device_by_label(devices, label):
    """
    Returns the device with the given label, raises error if the device is
    not found.

    devices
        list of vim.vm.device.VirtualDevice objects

    key
        Unique key of device
    """
    device_labels = [d for d in devices if d.deviceInfo.label == label]
    if device_labels:
        return device_labels[0]
    else:
        raise salt.exceptions.VMwareObjectNotFoundError(
            "Virtual machine device with " "label {} does not exist".format(label)
        )


def _convert_units(devices):
    """
    Updates the size and unit dictionary values with the new unit values

    devices
        List of device data objects
    """
    if devices:
        for device in devices:
            if "unit" in device and "size" in device:
                device.update(salt.utils.vmware.convert_to_kb(device["unit"], device["size"]))
    else:
        return False
    return True


def compare_vm_configs(new_config, current_config):
    """
    Compares virtual machine current and new configuration, the current is the
    one which is deployed now, and the new is the target config. Returns the
    differences between the objects in a dictionary, the keys are the
    configuration parameter keys and the values are differences objects: either
    list or recursive difference

    new_config:
        New config dictionary with every available parameter

    current_config
        Currently deployed configuration
    """
    diffs = {}
    keys = set(new_config.keys())

    # These values identify the virtual machine, comparison is unnecessary
    keys.discard("name")
    keys.discard("datacenter")
    keys.discard("datastore")
    for property_key in ("version", "image"):
        if property_key in keys:
            single_value_diff = recursive_diff(
                {property_key: current_config[property_key]},
                {property_key: new_config[property_key]},
            )
            if single_value_diff.diffs:
                diffs[property_key] = single_value_diff
            keys.discard(property_key)

    if "cpu" in keys:
        keys.remove("cpu")
        cpu_diff = recursive_diff(current_config["cpu"], new_config["cpu"])
        if cpu_diff.diffs:
            diffs["cpu"] = cpu_diff

    if "memory" in keys:
        keys.remove("memory")
        _convert_units([current_config["memory"]])
        _convert_units([new_config["memory"]])
        memory_diff = recursive_diff(current_config["memory"], new_config["memory"])
        if memory_diff.diffs:
            diffs["memory"] = memory_diff

    if "advanced_configs" in keys:
        keys.remove("advanced_configs")
        key = "advanced_configs"
        advanced_diff = recursive_diff(current_config[key], new_config[key])
        if advanced_diff.diffs:
            diffs[key] = advanced_diff

    if "disks" in keys:
        keys.remove("disks")
        _convert_units(current_config["disks"])
        _convert_units(new_config["disks"])
        disk_diffs = list_diff(current_config["disks"], new_config["disks"], "address")
        # REMOVE UNSUPPORTED DIFFERENCES/CHANGES
        # If the disk already exist, the backing properties like eagerly scrub
        # and thin provisioning
        # cannot be updated, and should not be identified as differences
        disk_diffs.remove_diff(diff_key="eagerly_scrub")
        # Filename updates are not supported yet, on VSAN datastores the
        # backing.fileName points to a uid + the vmdk name
        disk_diffs.remove_diff(diff_key="filename")
        # The adapter name shouldn't be changed
        disk_diffs.remove_diff(diff_key="adapter")
        if disk_diffs.diffs:
            diffs["disks"] = disk_diffs

    if "interfaces" in keys:
        keys.remove("interfaces")
        interface_diffs = list_diff(current_config["interfaces"], new_config["interfaces"], "mac")
        # The adapter name shouldn't be changed
        interface_diffs.remove_diff(diff_key="adapter")
        if interface_diffs.diffs:
            diffs["interfaces"] = interface_diffs

    # For general items where the identification can be done by adapter
    for key in keys:
        if key not in current_config or key not in new_config:
            raise ValueError(
                "A general device {} configuration was "
                "not supplied or it was not retrieved from "
                "remote configuration".format(key)
            )
        device_diffs = list_diff(current_config[key], new_config[key], "adapter")
        if device_diffs.diffs:
            diffs[key] = device_diffs

    return diffs


def _update_disks(disks_old_new):
    """
    Changes the disk size and returns the config spec objects in a list.
    The controller property cannot be updated, because controller address
    identifies the disk by the unit and bus number properties.

    disks_diffs
        List of old and new disk properties, the properties are dictionary
        objects
    """
    disk_changes = []
    if disks_old_new:
        devs = [disk["old"]["address"] for disk in disks_old_new]
        log.trace("Updating disks {}".format(devs))
        for item in disks_old_new:
            current_disk = item["old"]
            next_disk = item["new"]
            difference = recursive_diff(current_disk, next_disk)
            difference.ignore_unset_values = False
            if difference.changed():
                if next_disk["size"] < current_disk["size"]:
                    raise salt.exceptions.VMwareSaltError(
                        "Disk cannot be downsized size={} unit={} "
                        "controller_key={} "
                        "unit_number={}".format(
                            next_disk["size"],
                            next_disk["unit"],
                            current_disk["controller_key"],
                            current_disk["unit_number"],
                        )
                    )
                log.trace(
                    "Virtual machine disk will be updated "
                    "size={} unit={} controller_key={} "
                    "unit_number={}".format(
                        next_disk["size"],
                        next_disk["unit"],
                        current_disk["controller_key"],
                        current_disk["unit_number"],
                    )
                )
                device_config_spec = _apply_hard_disk(
                    current_disk["unit_number"],
                    current_disk["key"],
                    "edit",
                    size=next_disk["size"],
                    unit=next_disk["unit"],
                    controller_key=current_disk["controller_key"],
                )
                # The backing didn't change and we must supply one for
                # reconfigure
                device_config_spec.device.backing = current_disk["object"].backing
                disk_changes.append(device_config_spec)

    return disk_changes


def _update_scsi_devices(scsis_old_new, current_disks):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec specifying  the scsi
    properties as input the old and new configs are defined in a dictionary.

    scsi_diffs
        List of old and new scsi properties
    """
    device_config_specs = []
    if scsis_old_new:
        devs = [scsi["old"]["adapter"] for scsi in scsis_old_new]
        log.trace("Updating SCSI controllers {}".format(devs))
        for item in scsis_old_new:
            next_scsi = item["new"]
            current_scsi = item["old"]
            difference = recursive_diff(current_scsi, next_scsi)
            difference.ignore_unset_values = False
            if difference.changed():
                log.trace(
                    "Virtual machine scsi device will be updated "
                    "key={} bus_number={} type={} "
                    "bus_sharing={}".format(
                        current_scsi["key"],
                        current_scsi["bus_number"],
                        next_scsi["type"],
                        next_scsi["bus_sharing"],
                    )
                )
                # The sharedBus property is not optional
                # The type can only be updated if we delete the original
                # controller, create a new one with the properties and then
                # attach the disk object to the newly created controller, even
                # though the controller key stays the same the last step is
                # mandatory
                if next_scsi["type"] != current_scsi["type"]:
                    device_config_specs.append(_delete_device(current_scsi["object"]))
                    device_config_specs.append(
                        _apply_scsi_controller(
                            current_scsi["adapter"],
                            next_scsi["type"],
                            next_scsi["bus_sharing"],
                            current_scsi["key"],
                            current_scsi["bus_number"],
                            "add",
                        )
                    )
                    disks_to_update = []
                    for disk_key in current_scsi["device"]:
                        disk_objects = [disk["object"] for disk in current_disks]
                        disks_to_update.append(_get_device_by_key(disk_objects, disk_key))
                    for current_disk in disks_to_update:
                        disk_spec = vim.vm.device.VirtualDeviceSpec()
                        disk_spec.device = current_disk
                        disk_spec.operation = "edit"
                        device_config_specs.append(disk_spec)
                else:
                    device_config_specs.append(
                        _apply_scsi_controller(
                            current_scsi["adapter"],
                            current_scsi["type"],
                            next_scsi["bus_sharing"],
                            current_scsi["key"],
                            current_scsi["bus_number"],
                            "edit",
                        )
                    )
    return device_config_specs


def _update_network_adapters(interface_old_new, parent):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec specifying
    configuration(s) for changed network adapters, the adapter type cannot
    be changed, as input the old and new configs are defined in a dictionary.

    interface_old_new
        Dictionary with old and new keys which contains the current and the
        next config for a network device

    parent
        Parent managed object reference
    """
    network_changes = []
    if interface_old_new:
        devs = [inter["old"]["mac"] for inter in interface_old_new]
        log.trace("Updating network interfaces {}".format(devs))
        for item in interface_old_new:
            current_interface = item["old"]
            next_interface = item["new"]
            difference = recursive_diff(current_interface, next_interface)
            difference.ignore_unset_values = False
            if difference.changed():
                log.trace(
                    "Virtual machine network adapter will be updated "
                    "switch_type={} name={} adapter_type={} "
                    "mac={}".format(
                        next_interface["switch_type"],
                        next_interface["name"],
                        current_interface["adapter_type"],
                        current_interface["mac"],
                    )
                )
                device_config_spec = _apply_network_adapter_config(
                    current_interface["key"],
                    next_interface["name"],
                    current_interface["adapter_type"],
                    next_interface["switch_type"],
                    operation="edit",
                    mac=current_interface["mac"],
                    parent=parent,
                )
                network_changes.append(device_config_spec)
    return network_changes


def _update_serial_ports(serial_old_new):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec specifying to edit a
    deployed serial port configuration to the new given config

    serial_old_new
         Dictionary with old and new keys which contains the current and the
          next config for a serial port device
    """
    serial_changes = []
    if serial_old_new:
        devs = [serial["old"]["adapter"] for serial in serial_old_new]
        log.trace("Updating serial ports {}".format(devs))
        for item in serial_old_new:
            current_serial = item["old"]
            next_serial = item["new"]
            difference = recursive_diff(current_serial, next_serial)
            difference.ignore_unset_values = False
            if difference.changed():
                serial_changes.append(
                    _apply_serial_port(next_serial, current_serial["key"], "edit")
                )
        return serial_changes


def _update_cd_drives(drives_old_new, controllers=None, parent=None):
    """
    Returns a list of vim.vm.device.VirtualDeviceSpec specifying to edit a
    deployed cd drive configuration to the new given config

    drives_old_new
        Dictionary with old and new keys which contains the current and the
        next config for a cd drive

    controllers
        Controller device list

    parent
        Managed object reference of the parent object
    """
    cd_changes = []
    if drives_old_new:
        devs = [drive["old"]["adapter"] for drive in drives_old_new]
        log.trace("Updating cd/dvd drives {}".format(devs))
        for item in drives_old_new:
            current_drive = item["old"]
            new_drive = item["new"]
            difference = recursive_diff(current_drive, new_drive)
            difference.ignore_unset_values = False
            if difference.changed():
                if controllers:
                    controller = _get_device_by_label(controllers, new_drive["controller"])
                    controller_key = controller.key
                else:
                    controller_key = current_drive["controller_key"]
                cd_changes.append(
                    _apply_cd_drive(
                        current_drive["adapter"],
                        current_drive["key"],
                        new_drive["device_type"],
                        "edit",
                        client_device=new_drive["client_device"]
                        if "client_device" in new_drive
                        else None,
                        datastore_iso_file=new_drive["datastore_iso_file"]
                        if "datastore_iso_file" in new_drive
                        else None,
                        connectable=new_drive["connectable"],
                        controller_key=controller_key,
                        parent_ref=parent,
                    )
                )
    return cd_changes


def _delete_device(device):
    """
    Returns a vim.vm.device.VirtualDeviceSpec specifying to remove a virtual
    machine device

    device
        Device data type object
    """
    log.trace("Deleting device with type {}".format(type(device)))
    device_spec = vim.vm.device.VirtualDeviceSpec()
    device_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
    device_spec.device = device
    return device_spec


def _get_client(server, username, password, verify_ssl=None, ca_bundle=None):
    """
    Establish client through proxy or with user provided credentials.

    :param basestring server:
        Target DNS or IP of vCenter center.
    :param basestring username:
        Username associated with the vCenter center.
    :param basestring password:
        Password associated with the vCenter center.
    :param boolean verify_ssl:
        Verify the SSL certificate. Default: True
    :param basestring ca_bundle:
        Path to the ca bundle to use when verifying SSL certificates.
    :returns:
        vSphere Client instance.
    :rtype:
        vSphere.Client
    """
    # Get salted vSphere Client
    details = None
    if not (server and username and password):
        # User didn't provide CLI args so use proxy information
        details = __salt__["vcenter.get_details"]()
        server = details["vcenter"]
        username = details["username"]
        password = details["password"]

    if verify_ssl is None:
        if details is None:
            details = __salt__["vcenter.get_details"]()
        verify_ssl = details.get("verify_ssl", True)
        if verify_ssl is None:
            verify_ssl = True

    if ca_bundle is None:
        if details is None:
            details = __salt__["vcenter.get_details"]()
        ca_bundle = details.get("ca_bundle", None)

    if verify_ssl is False and ca_bundle is not None:
        log.error("Cannot set verify_ssl to False and ca_bundle together")
        return False

    if ca_bundle:
        ca_bundle = salt.utils.http.get_ca_bundle({"ca_bundle": ca_bundle})

    # Establish connection with client
    client = salt.utils.vmware.get_vsphere_client(
        server=server,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
    )
    # Will return None if utility function causes Unauthenticated error
    return client
