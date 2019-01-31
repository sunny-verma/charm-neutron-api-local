# Overview

This principle charm provides the OpenStack Neutron API service which
was previously provided by the nova-cloud-controller charm.

When this charm is related to the nova-cloud-controller charm the
nova-cloud controller charm will shutdown its api service, de-register
it from keystone and inform the compute nodes of the new neutron url.

# Usage

To deploy (partial deployment only):

    juju deploy neutron-api
    juju deploy neutron-openvswitch

    juju add-relation neutron-api mysql
    juju add-relation neutron-api rabbitmq-server
    juju add-relation neutron-api neutron-openvswitch
    juju add-relation neutron-api nova-cloud-controller

This charm also supports scale out and high availability using the
hacluster charm:

    juju deploy hacluster neutron-hacluster
    juju add-unit neutron-api
    juju set neutron-api vip=<VIP FOR ACCESS>
    juju add-relation neutron-hacluster neutron-api

## HA/Clustering

There are two mutually exclusive high availability options: using
virtual IP(s) or DNS. In both cases, a relationship to hacluster is
required which provides the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet
such that the VIP is a valid IP on the subnet for one of the node's
interfaces and each node has an interface in said subnet. The VIP
becomes a highly-available API endpoint.

At a minimum, the config option 'vip' must be set in order to use
virtual IP HA. If multiple networks are being used, a VIP should be
provided for each network, separated by spaces. Optionally, vip_iface
or vip_cidr may be specified.

To use DNS high availability there are several prerequisites. However,
DNS HA does not require the clustered nodes to be on the same subnet.
Currently the DNS HA feature is only available for MAAS 2.0 or greater
environments. MAAS 2.0 requires Juju 2.0 or greater. The clustered
nodes must have static or "reserved" IP addresses registered in MAAS.
The DNS hostname(s) must be pre-registered in MAAS before use with DNS
HA.

At a minimum, the config option 'dns-ha' must be set to true and at
least one of 'os-public-hostname', 'os-internal-hostname' or
'os-internal-hostname' must be set in order to use DNS HA. One or more
of the above hostnames may be set.

The charm will throw an exception in the following circumstances:
If neither 'vip' nor 'dns-ha' is set and the charm is related to
hacluster If both 'vip' and 'dns-ha' are set as they are mutually
exclusive. If 'dns-ha' is set and none of the
os-{admin,internal,public}-hostname(s) are set

# Restrictions

This charm only support deployment with OpenStack Icehouse or better.

# Internal DNS for Cloud Guests

The charm supports enabling internal DNS resolution for cloud guests in
accordance with the OpenStack DNS integration guide. To enable internal
DNS resolution, the 'enable-ml2-dns' option must be set to True. When
enabled, the domain name specified in the 'dns-domain' will be advertised
as the nameserver search path by the dhcp agents.

The Nova compute service will leverage this functionality when enabled.
When ports are allocated by the compute service, the dns_name of the port
is populated with a DNS sanitized version of the instance's display name.
The Neutron DHCP agents will then create host entries in the dnsmasq's
configuration files matching the dns_name of the port to the IP address
associated with the port.

Note that the DNS nameserver provided to the instance by the DHCP agent
depends on the tenant's network setup. The Neutron DHCP agent only advertises
itself as a nameserver when the Neutron subnet does not have nameservers
configured. If additional nameservers are needed and internal DNS is desired,
then the IP address of the DHCP port should be added to the subnet's
list of configured nameservers.

For more information refer to the OpenStack documentation on
[DNS Integration](https://docs.openstack.org/ocata/networking-guide/config-dns-int.html).

# External DNS for Cloud Guests

To add support for DNS record auto-generation when Neutron ports and
floating IPs are created the charm needs a relation with designate charm:

    juju deploy designate
    juju add-relation neutron-api designate

In order to enable the creation of reverse lookup (PTR) records, enable
"allow-reverse-dns-lookup" charm option:

    juju config neutron-api allow-reverse-dns-lookup=True

and configure the following charm options:

    juju config neutron-api ipv4-ptr-zone-prefix-size=<IPV4 PREFIX SIZE>
    juju config neutron-api ipv6-ptr-zone-prefix-size=<IPV6 PREFIX SIZE>

For example, if prefix sizes of your IPv4 and IPv6 subnets are
"24" (e.g. "192.168.0.0/24") and "64" (e.g. "fdcd:06ca:e498:216b::/64")
respectively, configure the charm options as follows:

    juju config neutron-api ipv4-ptr-zone-prefix-size=24
    juju config neutron-api ipv6-ptr-zone-prefix-size=64

For more information refer to the OpenStack documentation on
[DNS Integration](https://docs.openstack.org/ocata/networking-guide/config-dns-int.html)

# Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm
to be bound to network space configurations managed directly by Juju.
This is only supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the
network separation of public, internal and admin endpoints.

Access to the underlying MySQL instance can also be bound to a specific
space using the shared-db relation.

To use this feature, use the --bind option when deploying the charm:

    juju deploy neutron-api --bind "public=public-space internal=internal-space admin=admin-space shared-db=internal-space"

alternatively these can also be provided as part of a juju native
bundle configuration:

    neutron-api:
      charm: cs:xenial/neutron-api
      num_units: 1
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space
        shared-db: internal-space

NOTE: Spaces must be configured in the underlying provider prior to
attempting to use them.

NOTE: Existing deployments using os-*-network configuration options
will continue to function; these options are preferred over any network
space binding provided if set.

# Additional Middleware Requests by Neutron Plugin Charms

Some neutron plugins may require additional middleware to be added
to api-paste.ini. In order to support that a subordinate may pass
extra_middleware via the neutron-plugin-api-subordinate relation.

Relation data to be set by subordinates:
    {'extra_middleware': [{
            'type': 'middleware_type',
            'name': 'middleware_name',
            'config': {
                'setting_1': 'value_1',
                'setting_2': 'value_2'}}]}

It would not be correct to do that from your own plugin as this
requires the neutron-api service restart which should be handled in
this charm.

The developer guide for Neutron contains a description of the startup
process which makes it clear that api-paste.ini is parsed only once
in neutron-api's lifetime (see the "WSGI Application" section):

https://git.openstack.org/cgit/openstack/neutron/tree/doc/source/devref/api_layer.rst#n49

For the api-paste.ini format in general, please consult PasteDeploy
repository docs/index.txt, "Config Format" section:
https://bitbucket.org/ianb/pastedeploy

Classes in loadwsgi.py contain config_prefixes that can be used for
middleware types - these are the prefixes the charm code validates
passed data against:

https://bitbucket.org/ianb/pastedeploy/src/4b27133a2a7db58b213ae55b580039c11d2055c0/paste/deploy/loadwsgi.py?at=default&fileviewer=file-view-default
