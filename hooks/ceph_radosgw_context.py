from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.hahelpers.cluster import (
    determine_api_port,
    determine_apache_port,
)
from charmhelpers.core.host import cmp_pkgrevno
from charmhelpers.core.hookenv import (
    WARNING,
    config,
    log,
    relation_ids,
    related_units,
    relation_get,
    unit_get,
)
import os
import socket
import dns.resolver


class HAProxyContext(context.HAProxyContext):

    def __call__(self):
        ctxt = super(HAProxyContext, self).__call__()
        port = config('port')

        # Apache ports
        a_cephradosgw_api = determine_apache_port(port, singlenode_mode=True)

        port_mapping = {
            'cephradosgw-server': [port, a_cephradosgw_api]
        }

        ctxt['cephradosgw_bind_port'] = determine_api_port(
            port,
            singlenode_mode=True,
        )

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        return ctxt


class IdentityServiceContext(context.IdentityServiceContext):
    interfaces = ['identity-service']

    def __call__(self):
        ctxt = super(IdentityServiceContext, self).__call__()
        if not ctxt:
            return

        ctxt['admin_token'] = None
        for relid in relation_ids('identity-service'):
            for unit in related_units(relid):
                if not ctxt.get('admin_token'):
                    ctxt['admin_token'] = \
                        relation_get('admin_token', unit, relid)

        ctxt['auth_type'] = 'keystone'
        ctxt['user_roles'] = config('operator-roles')
        ctxt['cache_size'] = config('cache-size')
        ctxt['revocation_check_interval'] = config('revocation-check-interval')
        if self.context_complete(ctxt):
            return ctxt

        return {}


class MonContext(context.OSContextGenerator):
    interfaces = ['ceph-radosgw']

    def __call__(self):
        if not relation_ids('mon'):
            return {}
        hosts = []
        auths = []
        for relid in relation_ids('mon'):
            for unit in related_units(relid):
                ceph_public_addr = relation_get('ceph-public-address', unit,
                                                relid)
                if ceph_public_addr:
                    host_ip = self.get_host_ip(ceph_public_addr)
                    hosts.append('{}:6789'.format(host_ip))
                    _auth = relation_get('auth', unit, relid)
                    if _auth:
                        auths.append(_auth)
        if len(set(auths)) != 1:
            e = ("Inconsistent or absent auth returned by mon units. Setting "
                 "auth_supported to 'none'")
            log(e, level=WARNING)
            auth = 'none'
        else:
            auth = auths[0]
        hosts.sort()
        ctxt = {
            'auth_supported': auth,
            'mon_hosts': ' '.join(hosts),
            'hostname': socket.gethostname(),
            'old_auth': cmp_pkgrevno('radosgw', "0.51") < 0,
            'use_syslog': str(config('use-syslog')).lower(),
            'embedded_webserver': config('use-embedded-webserver'),
            'loglevel': config('loglevel'),
            'port': determine_apache_port(config('port'),
                                          singlenode_mode=True)
        }

        certs_path = '/var/lib/ceph/nss'
        paths = [os.path.join(certs_path, 'ca.pem'),
                 os.path.join(certs_path, 'signing_certificate.pem')]
        if all([os.path.isfile(p) for p in paths]):
            ctxt['cms'] = True

        if (config('use-ceph-optimised-packages') and
                not config('use-embedded-webserver')):
            ctxt['disable_100_continue'] = False
        else:
            # NOTE: currently only applied if NOT using embedded webserver
            ctxt['disable_100_continue'] = True

        if self.context_complete(ctxt):
            return ctxt

        return {}

    def get_host_ip(self, hostname=None):
        try:
            if not hostname:
                hostname = unit_get('private-address')
            # Test to see if already an IPv4 address
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            # This may throw an NXDOMAIN exception; in which case
            # things are badly broken so just let it kill the hook
            answers = dns.resolver.query(hostname, 'A')
            if answers:
                return answers[0].address