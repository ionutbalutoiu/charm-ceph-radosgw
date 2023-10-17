# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest.mock import patch

import ceph_radosgw_context as context
import charmhelpers.contrib.storage.linux.ceph as ceph
import charmhelpers.fetch as fetch

from test_utils import CharmTestCase

TO_PATCH = [
    'config',
    'log',
    'relation_get',
    'relation_ids',
    'related_units',
    'remote_service_name',
    'cmp_pkgrevno',
    'arch',
    'socket',
    'unit_public_ip',
    'determine_api_port',
    'cmp_pkgrevno',
    'leader_get',
    'multisite',
    'utils',
]


class HAProxyContextTests(CharmTestCase):
    def setUp(self):
        super(HAProxyContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.cmp_pkgrevno.return_value = 1
        self.arch.return_value = 'amd64'

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.openstack.context.is_ipv6_disabled')
    @patch('charmhelpers.contrib.openstack.context.get_relation_ip')
    @patch('charmhelpers.contrib.openstack.context.mkdir')
    @patch('charmhelpers.contrib.openstack.context.local_unit')
    @patch('charmhelpers.contrib.openstack.context.config')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch('charmhelpers.contrib.openstack.context.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    def test_ctxt(self, _harelation_ids, _ctxtrelation_ids, _haconfig,
                  _ctxtconfig, _local_unit, _mkdir, _get_relation_ip,
                  _is_ipv6_disabled, _mock_https):
        _mock_https.return_value = False
        _get_relation_ip.return_value = '10.0.0.10'
        _ctxtconfig.side_effect = self.test_config.get
        _haconfig.side_effect = self.test_config.get
        _harelation_ids.return_value = []
        haproxy_context = context.HAProxyContext()
        self.utils.listen_port.return_value = 80
        self.determine_api_port.return_value = 70
        expect = {
            'cephradosgw_bind_port': 70,
            'service_ports': {'cephradosgw-server': [80, 70]},
            'backend_options': {'cephradosgw-server': [{
                'option': 'httpchk GET /swift/healthcheck',
            }]},
            'https': False
        }
        self.assertEqual(expect, haproxy_context())
        _is_ipv6_disabled.assert_called_once_with()


class MonContextTest(CharmTestCase):
    maxDiff = None

    def setUp(self):
        super(MonContextTest, self).setUp(context, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.unit_public_ip.return_value = '10.255.255.255'
        self.cmp_pkgrevno.side_effect = lambda *args: 1
        self.arch.return_value = 'amd64'
        self.test_config.set('zonegroup', 'zonegroup1')
        self.test_config.set('realm', 'realmX')

    @staticmethod
    def plain_list_stub(key):
        if key == "zone":
            return ["default"]
        if key == "zonegroup":
            return ["zonegroup1"]
        if key == "realm":
            return ["realmX"]
        else:
            return []

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    @patch.object(context, 'ensure_host_resolvable_v6')
    def test_ctxt(
        self, mock_ensure_rsv_v6, mock_config_get, mock_relation_ids,
        mock_https,
    ):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return 'cephx'
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return 'testfsid'

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.multisite.plain_list = self.plain_list_stub
        self.determine_api_port.return_value = 70
        expect = {
            'auth_supported': 'cephx',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': False,
        }
        self.assertEqual(expect, mon_ctxt())
        self.assertFalse(mock_ensure_rsv_v6.called)

        self.test_config.set('prefer-ipv6', True)
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']
        expect['ipv6'] = True
        expect['port'] = "[::]:%s" % (70)
        self.assertEqual(expect, mon_ctxt())
        self.assertTrue(mock_ensure_rsv_v6.called)

    @patch('ceph_radosgw_context.https')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    @patch.object(context, 'ensure_host_resolvable_v6')
    def test_ctxt_with_https_proxy(self, mock_ensure_rsv_v6, mock_https):
        mock_https.return_value = True
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return 'cephx'
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return 'testfsid'

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.multisite.plain_list = self.plain_list_stub
        self.determine_api_port.return_value = 70
        expect = {
            'auth_supported': 'cephx',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': True,
        }
        self.assertEqual(expect, mon_ctxt())
        self.assertFalse(mock_ensure_rsv_v6.called)

        self.test_config.set('prefer-ipv6', True)
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']
        expect['ipv6'] = True
        expect['port'] = "[::]:%s" % (70)
        self.assertEqual(expect, mon_ctxt())
        self.assertTrue(mock_ensure_rsv_v6.called)

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    @patch.object(context, 'ensure_host_resolvable_v6')
    def test_list_of_addresses_from_ceph_proxy(
        self, mock_ensure_rsv_v6, mock_config_get, mock_relation_ids,
        mock_https,
    ):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1 10.5.4.2 10.5.4.3']
        self.cmp_pkgrevno.return_value = 1

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return 'cephx'
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return 'testfsid'

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.multisite.plain_list = self.plain_list_stub
        self.related_units.return_value = ['ceph-proxy/0']
        self.determine_api_port.return_value = 70
        expect = {
            'auth_supported': 'cephx',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': False,
        }
        self.assertEqual(expect, mon_ctxt())
        self.assertFalse(mock_ensure_rsv_v6.called)

        self.test_config.set('prefer-ipv6', True)
        addresses = ['10.5.4.1 10.5.4.2 10.5.4.3']
        expect['ipv6'] = True
        expect['port'] = "[::]:%s" % (70)
        self.assertEqual(expect, mon_ctxt())
        self.assertTrue(mock_ensure_rsv_v6.called)

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    def test_ctxt_missing_data(self, mock_config_get, mock_relation_ids,
                               mock_https):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        self.relation_get.return_value = None
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.assertEqual({}, mon_ctxt())

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    def test_ctxt_inconsistent_auths(self, mock_config_get, mock_relation_ids,
                                     mock_https):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']
        auths = ['cephx', 'cephy', 'cephz']

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return auths.pop()
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return 'testfsid'

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.multisite.plain_list = self.plain_list_stub
        self.determine_api_port.return_value = 70
        expect = {
            'auth_supported': 'none',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': False,
        }
        self.assertEqual(expect, mon_ctxt())

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    def test_ctxt_consistent_auths(self, mock_config_get, mock_relation_ids,
                                   mock_https):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']
        auths = ['cephx', 'cephx', 'cephx']

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return auths.pop()
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return 'testfsid'

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.determine_api_port.return_value = 70
        self.multisite.plain_list = self.plain_list_stub
        expect = {
            'auth_supported': 'cephx',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': False,
        }
        self.assertEqual(expect, mon_ctxt())

    def test_resolve_http_frontend(self):
        _test_version = '12.2.0'

        def _compare_version(package, version):
            return fetch.apt_pkg.version_compare(
                _test_version, version
            )

        # Older releases, default and invalid configuration
        self.cmp_pkgrevno.side_effect = _compare_version
        self.assertEqual('civetweb', context.resolve_http_frontend())

        # Default for Octopus but not Pacific
        _test_version = '15.2.0'
        self.assertEqual('beast', context.resolve_http_frontend())

        self.arch.return_value = 's390x'
        self.assertEqual('civetweb', context.resolve_http_frontend())

        # Default for Pacific and later
        _test_version = '16.2.0'
        self.assertEqual('beast', context.resolve_http_frontend())
        self.arch.return_value = 'amd64'
        self.assertEqual('beast', context.resolve_http_frontend())

    def test_validate_http_frontend(self):
        _test_version = '12.2.0'

        def _compare_version(package, version):
            return fetch.apt_pkg.version_compare(
                _test_version, version
            )

        self.cmp_pkgrevno.side_effect = _compare_version

        # Invalid configuration option
        with self.assertRaises(ValueError):
            context.validate_http_frontend('foobar')

        # beast config but ceph pre mimic
        with self.assertRaises(ValueError):
            context.validate_http_frontend('beast')

        # Mimic with valid configuration
        _test_version = '13.2.0'
        context.validate_http_frontend('beast')
        context.validate_http_frontend('civetweb')

        # beast config on unsupported s390x/octopus
        _test_version = '15.2.0'
        self.arch.return_value = 's390x'
        with self.assertRaises(ValueError):
            context.validate_http_frontend('beast')

        # beast config on s390x/pacific
        _test_version = '16.2.0'
        context.validate_http_frontend('beast')

    @patch('ceph_radosgw_context.https')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('charmhelpers.contrib.hahelpers.cluster.config_get')
    @patch.object(ceph, 'config', lambda *args:
                  '{"client.radosgw.gateway": {"rgw init timeout": 60}}')
    def test_ctxt_inconsistent_fsids(self, mock_config_get, mock_relation_ids,
                                     mock_https):
        mock_https.return_value = False
        mock_relation_ids.return_value = []
        mock_config_get.side_effect = self.test_config.get
        self.socket.gethostname.return_value = 'testhost'
        mon_ctxt = context.MonContext()
        addresses = ['10.5.4.1', '10.5.4.2', '10.5.4.3']
        fsids = ['testfsid', 'testfsid', None]

        def _relation_get(attr, unit, rid):
            if attr == 'ceph-public-address':
                return addresses.pop()
            elif attr == 'auth':
                return 'cephx'
            elif attr == 'rgw.testhost_key':
                return 'testkey'
            elif attr == 'fsid':
                return fsids.pop()

        self.relation_get.side_effect = _relation_get
        self.relation_ids.return_value = ['mon:6']
        self.related_units.return_value = ['ceph/0', 'ceph/1', 'ceph/2']
        self.multisite.plain_list = self.plain_list_stub
        self.determine_api_port.return_value = 70
        expect = {
            'auth_supported': 'cephx',
            'hostname': 'testhost',
            'mon_hosts': '10.5.4.1 10.5.4.2 10.5.4.3',
            'old_auth': False,
            'systemd_rgw': True,
            'unit_public_ip': '10.255.255.255',
            'use_syslog': 'false',
            'loglevel': 1,
            'port': 70,
            'client_radosgw_gateway': {'rgw init timeout': 60},
            'ipv6': False,
            'rgw_zone': 'default',
            'fsid': 'testfsid',
            'rgw_swift_versioning': False,
            'frontend': 'beast',
            'relaxed_s3_bucket_names': False,
            'rgw_zonegroup': 'zonegroup1',
            'rgw_realm': 'realmX',
            'behind_https_proxy': False,
        }
        self.assertEqual(expect, mon_ctxt())


class ApacheContextTest(CharmTestCase):

    def setUp(self):
        super(ApacheContextTest, self).setUp(context, TO_PATCH)
        self.config.side_effect = self.test_config.get


class SecondaryContextTest(CharmTestCase):

    def setUp(self):
        super(SecondaryContextTest, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.relation_ids.return_value = ['secondary:6']
        self.related_units.return_value = ['primary-ceph-radosgw/0']

    def test_complete_ctxt(self):
        test_ctxt = {
            'realm': 'realmX',
            'zonegroup': 'zonegroup1',
            'access_key': 's3_access_key',
            'secret': 's3_secret',
            'url': 'http://10.9.3.3:80',
        }
        self.test_relation.set(test_ctxt)
        ctxt = context.SecondaryContext()
        self.assertEqual(test_ctxt, ctxt())

    def test_incomplete_ctxt(self):
        self.test_relation.set({
            'realm': 'realmX',
            'zonegroup': 'zonegroup1',
            'url': 'http://10.9.3.3:80',
            'access_key': None,
            'secret': None,
        })
        ctxt = context.SecondaryContext()
        self.assertEqual({}, ctxt())


class S3CredentialsRelationContextTest(CharmTestCase):

    def setUp(self):
        super(S3CredentialsRelationContextTest, self).setUp(context, TO_PATCH)

    def test_get_data(self):
        self.relation_ids.return_value = [
            's3-credentials:6',
            's3-credentials:7',
            's3-credentials:8',
            's3-credentials:9',
        ]

        def _remote_service_name(name):
            if name == 's3-credentials:6':
                return 'minio-default'
            elif name == 's3-credentials:7':
                return 'minio-dev'
            elif name == 's3-credentials:8':
                return 'minio-prod'
            elif name == 's3-credentials:9':
                return 'minio-local'

        def _relation_get(rid, app):
            if app == 'minio-default':
                return {
                    'access-key': 'default-access-key',
                    'secret-key': 'default-secret-key',
                    'region': 'us-east-1',
                    'endpoint': 'http://10.13.1.2:9000',
                    'bucket': 'default',
                }
            elif app == 'minio-dev':
                return {
                    'access-key': 'dev-access-key',
                    'secret-key': 'dev-secret-key',
                    'region': 'us-east-1',
                    'endpoint': 'http://10.13.1.5:9000',
                    'bucket': 'staging,test*,dev',
                }
            elif app == 'minio-prod':
                return {
                    'access-key': 'prod-access-key',
                    'secret-key': 'prod-secret-key',
                    'region': 'us-east-2',
                    'endpoint': 'http://10.13.1.10:9000',
                    'bucket': 'prod',
                }
            elif app == 'minio-local':
                # This returns incomplete relation app data. It will not be
                # included in the relation context.
                return {
                    'region': 'local',
                    'endpoint': 'http://192.168.1.100:9000',
                }

        self.remote_service_name.side_effect = _remote_service_name
        self.relation_get.side_effect = _relation_get
        expected = {
            'minio-default': {
                'access-key': 'default-access-key',
                'secret-key': 'default-secret-key',
                'region': 'us-east-1',
                'endpoint': 'http://10.13.1.2:9000',
                'bucket': 'default',
            },
            'minio-dev': {
                'access-key': 'dev-access-key',
                'secret-key': 'dev-secret-key',
                'region': 'us-east-1',
                'endpoint': 'http://10.13.1.5:9000',
                'bucket': 'staging,test*,dev',
            },
            'minio-prod': {
                'access-key': 'prod-access-key',
                'secret-key': 'prod-secret-key',
                'region': 'us-east-2',
                'endpoint': 'http://10.13.1.10:9000',
                'bucket': 'prod',
            }
        }

        s3_rel_ctxt = context.S3CredentialsRelationContext()
        self.assertEqual(expected, s3_rel_ctxt)
