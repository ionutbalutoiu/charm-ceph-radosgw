# Copyright 2019 Canonical Ltd
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

import inspect
import os
import json
from unittest import mock

import multisite

from test_utils import CharmTestCase


def whoami():
    return inspect.stack()[1][3]


def get_zonegroup_stub():
    # populate dummy zone info
    zone = {}
    zone['id'] = "test_zone_id"
    zone['name'] = "test_zone"

    # populate dummy zonegroup info
    zonegroup = {}
    zonegroup['name'] = "test_zonegroup"
    zonegroup['master_zone'] = "test_zone_id"
    zonegroup['zones'] = [zone]
    return zonegroup


class TestMultisiteHelpers(CharmTestCase):
    maxDiff = None

    TO_PATCH = [
        'subprocess',
        'socket',
        'hookenv',
        'utils',
    ]

    def setUp(self):
        super(TestMultisiteHelpers, self).setUp(multisite, self.TO_PATCH)
        self.socket.gethostname.return_value = 'testhost'
        self.utils.request_per_unit_key.return_value = True

    def _testdata(self, funcname):
        return os.path.join(os.path.dirname(__file__),
                            'testdata',
                            '{}.json'.format(funcname))

    def test___key_name(self):
        self.assertEqual(
            multisite._key_name(),
            'rgw.testhost')
        self.utils.request_per_unit_key.return_value = False
        self.assertEqual(
            multisite._key_name(),
            'radosgw.gateway')

    def test_create_realm(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.create_realm('beedata', default=True)
            self.assertEqual(result['name'], 'beedata')
            self.subprocess.check_output.assert_called_with([
                'radosgw-admin', '--id=rgw.testhost',
                'realm', 'create',
                '--rgw-realm=beedata', '--default'
            ])

    def test_list_realms(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.list_realms()
            self.assertTrue('beedata' in result)

    def test_set_default_zone(self):
        multisite.set_default_realm('newrealm')
        self.subprocess.check_call.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'realm', 'default',
            '--rgw-realm=newrealm'
        ])

    def test_create_user(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            access_key, secret = multisite.create_user(
                'mrbees',
            )
            self.assertEqual(
                access_key,
                '41JJQK1HN2NAE5DEZUF9')
            self.assertEqual(
                secret,
                '1qhCgxmUDAJI9saFAVdvUTG5MzMjlpMxr5agaaa4')
            self.subprocess.check_output.assert_called_with([
                'radosgw-admin', '--id=rgw.testhost',
                'user', 'create',
                '--uid=mrbees',
                '--display-name=Synchronization User',
            ])

    def test_create_system_user(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            access_key, secret = multisite.create_system_user(
                'mrbees',
            )
            self.assertEqual(
                access_key,
                '41JJQK1HN2NAE5DEZUF9')
            self.assertEqual(
                secret,
                '1qhCgxmUDAJI9saFAVdvUTG5MzMjlpMxr5agaaa4')
            self.subprocess.check_output.assert_called_with([
                'radosgw-admin', '--id=rgw.testhost',
                'user', 'create',
                '--uid=mrbees',
                '--display-name=Synchronization User',
                '--system'
            ])

    def test_create_zonegroup(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.create_zonegroup(
                'brundall',
                endpoints=['http://localhost:80'],
                master=True,
                default=True,
                realm='beedata',
            )
            self.assertEqual(result['name'], 'brundall')
            self.subprocess.check_output.assert_called_with([
                'radosgw-admin', '--id=rgw.testhost',
                'zonegroup', 'create',
                '--rgw-zonegroup=brundall',
                '--endpoints=http://localhost:80',
                '--rgw-realm=beedata',
                '--default',
                '--master'
            ])

    def test_list_zonegroups(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.list_zonegroups()
            self.assertTrue('brundall' in result)

    def test_create_zone(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.create_zone(
                'brundall-east',
                endpoints=['http://localhost:80'],
                master=True,
                default=True,
                zonegroup='brundall',
                access_key='mykey',
                secret='mypassword',
                tier_type='cloud',
            )
            self.assertEqual(result['name'], 'brundall-east')
            self.subprocess.check_output.assert_called_with([
                'radosgw-admin', '--id=rgw.testhost',
                'zone', 'create',
                '--rgw-zone=brundall-east',
                '--endpoints=http://localhost:80',
                '--rgw-zonegroup=brundall',
                '--default', '--master',
                '--access-key=mykey',
                '--secret=mypassword',
                '--read-only=0',
                '--tier-type=cloud',
            ])

    def test_modify_zone(self):
        multisite.modify_zone(
            'brundall-east',
            endpoints=['http://localhost:80', 'https://localhost:443'],
            access_key='mykey',
            secret='secret',
            tier_config='connection.access_key=my-secret-s3-access-key',
            tier_config_rm='connection.host_style',
            readonly=True
        )
        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'modify',
            '--rgw-zone=brundall-east',
            '--endpoints=http://localhost:80,https://localhost:443',
            '--access-key=mykey', '--secret=secret',
            '--tier-config=connection.access_key=my-secret-s3-access-key',
            '--tier-config-rm=connection.host_style',
            '--read-only=1',
        ])

    def test_modify_zone_promote_master(self):
        multisite.modify_zone(
            'brundall-east',
            default=True,
            master=True,
        )
        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'modify',
            '--rgw-zone=brundall-east',
            '--master',
            '--default',
            '--read-only=0',
        ])

    def test_modify_zone_partial_credentials(self):
        multisite.modify_zone(
            'brundall-east',
            endpoints=['http://localhost:80', 'https://localhost:443'],
            access_key='mykey',
        )
        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'modify',
            '--rgw-zone=brundall-east',
            '--endpoints=http://localhost:80,https://localhost:443',
            '--read-only=0',
        ])

    def test_list_zones(self):
        with open(self._testdata(whoami()), 'rb') as f:
            self.subprocess.check_output.return_value = f.read()
            result = multisite.list_zones()
            self.assertTrue('brundall-east' in result)

    def test_update_period(self):
        multisite.update_period()
        self.subprocess.check_call.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'period', 'update', '--commit'
        ])

    @mock.patch.object(multisite, 'list_zonegroups')
    @mock.patch.object(multisite, 'list_zones')
    @mock.patch.object(multisite, 'update_period')
    def test_tidy_defaults(self,
                           mock_update_period,
                           mock_list_zones,
                           mock_list_zonegroups):
        mock_list_zones.return_value = ['default']
        mock_list_zonegroups.return_value = ['default']
        multisite.tidy_defaults()
        self.subprocess.call.assert_has_calls([
            mock.call(['radosgw-admin', '--id=rgw.testhost',
                       'zonegroup', 'remove',
                       '--rgw-zonegroup=default', '--rgw-zone=default']),
            mock.call(['radosgw-admin', '--id=rgw.testhost',
                       'zone', 'delete',
                       '--rgw-zone=default']),
            mock.call(['radosgw-admin', '--id=rgw.testhost',
                       'zonegroup', 'delete',
                       '--rgw-zonegroup=default'])
        ])
        mock_update_period.assert_called_with()

    @mock.patch.object(multisite, 'list_zonegroups')
    @mock.patch.object(multisite, 'list_zones')
    @mock.patch.object(multisite, 'update_period')
    def test_tidy_defaults_noop(self,
                                mock_update_period,
                                mock_list_zones,
                                mock_list_zonegroups):
        mock_list_zones.return_value = ['brundall-east']
        mock_list_zonegroups.return_value = ['brundall']
        multisite.tidy_defaults()
        self.subprocess.call.assert_not_called()
        mock_update_period.assert_not_called()

    def test_pull_realm(self):
        multisite.pull_realm(url='http://master:80',
                             access_key='testkey',
                             secret='testsecret')
        self.subprocess.check_output.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'realm', 'pull',
            '--url=http://master:80',
            '--access-key=testkey', '--secret=testsecret',
        ])

    def test_pull_period(self):
        multisite.pull_period(url='http://master:80',
                              access_key='testkey',
                              secret='testsecret')
        self.subprocess.check_output.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'period', 'pull',
            '--url=http://master:80',
            '--access-key=testkey', '--secret=testsecret',
        ])

    def test_list_buckets(self):
        self.subprocess.CalledProcessError = BaseException
        multisite.list_buckets('default', 'default')
        self.subprocess.check_output.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'bucket', 'list', '--rgw-zone=default',
            '--rgw-zonegroup=default'
        ])

    def test_rename_zonegroup(self):
        multisite.rename_zonegroup('default', 'test_zone_group')
        self.subprocess.call.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'rename', '--rgw-zonegroup=default',
            '--zonegroup-new-name=test_zone_group'
        ])

    def test_rename_zone(self):
        multisite.rename_zone('default', 'test_zone', 'test_zone_group')
        self.subprocess.call.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'rename', '--rgw-zone=default',
            '--zone-new-name=test_zone',
            '--rgw-zonegroup=test_zone_group'
        ])

    def test_get_zonegroup(self):
        multisite.get_zonegroup_info('test_zone')
        self.subprocess.check_output.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'get', '--rgw-zonegroup=test_zone'
        ])

    def test_modify_zonegroup_migrate(self):
        multisite.modify_zonegroup('test_zonegroup',
                                   endpoints=['http://localhost:80'],
                                   default=True, master=True,
                                   realm='test_realm')
        self.subprocess.check_output.assert_called_once_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'modify',
            '--rgw-zonegroup=test_zonegroup', '--rgw-realm=test_realm',
            '--endpoints=http://localhost:80', '--default', '--master',
        ])

    def test_modify_zone_migrate(self):
        multisite.modify_zone('test_zone', default=True, master=True,
                              endpoints=['http://localhost:80'],
                              zonegroup='test_zonegroup', realm='test_realm')
        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'modify',
            '--rgw-zone=test_zone', '--rgw-realm=test_realm',
            '--rgw-zonegroup=test_zonegroup',
            '--endpoints=http://localhost:80',
            '--master', '--default', '--read-only=0',
        ])

    @mock.patch.object(multisite, 'list_zones')
    @mock.patch.object(multisite, 'get_zonegroup_info')
    def test_get_local_zone(self, mock_get_zonegroup_info, mock_list_zones):
        mock_get_zonegroup_info.return_value = get_zonegroup_stub()
        mock_list_zones.return_value = ['test_zone']
        zone, _zonegroup = multisite.get_local_zone('test_zonegroup')
        self.assertEqual(
            zone,
            'test_zone'
        )

    def test_rename_multisite_config_zonegroup_fail(self):
        self.assertEqual(
            multisite.rename_multisite_config(
                ['default'], 'test_zonegroup',
                ['default'], 'test_zone'
            ),
            None
        )

        self.subprocess.call.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'rename', '--rgw-zonegroup=default',
            '--zonegroup-new-name=test_zonegroup'
        ])

    def test_modify_multisite_config_zonegroup_fail(self):
        self.assertEqual(
            multisite.modify_multisite_config(
                'test_zone', 'test_zonegroup',
                endpoints=['http://localhost:80'],
                realm='test_realm'
            ),
            None
        )

        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'modify', '--rgw-zonegroup=test_zonegroup',
            '--rgw-realm=test_realm',
            '--endpoints=http://localhost:80', '--default',
            '--master',
        ])

    @mock.patch.object(multisite, 'modify_zonegroup')
    def test_modify_multisite_config_zone_fail(self, mock_modify_zonegroup):
        mock_modify_zonegroup.return_value = True
        self.assertEqual(
            multisite.modify_multisite_config(
                'test_zone', 'test_zonegroup',
                endpoints=['http://localhost:80'],
                realm='test_realm'
            ),
            None
        )

        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'modify',
            '--rgw-zone=test_zone',
            '--rgw-realm=test_realm',
            '--rgw-zonegroup=test_zonegroup',
            '--endpoints=http://localhost:80',
            '--master', '--default', '--read-only=0',
        ])

    @mock.patch.object(multisite, 'rename_zonegroup')
    def test_rename_multisite_config_zone_fail(self, mock_rename_zonegroup):
        mock_rename_zonegroup.return_value = True
        self.assertEqual(
            multisite.rename_multisite_config(
                ['default'], 'test_zonegroup',
                ['default'], 'test_zone'
            ),
            None
        )

        self.subprocess.call.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zone', 'rename', '--rgw-zone=default',
            '--zone-new-name=test_zone',
            '--rgw-zonegroup=test_zonegroup',
        ])

    @mock.patch.object(json, 'loads')
    def test_remove_zone_from_zonegroup(self, json_loads):
        # json.loads() raises TypeError for mock objects.
        json_loads.returnvalue = []
        multisite.remove_zone_from_zonegroup(
            'test_zone', 'test_zonegroup',
        )

        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'remove', '--rgw-zonegroup=test_zonegroup',
            '--rgw-zone=test_zone',
        ])

    @mock.patch.object(json, 'loads')
    def test_add_zone_from_zonegroup(self, json_loads):
        # json.loads() raises TypeError for mock objects.
        json_loads.returnvalue = []
        multisite.add_zone_to_zonegroup(
            'test_zone', 'test_zonegroup',
        )

        self.subprocess.check_output.assert_called_with([
            'radosgw-admin', '--id=rgw.testhost',
            'zonegroup', 'add', '--rgw-zonegroup=test_zonegroup',
            '--rgw-zone=test_zone',
        ])

    @mock.patch.object(multisite, 'list_zonegroups')
    @mock.patch.object(multisite, 'get_local_zone')
    @mock.patch.object(multisite, 'list_buckets')
    def test_check_zone_has_buckets(self, mock_list_zonegroups,
                                    mock_get_local_zone,
                                    mock_list_buckets):
        mock_list_zonegroups.return_value = ['test_zonegroup']
        mock_get_local_zone.return_value = 'test_zone', 'test_zonegroup'
        mock_list_buckets.return_value = ['test_bucket_1', 'test_bucket_2']
        self.assertEqual(
            multisite.check_cluster_has_buckets(),
            True
        )

    def test_get_cloud_sync_tier_config(self):
        s3_rel_context = {
            'minio-default': {
                'access-key': 'default-access-key',
                'secret-key': 'default-secret-key',
                'region': 'us-east-1',
                'endpoint': 'http://10.13.1.2:9000',
                's3-uri-style': 'path',
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
                's3-uri-style': 'virtual',
            }
        }
        default_profile = 'minio-default'
        target_path = 'rgwx-${zonegroup}-${zone}-${sid}/${bucket}'

        tier_config = multisite.get_cloud_sync_tier_config(
            s3_rel_context=s3_rel_context,
            default_profile=default_profile,
            target_path=target_path)

        expected = {
            'connection_id': default_profile,
            'target_path': target_path,
            'connections': [
                {
                    'id': 'minio-default',
                    'region': 'us-east-1',
                    'endpoint': 'http://10.13.1.2:9000',
                    'access_key': 'default-access-key',
                    'secret': 'default-secret-key',
                    'host_style': 'path',
                },
                {
                    'id': 'minio-dev',
                    'region': 'us-east-1',
                    'endpoint': 'http://10.13.1.5:9000',
                    'access_key': 'dev-access-key',
                    'secret': 'dev-secret-key',
                },
                {
                    'id': 'minio-prod',
                    'region': 'us-east-2',
                    'endpoint': 'http://10.13.1.10:9000',
                    'access_key': 'prod-access-key',
                    'secret': 'prod-secret-key',
                    'host_style': 'virtual',
                },
            ],
            'profiles': [
                {
                    'connection_id': 'minio-dev',
                    'source_bucket': 'staging',
                    'target_path': target_path,
                },
                {
                    'connection_id': 'minio-dev',
                    'source_bucket': 'test*',
                    'target_path': target_path,
                },
                {
                    'connection_id': 'minio-dev',
                    'source_bucket': 'dev',
                    'target_path': target_path,
                },
                {
                    'connection_id': 'minio-prod',
                    'source_bucket': 'prod',
                    'target_path': target_path,
                },
            ],
        }
        self.assertEqual(tier_config, expected)

    def test_equal_tier_config(self):
        actual = {
            "connection_id": "<id>",
            "target_path": "<target_path>",
            "connections": [
                {
                    "id": "<id2>",
                    "endpoint": "<endpoint2>",
                },
                {
                    "id": "<id1>",
                    "endpoint": "<endpoint1>",
                },
            ],
            "profiles": [
                {
                    "connection_id": "<id>",
                    "source_bucket": "<bucket>",
                    "target_path": "<target_path>",
                }
            ],
        }
        expected = {
            "connection_id": "<id>",
            "profiles": [
                {
                    "connection_id": "<id>",
                    "source_bucket": "<bucket>",
                    "target_path": "<target_path>",
                }
            ],
            "connections": [
                {
                    "id": "<id1>",
                    "endpoint": "<endpoint1>",
                },
                {
                    "id": "<id2>",
                    "endpoint": "<endpoint2>",
                },
            ],
            "target_path": "<target_path>",
        }
        is_equal = multisite.equal_tier_config(actual, expected)
        self.assertTrue(is_equal)

    def test_non_equal_tier_config(self):
        actual = {
            "connection_id": "<id>",
            "target_path": "<target_path>",
            "connections": [
                {
                    "id": "<id>",
                    "endpoint": "<endpoint>",
                },
            ],
        }
        expected = {
            "connection_id": "<id>",
            "profiles": [
                {
                    "connection_id": "<id>",
                    "source_bucket": "<bucket>",
                    "target_path": "<target_path>",
                }
            ],
            "connections": [
                {
                    "id": "<id>",
                    "endpoint": "<endpoint>",
                },
            ],
            "target_path": "<target_path>",
        }
        is_equal = multisite.equal_tier_config(actual, expected)
        self.assertFalse(is_equal)

    def test_flatten_zone_tier_config(self):
        tier_config = {
            'connection': {
                'access_key': 's3_access_key',
                'secret': 's3_secret',
                'endpoint': 's3_endpoint',
            },
            'acls': [
                {
                    'type': 'acl1',
                    'source_id': 'source1',
                    'dest_id': 'dest1',
                },
                {
                    'type': 'acl2',
                    'source_id': 'source2',
                    'dest_id': 'dest2',
                },
            ],
            'connections': [
                {
                    'id': 'conn1',
                    'access_key': 'conn1_s3_access_key',
                    'secret': 'conn1_s3_secret',
                    'endpoint': 'conn1_s3_endpoint',
                },
            ],
            'profiles': [
                {
                    'source_bucket': 'bucket1',
                    'connection_id': 'conn1',
                    'acls_id': 'acl1',
                },
                {
                    'source_bucket': 'bucket2',
                    'connection_id': 'conn1',
                    'acls_id': 'acl2',
                },
            ],
            'target_path': 'rgwx-${zonegroup}-${zone}-${sid}/${bucket}'
        }
        flatten_config = multisite.flatten_zone_tier_config(tier_config)
        expected = [
            'connection.access_key=s3_access_key',
            'connection.secret=s3_secret',
            'connection.endpoint=s3_endpoint',
            'acls[0].type=acl1',
            'acls[0].source_id=source1',
            'acls[0].dest_id=dest1',
            'acls[1].type=acl2',
            'acls[1].source_id=source2',
            'acls[1].dest_id=dest2',
            'connections[0].id=conn1',
            'connections[0].access_key=conn1_s3_access_key',
            'connections[0].secret=conn1_s3_secret',
            'connections[0].endpoint=conn1_s3_endpoint',
            'profiles[0].source_bucket=bucket1',
            'profiles[0].connection_id=conn1',
            'profiles[0].acls_id=acl1',
            'profiles[1].source_bucket=bucket2',
            'profiles[1].connection_id=conn1',
            'profiles[1].acls_id=acl2',
            'target_path=rgwx-${zonegroup}-${zone}-${sid}/${bucket}',
        ]
        self.assertEqual(flatten_config, expected)
