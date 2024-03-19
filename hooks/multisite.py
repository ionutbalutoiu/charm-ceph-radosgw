#
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

import json
import functools
import subprocess
import socket
import utils

import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.decorators as decorators

RGW_ADMIN = 'radosgw-admin'


@decorators.retry_on_exception(num_retries=10, base_delay=5,
                               exc_type=subprocess.CalledProcessError)
def _check_output(cmd):
    """Logging wrapper for subprocess.check_ouput"""
    hookenv.log("Executing: {}".format(' '.join(cmd)), level=hookenv.DEBUG)
    return subprocess.check_output(cmd).decode('UTF-8')


@decorators.retry_on_exception(num_retries=5, base_delay=3,
                               exc_type=subprocess.CalledProcessError)
def _check_call(cmd):
    """Logging wrapper for subprocess.check_call"""
    hookenv.log("Executing: {}".format(' '.join(cmd)), level=hookenv.DEBUG)
    return subprocess.check_call(cmd)


def _call(cmd):
    """Logging wrapper for subprocess.call"""
    hookenv.log("Executing: {}".format(' '.join(cmd)), level=hookenv.DEBUG)
    return subprocess.call(cmd)


def _key_name():
    """Determine the name of the cephx key for the local unit"""
    if utils.request_per_unit_key():
        return 'rgw.{}'.format(socket.gethostname())
    else:
        return 'radosgw.gateway'


def _list(key):
    """
    Internal implementation for list_* functions

    :param key: string for required entity (zone, zonegroup, realm, user)
    :type key: str
    :return: List of specified entities found
    :rtype: list
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        key, 'list'
    ]
    try:
        result = json.loads(_check_output(cmd))
        hookenv.log("Results: {}".format(
            result),
            level=hookenv.DEBUG)
        if isinstance(result, dict):
            return result['{}s'.format(key)]
        else:
            return result
    except TypeError:
        return []


def plain_list(key):
    """Simple Implementation for list_*, where execution may fail expectedly.

    On failure, retries are not attempted and empty list is returned.

    :param key: string for required resource (zone, zonegroup, realm, user)
    :type key: str
    :return: list of specified entities found
    :rtype: list
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        key, 'list'
    ]
    try:
        result = json.loads(subprocess.check_output(
            cmd, stderr=subprocess.PIPE
        ).decode('UTF-8'))
        hookenv.log("Results: {}".format(result), level=hookenv.DEBUG)
        if isinstance(result, dict):
            return result['{}s'.format(key)]
        else:
            return result
    except subprocess.CalledProcessError:
        return []
    except TypeError:
        return []


@decorators.retry_on_exception(num_retries=5, base_delay=3,
                               exc_type=ValueError)
def list_zones(retry_on_empty=False):
    """
    List zones

    :param retry_on_empty: Whether to retry if no zones are returned.
    :type retry_on_empty: bool
    :return: List of specified entities found
    :rtype: list
    :raises: ValueError
    """
    _zones = _list('zone')
    if retry_on_empty and not _zones:
        hookenv.log("No zones found", level=hookenv.DEBUG)
        raise ValueError("No zones found")
    return _zones


list_realms = functools.partial(_list, 'realm')
list_zonegroups = functools.partial(_list, 'zonegroup')
list_users = functools.partial(_list, 'user')


def list_buckets(zone, zonegroup):
    """List Buckets served under the provided zone and zonegroup pair.

    :param zonegroup: Parent zonegroup.
    :type zonegroup: str
    :param zone: Parent zone.
    :type zone: str
    :returns: List of buckets found
    :rtype: list
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'bucket', 'list',
        '--rgw-zone={}'.format(zone),
        '--rgw-zonegroup={}'.format(zonegroup),
    ]
    try:
        return json.loads(_check_output(cmd))
    except subprocess.CalledProcessError:
        hookenv.log("Bucket queried for incorrect zone({})-zonegroup({}) "
                    "pair".format(zone, zonegroup), level=hookenv.ERROR)
        return None
    except TypeError:
        return None


def create_realm(name, default=False):
    """
    Create a new RADOS Gateway Realm.

    :param name: name of realm to create
    :type name: str
    :param default: set new realm as the default realm
    :type default: boolean
    :return: realm configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'realm', 'create',
        '--rgw-realm={}'.format(name)
    ]
    if default:
        cmd += ['--default']
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def set_default_realm(name):
    """
    Set the default RADOS Gateway Realm

    :param name: name of realm to create
    :type name: str
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'realm', 'default',
        '--rgw-realm={}'.format(name)
    ]
    _check_call(cmd)


def create_zonegroup(name, endpoints, default=False, master=False, realm=None):
    """
    Create a new RADOS Gateway zone Group

    :param name: name of zonegroup to create
    :type name: str
    :param endpoints: list of URLs to endpoints for zonegroup
    :type endpoints: list[str]
    :param default: set new zonegroup as the default zonegroup
    :type default: boolean
    :param master: set new zonegroup as the master zonegroup
    :type master: boolean
    :param realm: realm to use for zonegroup
    :type realm: str
    :return: zonegroup configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'create',
        '--rgw-zonegroup={}'.format(name),
        '--endpoints={}'.format(','.join(endpoints)),
    ]
    if realm:
        cmd.append('--rgw-realm={}'.format(realm))
    if default:
        cmd.append('--default')
    if master:
        cmd.append('--master')
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def modify_zonegroup(name, endpoints=None, default=False,
                     master=False, realm=None):
    """Modify an existing RADOS Gateway zonegroup

    An empty list of endpoints would cause NO-CHANGE in the configured
    endpoints for the zonegroup.

    :param name: name of zonegroup to modify
    :type name: str
    :param endpoints: list of URLs to endpoints for zonegroup
    :type endpoints: list[str]
    :param default: set zonegroup as the default zonegroup
    :type default: boolean
    :param master: set zonegroup as the master zonegroup
    :type master: boolean
    :param realm: realm name for provided zonegroup
    :type realm: str
    :return: zonegroup configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'modify',
        '--rgw-zonegroup={}'.format(name),
    ]
    if realm:
        cmd.append('--rgw-realm={}'.format(realm))
    if endpoints:
        cmd.append('--endpoints={}'.format(','.join(endpoints)))
    if default:
        cmd.append('--default')
    if master:
        cmd.append('--master')
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def create_zone(name, endpoints, default=False, master=False, zonegroup=None,
                access_key=None, secret=None, readonly=False, tier_type=None):
    """
    Create a new RADOS Gateway zone

    :param name: name of zone to create
    :type name: str
    :param endpoints: list of URLs to endpoints for zone
    :type endpoints: list[str]
    :param default: set new zone as the default zone
    :type default: boolean
    :param master: set new zone as the master zone
    :type master: boolean
    :param zonegroup: zonegroup to use for zone
    :type zonegroup: str
    :param access_key: access-key to use for the zone
    :type access_key: str
    :param secret: secret to use with access-key for the zone
    :type secret: str
    :param readonly: set zone as read only
    :type: readonly: boolean
    :param tier_type: tier type to use for the zone
    :type tier_type: str
    :return: dict of zone configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zone', 'create',
        '--rgw-zone={}'.format(name),
        '--endpoints={}'.format(','.join(endpoints)),
    ]
    if zonegroup:
        cmd.append('--rgw-zonegroup={}'.format(zonegroup))
    if default:
        cmd.append('--default')
    if master:
        cmd.append('--master')
    if access_key and secret:
        cmd.append('--access-key={}'.format(access_key))
        cmd.append('--secret={}'.format(secret))
    cmd.append('--read-only={}'.format(1 if readonly else 0))
    if tier_type:
        cmd.append('--tier-type={}'.format(tier_type))
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def modify_zone(name, endpoints=None, default=False, master=False,
                access_key=None, secret=None, readonly=False,
                realm=None, zonegroup=None, tier_type=None, tier_config=None,
                tier_config_rm=None):
    """Modify an existing RADOS Gateway zone

    :param name: name of zone to create
    :type name: str
    :param endpoints: list of URLs to endpoints for zone
    :type endpoints: list[str]
    :param default: set zone as the default zone
    :type default: boolean
    :param master: set zone as the master zone
    :type master: boolean
    :param access_key: access-key to use for the zone
    :type access_key: str
    :param secret: secret to use with access-key for the zone
    :type secret: str
    :param readonly: set zone as read only
    :type readonly: boolean
    :param realm: realm to use for zone
    :type realm: str
    :param zonegroup: zonegroup to use for zone
    :type zonegroup: str
    :param tier_type: tier type to use for the zone
    :type tier_type: str
    :param tier_config: tier config to use for the zone
    :type tier_config: str
    :param tier_config_rm: tier config to remove from the zone
    :type tier_config_rm: str
    :return: zone configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zone', 'modify',
        '--rgw-zone={}'.format(name),
    ]
    if realm:
        cmd.append('--rgw-realm={}'.format(realm))
    if zonegroup:
        cmd.append('--rgw-zonegroup={}'.format(zonegroup))
    if endpoints:
        cmd.append('--endpoints={}'.format(','.join(endpoints)))
    if access_key and secret:
        cmd.append('--access-key={}'.format(access_key))
        cmd.append('--secret={}'.format(secret))
    if master:
        cmd.append('--master')
    if default:
        cmd.append('--default')
    if tier_type:
        cmd.append('--tier-type={}'.format(tier_type))
    if tier_config:
        cmd.append('--tier-config={}'.format(tier_config))
    if tier_config_rm:
        cmd.append('--tier-config-rm={}'.format(tier_config_rm))
    cmd.append('--read-only={}'.format(1 if readonly else 0))
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def get_zone_info(name, zonegroup=None):
    """Fetch detailed info for the provided zone

    :param name: zone name
    :type name: str
    :param zonegroup: parent zonegroup name
    :type zonegroup: str
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zone', 'get',
        '--rgw-zone={}'.format(name),
    ]
    if zonegroup:
        cmd.append('--rgw-zonegroup={}'.format(zonegroup))
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def remove_zone_from_zonegroup(zone, zonegroup):
    """Remove RADOS Gateway zone from provided parent zonegroup

    Removal is different from deletion, this operation removes zone/zonegroup
    affiliation but does not delete the actual zone.

    :param zonegroup: parent zonegroup name
    :type zonegroup: str
    :param zone: zone name
    :type zone: str
    :return: modified zonegroup config
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'remove',
        '--rgw-zonegroup={}'.format(zonegroup),
        '--rgw-zone={}'.format(zone),
    ]
    try:
        result = _check_output(cmd)
        return json.loads(result)
    except (TypeError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "Error removing zone {} from zonegroup {}. Result: {}"
            .format(zone, zonegroup, result)) from exc


def add_zone_to_zonegroup(zone, zonegroup):
    """Add RADOS Gateway zone to provided zonegroup

    :param zonegroup: parent zonegroup name
    :type zonegroup: str
    :param zone: zone name
    :type zone: str
    :return: modified zonegroup config
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'add',
        '--rgw-zonegroup={}'.format(zonegroup),
        '--rgw-zone={}'.format(zone),
    ]
    try:
        result = _check_output(cmd)
        return json.loads(result)
    except (TypeError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "Error adding zone {} from zonegroup {}. Result: {}"
            .format(zone, zonegroup, result)) from exc


def update_period(fatal=True, zonegroup=None, zone=None, realm=None):
    """Update RADOS Gateway configuration period

    :param fatal: In failure case, whether CalledProcessError is to be raised.
    :type fatal: boolean
    :param zonegroup: zonegroup name
    :type zonegroup: str
    :param zone: zone name
    :type zone: str
    :param realm: realm name
    :type realm: str
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'period', 'update', '--commit'
    ]
    if zonegroup is not None:
        cmd.append('--rgw-zonegroup={}'.format(zonegroup))
    if zone is not None:
        cmd.append('--rgw-zone={}'.format(zone))
    if realm is not None:
        cmd.append('--rgw-realm={}'.format(realm))
    if fatal:
        _check_call(cmd)
    else:
        _call(cmd)


def tidy_defaults():
    """
    Purge any default zonegroup and zone definitions
    """
    if ('default' in list_zonegroups() and
            'default' in list_zones()):
        cmd = [
            RGW_ADMIN, '--id={}'.format(_key_name()),
            'zonegroup', 'remove',
            '--rgw-zonegroup=default',
            '--rgw-zone=default'
        ]
        _call(cmd)
        update_period()

    if 'default' in list_zones():
        cmd = [
            RGW_ADMIN, '--id={}'.format(_key_name()),
            'zone', 'delete',
            '--rgw-zone=default'
        ]
        _call(cmd)
        update_period()

    if 'default' in list_zonegroups():
        cmd = [
            RGW_ADMIN, '--id={}'.format(_key_name()),
            'zonegroup', 'delete',
            '--rgw-zonegroup=default'
        ]
        _call(cmd)
        update_period()


def get_user_creds(username):
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'user', 'info',
        '--uid={}'.format(username)
    ]
    result = json.loads(_check_output(cmd))
    return (result['keys'][0]['access_key'],
            result['keys'][0]['secret_key'])


def suspend_user(username):
    """
    Suspend a RADOS Gateway user

    :param username: username of user to create
    :type username: str
    """
    if username not in list_users():
        hookenv.log(
            "Cannot suspended user {}. User not found.".format(username),
            level=hookenv.DEBUG)
        return
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'user', 'suspend',
        '--uid={}'.format(username)
    ]
    _check_output(cmd)
    hookenv.log(
        "Suspended user {}".format(username),
        level=hookenv.DEBUG)


def create_user(username, system_user=False):
    """
    Create a RADOS Gateway user

    :param username: username of user to create
    :type username: str
    :param system_user: Whether to grant system user role
    :type system_user: bool
    :return: access key and secret
    :rtype: (str, str)
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'user', 'create',
        '--uid={}'.format(username),
        '--display-name=Synchronization User'
    ]
    if system_user:
        cmd.append('--system')
    try:
        result = json.loads(_check_output(cmd))
        return (result['keys'][0]['access_key'],
                result['keys'][0]['secret_key'])
    except TypeError:
        return (None, None)


def create_system_user(username):
    """
    Create a RADOS Gateway system user

    :param username: username of user to create
    :type username: str
    :return: access key and secret
    :rtype: (str, str)
    """
    return create_user(username, system_user=True)


def pull_realm(url, access_key, secret):
    """
    Pull in a RADOS Gateway Realm from a master RGW instance

    :param url: url of remote rgw deployment
    :type url: str
    :param access_key: access-key for remote rgw deployment
    :type access_key: str
    :param secret: secret for remote rgw deployment
    :type secret: str
    :return: realm configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'realm', 'pull',
        '--url={}'.format(url),
        '--access-key={}'.format(access_key),
        '--secret={}'.format(secret),
    ]
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def pull_period(url, access_key, secret):
    """
    Pull in a RADOS Gateway period from a master RGW instance

    :param url: url of remote rgw deployment
    :type url: str
    :param access_key: access-key for remote rgw deployment
    :type access_key: str
    :param secret: secret for remote rgw deployment
    :type secret: str
    :return: realm configuration
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'period', 'pull',
        '--url={}'.format(url),
        '--access-key={}'.format(access_key),
        '--secret={}'.format(secret),
    ]
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def rename_zone(name, new_name, zonegroup):
    """Rename an existing RADOS Gateway zone

    If the command execution succeeds, 0 is returned, otherwise
    None is returned to the caller.

    :param name: current name for the zone being renamed
    :type name: str
    :param new_name: new name for the zone being renamed
    :type new_name: str
    :rtype: int
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zone', 'rename',
        '--rgw-zone={}'.format(name),
        '--zone-new-name={}'.format(new_name),
        '--rgw-zonegroup={}'.format(zonegroup)
    ]
    result = _call(cmd)
    return 0 if result == 0 else None


def rename_zonegroup(name, new_name):
    """Rename an existing RADOS Gateway zonegroup

    If the command execution succeeds, 0 is returned, otherwise
    None is returned to the caller.

    :param name: current name for the zonegroup being renamed
    :type name: str
    :param new_name: new name for the zonegroup being renamed
    :type new_name: str
    :rtype: int
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'rename',
        '--rgw-zonegroup={}'.format(name),
        '--zonegroup-new-name={}'.format(new_name),
    ]
    result = _call(cmd)
    return 0 if result == 0 else None


def get_zonegroup_info(zonegroup):
    """Fetch detailed info for the provided zonegroup

    :param zonegroup: zonegroup Name for detailed query
    :type zonegroup: str
    :rtype: dict
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'zonegroup', 'get',
        '--rgw-zonegroup={}'.format(zonegroup),
    ]
    try:
        return json.loads(_check_output(cmd))
    except TypeError:
        return None


def get_sync_status():
    """
    Get sync status
    :returns: Sync Status Report from radosgw-admin
    :rtype: str
    """
    cmd = [
        RGW_ADMIN, '--id={}'.format(_key_name()),
        'sync', 'status',
    ]
    try:
        return _check_output(cmd)
    except subprocess.CalledProcessError:
        hookenv.log("Failed to fetch sync status", level=hookenv.ERROR)
        return None


def is_multisite_configured(zone, zonegroup):
    """Check if system is already multisite configured

    Checks if zone and zonegroup are configured appropriately and
    remote data sync source is detected in sync status

    :rtype: Boolean
    """
    local_zones = list_zones()
    if zone not in local_zones:
        hookenv.log("zone {} not found in local zones {}"
                    .format(zone, local_zones), level=hookenv.ERROR)
        return False

    local_zonegroups = list_zonegroups()
    if zonegroup not in local_zonegroups:
        hookenv.log("zonegroup {} not found in local zonegroups {}"
                    .format(zonegroup, local_zonegroups), level=hookenv.ERROR)
        return False

    sync_status = get_sync_status()
    hookenv.log("Multisite sync status {}".format(sync_status),
                level=hookenv.DEBUG)
    if sync_status is not None:
        return ('data sync source:' in sync_status)

    return False


def get_local_zone(zonegroup):
    """Get local zone to provided parent zonegroup.

    In multisite systems, zonegroup contains both local and remote zone info
    this method is used to fetch the zone local to querying site.

    :param zonegroup: parent zonegroup name.
    :type zonegroup: str
    :returns: tuple with parent zonegroup and local zone name
    :rtype: tuple
    """
    local_zones = list_zones()
    zonegroup_info = get_zonegroup_info(zonegroup)

    if zonegroup_info is None:
        hookenv.log("Failed to fetch zonegroup ({}) info".format(zonegroup),
                    level=hookenv.ERROR)
        return None, None

    # zonegroup info always contains self name and zones list so fetching
    # directly is safe.
    master_zonegroup = zonegroup_info['name']
    for zone_info in zonegroup_info['zones']:
        zone = zone_info['name']
        if zone in local_zones:
            return zone, master_zonegroup

    hookenv.log(
        "No local zone configured for zonegroup ({})".format(zonegroup),
        level=hookenv.ERROR
    )
    return None, None


def rename_multisite_config(zonegroups, new_zonegroup_name,
                            zones, new_zone_name):
    """Rename zone and zonegroup to provided new names.

    If zone list (zones) or zonegroup list (zonegroups) contain 1 element
    rename the only element present in the list to provided (new_) value.

    :param zonegroups: List of zonegroups available at site.
    :type zonegroups: list[str]
    :param new_zonegroup_name: Desired new name for master zonegroup.
    :type new_zonegroup_name: str
    :param zones: List of zones available at site.
    :type zones: list[str]
    :param new_zonegroup_name: Desired new name for master zone.
    :type new_zonegroup_name: str

    :return: Whether any of the zone or zonegroup is renamed.
    :rtype: Boolean
    """
    mutation = False
    if (len(zonegroups) == 1) and (len(zones) == 1):
        if new_zonegroup_name not in zonegroups:
            result = rename_zonegroup(zonegroups[0], new_zonegroup_name)
            if result is None:
                hookenv.log(
                    "Failed renaming zonegroup from {} to {}"
                    .format(zonegroups[0], new_zonegroup_name),
                    level=hookenv.ERROR
                )
                return None
            mutation = True

        if new_zone_name not in zones:
            result = rename_zone(zones[0], new_zone_name, new_zonegroup_name)
            if result is None:
                hookenv.log(
                    "Failed renaming zone from {} to {}"
                    .format(zones[0], new_zone_name), level=hookenv.ERROR
                )
                return None
            mutation = True

    if mutation:
        hookenv.log("Renamed zonegroup {} to {}, and zone {} to {}".format(
                    zonegroups[0], new_zonegroup_name,
                    zones[0], new_zone_name))
        return True

    return False


def modify_multisite_config(zone, zonegroup, endpoints=None, realm=None):
    """Configure zone and zonegroup as master for multisite system.

    :param zonegroup: zonegroup name being configured for multisite
    :type zonegroup: str
    :param zone: zone name being configured for multisite
    :type zone: str
    :param endpoints: list of URLs to RGW endpoints
    :type endpoints: list[str]
    :param realm: realm to use for multisite
    :type realm: str
    :rtype: Boolean
    """
    if modify_zonegroup(zonegroup, endpoints=endpoints, default=True,
                        master=True, realm=realm) is None:
        hookenv.log(
            "Failed configuring zonegroup {}".format(zonegroup),
            level=hookenv.ERROR
        )
        return None

    if modify_zone(zone, endpoints=endpoints, default=True,
                   master=True, zonegroup=zonegroup, realm=realm) is None:
        hookenv.log(
            "Failed configuring zone {}".format(zone), level=hookenv.ERROR
        )
        return None

    update_period(zonegroup=zonegroup, zone=zone)
    hookenv.log("Configured zonegroup {}, and zone {} for multisite".format(
                zonegroup, zone))
    return True


def check_zone_has_buckets(zone, zonegroup):
    """Checks whether provided zone-zonegroup pair contains any bucket.

    :param zone: zone name to query buckets in.
    :type zone: str
    :param zonegroup: Parent zonegroup of zone.
    :type zonegroup: str
    :rtype: Boolean
    """
    buckets = list_buckets(zone, zonegroup)
    if buckets is not None:
        return (len(buckets) > 0)
    hookenv.log(
        "Failed to query buckets for zone {} zonegroup {}"
        .format(zone, zonegroup),
        level=hookenv.WARNING
    )
    return False


def check_zonegroup_has_buckets(zonegroup):
    """Checks whether any bucket exists in the master zone of a zonegroup.

    :param zone: zonegroup name to query buckets.
    :type zone: str
    :rtype: Boolean
    """
    # NOTE(utkarshbhatthere): sometimes querying against a particular
    # zonegroup results in info of an entirely different zonegroup, thus to
    # prevent a query against an incorrect pair in such cases, both zone and
    # zonegroup names are taken from zonegroup info.
    master_zone, master_zonegroup = get_local_zone(zonegroup)

    # If master zone is not configured for zonegroup
    if master_zone is None:
        hookenv.log("No master zone configured for zonegroup {}"
                    .format(master_zonegroup), level=hookenv.WARNING)
        return False
    return check_zone_has_buckets(master_zone, master_zonegroup)


def check_cluster_has_buckets():
    """Iteratively check if ANY zonegroup has buckets on cluster.

    :rtype: Boolean
    """
    for zonegroup in list_zonegroups():
        if check_zonegroup_has_buckets(zonegroup):
            return True
    return False


def get_cloud_sync_tier_config(s3_rel_context, default_profile, target_path):
    """Create a tier config for the zone configured with cloud sync.

    This is a helper function used to create a tier config dict with all the
    values from 's3-credentials' relation (given as 's3_rel_context'), and the
    charm config values (given as 'default_profile' and 'target_path').

    :param s3_rel_context: relation data with all the remote applications in
        the 's3-credentials' relation. This value is returned by the
        'S3CredentialsRelationContext' relation context.
    :type s3_rel_context: dict
    :param default_profile: default S3 target to use for cloud sync.
    :type default_profile: str
    :param target_path: prefix added to the synced objects on the S3 target.
    :type target_path: str
    :return: tier config formed from the relation data and charm configs.
    :rtype: dict
    """
    tier_config = {
        'connections': [],
        'profiles': [],
        'connection_id': default_profile,
        'target_path': target_path,
    }
    for profile in s3_rel_context:
        s3_info = s3_rel_context[profile]
        conn = {
            'id': profile,
            'region': s3_info['region'],
            'endpoint': s3_info['endpoint'],
            'access_key': s3_info['access-key'],
            'secret': s3_info['secret-key'],
        }
        if s3_info.get('s3-uri-style'):
            conn['host_style'] = s3_info['s3-uri-style']
        tier_config['connections'].append(conn)
        if profile == default_profile:
            # we don't need to add default profile to profiles list
            continue
        buckets = s3_info['bucket'].split(',')
        for bucket in buckets:
            tier_config['profiles'].append({
                'connection_id': profile,
                'source_bucket': bucket,
                'target_path': target_path,
            })
    # remove empty lists from the tier config before returning
    for k in ['profiles', 'connections']:
        if len(tier_config[k]) == 0:
            tier_config.pop(k)
    return tier_config


def equal_tier_config(actual, expected):
    """Compares two tier configs and returns whether they are equal.

    The expected tier config format is:
    {
        "connection_id": "<id>",
        "target_path": "<target_path>",
        "connections": [
            {
                "id": "<id>",
                "access_key": <access>,
                "secret": <secret>,
                "region": "<region>",
                "endpoint": "<endpoint>",
                ...
            }
            ...
        ],
        profiles: [
            {
                "connection_id": "<id>",
                "source_bucket": "<bucket>",
                "target_path": "<target_path>",
                ...
            }
            ...
        ]
    }

    The tier config can get more complex than this, but the above format is
    what the charm is currently using. We only care to check if the charm
    configs updated the previously applied tier config. Order of the items in
    the nested lists and dicts is not important.

    :param actual: tier config for comparison.
    :type actual: dict
    :param expected: expected tier config (usually the value returned by
        'get_cloud_sync_tier_config' function).
    :type expected: dict
    :rtype: Boolean
    """
    if type(actual) is list and type(expected) is list:
        if len(actual) != len(expected):
            return False
        for actual_item in actual:
            found = False
            for expected_item in expected:
                if equal_tier_config(actual_item, expected_item):
                    found = True
                    break
            if not found:
                return False
        return True
    elif type(actual) is dict and type(expected) is dict:
        if len(actual) != len(expected):
            return False
        for k in actual:
            if not equal_tier_config(actual.get(k), expected.get(k)):
                return False
        return True
    return actual == expected


def flatten_zone_tier_config(config, root_key_name=''):
    """Returns a flatten list of zone tier config.
    This function is used to convert a dict tier config to a flatten list of
    key=value pairs that can be passed as '--tier-config' parameter to
    'radosgw-admin zone modify' command.
    For example, the following dict:
    {
        "connection": {
            "access_key": "<access>",
            "secret": "<secret>",
            "endpoint": "<endpoint>"
        },
        "acls": [
            {
                "type": "<id>",
                "source_id": "<source>",
                "dest_id": "<dest>"
            }
        ],
        "target_path": "<target_path>"
    }
    is flattened to:
    [
        'connection.access_key=<access>',
        'connection.secret=<secret>',
        'connection.endpoint=<endpoint>',
        'acls[0].type=<id>',
        'acls[0].source_id=<source>',
        'acls[0].dest_id=<dest>',
        'target_path=<target_path>'
    ]
    :param config: Dict with the zone tier config.
    :type config: dict
    :param root_key_name: Root key name for the config (optional).
    :type root_key_name: str
    :return: List of key=value pairs for the tier config.
    :rtype: list
    """
    flatten_config = []

    def flatten(elem, key_name=''):
        if type(elem) is dict:
            for i in elem:
                flatten(elem[i], '{}.{}'.format(key_name, i))
        elif type(elem) is list:
            for index, item in enumerate(elem):
                flatten(item, '{}[{}]'.format(key_name, index))
        else:
            flatten_config.append('{}={}'.format(key_name[1:], elem))

    flatten(config, root_key_name)

    return flatten_config
