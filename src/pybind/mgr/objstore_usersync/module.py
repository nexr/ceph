
"""
A cluster health alerting module for Atlassian statuspage.
"""

from mgr_module import MgrModule, HandleCommandResult
from threading import Event
import errno
import copy
import json
import xmltodict
import subprocess
import requests
from requests.auth import HTTPBasicAuth
import re

class ObjstoreUsersync(MgrModule):
    COMMANDS = [
    ]

    MODULE_OPTIONS = [
        {
            'name': 'interval',
            'type': 'int',
            'default': 30,
            'min': 30,
            'desc': 'How frequently to synchronize user (must be above 30)',
            'runtime': True,
        },
        {
            'name': 'sync_target',
            'default': 'ranger',
            'desc': 'Target to synchronize user.',
            'runtime': True,
        },
        {
            'name': 'sync_tenant',
            'default': 'nes',
            'desc': 'The tenant name for nes',
            'runtime': True,
        },
        {
            'name': 'allow_user_remove',
            'type': 'bool',
            'default': True,
            'desc': 'Whether objstore_usersync could be allowed to remove user or not',
            'runtime': True,
        },
        {
            'name': 'endpoint_map_update_cycle',
            'type': 'int',
            'default': 5,
            'min': 3,
            'desc': 'How much cycles to update cached endpoint map (must be above 3)',
            'runtime': True,
        },
        # sync target ranger config
        {
            'name': 'ranger_rest_url',
            'default': '',
            'desc': 'endpoint of target statuspage',
            'runtime': True,
        },
        {
            'name': 'ranger_admin_user',
            'default': '',
            'desc': 'User to authenticate ranger as',
            'runtime': True,
        },
        {
            'name': 'ranger_admin_password',
            'default': '',
            'desc': 'Password to authenticate ranger with',
            'runtime': True,
        },
        {
            'name': 'ranger_admin_password_path',
            'default': '',
            'desc': 'Path to file containing ranger admin password',
            'runtime': True,
        },
        {
            'name': 'ranger_user_initial_password',
            'default': 'abc12345',
            'desc': 'Password used when create new user. ' + \
                    'It should be minimum 8 characters with alpabet and number',
            'runtime': True,
        },
        {
            'name': 'ranger_service_initial_endpoint',
            'default': '',
            'desc': 'Radosgw(rgw) endpoint used when create new S3 ranger service.',
            'runtime': True,
        },
        {
            'name': 'ranger_user_hard_remove',
            'type': 'bool',
            'default': True,
            'desc': 'Whether remove user hardly or not. ' + \
                    'When it set False, the user would become invisible instead removed',
            'runtime': True,
        },
    ]

    # These are "native" Ceph options that this module cares about.
    NATIVE_OPTIONS = [
    ]


    def __init__(self, *args, **kwargs):
        super(ObjstoreUsersync, self).__init__(*args, **kwargs)

        # set up some members to enable the serve() method and shutdown()
        self.run = True
        self.event = Event()

        self.mgr_keyring = self.get_ceph_option('mgr_data') + '/keyring'

        self.def_ranger_endp = {
            'url'           : '',
            'admin_user'    : '',
            'admin_pw'      : '',
            'admin_pw_path' : '',
            'tenant'        : '',
            'group_id'      : '',
        }

        self.endpoint_map = {
            'ranger': {
                'default': self.def_ranger_endp
            }
        };

        # ensure config options members are initialized; see config_notify()
        self.config_notify()

        self.log.info("Init")

    def config_notify(self):
        """
        This method is called whenever one of our config options is changed.
        """
        # This is some boilerplate that stores MODULE_OPTIONS in a class
        # member, so that, for instance, the 'emphatic' option is always
        # available as 'self.emphatic'.
        for opt in self.MODULE_OPTIONS:
            setattr(self,
                    opt['name'],
                    self.get_module_option(opt['name']))
            self.log.debug(' mgr option %s = %s',
                           opt['name'], getattr(self, opt['name']))
        # Do the same for the native options.
        for opt in self.NATIVE_OPTIONS:
            setattr(self,
                    opt,
                    self.get_ceph_option(opt))
            self.log.debug(' native option %s = %s', opt, getattr(self, opt))

        self.def_ranger_endp[ 'url'           ] = self.ranger_rest_url
        self.def_ranger_endp[ 'admin_user'    ] = self.ranger_admin_user
        self.def_ranger_endp[ 'admin_pw'      ] = self.ranger_admin_password
        self.def_ranger_endp[ 'admin_pw_path' ] = self.ranger_admin_password_path
        self.def_ranger_endp[ 'tenant'        ] = self.sync_tenant
        self.def_ranger_endp[ 'group_id'      ] = ''

        if self.interval < 30: self.interval = 30
        if self.endpoint_map_update_cycle < 3: self.endpoint_map_update_cycle = 3


    def handle_command(self, inbuf, cmd):
        ret = 0
        out = ''
        err = ''

        return HandleCommandResult(
            retval=ret,   # exit code
            stdout=out,   # stdout
            stderr=err)

    def _exec_radosgw_admin(self, cmd):
        timeout_sec = int(self.interval / 2)
        if timeout_sec < 15: timeout_sec = 15

        full_cmd  = "timeout %d " % timeout_sec
        full_cmd += "radosgw-admin --name mgr.%s " % self.get_mgr_id()
        full_cmd += "--keyring %s " % self.mgr_keyring
        full_cmd += cmd

        subproc = subprocess.Popen(
            full_cmd.split(' '),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        out, err = subproc.communicate()
        rc = subproc.returncode

        return out, err, rc

    def _read_secret(self, file_path):
        ret_str = ""

        try: fd = open(file_path, "r")
        except Exception as e:
            self.log.warning("_read_secret(): %s" % e)
            return ret_str

        ret_str = fd.readline().rstrip()

        fd.close()

        return ret_str

    def _request_ranger_rest(self, method, path, endpoint = {}, data = {}):
        if len(endpoint) == 0:
            endpoint = self.endpoint_map['ranger']['default']

        method = method.upper()

        url = "%s/%s" % (endpoint['url'], path)
        url = re.sub("(http|https):/", r"\1://", re.sub("/+", "/", url))

        self.log.debug("%s request: %s" % (method, url))

        response = None

        admin_pw_path = endpoint['admin_pw_path']
        admin_pw = endpoint['admin_pw'] if len(admin_pw_path) == 0 else \
                   self._read_secret(admin_pw_path)

        basic_auth = HTTPBasicAuth(endpoint['admin_user'], admin_pw)

        if   method == "GET"    : response = requests.get(url, auth=basic_auth)
        elif method == "PUT"    : response = requests.put(url, auth=basic_auth, json=data)
        elif method == "POST"   : response = requests.post(url, auth=basic_auth, json=data)
        elif method == "DELETE" : response = requests.delete(url, auth=basic_auth)

        if response == None:
            self.log.warning("Not defined rest method")
            return {}, -1

        response_text  = response.text.encode('utf8')
        response_scode = response.status_code
        self.log.debug("%s (status code %d)" % (response_text, response_scode))

        try: response_dict = xmltodict.parse(response_text)
        except Exception as e:
            try: response_dict = json.loads(response_text)
            except Exception as e: response_dict = {}

        return response_dict, response_scode

    def _fetch_ranger_group_id(self, endpoint = {}):
        if len(endpoint) == 0:
            endpoint = self.endpoint_map['ranger']['default']

        sync_tenant = endpoint['tenant']

        group_query_path = "/xusers/groups/groupName/%s" % sync_tenant
        resp, scode = self._request_ranger_rest("get", group_query_path, endpoint)

        if scode == 200:
            endpoint['group_id'] = resp['vxGroup']['id']
        # the tenant group not founded
        elif scode == 400 and resp['vxResponse']['messageList']['name'] == 'DATA_NOT_FOUND':
            group_create_try_msg  = "'%s' ranger group is not exist. " % sync_tenant
            group_create_try_msg += "Try to create the tenant group"
            self.log.info(group_create_try_msg)

            data = { 'name': sync_tenant, 'description': 'group for nes tenant' }
            resp, scode = self._request_ranger_rest("post", "/xusers/groups", endpoint, data)

            if scode == 200:
                endpoint['group_id'] = resp['vxGroup']['id']
            else: # group create request failed
                self.log.warning("The ranger group creating trial is failed")
        else: # group query request failed
            self.log.warning("Failed to get ranger group info")

        return endpoint['group_id']

    def _get_objuser_info(self, user_name):
        ret_json = {}

        info_out, info_err, info_rc = self._exec_radosgw_admin("user info --uid %s" % user_name)
        is_success = (info_rc == 0)

        if is_success:
            ret_json = json.loads(info_out)
        else:
            self.log.warning("Failed to get '%s' user info: %s" % (user_name, info_err))

        return ret_json, is_success


    def _get_objuser_list(self):
        ret_list = []
        is_success = False

        max_entries = 1000;
        while True:
            list_out, list_err, list_rc = self._exec_radosgw_admin("user list --max-entries %d" % max_entries)
            is_success = (list_rc == 0)

            if not is_success:
                self.log.warning("Failed to get user list: " + list_err)
                break

            ret_json = json.loads(list_out)

            if ret_json['truncated'] == 'true':
                max_entries *= 10
                continue
            else:
               ret_list = ret_json['keys']

            break

        return ret_list, is_success

    def _print_endpoint_map(self):
        emap = self.endpoint_map

        self.log.debug("{")
        for type_key in emap.keys():
            self.log.debug("  " + type_key + ": [")

            for user_key in emap[type_key].keys():
                self.log.debug("    " + user_key + ": {")
                for item_key in emap[type_key][user_key]:
                    self.log.debug("      " + item_key + ": " + emap[type_key][user_key][item_key] + ",")
                self.log.debug("    },")
            self.log.debug("  ],")
        self.log.debug("}")

    def _update_endpoint_map(self):
        user_list, is_success = self._get_objuser_list()

        if not is_success:
            self.log.warning("Failed to get user list")
            return is_success

        self.def_ranger_endp['group_id'] = ''
        self.endpoint_map = {
            'ranger': {
                'default': self.def_ranger_endp
            }
        }

        for each_user in user_list:
            user_info, is_success = self._get_objuser_info(each_user)
            if not is_success: break

            if 'endpoints' not in user_info:
                self.log.debug("There is no 'endpoints' entity in '%s' user info" % each_user)
                continue

            user_endps = user_info['endpoints']
            for each_endp in user_endps:
                if not each_endp['enabled']: continue

                endp_type = each_endp['type']
                if endp_type not in self.endpoint_map: self.endpoint_map[endp_type] = {}

                self.endpoint_map[endp_type][each_user] = {
                    'url'           : each_endp['url'],
                    'admin_user'    : each_endp['admin_user'],
                    'admin_pw'      : each_endp['admin_password'],
                    'admin_pw_path' : each_endp['admin_password_path'],
                    'tenant'        : each_endp['tenant_group'],
                    'group_id'      : '',
                }
                self.log.debug("The '%s' endpoint of '%s' enter map" % (endp_type, each_user))

        self._print_endpoint_map()

        return is_success

    def _get_ranger_user_list(self, endpoint = {}):
        ret_list = []

        if len(endpoint) == 0:
            endpoint = self.endpoint_map['ranger']['default']

        group_id = endpoint['group_id']
        if group_id == '':
            group_id = self._fetch_ranger_group_id(endpoint)

        need_continue = True
        offset = 0
        while need_continue:
            user_list_path = "/xusers/%s/users?startIndex=%d" % (group_id, offset)
            resp, scode = self._request_ranger_rest("get", user_list_path, endpoint)
            is_success  = (scode == 200)

            if is_success:
                result_size = int(resp['vxUserList']['resultSize'])
                page_size   = int(resp['vxUserList']['pageSize'])

                # when result_size is 1, vXUsers was not array
                if result_size == 1:
                    ret_list.append(resp['vxUserList']['vXUsers']['name'])
                elif result_size > 1:
                    ret_list += map(lambda x: x['name'], resp['vxUserList']['vXUsers'])

                need_continue = (result_size == page_size)
                if need_continue: offset = offset + page_size

            else:
                self.log.warning("Failed to get ranger users")
                break

        return ret_list, is_success

    def _get_tgtuser_list(self, target, endpoint = {}):
        ret_list = []
        is_success = False

        if target == "ranger":
            ret_list, is_success = self._get_ranger_user_list(endpoint)
        else:
            self.log.warning("The '%s' is not supported list target" % target)

        return ret_list, is_success

    def _create_ranger_user(self, user_name, endpoint = {}):
        is_success = False

        if len(endpoint) == 0:
            endpoint = self.endpoint_map['ranger']['default']

        group_name = endpoint["tenant"]
        group_id   = endpoint["group_id"]
        if group_id == '':
            group_id = self._fetch_ranger_group_id(endpoint)

        resp, scode = self._request_ranger_rest("get", "/xusers/users/userName/" + user_name, endpoint)

        is_not_exist = ( scode == 200 and resp['vxUser']['isVisible'] == '0' ) or \
                       ( scode == 400 and \
                         resp['vxResponse']['messageList']['name'] == 'DATA_NOT_FOUND' )

        is_success = (scode == 200) or is_not_exist
        if not is_success:
            self.log.warning("Failed to get user info: " + user_name)
            return is_success

        user_id = ''
        if is_not_exist:
            self.log.debug("'%s' ranger user is not exist" % user_name)

            initial_pw = self.ranger_user_initial_password

            user_data = {
                'loginId'   : user_name,
                'note'      : 'created by nes',
                "password"  : initial_pw,
                "firstName" : user_name,
            }

            resp, scode = self._request_ranger_rest("post", "/users", endpoint, user_data)
            is_success  = (scode == 200 or scode == 404) # scode 404 if user already exist

            if not is_success:
                self.log.warning("Failed to create user '%s'" % user_name)
                return is_success

            xuser_data = {
                'name'        : user_name,
                'description' : 'created by nes',
                "password"    : initial_pw,
                "firstName"   : user_name,
                "isVisible"   : 1,
            }

            resp, scode = self._request_ranger_rest("post", "/xusers/users", endpoint, xuser_data)
            is_success  = (scode == 200)

            if is_success:
                user_id = resp['vxUser']['id']

                self.log.debug("The initial password of user '%s' is %s" % (user_name, initial_pw))
            else:
                self.log.warning("Failed to create xuser '%s'" % user_name)
                return is_success

        else: # user already exist
            user_id = resp['vxUser']['id']

        resp, scode = self._request_ranger_rest("get", "/xusers/%s/groups" % user_id, endpoint)
        is_success  = (scode == 200)

        user_groups = []
        if is_success:
            result_size = int(resp['vxGroupList']['resultSize'])

            # when result_size is 1, vXGroups was not array
            if result_size == 1:
                user_groups = [ resp['vxGroupList']['vXGroups']['id'] ]
            elif result_size > 1:
                user_groups = map(lambda x: x['id'], resp['vxGroupList']['vXGroups'])
        else:
            self.log.warning("Failed to get groups of user '%s'" % user_name)
            return is_success

        if group_id in user_groups:
            self.log.debug("The user '%s' is already member of tenant group" % user_name)
            return is_success

        groupuser_data = {
            "name"          : group_name,
            "parentGroupId" : group_id,
            "userId"        : user_id,
        }

        resp, scode = self._request_ranger_rest("post", "/xusers/groupusers", endpoint, groupuser_data)
        is_success  = (scode == 200)

        if not is_success:
            self.log.warning("Failed to add '%s' to nes tanant group" % user_name)
            return is_success

        user_info, is_success = self._get_objuser_info(user_name)
        if not is_success: return is_success

        s3_key_info = {
            'user': user_name,
            'access_key': 'accesskey',
            'secret_key': 'secretkey'
        }

        for each_key_info in user_info['keys']:
            if each_key_info['user'] != user_name: continue

            s3_key_info = each_key_info
            break

        service_endpoint = self.ranger_service_initial_endpoint
        if len(service_endpoint) == 0: service_endpoint = 'http://1.2.3.4:8080'

        service_define_data = {
            'name': s3_key_info['user'],
            'type': 's3',
            'description': "created by nes. " \
                         + "If want to change initail endpoint, " \
                         + "check the 'mgr/objstore_usersync/ranger_service_initial_endpoint' option.",
            'configs': {
                'endpoint'  : service_endpoint,
                'accesskey' : s3_key_info['access_key'],
                'password'  : s3_key_info['secret_key'],
            },
            'isEnabled': True,
        }

        resp, scode = self._request_ranger_rest("get", "plugins/services/name/" + user_name, endpoint)
        is_success = (scode == 200 or scode == 404)
        is_service_exist = (scode == 200)

        if not is_success:
            self.log.warning("Failed to get policies of '%s'" % user_name)
            return is_success

        if is_service_exist:
            del service_define_data['description']

            service_define_data['id'] = resp['id']

            resp, scode = self._request_ranger_rest("put", "/plugins/services/%d" % resp['id'], endpoint, service_define_data)
            is_success  = (scode == 200)

            if not is_success:
                self.log.warning("Failed to enable s3 service of '%s'" % user_name)
                return is_success

        else:
            resp, scode = self._request_ranger_rest("post", "/plugins/services", endpoint, service_define_data)
            is_success  = (scode == 200)

            if not is_success:
                self.log.warning("Failed to create s3 service of '%s'" % user_name)
                return is_success

            owner_policy_data = {
                'name': 'nes_default_policy',
                'service': user_name,
                'description': 'created by nes.',
                'resources': {
                    'path': {
                        'values'     : ['/*'],
                        'isRecursive': True,
                        'isExcludes' : False,
                    }
                },
                'policyItems': [
                    {
                        'users': [ '{OWNER}' ],
                        'accesses': [
                            { 'type': 'read', 'isAllowed': True },
                            { 'type': 'write', 'isAllowed': True },
                        ]
                    }
                ]
            }

            resp, scode = self._request_ranger_rest("post", "/plugins/policies", endpoint, owner_policy_data)
            is_success  = (scode == 200)

            if not is_success:
                self.log.warning("Failed to create default owner_policy of '%s'" % user_name)
                return is_success

        return is_success

    def _create_tgtuser(self, user_name, target = 'ranger', endpoint = {}):
        is_success = False

        if target == "ranger":
            is_success = self._create_ranger_user(user_name, endpoint)
        else:
            self.log.warning("The '%s' is not supported user create target" % target)

        return is_success

    def _remove_ranger_user(self, user_name, endpoint = {}):
        is_success = False

        if len(endpoint) == 0:
            endpoint = self.endpoint_map['ranger']['default']

        group_name = endpoint['tenant']
        group_id   = endpoint['group_id']
        if group_id == '':
            group_id = self._fetch_ranger_group_id(endpoint)

        resp, scode = self._request_ranger_rest("get", "/xusers/users/userName/" + user_name, endpoint)

        is_not_exist = ( scode == 400 and \
                         resp['vxResponse']['messageList']['name'] == 'DATA_NOT_FOUND' )

        is_success = (scode == 200) or is_not_exist

        if not is_success:
            self.log.warning("Failed to get user id: " + user_name)
            return is_success

        user_id = ''
        if is_not_exist:
            self.log.debug("'%s' ranger user is already removed" % user_name)
            return is_success
        else:
            user_id = resp['vxUser']['id']

        resp, scode = self._request_ranger_rest("get", "/xusers/%s/groups" % user_id, endpoint)
        is_success  = (scode == 200)

        user_groups = []
        if is_success:
            result_size = int(resp['vxGroupList']['resultSize'])

            # when result_size is 1, vXGroups was not array
            if result_size == 1:
                user_groups = [ resp['vxGroupList']['vXGroups']['id'] ]
            elif result_size > 1:
                user_groups = map(lambda x: x['id'], resp['vxGroupList']['vXGroups'])
        else:
            self.log.warning("Failed to get groups of user '%s'" % user_name)
            return is_success

        if group_id not in user_groups:
            self.log.debug("The user '%s' is not member of tenant group" % user_name)
            return is_success

        need_remove = (len(user_groups) == 1)

        group_remove_user_path = "xusers/group/%s/user/%s" % (group_name, user_name)

        resp, scode = self._request_ranger_rest("delete", group_remove_user_path, endpoint)
        is_success  = (scode == 204)

        if not is_success:
            self.log.warning("Failed to exclued user '%s' from tenant group" % user_name)
            return is_success

        if not need_remove:
            self.log.debug("The user '%s' does not need to be removed" % user_name)
            return is_success

        hard_remove = self.ranger_user_hard_remove

        remove_user_path = "/xusers/users/%s?forceDelete=%s" % (user_id, hard_remove)
        resp, scode = self._request_ranger_rest("delete", remove_user_path, endpoint)
        is_success  = (scode == 204)

        if not is_success:
            self.log.warning("Failed to remove '%s' user" % user_name)
            return is_success

        resp, scode = self._request_ranger_rest("get", "plugins/services/name/" + user_name, endpoint)
        is_success = (scode == 200 or scode == 404)
        is_service_exist = (scode == 200)

        if not is_success:
            self.log.warning("Failed to get s3 service of '%s'" % user_name)
            return is_success

        if is_service_exist:
            resp['isEnabled'] = False

            resp, scode = self._request_ranger_rest("put", "/plugins/services/%d" % resp['id'], endpoint, resp)
            is_success  = (scode == 200)

            if not is_success:
                self.log.warning("Failed to disable s3 service of '%s'" % user_name)
                return is_success

        return is_success

    def _remove_tgtuser(self, user_name, target = 'ranger', endpoint = {}):
        is_success = False

        if target == "ranger":
            is_success = self._remove_ranger_user(user_name, endpoint)
        else:
            self.log.warning("The '%s' is not supported user remove target" % target)

        return is_success

    def serve(self):
        """
        This method is called by the mgr when the module starts and can be
        used for any background activity.
        """
        self.log.info("Starting")

        is_first = True

        cycle_after_emap_update = self.endpoint_map_update_cycle

        make_tgtusers_pool_key = lambda endp: endp['url'] + '#' + endp['tenant']

        while self.run:
            # Do some useful background work here.
            if is_first:
                is_first = False
            else:
                self.log.debug('Sleeping for %d seconds', self.interval)
                ret = self.event.wait(self.interval)
                self.event.clear()
                cycle_after_emap_update += 1

            if cycle_after_emap_update >= self.endpoint_map_update_cycle:
                self._update_endpoint_map()
                cycle_after_emap_update = 0

            objusers, get_objusers_success = self._get_objuser_list()
            if not get_objusers_success:
              self.log.warning("Failed to get object store user list")
              continue

            sync_targets = self.sync_target.split(',')

            for each_target in sync_targets:
                self.log.info("Start %s usersync" % each_target)

                target_emap = self.endpoint_map[each_target]

                tgtusers_pool = {}
                for each_endp in target_emap.values():
                    pool_key = make_tgtusers_pool_key(each_endp)
                    if pool_key in tgtusers_pool: continue

                    tgtusers, get_tgtusers_success = self._get_tgtuser_list(each_target, each_endp)
                    if not get_tgtusers_success:
                        self.log.warning("Failed to get %s user list" % each_target)
                        tgtusers_pool[pool_key] = []
                        continue

                    tgtusers_pool[pool_key] = tgtusers

                for each_objuser in objusers:

                    emap_key = each_objuser if each_objuser in target_emap else 'default'
                    each_endp = target_emap[emap_key]

                    pool_key = make_tgtusers_pool_key(each_endp)
                    if each_objuser in tgtusers_pool[pool_key]:
                        tgtusers_pool[pool_key].remove(each_objuser)
                        continue

                    is_create_success = self._create_tgtuser(each_objuser, each_target, each_endp)
                    if is_create_success:
                        user_create_msg  = "The user '%s' was created " % each_objuser
                        user_create_msg += "in %s" % each_target
                        self.log.info(user_create_msg)
                    else:
                        user_create_fail_msg  = "Faled to create user '%s' " % each_objuser
                        user_create_fail_msg += "in %s" % each_target
                        self.log.warning(user_create_fail_msg)

                if not self.allow_user_remove: continue

                for each_endp in target_emap.values():
                    pool_key = make_tgtusers_pool_key(each_endp)

                    each_tgtusers = tgtusers_pool[pool_key]
                    for each_tgtuser in each_tgtusers:
                        is_remove_success = self._remove_tgtuser(each_tgtuser, each_target, each_endp)
                        if is_remove_success:
                            user_remove_msg  = "The user '%s' was removed " % each_tgtuser
                            user_remove_msg += "from %s" % each_target
                            self.log.info(user_remove_msg)
                        else:
                            user_remove_fail_msg  = "Faled to remove user '%s' " % each_tgtuser
                            user_remove_fail_msg += "from %s" % each_target
                            self.log.warning(user_remove_fail_msg)

                    tgtusers_pool[pool_key] = []

    def shutdown(self):
        """
        This method is called by the mgr when the module needs to shut
        down (i.e., when the serve() function needs to exit).
        """
        self.log.info('Stopping')
        self.run = False
        self.event.set()
