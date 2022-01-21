
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
            'name': 'ranger_user_initial_password',
            'default': 'abc12345',
            'desc': 'Password used when create new user. ' + \
                    'It should be minimum 8 characters with alpabet and number',
            'runtime': True,
        },
        {
            'name': 'ranger_user_hard_remove',
            'type': 'bool',
            'default': True,
            'desc': 'endpoint of target statuspage',
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

        self.mgr_keyring = self.get_ceph_option('mgr_data') + "/keyring"

        self.ranger_group_id = ""

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

        if self.interval < 30: self.interval = 30


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

    def _request_ranger_rest(self, method, path, data = {}):
        method = method.upper()

        url = "%s/%s" % (self.ranger_rest_url, path)
        url = re.sub("(http|https):/", r"\1://", re.sub("/+", "/", url))

        self.log.debug("%s request: %s" % (method, url))

        response = None

        basic_auth = HTTPBasicAuth(self.ranger_admin_user, self.ranger_admin_password)

        if   (method == "GET"   ) : response = requests.get(url, auth=basic_auth)
        elif (method == "PUT"   ) : response = requests.put(url, auth=basic_auth, json=data)
        elif (method == "POST"  ) : response = requests.post(url, auth=basic_auth, json=data)
        elif (method == "DELETE") : response = requests.delete(url, auth=basic_auth)

        if (response == None):
            self.log.warning("Not defined rest method")
            return {}, -1

        response_text  = response.text.encode('utf8')
        response_scode = response.status_code
        self.log.debug("%s (status code %d)" % (response_text, response_scode))

        try: response_dict = xmltodict.parse(response_text)
        except Exception as e: response_dict = {}

        return response_dict, response_scode

    def _fetch_ranger_group_id(self):
        self.ranger_group_id = ""

        group_query_path = "/xusers/groups/groupName/%s" % self.sync_tenant
        resp, scode = self._request_ranger_rest("get", group_query_path)

        if scode == 200:
            self.ranger_group_id = resp['vxGroup']['id']
        # the tenant group not founded
        elif scode == 400 and resp['vxResponse']['messageList']['name'] == 'DATA_NOT_FOUND':
            group_create_try_msg  = "'%s' ranger group is not exist. " % self.sync_tenant
            group_create_try_msg += "Try to create the tenant group"
            self.log.info(group_create_try_msg)

            data = { 'name': self.sync_tenant, 'description': 'group for nes tenant' }
            resp, scode = self._request_ranger_rest("post", "/xusers/groups", data)

            if scode == 200:
                self.ranger_group_id = resp['vxGroup']['id']
            else: # group create request failed
                self.log.warning("The ranger group creating trial is failed")
        else: # group query request failed
            self.log.warning("Failed to get ranger group info")

    def _get_objuser_list(self):
        ret_list = []

        list_out, list_err, list_rc = self._exec_radosgw_admin("user list")
        is_success = (list_rc == 0)

        if (is_success):
            ret_list = json.loads(list_out)
        else:
            self.log.warning("Failed to get user list: " + list_err)

        return ret_list, is_success

    def _get_ranger_user_list(self):
        ret_list = []

        group_id = self.ranger_group_id

        need_continue = True
        offset = 0
        while need_continue:
            user_list_path = "/xusers/%s/users?startIndex=%d" % (group_id, offset)
            resp, scode = self._request_ranger_rest("get", user_list_path)
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

    def _get_tgtuser_list(self, target):
        ret_list = []
        is_success = False

        if target == "ranger":
            ret_list, is_success = self._get_ranger_user_list()
        else:
            self.log.warning("The '%s' is not supported list target" % target)

        return ret_list, is_success

    def _create_ranger_user(self, user_name):
        is_success = False

        group_name = self.sync_tenant
        group_id   = self.ranger_group_id

        resp, scode = self._request_ranger_rest("get", "/xusers/users/userName/" + user_name)

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

            resp, scode = self._request_ranger_rest("post", "/users", user_data)
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

            resp, scode = self._request_ranger_rest("post", "/xusers/users", xuser_data)
            is_success  = (scode == 200)

            if is_success:
                user_id = resp['vxUser']['id']

                self.log.debug("The initial password of user '%s' is %s" % (user_name, initial_pw))
            else:
                self.log.warning("Failed to create xuser '%s'" % user_name)
                return is_success

        else: # user already exist
            user_id = resp['vxUser']['id']

        resp, scode = self._request_ranger_rest("get", "/xusers/%s/groups" % user_id)
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

        resp, scode = self._request_ranger_rest("post", "/xusers/groupusers", groupuser_data)
        is_success  = (scode == 200)

        if not is_success:
            self.log.warning("Failed to add '%s' to nes tanant group" % user_name)
            return is_success

        return is_success

    def _create_tgtuser(self, user_name, target = 'ranger'):
        is_success = False

        if target == "ranger":
            is_success = self._create_ranger_user(user_name)
        else:
            self.log.warning("The '%s' is not supported user create target" % target)

        return is_success

    def _remove_ranger_user(self, user_name):
        is_success = False

        group_name = self.sync_tenant
        group_id   = self.ranger_group_id

        resp, scode = self._request_ranger_rest("get", "/xusers/users/userName/" + user_name)

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

        resp, scode = self._request_ranger_rest("get", "/xusers/%s/groups" % user_id)
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

        resp, scode = self._request_ranger_rest("delete", group_remove_user_path)
        is_success  = (scode == 204)

        if not is_success:
            self.log.warning("Failed to exclued user '%s' from tenant group" % user_name)
            return is_success

        if not need_remove:
            self.log.debug("The user '%s' does not need to be removed" % user_name)
            return is_success

        hard_remove = self.ranger_user_hard_remove

        remove_user_path = "/xusers/users/%s?forceDelete=%s" % (user_id, hard_remove)
        resp, scode = self._request_ranger_rest("delete", remove_user_path)
        is_success  = (scode == 204)

        if not is_success:
            self.log.warning("Failed to remove '%s' user" % user_name)
            return is_success

        return is_success

    def _remove_tgtuser(self, user_name, target = 'ranger'):
        is_success = False

        if target == "ranger":
            is_success = self._remove_ranger_user(user_name)
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

        while self.run:
            # Do some useful background work here.
            if not is_first:
                self.log.debug('Sleeping for %d seconds', self.interval)
                ret = self.event.wait(self.interval)
                self.event.clear()

            is_first = False

            objusers, get_objusers_success = self._get_objuser_list()
            if not get_objusers_success:
              self.log.warning("Failed to get object store user list")
              continue

            sync_targets = self.sync_target.split(',')

            for each_target in sync_targets:
                self.log.info("Start %s usersync" % each_target)

                if each_target == "ranger": self._fetch_ranger_group_id()

                tgtusers, get_tgtusers_success = self._get_tgtuser_list(each_target)
                if not get_tgtusers_success:
                    self.log.warning("Failed to get %s user list" % each_target)
                    continue

                for each_objuser in objusers:
                    if each_objuser in tgtusers:
                        tgtusers.remove(each_objuser)
                        continue

                    is_create_success = self._create_tgtuser(each_objuser, each_target)
                    if is_create_success:
                        user_create_msg  = "The user '%s' was created " % each_objuser
                        user_create_msg += "in %s" % each_target
                        self.log.info(user_create_msg)
                    else:
                        user_create_fail_msg  = "Faled to create user '%s' " % each_objuser
                        user_create_fail_msg += "in %s" % each_target
                        self.log.warning(user_create_fail_msg)

                if not self.allow_user_remove: continue

                for each_tgtuser in tgtusers:
                    is_remove_success = self._remove_tgtuser(each_tgtuser, each_target)
                    if is_remove_success:
                        user_remove_msg  = "The user '%s' was removed " % each_tgtuser
                        user_remove_msg += "from %s" % each_target
                        self.log.info(user_remove_msg)
                    else:
                        user_remove_fail_msg  = "Faled to remove user '%s' " % each_tgtuser
                        user_remove_fail_msg += "from %s" % each_target
                        self.log.warning(user_remove_fail_msg)


    def shutdown(self):
        """
        This method is called by the mgr when the module needs to shut
        down (i.e., when the serve() function needs to exit).
        """
        self.log.info('Stopping')
        self.run = False
        self.event.set()
