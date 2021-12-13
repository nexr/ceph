
"""
A cluster health alerting module for Atlassian statuspage.
"""

from mgr_module import MgrModule, HandleCommandResult
from threading import Event
import errno
import json
import smtplib
import subprocess
import requests
from datetime import datetime
import re

class AtlassianStatuspage(MgrModule):
    COMMANDS = [
    ]

    MODULE_OPTIONS = [
        {
            'name': 'interval',
            'type': 'int',
            'default': 60,
            'min': 10,
            'desc': 'How frequently to check health status (must be above 10)',
            'runtime': True,
        },
        {
            'name': 'automation_mode',
            'default': 'email',
            'desc': 'method of statuspage automation. one of email or rest',
            'enum_allowed': ['email', 'rest'],
            'runtime': True,
        },
        {
            'name': 'page_id',
            'default': '',
            'desc': 'page ID of Atlassian statuspage. (used only rest mode)',
            'runtime': True,
        },
        {
            'name': 'component_id',
            'default': '',
            'desc': 'Component ID of Atlassian statuspage.',
            'runtime': True,
        },
        # rest API server (only vaild when automation_mode is 'rest')
        {
            'name': 'rest_token',
            'default': '',
            'desc': 'auth token for target statuspage',
            'runtime': True,
        },
        {
            'name': 'rest_url',
            'default': 'https://api.statuspage.io',
            'desc': 'endpoint of target statuspage',
            'runtime': True,
        },
        # smtp (only vaild when automation_mode is 'email')
        {
            'name': 'smtp_host',
            'desc': 'SMTP server',
            'runtime': True,
        },
        {
            'name': 'smtp_port',
            'type': 'int',
            'default': 465,
            'desc': 'SMTP port',
            'runtime': True,
        },
        {
            'name': 'smtp_ssl',
            'type': 'bool',
            'default': True,
            'desc': 'Use SSL to connect to SMTP server',
            'runtime': True,
        },
        {
            'name': 'smtp_user',
            'default': '',
            'desc': 'User to authenticate as',
            'runtime': True,
        },
        {
            'name': 'smtp_password',
            'default': '',
            'desc': 'Password to authenticate with',
            'runtime': True,
        },
        {
            'name': 'smtp_sender',
            'default': '',
            'desc': 'SMTP envelope sender',
            'runtime': True,
        },
        {
            'name': 'smtp_from_name',
            'default': 'Ceph',
            'desc': 'Email From: name',
            'runtime': True,
        },
    ]

    # These are "native" Ceph options that this module cares about.
    NATIVE_OPTIONS = [
    ]


    def __init__(self, *args, **kwargs):
        super(AtlassianStatuspage, self).__init__(*args, **kwargs)

        # set up some members to enable the serve() method and shutdown()
        self.run = True
        self.event = Event()

        self.mgr_keyring = self.get_ceph_option('mgr_data') + "/keyring"

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

        comp_name = self.component_id
        if self.automation_mode == 'rest':
            response = requests.get(
                self.rest_url + "/v1/pages/%s/components/%s" % (self.page_id, self.component_id),
                headers= { 'Authorization':"'OAuth %s" % self.rest_token }
            )
            if response.status_code == 200:
                try: response_json = json.loads(response.text.encode('utf8'))
                except Exception as e: response_json = {}

                if 'name' in response_json: comp_name = response_json['name']

        self.incident_name = '[mgr integration] status report(%s)' % comp_name

        if self.interval < 10: self.interval = 10


    def handle_command(self, inbuf, cmd):
        ret = 0
        out = ''
        err = ''

        return HandleCommandResult(
            retval=ret,   # exit code
            stdout=out,   # stdout
            stderr=err)

    def _health_check_msg(self, code, summary, detail='', severity='warning'):
        hc_code = code.upper()
        if hc_code == "": hc_code = "UNKNOWN"
        if not hc_code.startswith("ATLASSIAN_STATUSPAGE"): hc_code = "ATLASSIAN_STATUSPAGE_" + hc_code

        hc_summary = summary
        if hc_summary == "": hc_summary = "empty_summary"

        hc_detail = detail
        if hc_detail == "": hc_detail = hc_summary

        return {
            hc_code: {
                'severity': severity,
                'summary' : "[Module 'atlassian_statuspage'] " + summary,
                'detail'  : [ hc_detail ],
                'count'   : 1,
            }
        }

    def _diff(self, last, new):
        d = {}
        for code, alert in new.get('checks', {}).items():
            self.log.debug('new code %s alert %s' % (code, alert))
            if code not in last.get('checks', {}):
                if 'new' not in d:
                    d['new'] = {}
                d['new'][code] = alert
            elif alert['summary']['message'] != last['checks'][code]['summary']['message']:
                if 'updated' not in d:
                    d['updated'] = {}
                d['updated'][code] = alert
        for code, alert in last.get('checks', {}).items():
            self.log.debug('old code %s alert %s' % (code, alert))
            if code not in new.get('checks', {}):
                if 'cleared' not in d:
                    d['cleared'] = {}
                d['cleared'][code] = alert
        return d

    def _msg_format_stat(self, code, stat):
        msg = '[{sev}] {code}: {summary}\n'.format(
            code=code,
            sev=stat['severity'].split('_')[1],
            summary=stat['summary']['message'])
        for detail in stat['detail']:
            msg += '        {}\n'.format(detail['message'])
        return msg

    def _msg_format_contents(self, status, diff):
        msg = ""

        if 'new' in diff:
            msg += ('\n--- New ---\n')
            for code, stat in diff['new'].items():
                msg += self._msg_format_stat(code, stat)
        if 'updated' in diff:
            msg += ('\n--- Updated ---\n')
            for code, stat in diff['updated'].items():
                msg += self._msg_format_stat(code, stat)
        if 'cleared' in diff:
            msg += ('\n--- Cleared ---\n')
            for code, stat in diff['cleared'].items():
                msg += self._msg_format_stat(code, stat)

        msg += ('\n\n=== Full health status ===\n')
        for code, stat in status['checks'].items():
            msg += self._msg_format_stat(code, stat)

        return msg

    def _send_msg_to_atlassian_statuspage_through_rest(self, status, diff):
        self.log.debug('_send_msg_to_atlassian_statuspage_through_rest')

        if not re.match("^\w{12}$", self.component_id):
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'component_id' have invalid value.",
                "The 'component_id' config is invaild: %s. It must be '^\w{12}$' form" % self.component_id)

        if self.rest_url == '':
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'rest_url' have invalid value.",
                "The 'rest_url' config is empty")

        if self.rest_token == "":
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'rest_token' have invalid value.",
                "The 'rest_token' config is empty")

        headers = {'Authorization':"'OAuth %s" % self.rest_token}

        search_response = requests.get(
            self.rest_url + "/v1/pages/%s/incidents/unresolved" % (self.page_id),
            headers = headers,
        )
        search_response_text = search_response.text.encode('utf8')
        if 400 <= search_response.status_code < 600:
            return self._health_check_msg(
                'REST_ERROR',
                'unable to get unresolved component incidents from the statuspage',
                "%s (status code %d)" % (search_response_text, search_response.status_code))

        try:
            search_response_json = json.loads(search_response_text)
        except Exception as e:
            return self._health_check_msg(
                'DISORDER',
                "The json loading failure occur!",
                "The json loading failure occur when parsing search response")

        incident_id = ''
        for each_incident in search_response_json:
            if self.incident_name not in each_incident['name']: continue

            incident_id = each_incident['id']
            self.log.debug("The existing incident found: (%s) -> %s" % (incident_id, json.dumps(each_incident)))
            break


        cluster_status = status['status']
        comp_status = "UNKNOWN"
        if   cluster_status == "HEALTH_OK"   : comp_status = "operational"
        elif cluster_status == "HEALTH_WARN" : comp_status = "degraded_performance"
        elif cluster_status == "HEALTH_ERR"  : comp_status = "partial_outage"
        elif cluster_status == "HEALTH_DOWN" : comp_status = "major_outage"

        if comp_status == "UNKNOWN":
            return self._health_check_msg(
                'DISORDER',
                "The status is unknown!",
                "The status is unknown (ceph_status: %s, comp_status: %s)" % (cluster_status, comp_status))

        incident_status = "investigating"
        if comp_status == "operational" : incident_status = "resolved"

        data = {
            'incident': {
                'components': { self.component_id: comp_status },
                'component_ids': [ self.component_id ],
                'status': incident_status,
                'body': self._msg_format_contents(status, diff),
            }
        }

        if incident_id == '':
            request_url = self.rest_url + "/v1/pages/%s/incidents" % (self.page_id)
            data['incident']['name'] = self.incident_name + " " + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            response = requests.post(request_url, headers=headers, json=data)
        else:
            request_url = self.rest_url + "/v1/pages/%s/incidents/%s" % (self.page_id, incident_id)
            response = requests.put(request_url, headers=headers, json=data)

        self.log.debug("request url is '%s'" % request_url)
        self.log.debug("response of rest: [%d] %s" % (response.status_code, response.text.encode('utf8')))

        if incident_id != '' and response.status_code == 422: # Too many incident updates
            data['incident']['status'] = "resolved"
            data['incident'][ 'body' ] = "Too many updates in incident. Relsolve this incident and continue in new incident."
            response = requests.put(request_url, headers=headers, json=data)
            if 400 <= response.status_code < 600:
                return self._health_check_msg(
                    'REST_ERROR',
                    'unable to resolve incident',
                    "%s (status code %d)" % (response.text.encode('utf8'), response.status_code))
            else:
                return self._health_check_msg(
                    'REST_WARN',
                    "too many updates in incident. resolve incident %s and continue in new incident." % incident_id,
                    "%s (status code %d)" % (response.text.encode('utf8'), response.status_code))
        elif 400 <= response.status_code < 600:
            return self._health_check_msg(
                'REST_ERROR',
                'unable to send status info to statuspage component',
                "%s (status code %d)" % (response.text.encode('utf8'), response.status_code))

        return None

    def _send_msg_to_atlassian_statuspage_through_email(self, status, diff):
        self.log.debug('_send_msg_to_atlassian_statuspage_through_email')

        if not re.match("^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$", self.component_id):
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'component_id' have invalid value.",
                "The 'component_id' config is invaild: %s. It must be '^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$' form" % self.component_id)

        cluster_status = status['status']
        subject = cluster_status

        if cluster_status == "HEALTH_OK":
            comp_destination = 'component+{}@notifications.statuspage.io'.format(self.component_id)
            subject = subject + '(UP)'
        elif cluster_status == "HEALTH_WARN":
            comp_destination = 'component+{}+degraded_performance@notifications.statuspage.io'.format(self.component_id)
            subject = subject + '(DOWN)'
        elif cluster_status == "HEALTH_ERR":
            comp_destination = 'component+{}+partial_outage@notifications.statuspage.io'.format(self.component_id)
            subject = subject + '(DOWN)'
        elif cluster_status == "HEALTH_DOWN":
            comp_destination = 'component+{}@notifications.statuspage.io'.format(self.component_id)
            subject = subject + '(DOWN)'
        else:
            self.log.warning("Unexpected cluster status: "+comp_destination)
            return None

        message = ('From: {from_name} <{sender}>\n'
                   'Subject: {subject}\n'
                   'To: {target}\n'
                   '\n'
                   '{status}\n'.format(
                       sender=self.smtp_sender,
                       from_name=self.smtp_from_name,
                       subject=subject,
                       status=cluster_status,
                       target=comp_destination))

        message += self._msg_format_contents(status, diff)

        self.log.debug('message: %s' % message)

        # send
        try:
            if self.smtp_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            if self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.smtp_sender, comp_destination, message)
        except Exception as e:
            return self._health_check_msg('SMTP_ERROR', 'unable to send status info to statuspage component', str(e))

        self.log.debug('Sent email to %s' % comp_destination)

        return None

    def _send_msg_to_atlassian_statuspage(self, status, diff):
        if self.component_id == '':
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'component_id' have invalid value.",
                "The 'component_id' config is empty")

        if self.automation_mode == 'email':
            return self._send_msg_to_atlassian_statuspage_through_email(status, diff)
        elif self.automation_mode == 'rest':
            return self._send_msg_to_atlassian_statuspage_through_rest(status, diff)
        else:
            return self._health_check_msg(
                'CONFIG_INVALID',
                "The 'automation_mode' have invalid value.",
                "The 'automation_mode' config is invaild: %s" % self.automation_mode)

    def _send_msg(self, status, diff):
        checks = {}
        is_send_success = True
        r = self._send_msg_to_atlassian_statuspage(status, diff)
        if r:
            is_send_success = False
            for code, alert in r.items():
                checks[code] = alert
        self.set_health_checks(checks)
        return is_send_success

    def _is_ceph_conn_live(self):
        timeout_sec = int(self.interval / 2)
        if timeout_sec < 5: timeout_sec = 5
        elif timeout_sec > 15: timeout_sec = 15

        cmd = ['timeout', str(timeout_sec), 'ceph', '--name', "mgr.%s" % self.get_mgr_id(), '--keyring', self.mgr_keyring, 'status']
        checker = subprocess.Popen(cmd)
        checker.communicate()

        return (checker.returncode == 0)

    def serve(self):
        """
        This method is called by the mgr when the module starts and can be
        used for any background activity.
        """
        self.log.info("Starting")
        last_status = {
            'status': 'HEALTH_UKNOWN',
            'checks': {
                'MANAGER_NEWLY_ACTIVATE': {
                    'detail': [ { 'message': 'New mgr(%s) have been activated!' % self.get_mgr_id() } ],
                    'severity': 'HEALTH_UNKNOWN',
                    'summary': { 'message': 'New mgr have been activated!' }
                }
            }
        }

        while self.run:
            # Do some useful background work here.
            if self._is_ceph_conn_live():
                new_status = json.loads(self.get('health')['json'])
            else:
                new_status = {
                    'status': 'HEALTH_DOWN',
                    'checks': {
                        'CLUSTER_DOWN': {
                            'detail': [ { 'message': 'cluster down!' } ],
                            'severity': 'HEALTH_DOWN',
                            'summary': { 'message': 'cluster down!' }
                        }
                    }
                }

            self.log.debug('last_status %s' % last_status)
            self.log.debug('new_status %s' % new_status)
            diff = self._diff(last_status, new_status)
            self.log.debug('diff %s' % diff)

            if diff:
                mail_sent = self._send_msg(new_status, diff)
                if mail_sent: last_status = new_status
            else:
                last_status = new_status

            self.log.debug('Sleeping for %d seconds', self.interval)
            ret = self.event.wait(self.interval)
            self.event.clear()

    def shutdown(self):
        """
        This method is called by the mgr when the module needs to shut
        down (i.e., when the serve() function needs to exit).
        """
        self.log.info('Stopping')
        self.run = False
        self.event.set()
