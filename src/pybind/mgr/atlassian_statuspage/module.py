
"""
A cluster health alerting module for Atlassian statuspage.
"""

from mgr_module import MgrModule, HandleCommandResult
from threading import Event
import errno
import json
import smtplib
import subprocess

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
            'name': 'component_id',
            'default': '',
            'desc': 'Component UUID of Atlassian statuspage.',
            'runtime': True,
        },
        # smtp
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

        if self.interval < 10: self.interval = 10


    def handle_command(self, inbuf, cmd):
        ret = 0
        out = ''
        err = ''

        return HandleCommandResult(
            retval=ret,   # exit code
            stdout=out,   # stdout
            stderr=err)

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

    def _send_msg_to_atlassian_statuspage(self, status, diff):
        self.log.debug('_send_msg_to_atlassian_statuspage')

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

        if 'new' in diff:
            message += ('\n--- New ---\n')
            for code, stat in diff['new'].items():
                message += self._msg_format_stat(code, stat)
        if 'updated' in diff:
            message += ('\n--- Updated ---\n')
            for code, stat in diff['updated'].items():
                message += self._msg_format_stat(code, stat)
        if 'cleared' in diff:
            message += ('\n--- Cleared ---\n')
            for code, stat in diff['cleared'].items():
                message += self._msg_format_stat(code, stat)

        message += ('\n\n=== Full health status ===\n')
        for code, stat in status['checks'].items():
            message += self._msg_format_stat(code, stat)

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
            return {
                'ATLASSIAN_STATUSPAGE_SMTP_ERROR': {
                    'severity': 'warning',
                    'summary': 'unable to send status info to statuspage component',
                    'count': 1,
                    'detail': [ str(e) ]
                }
            }
        self.log.debug('Sent email to %s' % comp_destination)
        return None

    def _send_msg(self, status, diff):
        checks = {}
        is_send_success = True
        if self.component_id:
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

        cmd = ['timeout', str(timeout_sec), 'ceph', '--name', "mgr.%s" % self.get_mgr_id(),'status']
        checker = subprocess.Popen(cmd)
        checker.communicate()

        return (checker.returncode == 0)

    def serve(self):
        """
        This method is called by the mgr when the module starts and can be
        used for any background activity.
        """
        self.log.info("Starting")
        last_status = {}
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
