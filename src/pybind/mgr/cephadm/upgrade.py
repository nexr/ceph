import json
import logging
import time
import uuid

try:
    from typing import TYPE_CHECKING, Optional, Dict, NamedTuple
except ImportError:
    pass

import orchestrator
from cephadm.utils import name_to_config_section
from orchestrator import OrchestratorError, DaemonDescription

if TYPE_CHECKING:
    from .module import CephadmOrchestrator


# ceph daemon types that use the ceph container image.
# NOTE: listed in upgrade order!
CEPH_UPGRADE_ORDER = ['mgr', 'mon', 'crash', 'osd', 'mds', 'rgw', 'rbd-mirror']

logger = logging.getLogger(__name__)


class UpgradeState:
    def __init__(self,
                 target_name,
                 progress_id,
                 target_id = None,
                 repo_digest = None,
                 target_version = None,
                 error = None,
                 paused = None,
                 ):
        # type: (str, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[bool]) -> None
        self._target_name = target_name  # Use CephadmUpgrade.target_image instead.
        self.progress_id = progress_id
        self.target_id = target_id
        self.repo_digest = repo_digest
        self.target_version = target_version
        self.error = error
        self.paused = paused or False

    def to_json(self):
        # type: () -> dict
        return {
            'target_name': self._target_name,
            'progress_id': self.progress_id,
            'target_id': self.target_id,
            'repo_digest': self.repo_digest,
            'target_version': self.target_version,
            'error': self.error,
            'paused': self.paused,
        }

    @classmethod
    def from_json(cls, data):
        # type: (dict) -> Optional['UpgradeState']
        if data:
            return cls(**data)
        else:
            return None


class CephadmUpgrade:
    UPGRADE_ERRORS = [
        'UPGRADE_NO_STANDBY_MGR',
        'UPGRADE_FAILED_PULL',
        'UPGRADE_REDEPLOY_DAEMON',
    ]

    def __init__(self, mgr):
        # type: ("CephadmOrchestrator") -> None
        self.mgr = mgr

        t = self.mgr.get_store('upgrade_state')
        if t:
            self.upgrade_state = UpgradeState.from_json(json.loads(t)) # type: Optional[UpgradeState]
        else:
            self.upgrade_state = None

    @property
    def target_image(self):
        # type: () -> str
        assert self.upgrade_state
        if not self.mgr.use_repo_digest:
            return self.upgrade_state._target_name
        if not self.upgrade_state.repo_digest:
            return self.upgrade_state._target_name

        return self.upgrade_state.repo_digest

    def upgrade_status(self):
        # type: () -> orchestrator.UpgradeStatusSpec
        r = orchestrator.UpgradeStatusSpec()
        if self.upgrade_state:
            r.target_image = self.target_image
            r.in_progress = True
            if self.upgrade_state.error:
                r.message = 'Error: ' + str(self.upgrade_state.error)
            elif self.upgrade_state.paused:
                r.message = 'Upgrade paused'
        return r

    def upgrade_start(self, image, version):
        # type: (str, str) -> str
        if self.mgr.mode != 'root':
            raise OrchestratorError('upgrade is not supported in %s mode' % (
                self.mgr.mode))
        if version:
            try:
                (major, minor, patch) = version.split('.')
                assert int(minor) >= 0
                assert int(patch) >= 0
            except:
                raise OrchestratorError('version must be in the form X.Y.Z (e.g., 15.2.3)')
            if int(major) < 15 or (int(major) == 15 and int(minor) < 2):
                raise OrchestratorError('cephadm only supports octopus (15.2.0) or later')
            target_name = self.mgr.container_image_base + ':v' + str(version)
        elif image:
            target_name = image
        else:
            raise OrchestratorError('must specify either image or version')
        if self.upgrade_state:
            if self.upgrade_state._target_name != target_name:
                raise OrchestratorError(
                    'Upgrade to %s (not %s) already in progress' %
                    (self.upgrade_state._target_name, target_name))
            if self.upgrade_state.paused:
                self.upgrade_state.paused = False
                self._save_upgrade_state()
                return 'Resumed upgrade to %s' % self.target_image
            return 'Upgrade to %s in progress' % self.target_image
        self.upgrade_state = UpgradeState(
            target_name=target_name,
            progress_id=str(uuid.uuid4())
        )
        self._update_upgrade_progress(0.0)
        self._save_upgrade_state()
        self._clear_upgrade_health_checks()
        self.mgr.event.set()
        return 'Initiating upgrade to %s' % (target_name)

    def upgrade_pause(self):
        # type: () -> str
        if not self.upgrade_state:
            raise OrchestratorError('No upgrade in progress')
        if self.upgrade_state.paused:
            return 'Upgrade to %s already paused' % self.target_image
        self.upgrade_state.paused = True
        self._save_upgrade_state()
        return 'Paused upgrade to %s' % self.target_image

    def upgrade_resume(self):
        # type: () -> str
        if not self.upgrade_state:
            raise OrchestratorError('No upgrade in progress')
        if not self.upgrade_state.paused:
            return 'Upgrade to %s not paused' % self.target_image
        self.upgrade_state.paused = False
        self._save_upgrade_state()
        self.mgr.event.set()
        return 'Resumed upgrade to %s' % self.target_image

    def upgrade_stop(self):
        # type: () -> str
        if not self.upgrade_state:
            return 'No upgrade in progress'
        if self.upgrade_state.progress_id:
            self.mgr.remote('progress', 'complete',
                            self.upgrade_state.progress_id)
        target_image = self.target_image
        self.upgrade_state = None
        self._save_upgrade_state()
        self._clear_upgrade_health_checks()
        self.mgr.event.set()
        return 'Stopped upgrade to %s' % target_image

    def continue_upgrade(self):
        # type: () -> bool
        """
        Returns false, if nothing was done.
        :return:
        """
        if self.upgrade_state and not self.upgrade_state.paused:
            self._do_upgrade()
            return True
        return False

    def _wait_for_ok_to_stop(self, s):
        # type: (DaemonDescription) -> bool
        # only wait a little bit; the service might go away for something
        tries = 4
        while tries > 0:
            if not self.upgrade_state or self.upgrade_state.paused:
                return False

            r = self.mgr.cephadm_services[s.daemon_type].ok_to_stop([s.daemon_id])

            if not r.retval:
                logger.info('Upgrade: ' + str(r.stdout))
                return True
            logger.error('Upgrade: ' + str(r.stderr))

            time.sleep(15)
            tries -= 1
        return False

    def _clear_upgrade_health_checks(self):
        # type: () -> None
        for k in self.UPGRADE_ERRORS:
            if k in self.mgr.health_checks:
                del self.mgr.health_checks[k]
        self.mgr.set_health_checks(self.mgr.health_checks)

    def _fail_upgrade(self, alert_id, alert):
        # type: (str, dict) -> None
        assert alert_id in self.UPGRADE_ERRORS
        logger.error('Upgrade: Paused due to %s: %s' % (alert_id,
                                                        alert['summary']))
        if not self.upgrade_state:
            assert False, 'No upgrade in progress'

        self.upgrade_state.error = alert_id + ': ' + str(alert['summary'])
        self.upgrade_state.paused = True
        self._save_upgrade_state()
        self.mgr.health_checks[alert_id] = alert
        self.mgr.set_health_checks(self.mgr.health_checks)

    def _update_upgrade_progress(self, progress):
        # type: (float) -> None
        if not self.upgrade_state:
            assert False, 'No upgrade in progress'

        if not self.upgrade_state.progress_id:
            self.upgrade_state.progress_id = str(uuid.uuid4())
            self._save_upgrade_state()
        self.mgr.remote('progress', 'update', self.upgrade_state.progress_id,
                        ev_msg='Upgrade to %s' % self.target_image,
                        ev_progress=progress)

    def _save_upgrade_state(self):
        # type: () -> None
        if not self.upgrade_state:
            self.mgr.set_store('upgrade_state', None)
            return
        self.mgr.set_store('upgrade_state', json.dumps(self.upgrade_state.to_json()))

    def get_distinct_container_image_settings(self):
        # type: () -> Dict[str, str]
        # get all distinct container_image settings
        image_settings = {}
        ret, out, err = self.mgr.check_mon_command({
            'prefix': 'config dump',
            'format': 'json',
        })
        config = json.loads(out)
        for opt in config:
            if opt['name'] == 'container_image':
                image_settings[opt['section']] = opt['value']
        return image_settings

    def _do_upgrade(self):
        # type: () -> None
        if not self.upgrade_state:
            logger.debug('_do_upgrade no state, exiting')
            return

        target_image = self.target_image
        target_id = self.upgrade_state.target_id
        if not target_id or (self.mgr.use_repo_digest and not self.upgrade_state.repo_digest):
            # need to learn the container hash
            logger.info('Upgrade: First pull of %s' % target_image)
            try:
                target_id, target_version, repo_digest = self.mgr._get_container_image_info(
                    target_image)
            except OrchestratorError as e:
                self._fail_upgrade('UPGRADE_FAILED_PULL', {
                    'severity': 'warning',
                    'summary': 'Upgrade: failed to pull target image',
                    'count': 1,
                    'detail': [str(e)],
                })
                return
            self.upgrade_state.target_id = target_id
            self.upgrade_state.target_version = target_version
            self.upgrade_state.repo_digest = repo_digest
            self._save_upgrade_state()
            target_image = self.target_image
        target_version = self.upgrade_state.target_version
        logger.info('Upgrade: Target is %s with id %s' % (target_image,
                                                          target_id))

        image_settings = self.get_distinct_container_image_settings()

        daemons = self.mgr.cache.get_daemons()
        done = 0
        for daemon_type in CEPH_UPGRADE_ORDER:
            logger.info('Upgrade: Checking %s daemons...' % daemon_type)
            need_upgrade_self = False
            for d in daemons:
                if d.daemon_type != daemon_type:
                    continue
                if d.container_image_id == target_id:
                    logger.debug('daemon %s.%s version correct' % (
                        daemon_type, d.daemon_id))
                    done += 1
                    continue
                logger.debug('daemon %s.%s not correct (%s, %s, %s)' % (
                    daemon_type, d.daemon_id,
                    d.container_image_name, d.container_image_id, d.version))

                if self.mgr.daemon_is_self(d.daemon_type, d.daemon_id):
                    logger.info('Upgrade: Need to upgrade myself (mgr.%s)' %
                                self.mgr.get_mgr_id())
                    need_upgrade_self = True
                    continue

                # make sure host has latest container image
                out, err, code = self.mgr._run_cephadm(
                    d.hostname, '', 'inspect-image', [],
                    image=target_image, no_fsid=True, error_ok=True)
                if code or json.loads(''.join(out)).get('image_id') != target_id:
                    logger.info('Upgrade: Pulling %s on %s' % (target_image,
                                                               d.hostname))
                    out, err, code = self.mgr._run_cephadm(
                        d.hostname, '', 'pull', [],
                        image=target_image, no_fsid=True, error_ok=True)
                    if code:
                        self._fail_upgrade('UPGRADE_FAILED_PULL', {
                            'severity': 'warning',
                            'summary': 'Upgrade: failed to pull target image',
                            'count': 1,
                            'detail': [
                                'failed to pull %s on host %s' % (target_image,
                                                                  d.hostname)],
                        })
                        return
                    r = json.loads(''.join(out))
                    if r.get('image_id') != target_id:
                        logger.info('Upgrade: image %s pull on %s got new image %s (not %s), restarting' % (
                            target_image, d.hostname, r['image_id'], target_id))
                        self.upgrade_state.target_id = r['image_id']
                        self._save_upgrade_state()
                        return

                self._update_upgrade_progress(done / len(daemons))

                if not d.container_image_id:
                    if d.container_image_name == target_image:
                        logger.debug(
                            'daemon %s has unknown container_image_id but has correct image name' % (d.name()))
                        continue
                if not self._wait_for_ok_to_stop(d):
                    return
                logger.info('Upgrade: Redeploying %s.%s' %
                            (d.daemon_type, d.daemon_id))
                try:
                    self.mgr._daemon_action(
                        d.daemon_type,
                        d.daemon_id,
                        d.hostname,
                        'redeploy',
                        image=target_image
                    )
                except Exception as e:
                    self._fail_upgrade('UPGRADE_REDEPLOY_DAEMON', {
                        'severity': 'warning',
                        'summary': 'Upgrading daemon %s on host %s failed.' % (d.name(), d.hostname),
                        'count': 1,
                        'detail': [
                            'Upgrade daemon: %s: %s' % (d.name(), e)
                        ],
                    })
                return

            if need_upgrade_self:
                try:
                    self.mgr.mgr_service.fail_over()
                except OrchestratorError as e:
                    self._fail_upgrade('UPGRADE_NO_STANDBY_MGR', {
                        'severity': 'warning',
                        'summary': 'Upgrade: ' + str(e),
                        'count': 1,
                        'detail': [
                            'The upgrade process needs to upgrade the mgr, '
                            'but it needs at least one standby to proceed.',
                        ],
                    })
                    return

                return  # unreachable code, as fail_over never returns
            elif daemon_type == 'mgr':
                if 'UPGRADE_NO_STANDBY_MGR' in self.mgr.health_checks:
                    del self.mgr.health_checks['UPGRADE_NO_STANDBY_MGR']
                    self.mgr.set_health_checks(self.mgr.health_checks)

            # make sure 'ceph versions' agrees
            ret, out_ver, err = self.mgr.check_mon_command({
                'prefix': 'versions',
            })
            j = json.loads(out_ver)
            for version, count in j.get(daemon_type, {}).items():
                if version != target_version:
                    logger.warning(
                        'Upgrade: %d %s daemon(s) are %s != target %s' %
                        (count, daemon_type, version, target_version))

            # push down configs
            if image_settings.get(daemon_type) != target_image:
                logger.info('Upgrade: Setting container_image for all %s...' %
                            daemon_type)
                self.mgr.set_container_image(name_to_config_section(daemon_type), target_image)
            to_clean = []
            for section in image_settings.keys():
                if section.startswith(name_to_config_section(daemon_type) + '.'):
                    to_clean.append(section)
            if to_clean:
                logger.debug('Upgrade: Cleaning up container_image for %s...' %
                             to_clean)
                for section in to_clean:
                    ret, image, err = self.mgr.check_mon_command({
                        'prefix': 'config rm',
                        'name': 'container_image',
                        'who': section,
                    })

            logger.info('Upgrade: All %s daemons are up to date.' %
                        daemon_type)

        # clean up
        logger.info('Upgrade: Finalizing container_image settings')
        self.mgr.set_container_image('global', target_image)

        for daemon_type in CEPH_UPGRADE_ORDER:
            ret, image, err = self.mgr.check_mon_command({
                'prefix': 'config rm',
                'name': 'container_image',
                'who': name_to_config_section(daemon_type),
            })

        logger.info('Upgrade: Complete!')
        if self.upgrade_state.progress_id:
            self.mgr.remote('progress', 'complete',
                            self.upgrade_state.progress_id)
        self.upgrade_state = None
        self._save_upgrade_state()
        return
