import json
import logging
from threading import Lock

try:
    from typing import List, Dict, Any, Set, Union, Tuple, cast, Optional, TYPE_CHECKING
except ImportError:
    pass

from ceph.deployment import translate
from ceph.deployment.drive_group import DriveGroupSpec
from ceph.deployment.drive_selection import DriveSelection
from ceph.deployment.inventory import Device
from ceph.utils import datetime_to_str, str_to_datetime

from datetime import datetime
import orchestrator
from cephadm.utils import forall_hosts
from orchestrator import OrchestratorError
from mgr_module import MonCommandFailed

from cephadm.services.cephadmservice import CephadmDaemonSpec, CephService

if TYPE_CHECKING:
    from cephadm.module import CephadmOrchestrator

logger = logging.getLogger(__name__)


class OSDService(CephService):
    TYPE = 'osd'

    def create_from_spec(self, drive_group):
        # type: (DriveGroupSpec) -> str
        logger.debug("Processing DriveGroup " + str(drive_group))
        osd_id_claims = self.find_destroyed_osds()
        if osd_id_claims:
            logger.info(
                "Found osd claims for drivegroup %s -> %s" % (drive_group.service_id, osd_id_claims))

        @forall_hosts
        def create_from_spec_one(host, drive_selection):
            # type: (str, DriveSelection) -> Optional[str]
            cmd = self.driveselection_to_ceph_volume(drive_selection,
                                                     osd_id_claims.get(host, []))
            if not cmd:
                logger.debug("No data_devices, skipping DriveGroup: {}".format(
                    drive_group.service_id))
                return None
            logger.info('Applying drive group %s on host %s...' % (drive_group.service_id, host))
            env_vars = ["CEPH_VOLUME_OSDSPEC_AFFINITY=" + str(drive_group.service_id)] # type: List[str]
            ret_msg = self.create_single_host(
                host, cmd, replace_osd_ids=osd_id_claims.get(host, []), env_vars=env_vars
            )
            return ret_msg

        ret = create_from_spec_one(self.prepare_drivegroup(drive_group))
        return ", ".join(filter(None, ret))

    def create_single_host(self, host, cmd, replace_osd_ids, env_vars = None):
        # type: (str, str, List[str], Optional[List[str]]) -> str
        out, err, code = self._run_ceph_volume_command(host, cmd, env_vars=env_vars)

        if code == 1 and ', it is already prepared' in '\n'.join(err):
            # HACK: when we create against an existing LV, ceph-volume
            # returns an error and the above message.  To make this
            # command idempotent, tolerate this "error" and continue.
            logger.debug('the device was already prepared; continuing')
            code = 0
        if code:
            raise RuntimeError(
                'cephadm exited with an error code: %d, stderr:%s' % (
                    code, '\n'.join(err)))

        # check result
        out, err, code = self.mgr._run_cephadm(
            host, 'osd', 'ceph-volume',
            [
                '--',
                'lvm', 'list',
                '--format', 'json',
            ])
        before_osd_uuid_map = self.mgr.get_osd_uuid_map(only_up=True)
        try:
            osds_elems = json.loads('\n'.join(out))
        except ValueError:
            logger.exception('Cannot decode JSON: \'%s\'' % '\n'.join(out))
            osds_elems = {}
        fsid = self.mgr._cluster_fsid
        osd_uuid_map = self.mgr.get_osd_uuid_map()
        created = []
        for osd_id, osds in osds_elems.items():
            for osd in osds:
                if osd['tags']['ceph.cluster_fsid'] != fsid:
                    logger.debug('mismatched fsid, skipping %s' % osd)
                    continue
                if osd_id in before_osd_uuid_map and osd_id not in replace_osd_ids:
                    # if it exists but is part of the replacement operation, don't skip
                    continue
                if osd_id not in osd_uuid_map:
                    logger.debug('osd id {} does not exist in cluster'.format(osd_id))
                    continue
                if osd_uuid_map.get(osd_id) != osd['tags']['ceph.osd_fsid']:
                    logger.debug('mismatched osd uuid (cluster has %s, osd '
                                 'has %s)' % (
                                     osd_uuid_map.get(osd_id),
                                     osd['tags']['ceph.osd_fsid']))
                    continue

                created.append(osd_id)
                daemon_spec = CephadmDaemonSpec(
                    daemon_id=osd_id,
                    host=host,
                    daemon_type='osd',
                )
                self.mgr._create_daemon(
                    daemon_spec,
                    osd_uuid_map=osd_uuid_map)

        if created:
            self.mgr.cache.invalidate_host_devices(host)
            return "Created osd(s) %s on host '%s'" % (','.join(created), host)
        else:
            return "Created no osd(s) on host %s; already created?" % host

    def prepare_drivegroup(self, drive_group):
        # type: (DriveGroupSpec) -> List[Tuple[str, DriveSelection]]
        # 1) use fn_filter to determine matching_hosts
        matching_hosts = drive_group.placement.filter_matching_hostspecs(
            self.mgr.inventory.all_specs())
        # 2) Map the inventory to the InventoryHost object
        host_ds_map = []

        # set osd_id_claims

        def _find_inv_for_host(hostname, inventory_dict):
            # type: (str, dict) -> List[Device]
            # This is stupid and needs to be loaded with the host
            for _host, _inventory in inventory_dict.items():
                if _host == hostname:
                    return _inventory
            raise OrchestratorError("No inventory found for host: {}".format(hostname))

        # 3) iterate over matching_host and call DriveSelection
        logger.debug("Checking matching hosts -> " +str(matching_hosts))
        for host in matching_hosts:
            inventory_for_host = _find_inv_for_host(host, self.mgr.cache.devices)
            logger.debug("Found inventory for host " + str(inventory_for_host))

            # List of Daemons on that host
            dd_for_spec = self.mgr.cache.get_daemons_by_service(drive_group.service_name())
            dd_for_spec_and_host = [dd for dd in dd_for_spec if dd.hostname == host]

            drive_selection = DriveSelection(drive_group, inventory_for_host,
                                             existing_daemons=len(dd_for_spec_and_host))
            logger.debug("Found drive selection " + str(drive_selection))
            host_ds_map.append((host, drive_selection))
        return host_ds_map

    @staticmethod
    def driveselection_to_ceph_volume(drive_selection, osd_id_claims = None, preview = False):
        # type: (DriveSelection, Optional[List[str]], bool) -> Optional[str]
        logger.debug("Translating DriveGroup <%s> to ceph-volume command" % drive_selection.spec)
        cmd = translate.to_ceph_volume(drive_selection,
                                       osd_id_claims, preview=preview).run() # type: Optional[str]
        logger.debug("Resulting ceph-volume cmd: "+ str(cmd))
        return cmd

    def get_previews(self, host):
        # type: (str) -> List[Dict[str, Any]]
        # Find OSDSpecs that match host.
        osdspecs = self.resolve_osdspecs_for_host(host)
        return self.generate_previews(osdspecs, host)

    def generate_previews(self, osdspecs, for_host):
        # type: (List[DriveGroupSpec], str) -> List[Dict[str, Any]]
        """

        The return should look like this:

        [
          {'data': {<metadata>},
           'osdspec': <name of osdspec>,
           'host': <name of host>
           },

           {'data': ...,
            'osdspec': ..,
            'host': ..
           }
        ]

        Note: One host can have multiple previews based on its assigned OSDSpecs.
        """
        self.mgr.log.debug("Generating OSDSpec previews for " + str(osdspecs))
        ret_all = [] # type: List[Dict[str, Any]]
        if not osdspecs:
            return ret_all
        for osdspec in osdspecs:

            # populate osd_id_claims
            osd_id_claims = self.find_destroyed_osds()

            # prepare driveselection
            for host, ds in self.prepare_drivegroup(osdspec):
                if host != for_host:
                    continue

                # driveselection for host
                cmd = self.driveselection_to_ceph_volume(ds,
                                                         osd_id_claims.get(host, []),
                                                         preview=True)
                if not cmd:
                    logger.debug("No data_devices, skipping DriveGroup: {}".format(
                        osdspec.service_name()))
                    continue

                # get preview data from ceph-volume
                out, err, code = self._run_ceph_volume_command(host, cmd)
                if out:
                    try:
                        concat_out = json.loads(' '.join(out)) # type: Dict[str, Any]
                    except ValueError:
                        logger.exception('Cannot decode JSON: \'%s\'' % ' '.join(out))
                        concat_out = {}

                    ret_all.append({'data': concat_out,
                                    'osdspec': osdspec.service_id,
                                    'host': host})
        return ret_all

    def resolve_hosts_for_osdspecs(self, specs = None):
        # type: (Optional[List[DriveGroupSpec]]) -> List[str]
        osdspecs = []
        if specs:
            osdspecs = [cast(DriveGroupSpec, spec) for spec in specs]
        if not osdspecs:
            self.mgr.log.debug("No OSDSpecs found")
            return []
        return sum([spec.placement.filter_matching_hostspecs(self.mgr.inventory.all_specs()) for spec in osdspecs], [])

    def resolve_osdspecs_for_host(self, host, specs = None):
        # type: (str, Optional[List[DriveGroupSpec]]) -> List[DriveGroupSpec]
        matching_specs = []
        self.mgr.log.debug("Finding OSDSpecs for host: <%s>" % host)
        if not specs:
            specs = [cast(DriveGroupSpec, spec) for (sn, spec) in self.mgr.spec_store.spec_preview.items()
                     if spec.service_type == 'osd']
        for spec in specs:
            if host in spec.placement.filter_matching_hostspecs(self.mgr.inventory.all_specs()):
                self.mgr.log.debug("Found OSDSpecs for host: <%s> -> <%s>" % (host, spec))
                matching_specs.append(spec)
        return matching_specs

    def _run_ceph_volume_command(self, host, cmd, env_vars = None):
        # type: (str, str, Optional[List[str]]) -> Tuple[List[str], List[str], int]
        self.mgr.inventory.assert_host(host)

        # get bootstrap key
        ret, keyring, err = self.mgr.check_mon_command({
            'prefix': 'auth get',
            'entity': 'client.bootstrap-osd',
        })

        j = json.dumps({
            'config': self.mgr.get_minimal_ceph_conf(),
            'keyring': keyring,
        })

        split_cmd = cmd.split(' ')
        _cmd = ['--config-json', '-', '--']
        _cmd.extend(split_cmd)
        out, err, code = self.mgr._run_cephadm(
            host, 'osd', 'ceph-volume',
            _cmd,
            env_vars=env_vars,
            stdin=j,
            error_ok=True)
        return out, err, code

    def get_osdspec_affinity(self, osd_id):
        # type: (str) -> str
        return self.mgr.get('osd_metadata').get(osd_id, {}).get('osdspec_affinity', '')

    def find_destroyed_osds(self):
        # type: () -> Dict[str, List[str]]
        osd_host_map = dict() # type: Dict[str, List[str]]
        try:
            ret, out, err = self.mgr.check_mon_command({
                'prefix': 'osd tree',
                'states': ['destroyed'],
                'format': 'json'
            })
        except MonCommandFailed as e:
            logger.exception('osd tree failed')
            raise OrchestratorError(str(e))
        try:
            tree = json.loads(out)
        except ValueError:
            logger.exception('Cannot decode JSON: \'%s\'' % out)
            return osd_host_map

        nodes = tree.get('nodes', {})
        for node in nodes:
            if node.get('type') == 'host':
                osd_host_map.update(
                    {node.get('name'): [str(_id) for _id in node.get('children', list())]}
                )
        if osd_host_map:
            self.mgr.log.info("Found osd claims -> " + str(osd_host_map))
        return osd_host_map


class RemoveUtil(object):
    def __init__(self, mgr):
        # type: ("CephadmOrchestrator") -> None
        self.mgr = mgr # type: "CephadmOrchestrator"

    def get_osds_in_cluster(self):
        # type: () -> List[str]
        osd_map = self.mgr.get_osdmap()
        return [str(x.get('osd')) for x in osd_map.dump().get('osds', [])]

    def osd_df(self):
        # type: () -> dict
        base_cmd = 'osd df'
        ret, out, err = self.mgr.mon_command({
            'prefix': base_cmd,
            'format': 'json'
        })
        try:
            ret = json.loads(out)
        except ValueError:
            logger.exception('Cannot decode JSON: \'%s\'' % out)
            return {}
        return ret

    def get_pg_count(self, osd_id, osd_df = None):
        # type: (int, Optional[dict]) -> int
        if not osd_df:
            osd_df = self.osd_df()
        osd_nodes = osd_df.get('nodes', [])
        for osd_node in osd_nodes:
            if osd_node.get('id') == int(osd_id):
                return osd_node.get('pgs', -1)
        return -1

    def find_osd_stop_threshold(self, osds):
        # type: (List["OSD"]) -> Optional[List["OSD"]]
        """
        Cut osd_id list in half until it's ok-to-stop

        :param osds: list of osd_ids
        :return: list of ods_ids that can be stopped at once
        """
        if not osds:
            return []
        while not self.ok_to_stop(osds):
            if len(osds) <= 1:
                # can't even stop one OSD, aborting
                self.mgr.log.info(
                    "Can't even stop one OSD. Cluster is probably busy. Retrying later..")
                return []

            # This potentially prolongs the global wait time.
            self.mgr.event.wait(1)
            # splitting osd_ids in half until ok_to_stop yields success
            # maybe popping ids off one by one is better here..depends on the cluster size I guess..
            # There's a lot of room for micro adjustments here
            osds = osds[len(osds) // 2:]
        return osds

       # todo start draining
       #  return all([osd.start_draining() for osd in osds])

    def ok_to_stop(self, osds):
        # type: (List["OSD"]) -> bool
        cmd_args = {
            'prefix': "osd ok-to-stop",
            'ids': [str(osd.osd_id) for osd in osds]
        }
        return self._run_mon_cmd(cmd_args)

    def set_osd_flag(self, osds, flag):
        # type: (List["OSD"], str) -> bool
        base_cmd = "osd "+ str(flag)
        self.mgr.log.debug("running cmd: %s on ids %s" % (base_cmd, osds))
        ret, out, err = self.mgr.mon_command({
            'prefix': base_cmd,
            'ids': [str(osd.osd_id) for osd in osds]
        })
        if ret != 0:
            self.mgr.log.error("Could not set <%s> flag for osds: %s. <%s>" % (flag, osds, err))
            return False
        self.mgr.log.info("OSDs <%s> are now <%s>" % (osds, flag))
        return True

    def safe_to_destroy(self, osd_ids):
        # type: (List[int]) -> bool
        """ Queries the safe-to-destroy flag for OSDs """
        cmd_args = {'prefix': 'osd safe-to-destroy',
                    'ids': [str(x) for x in osd_ids]}
        return self._run_mon_cmd(cmd_args)

    def destroy_osd(self, osd_id):
        # type: (int) -> bool
        """ Destroys an OSD (forcefully) """
        cmd_args = {'prefix': 'osd destroy-actual',
                    'id': int(osd_id),
                    'yes_i_really_mean_it': True}
        return self._run_mon_cmd(cmd_args)

    def purge_osd(self, osd_id):
        # type: (int) -> bool
        """ Purges an OSD from the cluster (forcefully) """
        cmd_args = {
            'prefix': 'osd purge-actual',
            'id': int(osd_id),
            'yes_i_really_mean_it': True
        }
        return self._run_mon_cmd(cmd_args)

    def _run_mon_cmd(self, cmd_args):
        # type: (dict) -> bool
        """
        Generic command to run mon_command and evaluate/log the results
        """
        ret, out, err = self.mgr.mon_command(cmd_args)
        if ret != 0:
            self.mgr.log.debug("ran %s with mon_command" % cmd_args)
            self.mgr.log.error("cmd: %s failed with: %s. (errno:%d)" % (cmd_args.get('prefix'), err, ret))
            return False
        self.mgr.log.debug("cmd: %s returns: %s" % (cmd_args.get('prefix'), out))
        return True


class NotFoundError(Exception):
    pass


class OSD:

    def __init__(self,
                 osd_id,
                 remove_util,
                 drain_started_at = None,
                 process_started_at = None,
                 drain_stopped_at = None,
                 drain_done_at = None,
                 draining = False,
                 started = False,
                 stopped = False,
                 replace = False,
                 force = False,
                 hostname = None,
                 fullname = None,
                 ):
        # type: (int, RemoveUtil,
        #        Optional[datetime], Optional[datetime], Optional[datetime], Optional[datetime],
        #        bool, bool, bool, bool, bool, Optional[str], Optional[str]) -> None

        # the ID of the OSD
        self.osd_id = osd_id

        # when did process (not the actual draining) start
        self.process_started_at = process_started_at

        # when did the drain start
        self.drain_started_at = drain_started_at

        # when did the drain stop
        self.drain_stopped_at = drain_stopped_at

        # when did the drain finish
        self.drain_done_at = drain_done_at

        # did the draining start
        self.draining = draining

        # was the operation started
        self.started = started

        # was the operation stopped
        self.stopped = stopped

        # If this is a replace or remove operation
        self.replace = replace
        # If we wait for the osd to be drained
        self.force = force
        # The name of the node
        self.hostname = hostname
        # The full name of the osd
        self.fullname = fullname

        # mgr obj to make mgr/mon calls
        self.rm_util = remove_util # type: RemoveUtil

    def start(self):
        # type: () -> None
        if self.started:
            logger.debug("Already started draining " + str(self))
            return None
        self.started = True
        self.stopped = False

    def start_draining(self):
        # type: () -> bool
        if self.stopped:
            logger.debug("Won't start draining %s. OSD draining is stopped." % self)
            return False
        self.rm_util.set_osd_flag([self], 'out')
        self.drain_started_at = datetime.utcnow()
        self.draining = True
        logger.debug("Started draining %s." % self)
        return True

    def stop_draining(self):
        # type: () -> bool
        self.rm_util.set_osd_flag([self], 'in')
        self.drain_stopped_at = datetime.utcnow()
        self.draining = False
        logger.debug("Stopped draining %s." % self)
        return True

    def stop(self):
        # type: () -> None
        if self.stopped:
            logger.debug("Already stopped draining " + str(self))
            return None
        self.started = False
        self.stopped = True
        self.stop_draining()

    @property
    def is_draining(self):
        # type: () -> bool
        """
        Consider an OSD draining when it is
        actively draining but not yet empty
        """
        return self.draining and not self.is_empty

    @property
    def is_ok_to_stop(self):
        # type: () -> bool
        return self.rm_util.ok_to_stop([self])

    @property
    def is_empty(self):
        # type: () -> bool
        if self.get_pg_count() == 0:
            if not self.drain_done_at:
                self.drain_done_at = datetime.utcnow()
                self.draining = False
            return True
        return False

    def safe_to_destroy(self):
        # type: () -> bool
        return self.rm_util.safe_to_destroy([self.osd_id])

    def down(self):
        # type: () -> bool
        return self.rm_util.set_osd_flag([self], 'down')

    def destroy(self):
        # type: () -> bool
        return self.rm_util.destroy_osd(self.osd_id)

    def purge(self):
        # type: () -> bool
        return self.rm_util.purge_osd(self.osd_id)

    def get_pg_count(self):
        # type: () -> int
        return self.rm_util.get_pg_count(self.osd_id)

    @property
    def exists(self):
        # type: () -> bool
        return str(self.osd_id) in self.rm_util.get_osds_in_cluster()

    def drain_status_human(self):
        # type: () -> str
        default_status = 'not started'
        status = 'started' if self.started and not self.draining else default_status
        status = 'draining' if self.draining else status
        status = 'done, waiting for purge' if self.drain_done_at and not self.draining else status
        return status

    def pg_count_str(self):
        # type: () -> str
        return 'n/a' if self.get_pg_count() < 0 else str(self.get_pg_count())

    def to_json(self):
        # type: () -> dict
        out = dict() # type: Dict[str, Any]
        out['osd_id'] = self.osd_id
        out['started'] = self.started
        out['draining'] = self.draining
        out['stopped'] = self.stopped
        out['replace'] = self.replace
        out['force'] = self.force
        out['hostname'] = self.hostname  # type: ignore

        for k in ['drain_started_at', 'drain_stopped_at', 'drain_done_at', 'process_started_at']:
            if getattr(self, k):
                out[k] = datetime_to_str(getattr(self, k))
            else:
                out[k] = getattr(self, k)
        return out

    @classmethod
    def from_json(cls, inp, rm_util):
        # type: (Optional[Dict[str, Any]], RemoveUtil) -> Optional["OSD"]
        if not inp:
            return None
        for date_field in ['drain_started_at', 'drain_stopped_at', 'drain_done_at', 'process_started_at']:
            if inp.get(date_field):
                inp.update({date_field: str_to_datetime(inp.get(date_field, ''))})
        inp.update({'remove_util': rm_util})
        if 'nodename' in inp:
            hostname = inp.pop('nodename')
            inp['hostname'] = hostname
        return cls(**inp)

    def __hash__(self):
        # type: () -> int
        return hash(self.osd_id)

    def __eq__(self, other):
        # type: (object) -> bool
        if not isinstance(other, OSD):
            return NotImplemented
        return self.osd_id == other.osd_id

    def __repr__(self):
        # type: () -> str
        return "<OSD>(osd_id={}, draining={})".format(self.osd_id, self.draining)


class OSDRemovalQueue(object):

    def __init__(self, mgr):
        # type: ("CephadmOrchestrator") -> None
        self.mgr = mgr # type: "CephadmOrchestrator"
        self.osds = set() # type: Set[OSD]
        self.rm_util = RemoveUtil(mgr)

        # locks multithreaded access to self.osds. Please avoid locking
        # network calls, like mon commands.
        self.lock = Lock()

    def process_removal_queue(self):
        # type: () -> None
        """
        Performs actions in the _serve() loop to remove an OSD
        when criteria is met.

        we can't hold self.lock, as we're calling _remove_daemon in the loop
        """

        # make sure that we don't run on OSDs that are not in the cluster anymore.
        self.cleanup()

        # find osds that are ok-to-stop and not yet draining
        ok_to_stop_osds = self.rm_util.find_osd_stop_threshold(self.idling_osds())
        if ok_to_stop_osds:
            # start draining those
            _ = [osd.start_draining() for osd in ok_to_stop_osds]

        all_osds = self.all_osds()

        logger.debug(
            "{} OSDs are scheduled ".format(self.queue_size())
          + "for removal: " + str(all_osds))

        # Check all osds for their state and take action (remove, purge etc)
        new_queue = set() # type: Set[OSD]
        for osd in all_osds:  # type: OSD
            if not osd.force:
                # skip criteria
                if not osd.is_empty:
                    logger.info("OSD <%s> is not empty yet. Waiting a bit more" % osd.osd_id)
                    new_queue.add(osd)
                    continue

            if not osd.safe_to_destroy():
                logger.info(
                    "OSD <%s> is not safe-to-destroy yet. Waiting a bit more" % osd.osd_id)
                new_queue.add(osd)
                continue

            # abort criteria
            if not osd.down():
                # also remove it from the remove_osd list and set a health_check warning?
                raise orchestrator.OrchestratorError(
                    "Could not set OSD <%s> to 'down'" % osd.osd_id)

            if osd.replace:
                if not osd.destroy():
                    raise orchestrator.OrchestratorError(
                        "Could not destroy OSD <%s>" % osd.osd_id)
            else:
                if not osd.purge():
                    raise orchestrator.OrchestratorError("Could not purge OSD <%s>" % osd.osd_id)

            if not osd.exists:
                continue
            assert osd.fullname is not None
            assert osd.hostname is not None
            self.mgr._remove_daemon(osd.fullname, osd.hostname)
            logger.info("Successfully removed OSD <%s> on %s" % (osd.osd_id, osd.hostname))
            logger.debug("Removing %s from the queue." % osd.osd_id)

        # self could change while this is processing (osds get added from the CLI)
        # The new set is: 'an intersection of all osds that are still not empty/removed (new_queue) and
        # osds that were added while this method was executed'
        with self.lock:
            self.osds.intersection_update(new_queue)
            self._save_to_store()

    def cleanup(self):
        # type: () -> None
        # OSDs can always be cleaned up manually. This ensures that we run on existing OSDs
        with self.lock:
            for osd in self._not_in_cluster():
                self.osds.remove(osd)

    def _save_to_store(self):
        # type: () -> None
        osd_queue = [osd.to_json() for osd in self.osds]
        logger.debug("Saving %s to store" % osd_queue)
        self.mgr.set_store('osd_remove_queue', json.dumps(osd_queue))

    def load_from_store(self):
        # type: () -> None
        with self.lock:
            for k, v in self.mgr.get_store_prefix('osd_remove_queue').items():
                for osd in json.loads(v):
                    logger.debug("Loading osd ->%s from store" % osd)
                    osd_obj = OSD.from_json(osd, rm_util=self.rm_util)
                    if osd_obj is not None:
                        self.osds.add(osd_obj)

    def as_osd_ids(self):
        # type: () -> List[int]
        with self.lock:
            return [osd.osd_id for osd in self.osds]

    def queue_size(self):
        # type: () -> int
        with self.lock:
            return len(self.osds)

    def draining_osds(self):
        # type: () -> List["OSD"]
        with self.lock:
            return [osd for osd in self.osds if osd.is_draining]

    def idling_osds(self):
        # type: () -> List["OSD"]
        with self.lock:
            return [osd for osd in self.osds if not osd.is_draining and not osd.is_empty]

    def empty_osds(self):
        # type: () -> List["OSD"]
        with self.lock:
            return [osd for osd in self.osds if osd.is_empty]

    def all_osds(self):
        # type: () -> List["OSD"]
        with self.lock:
            return [osd for osd in self.osds]

    def _not_in_cluster(self):
        return [osd for osd in self.osds if not osd.exists]

    def enqueue(self, osd):
        # type: ("OSD") -> None
        if not osd.exists:
            raise NotFoundError()
        with self.lock:
            self.osds.add(osd)
        osd.start()

    def rm(self, osd):
        # type: ("OSD") -> None
        if not osd.exists:
            raise NotFoundError()
        osd.stop()
        with self.lock:
            try:
                logger.debug('Removing %s from the queue.' % osd)
                self.osds.remove(osd)
            except KeyError:
                logger.debug("Could not find %s in queue." % osd)
                raise KeyError

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, OSDRemovalQueue):
            return False
        with self.lock:
            return self.osds == other.osds
