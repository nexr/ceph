import logging

try:
    from typing import List, Any, Tuple, Dict
except ImportError:
    pass

from ceph.deployment.service_spec import CustomContainerSpec

from .cephadmservice import CephadmService, CephadmDaemonSpec

logger = logging.getLogger(__name__)


class CustomContainerService(CephadmService):
    TYPE = 'container'

    def prepare_create(self, daemon_spec):
        # type: (CephadmDaemonSpec[CustomContainerSpec]) -> CephadmDaemonSpec
        assert self.TYPE == daemon_spec.daemon_type
        return daemon_spec

    def generate_config(self, daemon_spec):
        # type: (CephadmDaemonSpec[CustomContainerSpec]) -> Tuple[Dict[str, Any], List[str]]
        assert self.TYPE == daemon_spec.daemon_type
        assert daemon_spec.spec
        deps = [] # type: List[str]
        spec = daemon_spec.spec # type: CustomContainerSpec
        config = spec.config_json() # type: Dict[str, Any]
        logger.debug(
            'Generated configuration for \'%s\' service: config-json=%s, dependencies=%s' %
            (self.TYPE, config, deps))
        return config, deps
