# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import errno
import inspect
import sys

import array_lbaasv2_agent.common.exceptions as exceptions

try:
    from oslo_config import cfg
    from oslo_log import log as oslo_logging
    from oslo_service import service
except ImportError as CriticalError:
    frame = inspect.getframeinfo(inspect.currentframe())
    CriticalError = \
        exceptions.ArrayMissingDependencies(message=str(CriticalError),
                                         frame=frame)
    sys.exit(CriticalError.errno)

try:
    from neutron.agent.common import config
except ImportError:
    from neutron.conf.agent import common as config

try:
    from neutron.common import config as common_config
    from neutron.common import rpc as n_rpc
except ImportError as Error:
    pass

import array_lbaasv2_agent.v2.agent_manager as manager
import array_lbaasv2_agent.common.constants as arrayconstants

LOG = oslo_logging.getLogger(__name__)

OPTS = [
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help='Seconds between periodic task runs'
    )
]


class ArrayAgentService(n_rpc.Service):
    """Array Agent service class."""

    def start(self):
        """Start the Array agent service."""
        self.tg.add_timer(
            cfg.CONF.periodic_interval,
            self.manager.run_periodic_tasks,
            None,
            None
        )   # tg = olso_service thread group to run periodic tasks
        super(ArrayAgentService, self).start()


def main():
    """Array LBaaS agent for OpenStack."""
    cfg.CONF.register_opts(OPTS)

    config.register_agent_state_opts_helper(cfg.CONF)
    config.register_root_helper(cfg.CONF)

    common_config.init(sys.argv[1:])
    # alias for common_config.setup_logging()...
    config.setup_logging()

    mgr = manager.LbaasAgentManager(cfg.CONF)

    svc = ArrayAgentService(
        host=mgr.agent_host,
        topic=arrayconstants.TOPIC_LOADBALANCER_AGENT_V2,
        manager=mgr
    )
    service.launch(cfg.CONF, svc).wait()


if __name__ == '__main__':
    try:
        Error
    except NameError:
        sys.exc_clear()
    else:
        # We already had an exception, ABORT!
        LOG.exception(str(Error))
        sys.exit(errno.ENOSYS)
    main()
