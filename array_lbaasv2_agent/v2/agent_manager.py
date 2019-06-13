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

from oslo_config import cfg
from oslo_log import helpers as log_helpers
import logging
import oslo_messaging
import uuid

try:
    from neutron import context
except ImportError as CriticalError:
    from neutron_lib import context

from neutron.agent import rpc as agent_rpc

from oslo_service import loopingcall
from oslo_service import periodic_task

from array_lbaasv2_agent.common.exceptions import ArrayADCException
from array_lbaasv2_agent.common import constants as constants_v2
from array_lbaasv2_agent.common.device_driver import ArrayADCDriver
from array_lbaasv2_agent.v2 import plugin_api

LOG = logging.getLogger(__name__)


class LbaasAgentManager(periodic_task.PeriodicTasks):
    """Periodic task that is an endpoint for plugin to agent RPC."""

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, conf):
        super(LbaasAgentManager, self).__init__(conf)

        LOG.info('Initializing LbaasAgentManager with conf %s' % conf)
        cfg.CONF.log_opt_values(LOG, logging.INFO)
        self.conf = conf

        self.context = context.get_admin_context_without_session()

        self.agent_host = None
        if self.conf.agent_id:
            self.agent_host = self.conf.agent_id
            LOG.debug('setting agent host to %s' % self.agent_host)
        else:
            agent_hash = str(uuid.uuid1())
            self.agent_host = conf.host + ":" + agent_hash
            LOG.debug('setting agent host to %s' % self.agent_host)

        ## callback to plugin
        self._setup_plugin_rpc()

        # Load the driver.
        self.driver = ArrayADCDriver(conf, self.plugin_rpc, self.context)

        self.agent_state = {
            'binary': constants_v2.AGENT_BINARY_NAME,
            'host': self.agent_host,
            'topic': constants_v2.TOPIC_LOADBALANCER_AGENT_V2,
            'configurations': {'device_drivers': ['array']},
            'agent_type': constants_v2.ARRAY_AGENT_TYPE_LOADBALANCERV2,
            'start_flag': True,
        }

    def _setup_plugin_rpc(self):
        self.plugin_rpc = plugin_api.ArrayPluginApi(
            constants_v2.TOPIC_PROCESS_ON_HOST_V2,
            self.conf.host
        )

        self.report_state_rpc = agent_rpc.PluginReportStateAPI(constants_v2.TOPIC_PROCESS_ON_HOST_V2)
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(interval=30)


    def _report_state(self):
        LOG.info("entering _report_state");
        self.report_state_rpc.report_state(self.context, self.agent_state)

    @log_helpers.log_method_call
    def create_loadbalancer_and_allocate_vip(self, context, obj):
        try:
            self.driver.create_loadbalancer_and_allocate_vip(obj)
            self.plugin_rpc.lb_successful_completion(context, obj, False, True)
        except ArrayADCException as e:
            LOG.exception('could not create loadbalancer: %s', e.msg)
            self.plugin_rpc.lb_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_loadbalancer(self, context, obj):
        try:
            self.driver.create_loadbalancer(obj)
            self.plugin_rpc.lb_successful_completion(context, obj, False, True)
        except ArrayADCException as e:
            LOG.exception('could not create loadbalancer: %s', e.msg)
            self.plugin_rpc.lb_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_loadbalancer(self, context, obj, old_obj):
        try:
            self.driver.update_loadbalancer(obj, old_obj)
            self.plugin_rpc.lb_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update loadbalancer: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.lb_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_loadbalancer(self, context, obj):
        try:
            self.driver.delete_loadbalancer(obj)
            self.plugin_rpc.lb_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete loadbalancer: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.lb_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_listener(self, context, obj):
        try:
            self.driver.create_listener(obj)
            self.plugin_rpc.listener_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create listener: %s', e.msg)
            self.plugin_rpc.listener_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_listener(self, context, obj, old_obj):
        try:
            self.driver.update_listener(obj, old_obj)
            self.plugin_rpc.listener_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update loadbalancer: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.listener_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_listener(self, context, obj):
        try:
            self.driver.delete_listener(obj)
            self.plugin_rpc.listener_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete listener: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.listener_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_pool(self, context, obj):
        try:
            self.driver.create_pool(obj)
            self.plugin_rpc.pool_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create pool: %s', e.msg)
            self.plugin_rpc.pool_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_pool(self, context, obj, old_obj):
        try:
            self.driver.update_pool(obj, old_obj)
            self.plugin_rpc.pool_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update pool: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.pool_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_pool(self, context, obj):
        try:
            self.driver.delete_pool(obj)
            self.plugin_rpc.pool_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete pool: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.pool_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_member(self, context, obj):
        try:
            self.driver.create_member(obj)
            self.plugin_rpc.member_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create member: %s', e.msg)
            self.plugin_rpc.member_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_member(self, context, obj, old_obj):
        try:
            self.driver.update_member(obj, old_obj)
            self.plugin_rpc.member_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update member: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.member_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_member(self, context, obj):
        try:
            self.driver.delete_member(obj)
            self.plugin_rpc.member_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete member: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.member_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_health_monitor(self, context, obj):
        try:
            self.driver.create_health_monitor(obj)
            self.plugin_rpc.hm_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create health_monitor: %s', e.msg)
            self.plugin_rpc.hm_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_health_monitor(self, context, obj, old_obj):
        try:
            self.driver.update_health_monitor(obj, old_obj)
            self.plugin_rpc.hm_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update hm: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.hm_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_health_monitor(self, context, obj):
        try:
            self.driver.delete_health_monitor(obj)
            self.plugin_rpc.hm_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete hm: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.hm_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_loadbalancer_stats(self, context, obj):
        pass

    @log_helpers.log_method_call
    def create_l7rule(self, context, obj):
        try:
            self.driver.create_l7rule(obj)
            self.plugin_rpc.l7rule_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create l7rule: %s', e.msg)
            self.plugin_rpc.l7rule_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_l7rule(self, context, obj, old_obj):
        try:
            self.driver.update_l7rule(obj, old_obj)
            self.plugin_rpc.l7rule_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update l7rule: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.l7rule_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_l7rule(self, context, obj):
        try:
            self.driver.delete_l7rule(obj)
            self.plugin_rpc.l7rule_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete l7rule: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.l7rule_failed_completion(context, obj)

    @log_helpers.log_method_call
    def create_l7policy(self, context, obj):
        try:
            self.driver.create_l7policy(obj)
            self.plugin_rpc.l7policy_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not create l7policy: %s', e.msg)
            self.plugin_rpc.l7policy_failed_completion(context, obj)

    @log_helpers.log_method_call
    def update_l7policy(self, context, obj, old_obj):
        try:
            self.driver.update_l7policy(obj, old_obj)
            self.plugin_rpc.l7policy_successful_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not update l7policy: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.l7policy_failed_completion(context, obj)

    @log_helpers.log_method_call
    def delete_l7policy(self, context, obj):
        try:
            self.driver.delete_l7policy(obj)
            self.plugin_rpc.l7policy_deleting_completion(context, obj)
        except ArrayADCException as e:
            LOG.exception('could not delete l7policy: %s, %s', obj['id'], e.msg)
            self.plugin_rpc.l7policy_failed_completion(context, obj)

