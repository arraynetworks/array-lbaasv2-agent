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
        self.agent_host = conf.arraynetworks.agent_host
        self.env_postfix = conf.arraynetworks.environment_postfix

        if self.env_postfix:
            LOG.debug("----------------env_postfix: %s--------------", self.env_postfix)
        else:
            LOG.debug("----------------env_postfix is None --------------")

        ## callback to plugin
        self._setup_plugin_rpc()

        # Load the driver.
        self.driver = ArrayADCDriver(conf, self.plugin_rpc, self.context)

        configurations = {}
        configurations['device_drivers'] = ['array']
        if self.env_postfix:
            configurations['environment'] = self.env_postfix

        self.agent_state = {
            'binary': constants_v2.AGENT_BINARY_NAME,
            'host': self.agent_host,
            'topic': constants_v2.TOPIC_LOADBALANCER_AGENT_V2,
            'configurations': configurations,
            'agent_type': constants_v2.ARRAY_AGENT_TYPE_LOADBALANCERV2,
            'start_flag': True,
        }

        if callable(getattr(self.driver.driver, 'init_array_device', None)):
            self.driver.driver.init_array_device(self)


    def _setup_plugin_rpc(self):
        topic = constants_v2.TOPIC_PROCESS_ON_HOST_V2
        if self.env_postfix:
            topic = topic + '_' + self.env_postfix
        self.plugin_rpc = plugin_api.ArrayPluginApi(topic, self.conf.host)

        self.report_state_rpc = agent_rpc.PluginReportStateAPI(topic)
        heartbeat_agent_status = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat_agent_status.start(interval=30)

        heartbeat_lb_status = loopingcall.FixedIntervalLoopingCall(self.update_lb_status)
        heartbeat_lb_status.start(interval=45)

        recovery_lb_status = loopingcall.FixedIntervalLoopingCall(self.recovery_lbs_configuration)
        recovery_lb_status.start(interval=60)

        scrub_dead_agents = loopingcall.FixedIntervalLoopingCall(self.scrub_dead_agents)
        scrub_dead_agents.start(interval=150)


    def scrub_dead_agents(self):
        try:
            self.plugin_rpc.scrub_dead_agents(context)
        except Exception as e:
            LOG.debug("failed to scrub dead agents: %s" % e.message)


    def update_lb_status(self):
        try:
            self.driver.driver.update_member_status(self.agent_host)
        except Exception as e:
            LOG.debug("failed to update member status: %s" % e.message)

    def _report_state(self):
        LOG.info("entering _report_state");
        self.report_state_rpc.report_state(self.context, self.agent_state)

    def recovery_lbs_configuration(self):
        LOG.info("Recovery LB configuration...");
        try:
            self.driver.driver.recovery_lbs_configuration()
        except Exception as e:
            LOG.debug("failed to recovery LBs configuration: %s" % e.message)

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
        except Exception as e:
            LOG.exception('failed to create loadbalancer: %s', e.message)
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
            self.plugin_rpc.lb_deleting_completion(context, obj)
        except Exception as e:
            LOG.exception('failed to delete loadbalancer: %s, %s', obj['id'], e.message)
            self.plugin_rpc.lb_deleting_completion(context, obj)

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
            self.plugin_rpc.l7rule_deleting_completion(context, obj)

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

