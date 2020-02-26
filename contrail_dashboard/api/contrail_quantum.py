# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#    Copyright (c) 2013 Juniper Networks, Inc. All rights reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import absolute_import

import logging
import pdb

from netaddr import *
from neutronclient.v2_0 import client as neutron_client

from openstack_dashboard.api.base import APIDictWrapper, url_for

from openstack_dashboard.api.neutron import *

LOG = logging.getLogger(__name__)


class ExtensionsContrailIpam(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron ipam"""
    _attrs = ['name', 'id', 'mgmt', 'tenant_id']

    def __init__(self, apiresource):
        if ('mgmt' not in apiresource.keys() or
                apiresource['mgmt'] is None):
            apiresource['mgmt'] = {'dhcp_option_list': {'dhcp_option': []}}
        if 'ipam_method' in apiresource['mgmt'].keys():
            apiresource['addr_type'] = \
                'DHCP' if apiresource['mgmt']['ipam_method'] == 'dhcp' else 'Fixed'
        else:
            apiresource['addr_type'] = "Unknown"
        if 'dhcp_option_list' not in apiresource['mgmt'].keys():
            apiresource['mgmt'] = {'dhcp_option_list': {'dhcp_option': []}}

        super(ExtensionsContrailIpam, self).__init__(apiresource)


def ipam_summary(request, **params):
    LOG.debug("ipam_summary(): params=%s" % (params))
    ipams = neutronclient(request).list_ipams(**params).get('ipams')
    return [ExtensionsContrailIpam(n) for n in ipams]


def ipam_summary_for_tenant(request, tenant_id, **params):
    """Return a ipam summary list available for the tenant.
    The list contains ipams owned by the tenant.
    If requested_ipams specified, it searches requested_ipams only.
    """
    LOG.debug("ipam_summary_for_tenant(): tenant_id=%s, params=%s"
              % (tenant_id, params))

    ipams = ipam_summary(request, tenant_id=tenant_id, **params)

    return ipams


def ipam_show(request, ipam_id, **params):
    """Return an IPAM object with the requested id.
    """
    LOG.debug("ipam_show(): id = %s, params=%s" % (ipam_id, params))
    ipam = neutronclient(request).show_ipam(ipam_id, **params).get('ipam')

    return ExtensionsContrailIpam(ipam)


def ipam_create(request, name, **kwargs):
    """
    Create an ipam.
    {
        'name': 'foo',
        'mgmt': {
            'ipam_method': 'dhcp|fixed',
            'dhcp_option_list': {
                'dhcp_option': [
                    {
                        'dhcp_option_name': 'opt_1',
                        'dhcp_option_value': 'opt_1_value'
                    },
                    {
                        'dhcp_option_name': 'opt_1',
                        'dhcp_option_value': 'opt_1_value'
                    }
                ]
            }
        }
    }
    :param request: request context
    :param name: name of the ipam to be created
    :param tenant_id: (optional) tenant id of the ipam to be created
    :param mgmt['ipam_method']: dhcp or fixed
    :returns: ExtensionsContrailIpam object
    """
    LOG.debug("ipam_create(): name=%s, kwargs=%s" % (name, kwargs))
    body = {'ipam': {'name': name}}
    body['ipam'].update(kwargs)
    ipam = neutronclient(request).create_ipam(body=body).get('ipam')
    return ExtensionsContrailIpam(ipam)


def ipam_modify(request, ipam_id, **kwargs):
    LOG.debug("ipam_modify(): ipam-id=%s, kwargs=%s" % (ipam_id, kwargs))
    body = {'ipam': kwargs}
    ipam = neutronclient(request).update_ipam(ipam_id,
                                              body=body).get('ipam')
    return ExtensionsContrailIpam(ipam)


def ipam_delete(request, ipam_id):
    LOG.debug("ipam_delete(): ipam-id=%s" % ipam_id)
    neutronclient(request).delete_ipam(ipam_id)


class ExtensionsContrailPolicy(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron network policies"""
    _attrs = ['name', 'fq_name', 'id', 'entries', 'tenant_id', 'nets_using']

    def __init__(self, apiresource):
        super(ExtensionsContrailPolicy, self).__init__(apiresource)
        if (apiresource['entries'] is None or
                apiresource['entries']['policy_rule'] is None):
            apiresource['entries'] = {}
            apiresource['entries']['policy_rule'] = []

        if 'nets_using' in apiresource.keys():
            apiresource['policy_net_ref_cnt'] = len(apiresource['nets_using'])
        else:
            apiresource['nets_using'] = []
            apiresource['policy_net_ref_cnt'] = 0
        i = 1
        for rule in apiresource['entries']['policy_rule']:
            rule['rule_sequence'] = i
            i = i + 1


def policy_summary(request, **params):
    LOG.debug("policy_summary(): params=%s" % (params))
    policies = neutronclient(request).list_policys(**params)
    # workaround for wrong pluralization of policy
    policy_key = 'policies' if 'policies' in policies else 'policys'
    return [ExtensionsContrailPolicy(p) for p in policies.get(policy_key, [])]


def policy_summary_for_tenant(request, tenant_id, **params):
    """Return a policy summary list available for the tenant.
    The list contains policies owned by the tenant.
    If requested_policys specified, it searches requested_policys only.
    """
    LOG.debug("policy_summary_for_tenant(): tenant_id=%s, params=%s"
              % (tenant_id, params))
    policies = policy_summary(request, tenant_id=tenant_id, **params)
    return policies


def policy_create(request, name, **kwargs):
    """
    Create a Network Policy.
    :param request: request context
    :param name: name of the network policy to be created
    :param tenant_id: (optional) tenant id of the ipam to be created
    :returns: ExtensionsContrailPolicy object
    """
    LOG.debug("policy_create(): name=%s, kwargs=%s" % (name, kwargs))
    body = {'policy': {'name': name, 'entries': {}}}
    policy = neutronclient(request).create_policy(body=body).get('policy')
    return ExtensionsContrailPolicy(policy)


def policy_delete(request, policy_id):
    LOG.debug("policy_delete(): policy-id=%s" % policy_id)
    neutronclient(request).delete_policy(policy_id)


def policy_show(request, policy_id, **params):
    LOG.debug("policy_summary_get(): pol-id=%s, params=%s" %
              (policy_id, params))
    policy = neutronclient(request).show_policy(policy_id, **params).get('policy')
    return ExtensionsContrailPolicy(policy)


def policy_modify(request, policy_id, **kwargs):
    LOG.debug("policy_modify(): policy-id=%s, kwargs=%s" % (policy_id, kwargs))
    body = {'policy': kwargs}
    policy = neutronclient(request).update_policy(policy_id, body=body).get('policy')
    return ExtensionsContrailPolicy(policy)
