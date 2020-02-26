# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Copyright 2012 Nebula, Inc.
# Copyright 2012 OpenStack Foundation
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

from django.utils.translation import ugettext_lazy as _  # noqa

from horizon import exceptions
from horizon import messages
from horizon import tabs

from openstack_dashboard import api
from contrail_dashboard.api.contrail_quantum import *

from contrail_dashboard.content.networks.tables import NetworksTable
from contrail_dashboard.content.networks.policy.tables \
    import NetworkPolicyTable
from contrail_dashboard.content.networks.ipam.tables import NetworkIpamTable


class NetworksTab(tabs.TableTab):
    table_classes = (NetworksTable,)
    name = _("Networks")
    slug = "networks_tab"
    template_name = "horizon/common/_detail_table.html"

    def get_networks_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            networks = api.neutron.network_list_for_tenant(self.request,
                                                           tenant_id)
            networks = [n for n in networks if 'snat-si' not in n.name_or_id]
        except Exception:
            networks = []
            msg = _('Network list can not be retrieved.')
            exceptions.handle(self.request, msg)
        for n in networks:
            n.set_id_as_name_if_empty()
        return networks


class NetworkPolicyTab(tabs.TableTab):
    table_classes = (NetworkPolicyTable,)
    name = _("Network Policies")
    slug = "policy_tab"
    template_name = "horizon/common/_detail_table.html"

    def get_policy_data(self):
        tenant_id = self.request.user.tenant_id
        try:
            policy = policy_summary_for_tenant(self.request, tenant_id)
        except Exception:
            policy = []
            exceptions.handle(self.request,
                              _('Unable to retrieve network policies.'))
        return policy


class NetworkIpamTab(tabs.TableTab):
    table_classes = (NetworkIpamTable,)
    name = _("Network IPAMs")
    slug = "ipam_tab"
    template_name = "horizon/common/_detail_table.html"

    def get_ipam_data(self):
        tenant_id = self.request.user.tenant_id
        try:
            ipam = ipam_summary_for_tenant(self.request, tenant_id)
        except Exception:
            ipam = []
            exceptions.handle(self.request,
                              _('Unable to retrieve network ipams.'))
        return ipam


class networksTabs(tabs.TabGroup):
    slug = "networks_tabs"
    tabs = (NetworksTab, NetworkPolicyTab, NetworkIpamTab,)
    sticky = True
