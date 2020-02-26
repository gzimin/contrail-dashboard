# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nebula, Inc.
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

import ast

from django.conf import settings  # noqa
from django.core.urlresolvers import reverse  # noqa
from django.utils.translation import ugettext_lazy as _  # noqa
from django.utils.translation import ungettext_lazy
from django import template

from horizon import tables

from openstack_dashboard import api
from openstack_dashboard.utils import filters

from contrail_dashboard.api.contrail_quantum import *


class IpamFilterAction(tables.FilterAction):
    def filter(self, table, ipam, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (ipam.name or "").lower()]):
                return True
            return False

        return filter(comp, ipam)


class DeleteIpam(tables.DeleteAction):
    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Network IPAM",
            u"Delete Network IPAMs",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Deleted Network IPAM",
            u"Deleted Network IPAMs",
            count
        )

    def delete(self, request, obj_id):
        ipam_delete(request, obj_id)


class CreateIpam(tables.LinkAction):
    name = "create"
    verbose_name = _("Create Network IPAM")
    url = "horizon:project:networks:ipam:create"
    icon = "plus"
    classes = ("ajax-modal", "btn-create")


class EditIpam(tables.LinkAction):
    name = "edit"
    verbose_name = _("Edit Network IPAM")
    url = "horizon:project:networks:ipam:update"
    icon = "pencil"
    classes = ("ajax-modal", "btn-edit")


def get_dns_details(ipam_obj):
    dns_detail_str = ''

    ipam = ipam_obj.__dict__['_apidict']['mgmt']

    if 'ipam_dns_method' not in ipam:
        return 'None'

    if ipam['ipam_dns_method'] == 'default-dns-server':
        dns_detail_str += 'Default DNS Server'

    if ipam['ipam_dns_method'] == 'none':
        dns_detail_str += 'None'

    if ipam['ipam_dns_method'] == 'tenant-dns-server':
        dns_detail_str += 'Tenant DNS'
        if ('ipam_dns_server' in ipam and
            'tenant_dns_server_address' in ipam['ipam_dns_server'] and
                'ip_address' in ipam['ipam_dns_server']['tenant_dns_server_address']):
            for ip in ipam['ipam_dns_server']['tenant_dns_server_address']['ip_address']:
                dns_detail_str += ' ' + str(ip)

    if ipam['ipam_dns_method'] == 'virtual-dns-server':
        dns_detail_str += 'Virtual DNS'
        if ('ipam_dns_server' in ipam and
                'virtual_dns_server_name' in ipam['ipam_dns_server']):
            dns_detail_str += ' ' + ipam['ipam_dns_server']['virtual_dns_server_name']

    if 'dhcp_option_list' in ipam:
        dhcp_list = ipam['dhcp_option_list']
        if dhcp_list and 'dhcp_option' in dhcp_list:
            for dhcp_opt in ipam['dhcp_option_list']['dhcp_option']:
                if dhcp_opt['dhcp_option_name'] == '6':
                    dns_detail_str += ' ' + dhcp_opt['dhcp_option_value']

    return dns_detail_str


def get_ntp_servers(ipam_obj):
    ntp_details = ''

    ipam = ipam_obj.__dict__['_apidict']['mgmt']

    if 'dhcp_option_list' in ipam:
        dhcp_list = ipam['dhcp_option_list']
        if dhcp_list and 'dhcp_option' in dhcp_list:
            for dhcp_opt in ipam['dhcp_option_list']['dhcp_option']:
                if dhcp_opt['dhcp_option_name'] == '4':
                    ntp_details += ' ' + dhcp_opt['dhcp_option_value']

    return ntp_details


def get_domains(ipam_obj):
    domain_details = ''

    ipam = ipam_obj.__dict__['_apidict']['mgmt']

    if 'dhcp_option_list' in ipam:
        dhcp_list = ipam['dhcp_option_list']
        if dhcp_list and 'dhcp_option' in dhcp_list:
            for dhcp_opt in ipam['dhcp_option_list']['dhcp_option']:
                if dhcp_opt['dhcp_option_name'] == '15':
                    domain_details += ' ' + dhcp_opt['dhcp_option_value']

    return domain_details


class NetworkIpamTable(tables.DataTable):
    name = tables.Column("name", verbose_name=_("Name"))
    dns_details = tables.Column(get_dns_details, verbose_name=_("DNS Method"))
    ntp_servers = tables.Column(get_ntp_servers, verbose_name=_("NTP Server(s)"))
    domain_name = tables.Column(get_domains, verbose_name=_("Domain Name(s)"))

    def sanitize_id(self, obj_id):
        return filters.get_int_or_uuid(obj_id)

    class Meta:
        name = "ipam"
        verbose_name = _("Network IPAMs")
        table_actions = (IpamFilterAction, CreateIpam, DeleteIpam,)
        row_actions = (EditIpam, DeleteIpam)
