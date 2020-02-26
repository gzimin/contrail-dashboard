# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
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

from django.conf import settings  # noqa
from django.core.urlresolvers import reverse  # noqa
from django.core import validators
from django.forms import ValidationError  # noqa
from django.utils.translation import ugettext_lazy as _  # noqa

from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.forms import fields
from horizon.utils import validators as utils_validators

from openstack_dashboard import api
from contrail_dashboard.api.contrail_quantum import *
from openstack_dashboard.utils import filters

from netaddr import *


class CreateNetworkIpam(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Name"),
                           error_messages={
                               'required': _('This field is required.'),
                               'invalid': _("The string may only contain"
                                            " ASCII characters and numbers.")},
                           validators=[validators.validate_slug])

    dnsmethod = forms.ChoiceField(label=_('DNS Method'),
                                  choices=[('default', _('Default')),
                                           ('vdns', _('Virtual DNS')),
                                           ('tenantdns', _('Tenant DNS')),
                                           ('none', _('None'))],
                                  widget=forms.Select(attrs={'class': 'switchable',
                                                             'data-slug': 'dnsmethod'}))

    vdns = forms.CharField(label=_("Virtual DNS"),
                           required=False,
                           help_text=_("FQ Name of Virtual DNS i.e. default-domain:vdns"),
                           widget=forms.TextInput(
                               attrs={'class': 'switched',
                                      'data-switch-on': 'dnsmethod',
                                      'data-dnsmethod-vdns': _('Virtual DNS')}))

    tenantdns = fields.IPField(label=_("Tenant DNS Server IP"),
                               required=False,
                               help_text=_("Tenant managed DNS Server's IP Address"),
                               version=fields.IPv4,
                               mask=False,
                               widget=forms.TextInput(
                                   attrs={'class': 'switched',
                                          'data-switch-on': 'dnsmethod',
                                          'data-dnsmethod-tenantdns': _('Tenant DNS Server IP')}))

    ntpip = fields.IPField(label=_("NTP Server IP"),
                           required=False,
                           help_text=_("IP Address of the NTP Server"),
                           version=fields.IPv4,
                           mask=False,
                           widget=forms.TextInput())

    domainname = forms.CharField(label=_("Domain Name"),
                                 required=False,
                                 help_text=_("Domain Name i.e. openstack.org"),
                                 widget=forms.TextInput())

    def clean(self):
        cleaned_data = super(CreateNetworkIpam, self).clean()
        name = cleaned_data.get("name")
        dnsmethod = cleaned_data.get("dnsmethod")
        vdns = cleaned_data.get("vdns")
        tenantdns = cleaned_data.get("tenantdns")
        ntpip = cleaned_data.get("ntpip")
        domainname = cleaned_data.get("domainname")

        if dnsmethod == 'vdns' and not len(vdns):
            msg = _('Virtual DNS : Enter a valid Virtual DNS in FQN format')
            raise ValidationError(msg)

        if dnsmethod == 'tenantdns':
            if not tenantdns:
                msg = _('Tenant DNS Server IP : Enter Tenant DNS Server IP address')
                raise ValidationError(msg)
            elif not len(tenantdns):
                msg = _('Tenant DNS Server IP : Enter Tenant DNS Server IP address')
                raise ValidationError(msg)

        return cleaned_data

    def handle(self, request, data):
        params = {'name': data['name'],
                  'mgmt': {'ipam_method': None,
                           'dhcp_option_list': {'dhcp_option': []}}}

        if data['domainname']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                {'dhcp_option_name': '15',
                 'dhcp_option_value': data['domainname']}
            )

        if data['ntpip']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                {'dhcp_option_name': '4',
                 'dhcp_option_value': data['ntpip']}
            )

        params['mgmt']['ipam_dns_server'] = {}
        params['mgmt']['ipam_dns_server']['tenant_dns_server_address'] = {}
        params['mgmt']['ipam_dns_server']['virtual_dns_server_name'] = None

        if data['dnsmethod'] == 'default':
            params['mgmt']['ipam_dns_method'] = 'default-dns-server'

        if data['dnsmethod'] == 'none':
            params['mgmt']['ipam_dns_method'] = 'none'

        if data['dnsmethod'] == 'tenantdns':
            params['mgmt']['ipam_dns_method'] = 'tenant-dns-server'
            if data['tenantdns']:
                params['mgmt']['ipam_dns_server']['tenant_dns_server_address']['ip_address'] = []
                params['mgmt']['ipam_dns_server']['tenant_dns_server_address']['ip_address'].append(data['tenantdns'])

        if data['dnsmethod'] == 'vdns':
            params['mgmt']['ipam_dns_method'] = 'virtual-dns-server'
            params['mgmt']['ipam_dns_server']['virtual_dns_server_name'] = data['vdns']
        try:
            ipam = ipam_create(request, **params)
            messages.success(request,
                             _('Successfully created network ipam: %s') % data['name'])
            return ipam
        except Exception:
            redirect = reverse("horizon:project:networks:index")
            exceptions.handle(request,
                              _('Unable to create network ipam.'),
                              redirect=redirect)


class UpdateIpam(forms.SelfHandlingForm):
    id = forms.CharField(widget=forms.HiddenInput())
    name = forms.CharField(label=_("Name"),
                           widget=forms.TextInput(attrs={'readonly': 'readonly'}),
                           validators=[validators.validate_slug])

    dnsmethod = forms.ChoiceField(label=_('DNS Method'),
                                  choices=[('default', _('Default')),
                                           ('vdns', _('Virtual DNS')),
                                           ('tenantdns', _('Tenant DNS')),
                                           ('none', _('None'))],
                                  widget=forms.Select(attrs={
                                      'class': 'switchable',
                                      'data-slug': 'dnsmethod'}))

    vdns = forms.CharField(label=_("Virtual DNS"),
                           required=False,
                           help_text=_("FQ Name of Virtual DNS i.e. default-domain:vdns"),
                           widget=forms.TextInput(attrs={
                               'class': 'switched',
                               'data-switch-on': 'dnsmethod',
                               'data-dnsmethod-vdns': _('Virtual DNS')}))

    tenantdns = fields.IPField(label=_("Tenant DNS Server IP"),
                               required=False,
                               help_text=_("Tenant managed DNS Server's IP Address"),
                               version=fields.IPv4,
                               mask=False,
                               widget=forms.TextInput(attrs={
                                   'class': 'switched',
                                   'data-switch-on': 'dnsmethod',
                                   'data-dnsmethod-tenantdns': _('Tenant DNS Server IP')}))

    ntpip = fields.IPField(label=_("NTP Server IP"),
                           required=False,
                           help_text=_("IP Address of the NTP Server"),
                           version=fields.IPv4,
                           mask=False,
                           widget=forms.TextInput())

    domainname = forms.CharField(label=_("Domain Name"),
                                 required=False,
                                 help_text=_("Domain Name i.e. openstack.org"),
                                 widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        ipam_obj = kwargs.pop('ipam_obj', {})
        mgmt = ipam_obj.__dict__['_apidict']['mgmt']
        super(UpdateIpam, self).__init__(*args, **kwargs)
        if mgmt['ipam_dns_method'] == 'default-dns-server':
            self.fields['dnsmethod'].initial = 'default'

        if mgmt['ipam_dns_method'] == 'tenant-dns-server':
            self.fields['dnsmethod'].initial = 'tenantdns'
            if ('ipam_dns_server' in mgmt and
                'tenant_dns_server_address' in mgmt['ipam_dns_server'] and
                    'ip_address' in mgmt['ipam_dns_server']['tenant_dns_server_address']):
                for ip in mgmt['ipam_dns_server']['tenant_dns_server_address']['ip_address']:
                    self.fields['tenantdns'].initial = ip

        if mgmt['ipam_dns_method'] == 'virtual-dns-server':
            self.fields['dnsmethod'].initial = 'vdns'
            if ('ipam_dns_server' in mgmt and
                'virtual_dns_server_name' in mgmt['ipam_dns_server'] and
                    mgmt['ipam_dns_server']['virtual_dns_server_name'] is not None):
                self.fields['vdns'].initial = mgmt['ipam_dns_server']['virtual_dns_server_name']

        if mgmt['ipam_dns_method'] == 'none':
            self.fields['dnsmethod'].initial = 'none'

        if 'dhcp_option_list' in mgmt:
            dhcp_list = mgmt['dhcp_option_list']
            if dhcp_list and 'dhcp_option' in dhcp_list:
                for entry in mgmt['dhcp_option_list']['dhcp_option']:
                    if entry['dhcp_option_name'] == '4':
                        self.fields['ntpip'].initial = entry['dhcp_option_value']
                    if entry['dhcp_option_name'] == '15':
                        self.fields['domainname'].initial = entry['dhcp_option_value']

    def clean(self):
        cleaned_data = super(UpdateIpam, self).clean()
        name = cleaned_data.get("name")
        dnsmethod = cleaned_data.get("dnsmethod")
        vdns = cleaned_data.get("vdns")
        tenantdns = cleaned_data.get("tenantdns")
        ntpip = cleaned_data.get("ntpip")
        domainname = cleaned_data.get("domainname")

        if dnsmethod == 'vdns' and not len(vdns):
            msg = _('Virtual DNS : Enter a valid Virtual DNS in FQN format')
            raise ValidationError(msg)

        if dnsmethod == 'tenantdns':
            if not tenantdns:
                msg = _('Tenant DNS Server IP : Enter Tenant DNS Server IP address')
                raise ValidationError(msg)
            elif not len(tenantdns):
                msg = _('Tenant DNS Server IP : Enter Tenant DNS Server IP address')
                raise ValidationError(msg)

        return cleaned_data

    def handle(self, request, data):
        params = {'mgmt': {'ipam_method': None,
                           'dhcp_option_list': {'dhcp_option': []}}}

        if data['domainname']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                {'dhcp_option_name': '15',
                 'dhcp_option_value':
                 data['domainname']})

        if data['ntpip']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                {'dhcp_option_name': '4',
                 'dhcp_option_value':
                 data['ntpip']})

        params['mgmt']['ipam_dns_server'] = {}
        params['mgmt']['ipam_dns_server']['tenant_dns_server_address'] = {}
        params['mgmt']['ipam_dns_server']['virtual_dns_server_name'] = None

        if data['dnsmethod'] == 'default':
            params['mgmt']['ipam_dns_method'] = 'default-dns-server'

        if data['dnsmethod'] == 'none':
            params['mgmt']['ipam_dns_method'] = 'none'

        if data['dnsmethod'] == 'tenantdns':
            params['mgmt']['ipam_dns_method'] = 'tenant-dns-server'
            if data['tenantdns']:
                params['mgmt']['ipam_dns_server']['tenant_dns_server_address']['ip_address'] = []
                params['mgmt']['ipam_dns_server']['tenant_dns_server_address']['ip_address'].append(data['tenantdns'])

        if data['dnsmethod'] == 'vdns':
            params['mgmt']['ipam_dns_method'] = 'virtual-dns-server'
            params['mgmt']['ipam_dns_server']['virtual_dns_server_name'] = data['vdns']

        try:
            ipam = ipam_modify(request, ipam_id=data['id'], **params)
            messages.success(request,
                             _('Successfully updated network ipam: %s') % data['name'])
            return ipam
        except Exception:
            redirect = reverse("horizon:project:networks:index")
            exceptions.handle(request,
                              _('Unable to update network ipam.'),
                              redirect=redirect)
