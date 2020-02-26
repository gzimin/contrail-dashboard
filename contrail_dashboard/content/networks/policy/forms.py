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


class CreatePolicy(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Name"),
                           error_messages={
                               'required': _('This field is required.'),
                               'invalid': _("The string may only contain"
                                            " ASCII characters and numbers.")},
                           validators=[validators.validate_slug])

    def handle(self, request, data):
        try:
            policy = policy_create(request, data['name'])
            messages.success(request,
                             _('Successfully created network policy: %s') % data['name'])
            return policy
        except Exception:
            redirect = reverse("horizon:project:networks:index")
            exceptions.handle(request,
                              _('Unable to create network policy.'),
                              redirect=redirect)


class UpdatePolicy(forms.SelfHandlingForm):
    id = forms.CharField(widget=forms.HiddenInput())
    name = forms.CharField(label=_("Name"),
                           error_messages={
                               'required': _('This field is required.'),
                               'invalid': _("The string may only contain"
                                            " ASCII characters and numbers.")},
                           validators=[validators.validate_slug])

    def handle(self, request, data):
        try:
            policy = policy_modify(request, policy_id=data['id'], name=data['name'])
            messages.success(request,
                             _('Successfully updated network policy: %s') % data['name'])
            return policy
        except Exception:
            redirect = reverse("horizon:project:networks:index")
            exceptions.handle(request,
                              _('Unable to update network policy.'),
                              redirect=redirect)


class AddRule(forms.SelfHandlingForm):
    id = forms.CharField(widget=forms.HiddenInput())
    sequence_id = forms.ChoiceField(label=_('Sequence Id'),
                                    help_text=_("Choose the Sequence Id for "
                                                " this rule."))

    simple_action = forms.ChoiceField(label=_('Action'),
                                      choices=[('pass', 'Pass'),
                                               ('deny', 'Deny')],
                                      help_text=_("Actions that will be applied "
                                                  " on the traffic that matches"
                                                  " the rules"))
    protocol = forms.ChoiceField(label=_('IP Protocol'),
                                 choices=[('any', 'ANY'),
                                          ('tcp', 'TCP'),
                                          ('udp', 'UDP'),
                                          ('icmp', 'ICMP')],
                                 help_text=_("TCP, UDP, ICMP or All protocols"))

    direction = forms.ChoiceField(label=_('Direction'),
                                  choices=[('<>', '<> Bidirectional'),
                                           ('>', '> Unidirectional')],
                                  help_text=_("Direction of traffic on which"
                                              " the rule will be applied"))

    srctype = forms.ChoiceField(label=_('Source Type'),
                                choices=[('srcnets', _('Source Network')),
                                         ('srccidr', _('Source CIDR')),
                                         ('srcpols', _('Source Network Policy'))],
                                help_text=_('To specify an allowed IP '
                                            'range, select "CIDR". To '
                                            'allow access from a network '
                                            'select "Network". To '
                                            'allow access from a network '
                                            'policy select "Network Policy".'),
                                widget=forms.Select(attrs={
                                    'class': 'switchable',
                                    'data-slug': 'srctype'}))

    dsttype = forms.ChoiceField(label=_('Destination Type'),
                                choices=[('dstnets', _('Destination Network')),
                                         ('dstcidr', _('Destination CIDR')),
                                         ('dstpols', _('Destination Network Policy'))],
                                help_text=_('To specify an allowed IP '
                                            'range, select "CIDR". To '
                                            'allow access from a network '
                                            'select "Network". To '
                                            'allow access from a network '
                                            'policy select "Network Policy".'),
                                widget=forms.Select(attrs={
                                    'class': 'switchable',
                                    'data-slug': 'dsttype'}))

    srccidr = fields.IPField(label=_("Source CIDR"),
                             required=False,
                             initial="0.0.0.0/0",
                             help_text=_("Classless Inter-Domain Routing "
                                         "(e.g. 192.168.0.0/24)"),
                             version=fields.IPv4,
                             mask=True,
                             widget=forms.TextInput(attrs={
                                 'class': 'switched',
                                 'data-switch-on': 'srctype',
                                 'data-srctype-srccidr': _('Source CIDR')}))

    srcnets = forms.ChoiceField(label=_('Source Network'),
                                required=False,
                                widget=forms.Select(attrs={
                                    'class': 'switched',
                                    'data-switch-on': 'srctype',
                                    'data-srctype-srcnets': _('Source Network')}))

    srcpols = forms.ChoiceField(label=_('Source Network Policy'),
                                required=False,
                                widget=forms.Select(attrs={
                                    'class': 'switched',
                                    'data-switch-on': 'srctype',
                                    'data-srctype-srcpols': _('Source Network Policy')}))

    dstcidr = fields.IPField(label=_("Destination CIDR"),
                             required=False,
                             initial="0.0.0.0/0",
                             help_text=_("Classless Inter-Domain Routing "
                                         "(e.g. 192.168.0.0/24)"),
                             version=fields.IPv4,
                             mask=True,
                             widget=forms.TextInput(attrs={
                                 'class': 'switched',
                                 'data-switch-on': 'dsttype',
                                 'data-dsttype-dstcidr': _('Destination CIDR')}))

    dstnets = forms.ChoiceField(label=_('Destination Network'),
                                required=False,
                                widget=forms.Select(attrs={
                                    'class': 'switched',
                                    'data-switch-on': 'dsttype',
                                    'data-dsttype-dstnets': _('Destination Network')}))

    dstpols = forms.ChoiceField(label=_('Destination Network Policy'),
                                required=False,
                                widget=forms.Select(attrs={
                                    'class': 'switched',
                                    'data-switch-on': 'dsttype',
                                    'data-dsttype-dstpols': _('Destination Network Policy')}))

    src_ports = forms.CharField(label=_("Source Ports"),
                                required=False,
                                help_text=_("Originating Port list i.e. "
                                            "80 or 80,443,8080,8443-8446"),
                                initial="any")

    dst_ports = forms.CharField(label=_("Destination Ports"),
                                required=False,
                                help_text=_("Destination Port list i.e. "
                                            "80 or 80,443,8080,8443-8446"),
                                initial="any")

    def __init__(self, *args, **kwargs):
        policy_list = kwargs.pop('policy_list', [])
        network_list = kwargs.pop('network_list', [])
        services_list = kwargs.pop('services_list', [])
        super(AddRule, self).__init__(*args, **kwargs)
        if policy_list:
            policy_choices = policy_list
        else:
            policy_choices = [("", _("No network policies available"))]
        self.fields['srcpols'].choices = policy_choices
        self.fields['dstpols'].choices = policy_choices

        if network_list:
            network_choices = network_list
        else:
            network_choices = []
        self.fields['srcnets'].choices = network_choices
        self.fields['dstnets'].choices = network_choices

        pol_id = kwargs['initial']['id']
        sequence_id_choices = [("last", "Last Rule"),
                               ("first", "First Rule")]
        try:
            pol_obj = policy_show(self.request, policy_id=pol_id)

            seq_list = []
            for rule in pol_obj['entries']['policy_rule']:
                seq_val = "after:{0}".format(rule['rule_sequence'])
                seq_val_lbl = "{0}".format(rule['rule_sequence'])
                seq_list.append((seq_val, seq_val_lbl))
            sequence_id_choices.append(('After Rule', seq_list))
        except:
            pol_obj = {}

        self.fields['sequence_id'].choices = sequence_id_choices

    def clean(self):
        cleaned_data = super(AddRule, self).clean()
        simple_action = cleaned_data.get("simple_action", None)
        direction = cleaned_data.get("direction", None)
        protocol = cleaned_data.get("protocol", None)
        src_ports = cleaned_data.get("src_ports", None)
        dst_ports = cleaned_data.get("dst_ports", None)
        sequence_id = cleaned_data.get("sequence_id", None)
        srctype = cleaned_data.get("srctype", None)
        dsttype = cleaned_data.get("dsttype", None)
        srccidr = cleaned_data.get("srccidr", None)
        srcnets = cleaned_data.get("srcnets", None)
        srcpols = cleaned_data.get("srcpols", None)
        dstcidr = cleaned_data.get("dstcidr", None)
        dstnets = cleaned_data.get("dstnets", None)
        dstpols = cleaned_data.get("dstpols", None)

        return cleaned_data

    def handle(self, request, data):
        policy_id = data['id']
        src_port_list = []
        if data['src_ports'] == 'any':
            sport = {'end_port': -1, 'start_port': -1}
            src_port_list.append(sport)
        elif len(data['src_ports']):
            src_port_str = data['src_ports'].split(',')
            for s in src_port_str:
                range_str = s.split('-')
                if len(range_str) == 2:
                    sport = {'end_port': int(range_str[1]),
                             'start_port': int(range_str[0])}
                elif len(range_str) == 1:
                    sport = {'end_port': int(range_str[0]),
                             'start_port': int(range_str[0])}
                src_port_list.append(sport)

        dst_port_list = []
        if data['dst_ports'] == 'any':
            dport = {'end_port': -1, 'start_port': -1}
            dst_port_list.append(dport)
        elif len(data['dst_ports']):
            dst_port_str = data['dst_ports'].split(',')
            for d in dst_port_str:
                drange_str = d.split('-')
                if len(drange_str) == 2:
                    dport = {'end_port': int(drange_str[1]),
                             'start_port': int(drange_str[0])}
                elif len(drange_str) == 1:
                    dport = {'end_port': int(drange_str[0]),
                             'start_port': int(drange_str[0])}
                dst_port_list.append(dport)

        rule = {'direction': data['direction'],
                'protocol': data['protocol'],
                'action_list': {'simple_action': data['simple_action']},
                'src_ports': src_port_list,
                'dst_ports': dst_port_list,
                'application': [],
                'rule_sequence': {'major': -1, 'minor': -1}}

        if data['srctype'] == 'srcnets':
            rule['src_addresses'] = [{
                'security_group': None,
                'subnet': None,
                'virtual_network': data['srcnets'],
                'network_policy': None
            }]
        elif data['srctype'] == 'srccidr':
            ip = IPNetwork(data['srccidr'])
            rule['src_addresses'] = [{
                'security_group': None,
                'subnet': {
                    'ip_prefix': str(ip.ip),
                    'ip_prefix_len': ip.prefixlen
                },
                'virtual_network': None,
                'network_policy': None
            }]
        elif data['srctype'] == 'srcpols':
            rule['src_addresses'] = [{
                'security_group': None,
                'subnet': None,
                'virtual_network': None,
                'network_policy': data['srcpols']
            }]

        if data['dsttype'] == 'dstnets':
            rule['dst_addresses'] = [{
                'security_group': None,
                'subnet': None,
                'virtual_network': data['dstnets'],
                'network_policy': None
            }]
        elif data['dsttype'] == 'dstcidr':
            ip = IPNetwork(data['dstcidr'])
            rule['dst_addresses'] = [{
                'security_group': None,
                'subnet': {
                    'ip_prefix': str(ip.ip),
                    'ip_prefix_len': ip.prefixlen
                },
                'virtual_network': None,
                'network_policy': None
            }]
        elif data['dsttype'] == 'dstpols':
            rule['dst_addresses'] = [{
                'security_group': None,
                'subnet': None,
                'virtual_network': None,
                'network_policy': data['dstpols']
            }]

        try:
            policy_obj = policy_show(request, policy_id=policy_id)
            if not policy_obj['entries']:
                policy_obj['entries'] = {}
                policy_obj['entries']['policy_rule'] = []
            if data['sequence_id'] == 'last':
                policy_obj['entries']['policy_rule'].append(rule)
            elif data['sequence_id'] == 'first':
                policy_obj['entries']['policy_rule'].insert(0, rule)
            else:
                seq = int(data['sequence_id'].split(':')[1])
                policy_obj['entries']['policy_rule'].insert(seq, rule)

            policy_update_dict = policy_obj.__dict__['_apidict']['entries']

            for rule in policy_update_dict['policy_rule']:
                rule['rule_sequence'] = {'major': -1, 'minor': -1}

            policy = policy_modify(request, policy_id=policy_id,
                                   entries=policy_update_dict)
            messages.success(request,
                             _('Successfully added rule to policy : %s') % policy.name)
            return policy
        except:
            redirect = reverse("horizon:project:networks:"
                               "policy:detail", args=[data['id']])
            exceptions.handle(request, _('Unable to add rule to policy.'),
                              redirect=redirect)
