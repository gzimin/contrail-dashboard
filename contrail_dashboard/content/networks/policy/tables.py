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


class PolicyFilterAction(tables.FilterAction):
    def filter(self, table, policy, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (policy.name or "").lower()]):
                return True
            return False

        return filter(comp, policy)


class DeletePolicy(tables.DeleteAction):
    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Network Policy",
            u"Delete Network Policies",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Deleted Network Policy",
            u"Deleted Network Policies",
            count
        )

    def delete(self, request, obj_id):
        policy_delete(request, obj_id)


class CreatePolicy(tables.LinkAction):
    name = "create"
    verbose_name = _("Create Network Policy")
    url = "horizon:project:networks:policy:create"
    icon = "plus"
    classes = ("ajax-modal", "btn-create")


class EditPolicy(tables.LinkAction):
    name = "edit"
    verbose_name = _("Edit Network Policy")
    url = "horizon:project:networks:policy:update"
    icon = "pencil"
    classes = ("ajax-modal", "btn-edit")


class EditRules(tables.LinkAction):
    name = "edit_rules"
    verbose_name = _("Edit Rules")
    url = "horizon:project:networks:policy:detail"
    icon = "pencil"
    classes = ("btn-edit")


def get_associated_nets(policy):
    if hasattr(policy, 'nets_using') and len(policy['nets_using']):
        template_name = 'project/networks/_networks.html'
        context = {"networks": policy.nets_using}
        return template.loader.render_to_string(template_name, context)
    else:
        return '-'


def policy_net_display(nets):
    net_disp_all = ''
    for net in nets:
        net_disp = ''
        if net['security_group'] is not None:
            net_disp += 'security-group ' + str(net['security_group'])
        if net['subnet'] is not None:
            net_disp += str(net['subnet']['ip_prefix']) + "/" + str(net['subnet']['ip_prefix_len'])

        if net['virtual_network'] is not None:
            net_disp += 'network '
            net_fqn = net['virtual_network'].split(':')
            if len(net_fqn) == 3:
                net_disp += "{0} ({1})".format(net_fqn[2],
                                               net_fqn[1])
            else:
                net_disp += net_fqn[0].upper()

        if 'network_policy' in net:
            if net['network_policy'] is not None:
                net_disp += 'policy '
                pol_fqn = net['network_policy'].split(':')
                if len(pol_fqn) == 3:
                    net_disp += "{0} ({1})".format(pol_fqn[2],
                                                   pol_fqn[1])
                else:
                    net_disp += pol_fqn[0].upper()

    return net_disp


def policy_ports_display(ports):
    ports_str = ''
    if len(ports) == 1 and ports[0]['start_port'] == -1:
        ports_str += "ANY"
    else:
        for p in ports:
            ports_str += " " + str(p['start_port'])
            if p['start_port'] != p['end_port']:
                ports_str += "-" + str(p['end_port'])
            if not p == ports[-1]:
                ports_str += ","

    return ports_str


def get_policy_rule_action(rule):
    rule_display = ''
    if 'simple_action' in rule and rule['simple_action'] is not None:
        rule_display += rule['simple_action']
    elif rule['action_list']:
        if rule['action_list']['simple_action']:
            rule_display += rule['action_list']['simple_action']
        else:
            rule_display += 'pass'
    return rule_display.upper()


def get_policy_rule_protocol(rule):
    return rule['protocol'].upper()


def format_policy_rule(rule):
    rule_display = ''
    if 'simple_action' in rule and rule['simple_action'] is not None:
        rule_display += rule['simple_action']
    elif rule['action_list']:
        if rule['action_list']['simple_action']:
            rule_display += rule['action_list']['simple_action']
        else:
            rule_display += 'pass'

    if not len(rule['application']):
        rule_display += " protocol " + rule['protocol']
        rule_display += " " + policy_net_display(rule['src_addresses']).lower()
        rule_display += ' ports ' + policy_ports_display(rule['src_ports']).lower()
        rule_display += " " + rule['direction']
        rule_display += " " + policy_net_display(rule['dst_addresses']).lower()
        rule_display += ' ports ' + policy_ports_display(rule['dst_ports']).lower()

    if rule['action_list']:
        if rule['action_list']['gateway_name'] or \
           rule['action_list']['apply_service'] or \
           rule['action_list']['assign_routing_instance'] or \
           rule['action_list']['mirror_to']:
            rule_display += " action "
        if rule['action_list']['gateway_name']:
            rule_display += 'gateway ' + rule['action_list']['gateway']
        if rule['action_list']['assign_routing_instance']:
            rule_display += 'route ' + rule['action_list']['assign_routing_instance']
        if rule['action_list']['apply_service']:
            rule_display += "services "
            for service in rule['action_list']['apply_service']:
                service_fqn = service.split(':')
                rule_display += " " + service_fqn[2] + ' (' + service_fqn[1] + ')'
        if rule['action_list']['mirror_to']:
            rule_display += "mirrors "
            ana_fqn = rule['action_list']['mirror_to']['analyzer_name'].split(':')
            rule_display += " " + ana_fqn[2] + ' (' + ana_fqn[1] + ')'
    return rule_display


def get_rule_source(rule):
    template_name = 'project/networks/policy/_rule_source_format.html'
    rule_nets = policy_net_display(rule['src_addresses']).split()
    context = {'nets': rule_nets}
    return template.loader.render_to_string(template_name, context)


def get_rule_dest(rule):
    template_name = 'project/networks/policy/_rule_source_format.html'
    rule_nets = policy_net_display(rule['dst_addresses']).split()
    context = {'nets': rule_nets}
    return template.loader.render_to_string(template_name, context)


def get_source_port_range(rule):
    return policy_ports_display(rule['src_ports'])


def get_dest_port_range(rule):
    return policy_ports_display(rule['dst_ports'])


def format_rule_actions(rule):
    rule_display = ''
    if rule['action_list']:
        if rule['action_list']['gateway_name']:
            rule_display += 'gateway ' + rule['action_list']['gateway']
        if rule['action_list']['assign_routing_instance']:
            rule_display += 'route ' + rule['action_list']['assign_routing_instance']
        if rule['action_list']['apply_service']:
            rule_display += "services "
            for service in rule['action_list']['apply_service']:
                service_fqn = service.split(':')
                rule_display += " " + service_fqn[2] + ' (' + service_fqn[1] + ')'
        if rule['action_list']['mirror_to']:
            rule_display += "mirrors "
            ana_fqn = rule['action_list']['mirror_to']['analyzer_name'].split(':')
            rule_display += " " + ana_fqn[2] + ' (' + ana_fqn[1] + ')'
    if not len(rule_display):
        return '-'
    return rule_display


def get_rule_actions(rule):
    template_name = 'project/networks/policy/_rule_action_format.html'
    rule_actions = format_rule_actions(rule).split()
    context = {'actions': rule_actions}
    return template.loader.render_to_string(template_name, context)


def format_policy_rule_sequence(rule):
    sequence = rule['rule_sequence']
    if sequence:
        return "{0}".format(sequence)
    return "None"


def get_policy_rules(policy):
    template_name = 'project/networks/policy/_rule_format.html'
    if hasattr(policy, 'entries'):
        rule_arr = []
        try:
            for rule in policy.entries['policy_rule']:
                rule_arr.append(format_policy_rule(rule).split(' '))
        except:
            pass
    else:
        rule_arr = []
    context = {'rules': rule_arr}
    if not len(rule_arr):
        return '-'
    return template.loader.render_to_string(template_name, context)


class NetworkPolicyTable(tables.DataTable):
    name = tables.Column("name", verbose_name=_("Name"))
    assoc_nets = tables.Column(get_associated_nets, verbose_name=_("Associated Networks"))
    policy_rules = tables.Column(get_policy_rules, verbose_name=_("Rules"))

    def sanitize_id(self, obj_id):
        return filters.get_int_or_uuid(obj_id)

    class Meta:
        name = "policy"
        verbose_name = _("Network Policies")
        table_actions = (PolicyFilterAction, CreatePolicy, DeletePolicy,)
        row_actions = (EditRules, DeletePolicy)


class CreateRule(tables.LinkAction):
    name = "add_rule"
    verbose_name = _("Add Rule")
    url = "horizon:project:networks:policy:add_rule"
    icon = "plus"
    classes = ("ajax-modal", "btn-create")

    def get_link_url(self):
        return reverse(self.url, args=[self.table.kwargs['policy_id']])


class DeleteRule(tables.DeleteAction):
    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Rule",
            u"Delete Rules",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Deleted Rule",
            u"Deleted Rules",
            count
        )

    def get_success_url(self, request):
        pol_id = self.table.kwargs['policy_id']
        return reverse("horizon:project:networks:"
                       "policy:detail", args=[pol_id])

    def delete(self, request, obj_id):
        policy_id = self.table.kwargs['policy_id']
        policy = policy_show(request, policy_id=policy_id)
        rules = policy['entries']['policy_rule']
        rule_obj = ast.literal_eval(obj_id)
        rule_obj.pop('policy_id', None)
        rule_obj['rule_sequence'] = {}
        for r in rules:
            r['rule_sequence'] = {}
            if cmp(rule_obj, r) == 0:
                rules.remove(r)
                break
        for r in rules:
            r['rule_sequence'] = {'major': -1,
                                  'minor': -1}

        rules_dict = policy.__dict__['_apidict']['entries']
        pol = policy_modify(request, policy_id=policy_id,
                            entries=rules_dict)

        return reverse("horizon:project:networks:"
                       "policy:detail", args=[policy_id])


class RulesTable(tables.DataTable):
    sequence = tables.Column(format_policy_rule_sequence,
                             verbose_name=_("#"))
    action = tables.Column(get_policy_rule_action,
                           verbose_name=_("Action"))
    protocol = tables.Column(get_policy_rule_protocol,
                             verbose_name=_("Protocol"))
    source = tables.Column(get_rule_source,
                           verbose_name=_("Source"))
    source_port = tables.Column(get_source_port_range,
                                verbose_name=_("Ports"))
    direction = tables.Column("direction",
                              verbose_name=_("Direction"))
    destination = tables.Column(get_rule_dest,
                                verbose_name=_("Destination"))
    dest_port = tables.Column(get_dest_port_range,
                              verbose_name=_("Ports"))
    servcies = tables.Column(get_rule_actions,
                             verbose_name=_("Rule Actions"))

    # def sanitize_id(self, obj_id):
    #     return filters.get_int_or_uuid(obj_id)

    def get_object_display(self, rules):
        return str(format_policy_rule(rules))

    def get_object_name(self, rules):
        return str(format_policy_rule_sequence(rules))

    def get_object_id(self, rules):
        return unicode(rules)

    class Meta:
        name = "rules"
        verbose_name = _("Network Policy Rules")
        table_actions = (CreateRule, DeleteRule)
