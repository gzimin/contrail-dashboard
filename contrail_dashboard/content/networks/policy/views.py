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

"""
Views for managing instances.
"""
from django.core.urlresolvers import reverse  # noqa
from django.core.urlresolvers import reverse_lazy  # noqa
from django.utils.translation import ugettext_lazy as _  # noqa

from horizon import exceptions
from horizon import forms
from horizon import tables

from openstack_dashboard import api
from contrail_dashboard.api.contrail_quantum import *
from openstack_dashboard.utils import filters

from contrail_dashboard.content.networks.policy import forms as project_forms
from contrail_dashboard.content.networks.policy import tables as project_tables


class DetailView(tables.DataTableView):
    table_class = project_tables.RulesTable
    template_name = 'project/networks/policy/detail.html'

    def _get_data(self):
        if not hasattr(self, '_pol'):
            pol_id = filters.get_int_or_uuid(self.kwargs['policy_id'])
            try:
                self._pol = policy_show(self.request, pol_id)
            except Exception:
                redirect = reverse('horizon:project:networks:index')
                exceptions.handle(self.request,
                                  _('Unable to retrieve network policy.'),
                                  redirect=redirect)
        return self._pol

    def get_data(self):
        rules = []
        try:
            entries = self._get_data().entries
            if entries:
                rules = entries['policy_rule']
                for r in rules:
                    r['policy_id'] = self._get_data().id
        except:
            self.object = None
            exceptions.handle(self.request,
                              _('Unable to retrieve policy rules.'))
        return rules

    def get_context_data(self, **kwargs):
        context = super(DetailView, self).get_context_data(**kwargs)
        context["policy"] = self._get_data()
        return context


class UpdateView(forms.ModalFormView):
    form_class = project_forms.UpdatePolicy
    template_name = 'project/networks/policy/update.html'
    success_url = reverse_lazy('horizon:project:networks:index')

    def get_object(self):
        if not hasattr(self, "_object"):
            pol_id = filters.get_int_or_uuid(self.kwargs['policy_id'])
            try:
                self._object = policy_show(self.request, pol_id)
            except Exception:
                msg = _('Unable to retrieve network policy.')
                url = reverse('horizon:project:networks:index')
                exceptions.handle(self.request, msg, redirect=url)
        return self._object

    def get_context_data(self, **kwargs):
        context = super(UpdateView, self).get_context_data(**kwargs)
        context["policy"] = self.get_object()
        return context

    def get_initial(self):
        policy = self.get_object()
        return {'id': self.kwargs['policy_id'],
                'name': policy.name}


class AddRuleView(forms.ModalFormView):
    form_class = project_forms.AddRule
    template_name = 'project/networks/policy/add_rule.html'

    def get_success_url(self):
        pol_id = self.kwargs['policy_id']
        return reverse("horizon:project:networks:"
                       "policy:detail", args=[pol_id])

    def get_context_data(self, **kwargs):
        context = super(AddRuleView, self).get_context_data(**kwargs)
        context["policy_id"] = self.kwargs['policy_id']
        return context

    def get_initial(self):
        return {'id': self.kwargs['policy_id']}

    def get_form_kwargs(self):
        kwargs = super(AddRuleView, self).get_form_kwargs()

        try:
            policies = policy_summary(self.request)
        except Exception:
            policies = []

        network_policies = []
        for policy in policies:
                network_policies.append(("{0}:{1}:{2}".format(policy.fq_name[0],
                                                              policy.fq_name[1],
                                                              policy.fq_name[2]),
                                         "{0} ({1})".format(policy.fq_name[2],
                                                            policy.fq_name[1])))
        kwargs['policy_list'] = network_policies

        try:
            nets = api.neutron.network_list(self.request)
        except Exception:
            nets = []

        networks = [('any', 'ANY (All Networks in Current Project)'),
                    ('local', 'LOCAL (All Networks to which this policy is associated)')]
        for network in nets:
                networks.append(("{0}:{1}:{2}".format(network.fq_name[0],
                                                      network.fq_name[1],
                                                      network.fq_name[2]),
                                 "{0} ({1})".format(network.fq_name[2],
                                                    network.fq_name[1])))
        kwargs['network_list'] = networks

        services = [('default-domain:admin:test', 'test'), ('default-domain:demo:svc-2', 'svc-2')]
        kwargs['services_list'] = services

        return kwargs


class CreateView(forms.ModalFormView):
    form_class = project_forms.CreatePolicy
    template_name = 'project/networks/policy/create.html'
    success_url = reverse_lazy('horizon:project:networks:index')
