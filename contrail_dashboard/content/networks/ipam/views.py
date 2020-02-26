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

from contrail_dashboard.content.networks.ipam import forms as project_forms
from contrail_dashboard.content.networks.ipam import tables as project_tables


class UpdateView(forms.ModalFormView):
    form_class = project_forms.UpdateIpam
    template_name = 'project/networks/ipam/update.html'
    success_url = reverse_lazy('horizon:project:networks:index')

    def get_object(self):
        if not hasattr(self, "_object"):
            ipam_id = filters.get_int_or_uuid(self.kwargs['ipam_id'])
            try:
                self._object = ipam_show(self.request, ipam_id)
            except Exception:
                msg = _('Unable to retrieve network ipam.')
                url = reverse('horizon:project:networks:index')
                exceptions.handle(self.request, msg, redirect=url)
        return self._object

    def get_context_data(self, **kwargs):
        context = super(UpdateView, self).get_context_data(**kwargs)
        context["ipam"] = self.get_object()
        return context

    def get_initial(self):
        ipam = self.get_object()
        return {'id': self.kwargs['ipam_id'],
                'name': ipam.name}

    def get_form_kwargs(self):
        kwargs = super(UpdateView, self).get_form_kwargs()
        ipam = self.get_object()
        kwargs['ipam_obj'] = ipam
        return kwargs


class CreateView(forms.ModalFormView):
    form_class = project_forms.CreateNetworkIpam
    template_name = 'project/networks/ipam/create.html'
    success_url = reverse_lazy('horizon:project:networks:index')
