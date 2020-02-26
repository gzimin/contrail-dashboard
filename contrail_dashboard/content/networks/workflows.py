# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NEC Corporation
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


import logging
import netaddr

from distutils.version import LooseVersion
from django.core.urlresolvers import reverse  # noqa
from django.utils.translation import ugettext_lazy as _  # noqa

from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.forms import fields
from horizon import workflows

from openstack_dashboard import api
from openstack_dashboard.dashboards.project.networks.subnets import utils
from openstack_dashboard import policy

from contrail_dashboard.api.contrail_quantum import *

LOG = logging.getLogger(__name__)

IPAM_CREATE_URL = "horizon:project:networks:ipam:create"
OC_VERSION = getattr(settings, "OPENCONTRAIL_VERSION", "3.2")

POLICYS_KEY = "contrail:policys"
IPAM_FQ_NAME_KEY = "contrail:ipam_fq_name"
if LooseVersion(OC_VERSION) >= LooseVersion("4.0"):
    POLICYS_KEY = "policys"
    IPAM_FQ_NAME_KEY = "ipam_fq_name"


class CreateNetworkInfoAction(workflows.Action):
    net_name = forms.CharField(max_length=255,
                               label=_("Network Name"),
                               required=False)
    admin_state = forms.BooleanField(
        label=_("Enable Admin State"),
        initial=True,
        required=False,
        help_text=_("The state to start the network in."))
    shared = forms.BooleanField(label=_("Shared"), initial=False,
                                required=False)
    with_subnet = forms.BooleanField(label=_("Create Subnet"),
                                     widget=forms.CheckboxInput(attrs={
                                         'class': 'switchable',
                                         'data-slug': 'with_subnet',
                                         'data-hide-tab': 'create_network__'
                                                          'createsubnetinfo'
                                                          'action,'
                                                          'create_network__'
                                                          'createsubnetdetail'
                                                          'action',
                                         'data-hide-on-checked': 'false'
                                     }),
                                     initial=True,
                                     required=False)

    def __init__(self, request, *args, **kwargs):
        super(CreateNetworkInfoAction, self).__init__(request,
                                                      *args, **kwargs)
        if not policy.check((("network", "create_network:shared"),), request):
            self.fields['shared'].widget = forms.HiddenInput()

    class Meta:
        name = _("Network")
        help_text = _('Create a new network. '
                      'In addition, a subnet associated with the network '
                      'can be created in the following steps of this wizard.')


class CreateNetworkInfo(workflows.Step):
    action_class = CreateNetworkInfoAction
    contributes = ("net_name", "admin_state", "with_subnet", "shared")


class CreateSubnetInfoAction(workflows.Action):
    subnet_name = forms.CharField(max_length=255,
                                  widget=forms.TextInput(attrs={
                                  }),
                                  label=_("Subnet Name"),
                                  required=False)

    ipam = forms.DynamicTypedChoiceField(label=_("IPAM"),
                                         required=False,
                                         empty_value=None,
                                         add_item_link=IPAM_CREATE_URL,
                                         help_text=_("Choose IPAM that will be "
                                                     "associated with the IP Block"))

    address_source = forms.ChoiceField(
        required=False,
        label=_('Network Address Source'),
        choices=[('manual', _('Enter Network Address manually')),
                 ('subnetpool', _('Allocate Network Address from a pool'))],
        widget=forms.ThemableSelectWidget(attrs={
            'class': 'switchable',
            'data-slug': 'source',
        }))

    subnetpool = forms.ChoiceField(
        label=_("Address pool"),
        widget=forms.ThemableSelectWidget(attrs={
            'class': 'switched switchable',
            'data-slug': 'subnetpool',
            'data-switch-on': 'source',
            'data-source-subnetpool': _('Address pool')},
            data_attrs=('name', 'prefixes',
                        'ip_version',
                        'min_prefixlen',
                        'max_prefixlen',
                        'default_prefixlen'),
            transform=lambda x: "%s (%s)" % (x.name, ", ".join(x.prefixes))
                                if 'prefixes' in x else "%s" % (x.name)),
        required=False)

    prefixlen = forms.ChoiceField(widget=forms.ThemableSelectWidget(attrs={
                                  'class': 'switched',
                                  'data-switch-on': 'subnetpool',
                                  }),
                                  label=_('Network Mask'),
                                  required=False)

    cidr = forms.IPField(label=_("Network Address"),
                         required=False,
                         initial="",
                         widget=forms.TextInput(attrs={
                             'class': 'switched',
                             'data-switch-on': 'source',
                             'data-source-manual': _("Network Address"),
                         }),
                         help_text=_("Network address in CIDR format "
                                     "(e.g. 192.168.0.0/24, 2001:DB8::/48)"),
                         version=forms.IPv4 | forms.IPv6,
                         mask=True)
    ip_version = forms.ChoiceField(choices=[(4, 'IPv4'), (6, 'IPv6')],
                                   widget=forms.ThemableSelectWidget(attrs={
                                       'class': 'switchable',
                                       'data-slug': 'ipversion',
                                   }),
                                   label=_("IP Version"),
                                   required=False)
    gateway_ip = forms.IPField(
        label=_("Gateway IP"),
        widget=forms.TextInput(attrs={
            'class': 'switched',
            'data-switch-on': 'gateway_ip',
            'data-source-manual': _("Gateway IP")
        }),
        required=False,
        initial="",
        help_text=_("IP address of Gateway (e.g. 192.168.0.254) "
                    "The default value is the first IP of the "
                    "network address "
                    "(e.g. 192.168.0.1 for 192.168.0.0/24, "
                    "2001:DB8::1 for 2001:DB8::/48). "
                    "If you use the default, leave blank. "
                    "If you do not want to use a gateway, "
                    "check 'Disable Gateway' below."),
        version=forms.IPv4 | forms.IPv6,
        mask=False)
    no_gateway = forms.BooleanField(label=_("Disable Gateway"),
                                    widget=forms.CheckboxInput(attrs={
                                        'class': 'switchable',
                                        'data-slug': 'gateway_ip',
                                        'data-hide-on-checked': 'true'
                                    }),
                                    initial=False,
                                    required=False)

    check_subnet_range = True

    class Meta(object):
        name = _("Subnet")
        help_text = _('Creates a subnet associated with the network.'
                      ' You need to enter a valid "Network Address"'
                      ' and "Gateway IP". If you did not enter the'
                      ' "Gateway IP", the first value of a network'
                      ' will be assigned by default. If you do not want'
                      ' gateway please check the "Disable Gateway" checkbox.'
                      ' Advanced configuration is available by clicking on'
                      ' the "Subnet Details" tab.')

    def __init__(self, request, context, *args, **kwargs):
        super(CreateSubnetInfoAction, self).__init__(request, context, *args,
                                                     **kwargs)
        if 'with_subnet' in context:
            self.fields['with_subnet'] = forms.BooleanField(
                initial=context['with_subnet'],
                required=False,
                widget=forms.HiddenInput()
            )

        if not getattr(settings, 'OPENSTACK_NEUTRON_NETWORK',
                       {}).get('enable_ipv6', True):
            self.fields['ip_version'].widget = forms.HiddenInput()
            self.fields['ip_version'].initial = 4

        try:
            if api.neutron.is_extension_supported(request,
                                                  'subnet_allocation'):
                self.fields['subnetpool'].choices = \
                    self.get_subnetpool_choices(request)
            else:
                self.hide_subnetpool_choices()
        except Exception:
            self.hide_subnetpool_choices()
            msg = _('Unable to initialize subnetpools')
            exceptions.handle(request, msg)
        if len(self.fields['subnetpool'].choices) > 1:
            # Pre-populate prefixlen choices to satisfy Django
            # ChoiceField Validation. This is overridden w/data from
            # subnetpool on select.
            self.fields['prefixlen'].choices = \
                zip(list(range(0, 128 + 1)),
                    list(range(0, 128 + 1)))
            # Populate data-fields for switching the prefixlen field
            # when user selects a subnetpool other than
            # "Provider default pool"
            for (id, name) in self.fields['subnetpool'].choices:
                if not len(id):
                    continue
                key = 'data-subnetpool-' + id
                self.fields['prefixlen'].widget.attrs[key] = \
                    _('Network Mask')
        else:
            self.hide_subnetpool_choices()

        # Create IPAM choices
        tenant_id = self.request.user.tenant_id
        try:
            ipams = ipam_summary(self.request)
            if ipams:
                ipam_choices = [(ipam.id, "{0} ({1})".format(ipam.fq_name[2], ipam.fq_name[1]))
                                for ipam
                                in ipams]
                ipam_choices.append(('None', 'None'))
            else:
                ipam_choices = [('None', 'Create a new IPAM')]
        except:
            ipam_choices = [('None', 'None')]
            exceptions.handle(self.request, _('Unable to retrieve ipam list'))
        self.fields['ipam'].choices = ipam_choices

    def get_subnetpool_choices(self, request):
        subnetpool_choices = [('', _('Select a pool'))]

        for subnetpool in api.neutron.subnetpool_list(request):
            subnetpool_choices.append((subnetpool.id, subnetpool))
        return subnetpool_choices

    def hide_subnetpool_choices(self):
        self.fields['address_source'].widget = forms.HiddenInput()
        self.fields['subnetpool'].choices = []
        self.fields['subnetpool'].widget = forms.HiddenInput()
        self.fields['prefixlen'].widget = forms.HiddenInput()

    def _check_subnet_range(self, subnet, allow_cidr):
        allowed_net = netaddr.IPNetwork(allow_cidr)
        return subnet in allowed_net

    def _check_cidr_allowed(self, ip_version, subnet):
        if not self.check_subnet_range:
            return

        allowed_cidr = getattr(settings, "ALLOWED_PRIVATE_SUBNET_CIDR", {})
        version_str = 'ipv%s' % ip_version
        allowed_ranges = allowed_cidr.get(version_str, [])
        if allowed_ranges:
            under_range = any(self._check_subnet_range(subnet, allowed_range)
                              for allowed_range in allowed_ranges)
            if not under_range:
                range_str = ', '.join(allowed_ranges)
                msg = (_("CIDRs allowed for user private %(ip_ver)s "
                         "networks are %(allowed)s.") %
                       {'ip_ver': '%s' % version_str,
                        'allowed': range_str})
                raise forms.ValidationError(msg)

    def _check_subnet_data(self, cleaned_data, is_create=True):
        cidr = cleaned_data.get('cidr')
        ipam = cleaned_data.get('ipam')
        ip_version = int(cleaned_data.get('ip_version'))
        gateway_ip = cleaned_data.get('gateway_ip')
        no_gateway = cleaned_data.get('no_gateway')
        address_source = cleaned_data.get('address_source')
        subnetpool = cleaned_data.get('subnetpool')

        if not subnetpool and address_source == 'subnetpool':
            msg = _('Specify "Address pool" or select '
                    '"Enter Network Address manually" and specify '
                    '"Network Address".')
            raise forms.ValidationError(msg)
        if not cidr and address_source != 'subnetpool':
            msg = _('Specify "Network Address" or '
                    'clear "Create Subnet" checkbox in previous step.')
            raise forms.ValidationError(msg)
        if cidr:
            subnet = netaddr.IPNetwork(cidr)
            if subnet.version != ip_version:
                msg = _('Network Address and IP version are inconsistent.')
                raise forms.ValidationError(msg)
            if (ip_version == 4 and subnet.prefixlen == 32) or \
                    (ip_version == 6 and subnet.prefixlen == 128):
                msg = _("The subnet in the Network Address is "
                        "too small (/%s).") % subnet.prefixlen
                self._errors['cidr'] = self.error_class([msg])
            self._check_cidr_allowed(ip_version, subnet)

        if not no_gateway and gateway_ip:
            if netaddr.IPAddress(gateway_ip).version is not ip_version:
                msg = _('Gateway IP and IP version are inconsistent.')
                raise forms.ValidationError(msg)
        if not is_create and not no_gateway and not gateway_ip:
            msg = _('Specify IP address of gateway or '
                    'check "Disable Gateway" checkbox.')
            raise forms.ValidationError(msg)

    def clean(self):
        cleaned_data = super(CreateSubnetInfoAction, self).clean()
        with_subnet = cleaned_data.get('with_subnet')
        if not with_subnet:
            return cleaned_data
        self._check_subnet_data(cleaned_data)
        return cleaned_data


class CreateSubnetInfo(workflows.Step):
    action_class = CreateSubnetInfoAction
    contributes = ("subnet_name", "ipam", "cidr",
                   "ip_version", "gateway_ip", "no_gateway",
                   "subnetpool", "prefixlen", "address_source")


class CreateSubnetDetailAction(workflows.Action):
    enable_dhcp = forms.BooleanField(label=_("Enable DHCP"),
                                     initial=True, required=False)
    ipv6_modes = forms.ChoiceField(
        label=_("IPv6 Address Configuration Mode"),
        widget=forms.ThemableSelectWidget(attrs={
            'class': 'switched',
            'data-switch-on': 'ipversion',
            'data-ipversion-6': _("IPv6 Address Configuration Mode"),
        }),
        initial=utils.IPV6_DEFAULT_MODE,
        required=False,
        help_text=_("Specifies how IPv6 addresses and additional information "
                    "are configured. We can specify SLAAC/DHCPv6 stateful/"
                    "DHCPv6 stateless provided by OpenStack, "
                    "or specify no option. "
                    "'No options specified' means addresses are configured "
                    "manually or configured by a non-OpenStack system."))
    allocation_pools = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4}),
        label=_("Allocation Pools"),
        help_text=_("IP address allocation pools. Each entry is: "
                    "start_ip_address,end_ip_address "
                    "(e.g., 192.168.1.100,192.168.1.120) "
                    "and one entry per line."),
        required=False)
    dns_nameservers = forms.CharField(
        widget=forms.widgets.Textarea(attrs={'rows': 4}),
        label=_("DNS Name Servers"),
        help_text=_("IP address list of DNS name servers for this subnet. "
                    "One entry per line."),
        required=False)
    host_routes = forms.CharField(
        widget=forms.widgets.Textarea(attrs={'rows': 4}),
        label=_("Host Routes"),
        help_text=_("Additional routes announced to the hosts. "
                    "Each entry is: destination_cidr,nexthop "
                    "(e.g., 192.168.200.0/24,10.56.1.254) "
                    "and one entry per line."),
        required=False)

    class Meta:
        name = _("Subnet Detail")
        help_text = _('You can specify additional attributes for the subnet.')

    def __init__(self, request, context, *args, **kwargs):
        super(CreateSubnetDetailAction, self).__init__(request, context,
                                                       *args, **kwargs)
        if not getattr(settings, 'OPENSTACK_NEUTRON_NETWORK',
                       {}).get('enable_ipv6', True):
            self.fields['ipv6_modes'].widget = forms.HiddenInput()

    def populate_ipv6_modes_choices(self, request, context):
        return [(value, _("%s (Default)") % label)
                if value == utils.IPV6_DEFAULT_MODE
                else (value, label)
                for value, label in utils.IPV6_MODE_CHOICES]

    def _convert_ip_address(self, ip, field_name):
        try:
            return netaddr.IPAddress(ip)
        except (netaddr.AddrFormatError, ValueError):
            msg = (_('%(field_name)s: Invalid IP address (value=%(ip)s)')
                   % {'field_name': field_name, 'ip': ip})
            raise forms.ValidationError(msg)

    def _convert_ip_network(self, network, field_name):
        try:
            return netaddr.IPNetwork(network)
        except (netaddr.AddrFormatError, ValueError):
            msg = (_('%(field_name)s: Invalid IP address (value=%(network)s)')
                   % {'field_name': field_name, 'network': network})
            raise forms.ValidationError(msg)

    def _check_allocation_pools(self, allocation_pools):
        for p in allocation_pools.splitlines():
            p = p.strip()
            if not p:
                continue
            pool = p.split(',')
            if len(pool) != 2:
                msg = _('Start and end addresses must be specified '
                        '(value=%s)') % p
                raise forms.ValidationError(msg)
            start, end = [self._convert_ip_address(ip, "allocation_pools")
                          for ip in pool]
            if start > end:
                msg = _('Start address is larger than end address '
                        '(value=%s)') % p
                raise forms.ValidationError(msg)

    def _check_dns_nameservers(self, dns_nameservers):
        for ns in dns_nameservers.splitlines():
            ns = ns.strip()
            if not ns:
                continue
            self._convert_ip_address(ns, "dns_nameservers")

    def _check_host_routes(self, host_routes):
        for r in host_routes.splitlines():
            r = r.strip()
            if not r:
                continue
            route = r.split(',')
            if len(route) != 2:
                msg = _('Host Routes format error: '
                        'Destination CIDR and nexthop must be specified '
                        '(value=%s)') % r
                raise forms.ValidationError(msg)
            self._convert_ip_network(route[0], "host_routes")
            self._convert_ip_address(route[1], "host_routes")

    def clean(self):
        cleaned_data = super(CreateSubnetDetailAction, self).clean()
        self._check_allocation_pools(cleaned_data.get('allocation_pools'))
        self._check_host_routes(cleaned_data.get('host_routes'))
        self._check_dns_nameservers(cleaned_data.get('dns_nameservers'))
        return cleaned_data


class CreateSubnetDetail(workflows.Step):
    action_class = CreateSubnetDetailAction
    contributes = ("enable_dhcp", "ipv6_modes", "allocation_pools",
                   "dns_nameservers", "host_routes")


class UpdateNetworkPolicyAction(workflows.MembershipAction):
    def __init__(self, request, *args, **kwargs):
        super(UpdateNetworkPolicyAction, self).__init__(request,
                                                        *args,
                                                        **kwargs)
        err_msg = _('Unable to retrieve Network Policy list. '
                    'Please try again later.')
        context = args[0]

        default_role_field_name = self.get_default_role_field_name()
        self.fields[default_role_field_name] = forms.CharField(required=False)
        self.fields[default_role_field_name].initial = 'member'

        field_name = self.get_member_field_name('member')
        self.fields[field_name] = forms.MultipleChoiceField(required=False)

        # Fetch the policy list and add to policy options
        all_policies = []
        try:
            all_policies = policy_summary(self.request)
        except Exception:
            exceptions.handle(request, err_msg)

        policy_list = [("{0}:{1}:{2}".format(policy.fq_name[0],
                                             policy.fq_name[1],
                                             policy.fq_name[2]),
                        "{0} ({1})".format(policy.fq_name[2],
                                           policy.fq_name[1]))
                       for policy
                       in all_policies]

        self.fields[field_name].choices = policy_list

    class Meta:
        name = _("Associate Network Policies")
        slug = "update_network_policies"


class UpdateNetworkPolicy(workflows.UpdateMembersStep):
    action_class = UpdateNetworkPolicyAction
    help_text = _("You can associate Policies to this network by moving Policies "
                  "from the left column to the right column.")
    available_list_title = _("All Polices")
    members_list_title = _("Selected Policies")
    no_available_text = _("No Policies found.")
    no_members_text = _("No Policy selected.")
    show_roles = False
    # depends_on = ("network_id",)
    contributes = ("attached_policies",)

    def contribute(self, data, context):
        if data:
            member_field_name = self.get_member_field_name('member')
            context['attached_policies'] = data.get(member_field_name, [])
        return context


class CreateNetwork(workflows.Workflow):
    slug = "create_network"
    name = _("Create Network")
    finalize_button_name = _("Create")
    success_message = _('Created network "%s".')
    failure_message = _('Unable to create network "%s".')
    default_steps = (CreateNetworkInfo,
                     CreateSubnetInfo,
                     CreateSubnetDetail,
                     UpdateNetworkPolicy)

    def get_success_url(self):
        return reverse("horizon:project:networks:index")

    def get_failure_url(self):
        return reverse("horizon:project:networks:index")

    def format_status_message(self, message):
        name = self.context.get('net_name') or self.context.get('net_id', '')
        return message % name

    def _create_network(self, request, data):
        try:
            params = {'name': data['net_name'],
                      'admin_state_up': data['admin_state'],
                      'shared': data['shared']}
            policy_list = []
            for pol in data['attached_policies']:
                policy_str = pol.split(':')
                pol_fq_name = [policy_str[0],
                               policy_str[1],
                               policy_str[2]]
                policy_list.append(pol_fq_name)
            params[POLICYS_KEY] = policy_list
            network = api.neutron.network_create(request, **params)
            network.set_id_as_name_if_empty()
            self.context['net_id'] = network.id
            msg = _('Network "%s" was successfully created.') % network.name
            LOG.error(msg)
            return network
        except Exception as e:
            msg = (_('Failed to create network "%(network)s": %(reason)s') %
                   {"network": data['net_name'], "reason": e})
            LOG.info(msg)
            redirect = self.get_failure_url()
            exceptions.handle(request, msg, redirect=redirect)
            return False

    def _setup_subnet_parameters(self, params, data, is_create=True):
        """Setup subnet parameters

        This methods setups subnet parameters which are available
        in both create and update.
        """
        is_update = not is_create
        params['enable_dhcp'] = data['enable_dhcp']
        if int(data['ip_version']) == 6:
            ipv6_modes = utils.get_ipv6_modes_attrs_from_menu(
                data['ipv6_modes'])
            if ipv6_modes[0] and is_create:
                params['ipv6_ra_mode'] = ipv6_modes[0]
            if ipv6_modes[1] and is_create:
                params['ipv6_address_mode'] = ipv6_modes[1]
        if is_create and data['allocation_pools']:
            pools = [dict(zip(['start', 'end'], pool.strip().split(',')))
                     for pool in data['allocation_pools'].splitlines()
                     if pool.strip()]
            params['allocation_pools'] = pools
        if data['host_routes'] or is_update:
            routes = [dict(zip(['destination', 'nexthop'],
                               route.strip().split(',')))
                      for route in data['host_routes'].splitlines()
                      if route.strip()]
            params['host_routes'] = routes
        if data['dns_nameservers'] or is_update:
            nameservers = [ns.strip()
                           for ns in data['dns_nameservers'].splitlines()
                           if ns.strip()]
            params['dns_nameservers'] = nameservers

    def _create_subnet(self, request, data, network=None, tenant_id=None,
                       no_redirect=False):
        if network:
            network_id = network.id
            network_name = network.name
        else:
            network_id = self.context.get('network_id')
            network_name = self.context.get('network_name')

        if data['ipam'] != 'None':
            try:
                ipam_obj = ipam_show(self.request, ipam_id=data['ipam'])
                params = {'network_id': network_id,
                          'name': data['subnet_name'],
                          'cidr': data['cidr'],
                          'ip_version': int(data['ip_version']),
                          IPAM_FQ_NAME_KEY: ipam_obj.fq_name}
            except Exception as e:
                msg = _('Failed to read ipam "%(sub)s" for network "%(net)s": '
                        ' %(reason)s')
                if no_redirect:
                    redirect = None
                else:
                    redirect = self.get_failure_url()
                exceptions.handle(request,
                                  msg % {"sub": data['cidr'], "net": network_name,
                                         "reason": e},
                                  redirect=redirect)
        else:
            params = {'network_id': network_id,
                      'name': data['subnet_name']}
        try:
            if 'cidr' in data and data['cidr']:
                params['cidr'] = data['cidr']
            if 'ip_version' in data and data['ip_version']:
                params['ip_version'] = int(data['ip_version'])
            if tenant_id:
                params['tenant_id'] = tenant_id
            if data['no_gateway']:
                params['gateway_ip'] = None
            elif data['gateway_ip']:
                params['gateway_ip'] = data['gateway_ip']
            if 'subnetpool' in data and len(data['subnetpool']):
                params['subnetpool_id'] = data['subnetpool']
                if 'prefixlen' in data and len(data['prefixlen']):
                    params['prefixlen'] = data['prefixlen']

            self._setup_subnet_parameters(params, data)

            subnet = api.neutron.subnet_create(request, **params)
            self.context['subnet_id'] = subnet.id
            msg = _('Subnet "%s" was successfully created.') % data['cidr']
            LOG.debug(msg)
            return subnet
        except Exception as e:
            if network_name:
                msg = _('Failed to create subnet "%(sub)s" for network '
                        '"%(net)s": %(reason)s')
            else:
                msg = _('Failed to create subnet "%(sub)s": %(reason)s')
            if no_redirect:
                redirect = None
            else:
                redirect = self.get_failure_url()
            exceptions.handle(request,
                              msg % {"sub": data['cidr'], "net": network_name,
                                     "reason": e},
                              redirect=redirect)
            return False

    def _delete_network(self, request, network):
        """Delete the created network when subnet creation failed."""
        try:
            api.neutron.network_delete(request, network.id)
            LOG.debug('Delete the created network %s '
                      'due to subnet creation failure.', network.id)
            msg = _('Delete the created network "%s" '
                    'due to subnet creation failure.') % network.name
            redirect = self.get_failure_url()
            messages.info(request, msg)
            raise exceptions.Http302(redirect)
        except Exception as e:
            LOG.info('Failed to delete network %(id)s: %(exc)s',
                     {'id': network.id, 'exc': e})
            msg = _('Failed to delete network "%s"') % network.name
            redirect = self.get_failure_url()
            exceptions.handle(request, msg, redirect=redirect)

    def handle(self, request, data):
        network = self._create_network(request, data)
        if not network:
            return False
        # If we do not need to create a subnet, return here.
        if not data['with_subnet']:
            return True
        subnet = self._create_subnet(request, data, network, no_redirect=True)
        if subnet:
            return True
        else:
            self._delete_network(request, network)
            return False


class ModifyNetworkPolicyAction(workflows.MembershipAction):
    def __init__(self, request, *args, **kwargs):
        super(ModifyNetworkPolicyAction, self).__init__(request,
                                                        *args,
                                                        **kwargs)
        err_msg = _('Unable to retrieve Network Policy list. '
                    'Please try again later.')
        context = args[0]

        default_role_field_name = self.get_default_role_field_name()
        self.fields[default_role_field_name] = forms.CharField(required=False)
        self.fields[default_role_field_name].initial = 'member'

        field_name = self.get_member_field_name('member')
        self.fields[field_name] = forms.MultipleChoiceField(required=False)

        # Fetch the policy list and add to policy options
        all_policies = []
        try:
            all_policies = policy_summary(self.request)
        except Exception:
            exceptions.handle(request, err_msg)

        policy_list = [("{0}:{1}:{2}".format(policy.fq_name[0],
                                             policy.fq_name[1],
                                             policy.fq_name[2]),
                        "{0} ({1})".format(policy.fq_name[2],
                                           policy.fq_name[1]))
                       for policy
                       in all_policies]

        self.fields[field_name].choices = policy_list

        network_id = context.get('network_id', '')
        attached_pols = []
        network_policys = []
        msg = _('Rahul Net od %s') % str(network_id)
        LOG.error(msg)
        if network_id:
            net_obj = network_get(request, network_id)
            try:
                network_policys = net_obj.policys
            except:
                pass
        if network_policys:
            attached_pols = ["{0}:{1}:{2}".format(policy[0],
                                                  policy[1],
                                                  policy[2])
                             for policy
                             in network_policys]
        self.fields[field_name].initial = attached_pols
        msg = _('Rahul net policies %s') % str(network_policys)
        LOG.error(msg)
        msg = _('Rahul attached policies %s') % str(attached_pols)
        LOG.error(msg)

    def handle(self, request, data):
        attached_policies = data["attached_policies"]
        policy_list = []
        for pol in data['attached_policies']:
            policy_str = pol.split(':')
            pol_fq_name = [policy_str[0],
                           policy_str[1],
                           policy_str[2]]
            policy_list.append(pol_fq_name)
        params = {POLICYS_KEY: policy_list}
        net_id = data['network_id']
        try:
            network_update(request,
                           network_id=net_id, **params)
        except Exception:
            exceptions.handle(request, _('Unable to modify Associated Policies.'))
            return False
        return True

    class Meta:
        name = _("Modify Network Policies")
        slug = "modify_network_policies"


class ModifyNetworkPolicy(workflows.UpdateMembersStep):
    action_class = ModifyNetworkPolicyAction
    help_text = _("You can associate Policies to this network by moving Policies "
                  "from the left column to the right column.")
    available_list_title = _("All Polices")
    members_list_title = _("Selected Policies")
    no_available_text = _("No Policies found.")
    no_members_text = _("No Policy selected.")
    show_roles = False
    depends_on = ("network_id",)
    contributes = ("attached_policies",)

    def contribute(self, data, context):
        if data:
            member_field_name = self.get_member_field_name('member')
            context['attached_policies'] = data.get(member_field_name, [])
        return context


class UpdateNetworkAttachedPolicies(workflows.Workflow):
    slug = "update_network_attached_policies"
    name = _("Modify Associated Policies")
    finalize_button_name = _("Save")
    success_message = _('Modified Associated Policies "%s".')
    failure_message = _('Unable to modify associated policies')
    success_url = "horizon:project:networks:index"
    default_steps = (ModifyNetworkPolicy,)
