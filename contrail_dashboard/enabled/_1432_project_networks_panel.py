from django.utils.translation import ugettext_lazy as _


# The slug of the panel to be added to HORIZON_CONFIG. Required.
PANEL = 'networks'
# The slug of the dashboard the PANEL associated with. Required.
PANEL_DASHBOARD = 'project'
# Python panel class of the PANEL to be added.
ADD_PANEL = 'contrail_dashboard.content.networks.panel.Networks'
# The slug of the panel group the PANEL is associated with.
PANEL_GROUP = 'contrail_network'
PANEL_GROUP_NAME = _('ContrailNetwork')

ADD_INSTALLED_APPS = ["contrail_dashboard", ]

# Automatically discover static resources in installed apps
AUTO_DISCOVER_STATIC_FILES = True
