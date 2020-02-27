from django.utils.translation import ugettext_lazy as _


# The slug of the panel group the PANEL is associated with.
PANEL_GROUP = 'contrail_network'
# The display name of the PANEL_GROUP. Required.
PANEL_GROUP_NAME = _('ContrailNetwork')
# The slug of the dashboard the PANEL_GROUP associated with. Required.
PANEL_GROUP_DASHBOARD = 'project'

ADD_INSTALLED_APPS = ["contrail_dashboard", ]
# Automatically discover static resources in installed apps
AUTO_DISCOVER_STATIC_FILES = True
