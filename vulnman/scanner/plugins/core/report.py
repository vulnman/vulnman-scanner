import pluginlib
from vulnman.scanner.plugins.core import base as baseplugin


@pluginlib.Parent("reportplugin")
class ReportPlugin(baseplugin.Plugin):
    pass
