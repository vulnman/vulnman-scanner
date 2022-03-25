import pluginlib
from autorecon.core.plugins import baseplugin


@pluginlib.Parent("reportplugin")
class ReportPlugin(baseplugin.Plugin):
    pass
