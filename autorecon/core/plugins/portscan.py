import pluginlib
import sys
import re
from autorecon.core.plugins import baseplugin


@pluginlib.Parent("portscan")
class PortScan(baseplugin.Plugin):
    
    def __init__(self, autorecon):
        super(PortScan, self).__init__(autorecon)
        self.type = None
        self.specific_ports = False

    @pluginlib.abstractmethod
    async def run(self, target):
        pass

    @pluginlib.abstractmethod
    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pass
