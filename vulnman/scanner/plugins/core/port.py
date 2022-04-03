import pluginlib
from vulnman.scanner.plugins.core import base as plugins


@pluginlib.Parent("portscan")
class PortScanPlugin(plugins.Plugin):

    def __init__(self, autorecon):
        super(PortScanPlugin, self).__init__(autorecon)
        self.type = None
        self.specific_ports = False

    @pluginlib.abstractmethod
    async def run(self, target):
        pass

    async def on_new_output_line(self, output, cmd, target=None, service=None):
        pass

    @pluginlib.abstractmethod
    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pass
