from autorecon.core.plugins import portscan
from autorecon.config import config


class QuickTCPPortScan(portscan.PortScan):
    _alias_ = "top-tcp-ports"
    _tags = ["default", "default-port-scan"]
    priority = 0

    def __init__(self, autorecon):
        super().__init__(autorecon)
        self.type = 'tcp'
        self.priority = 0

    async def run(self, target):
        if target.ports: # Don't run this plugin if there are custom ports.
            return []
        traceroute_os = ' -A --osscan-guess'

        process, stdout, stderr = await target.execute(
            'nmap {nmap_extra} -sV -sC --version-all' + traceroute_os + \
            ' -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}', 
            blocking=False)
        services = await target.extract_services(stdout)
        await process.wait()
        return services

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        self.logger.info(output)
