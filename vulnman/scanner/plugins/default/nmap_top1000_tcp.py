import re
from vulnman.scanner.plugins import core as plugins
from vulnman.core.utils.logging import logger
from vulnman.core import assets


class QuickTCPPortScan(plugins.PortScanPlugin):
    _alias_ = "top-tcp-ports"
    _tags = ["default", "default-port-scan"]
    priority = 0

    def __init__(self, autorecon):
        super().__init__(autorecon)
        self.type = 'tcp'
        self.priority = 0

    async def run(self, target):
        # Don't run this plugin if there are custom ports
        if target.ports:
            return []
        traceroute_os = ' -A --osscan-guess'

        process, stdout, stderr = await target.execute(
            'nmap -sV -sC --version-all' + traceroute_os +
            ' -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}',
            blocking=False)
        # services = await target.extract_services(stdout)
        services = await self.extract_services(stdout)
        await process.wait()
        return services

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn("[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)

    async def extract_services(self, stream):
        services = []
        while True:
            line = await stream.readline()
            if line is not None:
                service = self.extract_service(line)
                if service:
                    services.append(service)
            else:
                break
        return services

    def extract_service(self, line):
        regex = r'^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
        match = re.search(regex, line)
        if match:
            protocol = match.group('protocol').lower()
            port = int(match.group('port'))
            service = match.group('service')
            secure = True if 'ssl' in service or 'tls' in service else False

            if service.startswith('ssl/') or service.startswith('tls/'):
                service = service[4:]
            return assets.Service(protocol, port, service, secure)
        else:
            return None
