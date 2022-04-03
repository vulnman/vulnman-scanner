import os
import re
from vulnman.scanner.plugins import core as plugins
from vulnman.core.utils.logging import logger
from vulnman.core import assets


class Top100UDPPortScan(plugins.PortScanPlugin):
    _alias_ = "top-100-udp-ports"
    _tags = ["default", "default-port-scan", "long"]
    priority = 0

    def __init__(self, autorecon):
        super().__init__(autorecon)
        self.type = 'udp'
        self.specific_ports = True
        self.priority = 0

    async def run(self, target):
        if os.getuid() != 0:
            logger.error("UDP scan requires vulnman-scanner to be run with root privileges")
            return
        if target.ports:
            if target.ports["udp"]:
                process, stdout, stderr = await target.execute(
                    'nmap {nmap_extra} -sU -A --osscan-guess -p ' + target.ports['udp'] +
                    ' -oN "{scandir}/_custom_ports_udp_nmap.txt" -oX "{scandir}/xml/_custom_ports_udp_nmap.xml" '
                    '{address}', blocking=False)
            else:
                return []
        else:
            process, stdout, stderr = await target.execute(
                'nmap {nmap_extra} -sU -A --top-ports 100 -oN "{scandir}/_top_100_udp_nmap.txt" -oX '
                '"{scandir}/xml/_top_100_udp_nmap.xml" {address}', blocking=False)
        services = []
        while True:
            line = await stdout.readlines()
            if line is not None:
                match = re.search(r'^Discovered open port ([0-9]+)/udp', line)
                if match:
                    logger.info('Discovered open port {bmagenta}udp/' + match.group(1) + '{rst} on {byellow}' +
                                target.address + '{rst}', verbosity=1)
                service = self.extract_service(line)
                if service:
                    services.append(service)
            else:
                break
        await process.wait()
        return services

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn("[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)

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

