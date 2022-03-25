import re
from autorecon.core.plugins import servicescan
from autorecon.core.vulns import Vulnerability


class Whatweb(servicescan.ServiceScan):
    _alias_ = 'whatweb'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "http"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp' and service.target.ipversion == 'IPv4':
            cmd = "whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port} 2>&1"
            await service.execute(cmd, outfile='{protocol}_{port}_{http_scheme}_whatweb.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pass
