import re
from autorecon.core.plugins import servicescan

NUCLEI_VULNERABILITY_MAP = {

}

class Nuclei(servicescan.ServiceScan):
    _alias_ = 'nuclei'
    _version_ = '0.0.1'
    _tags = ["default", "http"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == "tcp":
            scandir = service.target.scandir
            await service.execute(self, 'nuclei -irr -t /usr/share/nuclei-templates -json -nc '
                '-u {http_scheme}://{addressv6}:{port} 2>&1', outfile='{protocol}_{port}_nuclei.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pass
