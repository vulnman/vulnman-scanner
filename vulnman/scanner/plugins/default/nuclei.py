from vulnman.scanner.plugins import core as plugins
from vulnman.core.utils import logger


NUCLEI_VULNERABILITY_MAP = {

}


class Nuclei(plugins.ServiceScanPlugin):
    _alias_ = 'nuclei'
    _version_ = '0.0.1'
    _tags = ["default", "http"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == "tcp":
            await service.execute(self, 'nuclei -irr -t /usr/share/nuclei-templates -json -nc '
                                        '-u {http_scheme}://{addressv6}:{port} 2>&1',
                                  outfile='{scandir}/{protocol}{port}/{protocol}_{port}_nuclei.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn("[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)
