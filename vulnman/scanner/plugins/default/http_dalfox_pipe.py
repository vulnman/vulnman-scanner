from vulnman.scanner.plugins import core
from vulnman.core.utils.logging import logger


class HTTPDalfoxPipe(core.ServiceScanPlugin):
    _alias_ = "dalfox-pipe"
    _version_ = '0.0.1'
    _tags = ["http", "active"]
    toolnames = ["dalfox", "hakrawler"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            command = 'echo "{http_scheme}://{address}:{port}" | hakrawler -u -subs | grep {address} | dalfox pipe -o {scandir}/{protocol}{port}/dalfox_pipe.txt --no-color --poc-type=http-request'
            await service.execute(self, command, blocking=True)

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn("[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)
