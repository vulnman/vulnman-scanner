from vulnman.scanner.plugins import core as plugins
from vulnman.core.utils.logging import logger


class Gobuster(plugins.ServiceScanPlugin):
    _alias_ = 'gobuster'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "http", "long"]
    toolname = "gobuster"
    WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_option('ext', default='txt,html,php,asp,aspx,jsp',
                        help='The extensions you wish to fuzz (no dot, comma separated). Default: %(default)s')

    async def run(self, service):
        if service.protocol == 'tcp':
            name = self.WORDLIST.split("/")[-1]
            await service.execute(self, 'gobuster dir -u {http_scheme}://{addressv6}:{port}/ -w ' + self.WORDLIST +
                                  ' -e -k -x "' + self.get_option('ext') + '" -z -o "{scandir}/{protocol}{port}/'
                                                                           '{protocol}_{port}_{http_scheme}_gobuster_'
                                  + name + '.txt"')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn("[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)
