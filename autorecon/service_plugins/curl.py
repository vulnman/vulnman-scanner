import re
from autorecon.core.plugins import servicescan
from autorecon.core.vulns import Proof


class HTTPCheck(servicescan.ServiceScan):
    _alias_ = 'http-check'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "http", "test"]
    toolname = "curl"

    def configure(self):
        self.add_option("path", default="/", help="The path on the web server to curl. Default: %(default)s")
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            await service.execute('curl -sSik {http_scheme}://{addressv6}:{port}' + self.get_option('path'), outfile='{protocol}_{port}_{http_scheme}_curl.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pattern = re.compile(r"(Server:\W{1}.*)")
        matched = re.search(pattern, output)
        if matched:
            text_proof = "```\n$ %s\n[...]\n§§%s§§\n[...]\n```" % (cmd, matched.group())
            proofs = [
                Proof(self, cmd, text_proof)
            ]
            self.logger.error(str(target.__dict__))
            service.add_vulnerability("version_info", proofs, self)
