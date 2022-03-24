import re
from autorecon.core.plugins import servicescan


class HTTPCheck(servicescan.ServiceScan):
    _alias_ = 'http-check'
    _version_ = '0.0.1'
    tags = ["defeault", "safe", "http", "test"]

    def configure(self):
        self.add_option("path", default="/", help="The path on the web server to curl. Default: %(default)s")
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp':
            await service.execute('curl -sSik {http_scheme}://{addressv6}:{port}' + self.get_option('path'), outfile='{protocol}_{port}_{http_scheme}_curl.html')

    async def on_plugin_end(self, output):
        patterns = [
            re.compile(r"(Server:\W{1}.*)"),
            re.compile(r"(Referrer-Policy:\W{1}.*)")
        ]
        for pattern in patterns:
            output = re.sub(pattern, r"§§\1§§", output)
            output = "```\n%s\n```" % output
        return output
