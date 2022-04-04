import re
from vulnman.scanner.plugins import core as plugins


class TestSSL(plugins.ServiceScanPlugin):
    _alias_ = 'testssl'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "tls", "ssl"]
    toolname = "testssl"

    def configure(self):
        self.match_all_service_names(True)
        self.require_ssl(True)

    async def run(self, service):
        if service.protocol == 'tcp' and service.secure:
            cmd = "testssl --color 0 {address}:{port}"
            await service.execute(self, cmd, outfile='{scandir}/{protocol}{port}/{protocol}_{port}_testssl.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        self.check_sweet32(output, cmd, service)

    def check_sweet32(self, output, cmd, service):
        pattern = re.compile(r"(SWEET32 \(CVE-2016-2183, CVE-2016-6329\)\s+VULNERABLE, uses 64 bit block ciphers)")
        match = pattern.search(output)
        if not match:
            return
        proofs = self.proof_from_regex_oneline(cmd, pattern, output)
        if proofs:
            service.add_vulnerability("sweet32", proofs, self)
