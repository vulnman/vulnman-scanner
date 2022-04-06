import re
from vulnman.scanner.plugins import core as plugins


class NmapHTTP(plugins.ServiceScanPlugin):
    _alias_ = "nmap-http"
    _tags = ["http", "safe", "default"]
    _version_ = "0.0.1"
    toolname = "nmap"

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        await service.execute(self, 'nmap -sV -p {port} -sC -oN "{scandir}/{protocol}{port}/{protocol}_{port}_'
                                    '{http_scheme}_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_{http_scheme}_'
                                    'nmap.xml" {address}')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        # search version information
        pattern = re.compile(r"(open\W*)(http*[-\w]*)(\s+)(.*[\d]+.*)")
        cmd = service.parse_string_vals("nmap -sV -sC -p {port} {address}")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output, highlight_group=4)
        if proofs:
            service.add_vulnerability("version_info", proofs, self)
