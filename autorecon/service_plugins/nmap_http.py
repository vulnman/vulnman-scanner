import re
from autorecon.core.plugins import servicescan


class NmapHTTP(servicescan.ServiceScan):
    _alias_ = "nmap-http"
    _tags = ["http", "safe", "default2"]
    _version_ = "0.0.1"
    toolname = "nmap"

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        await service.execute('nmap {nmap_extra} -sV -p {port} -sC -oN "{scandir}/{protocol}_{port}_{http_scheme}_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_{http_scheme}_nmap.xml" {address}')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        # search version information
        pattern = re.compile(r"(open\W*)(http*[-\w]*)(.*[\d]+.*)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output, highlight_group=3)
        #if pattern.search(output):
        #    proof = re.sub(pattern, r"§§\3§§", output)
        #    proof = "```\n$ %s\n%s\n```" % (cmd, proof)
        if proofs:
            service.add_vulnerability(
                "version-information", proofs, self
            )
