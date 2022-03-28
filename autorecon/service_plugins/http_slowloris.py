import re
from autorecon.core.plugins import servicescan


class SlowlorisDOS(servicescan.ServiceScan):
    _alias_ = "slowloris-dos"
    _tags = ["default", "http"]
    _version_ = '0.0.1'
    toolname = "nmap"

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == "tcp":
            cmd = 'nmap --script=http-slowloris-check -p {port} {address} -oN "{scandir}/{protocol}_{port}_{http_scheme}_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_{http_scheme}_nmap.xml"'
            await service.execute(cmd)

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        pattern = re.compile(r"(VULNERABLE:)(.*)(Disclosure)", re.DOTALL)
        if pattern.match(output):
            highlight_pattern = re.compile(r"(VULNERABLE:)")
            proofs = self.proof_from_regex_online(cmd, pattern, output)
            if proofs:
                service.add_vulnerability("slowloris-dos", proofs, self)
