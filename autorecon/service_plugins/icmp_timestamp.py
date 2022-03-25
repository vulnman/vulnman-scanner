import re
from autorecon.core.plugins import servicescan


class ICMPTimestamp(servicescan.ServiceScan):
    _alias_ = "icmp-timestamp"
    _version_ = '0.0.1'
    _tags = ["default", "safe", "icmp"]
    toolname = "hping"

    def configure(self):
        self.match_all_service_names(True)
        self.run_once(True)

    async def run(self, service):
        cmd = '%s -c 5 -p {port} -S --tcp-timestamp {addressv6}' % self.toolname
        await service.execute(cmd, outfile="icmp_timestamp_hping.txt")

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        # group 2 is system uptime
        pattern = re.compile(r"(System uptime seems:.*)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output)
        if proofs:
            service.add_vulnerability("icmp-timestamp", proofs, self)
