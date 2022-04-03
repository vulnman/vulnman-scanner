import re
from vulnman.scanner.plugins import core as plugins


class ICMPTimestamp(plugins.ServiceScanPlugin):
    _alias_ = "icmp-timestamp"
    _version_ = '0.0.1'
    _tags = ["default", "safe", "icmp"]
    toolname = "hping"

    def configure(self):
        self.match_all_service_names(True)
        self.run_once(True)

    async def run(self, service):
        cmd = '%s -c 5 -p {port} -S --tcp-timestamp {addressv6}' % self.toolname
        await service.execute(self, cmd, outfile="{scandir}/icmp_timestamp_hping.txt")

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        # group 2 is system uptime
        pattern = re.compile(r"(System uptime seems:.*)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output)
        if proofs:
            service.add_vulnerability("icmp-timestamp", proofs, self)
