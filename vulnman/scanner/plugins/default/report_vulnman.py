from vulnman.scanner.plugins import core as plugins
from vulnman.api.client import VulnmanClient


class Vulnman(plugins.ReportPlugin):
    _alias_ = "vulnman"
    _version_ = "0.0.1"

    def configure(self):
        self.add_option(
            "vulnman_host", default="http://localhost:8000",
            help="The vulnman host. Default: %(default)s")
        self.add_option("vulnman_token", help="The vulnman api token.")

    async def run(self, targets):
        client = VulnmanClient(
            self.get_option("vulnman_host"),
            self.get_option("vulnman_token"))

        for target in targets:
            host = client.create_host(target.ip)
            for service_obj in target.scans.get("services", {}).keys():
                service = client.create_service(
                    host["uuid"], service_obj.name, service_obj.port,
                    service_obj.protocol)
                for vuln_obj in service_obj.vulnerabilities:
                    vuln = client.create_vulnerability(
                        vuln_obj.name, service["uuid"], "service",
                        vuln_obj.vuln_id)
                    for proof_obj in vuln_obj.proofs:
                        client.create_text_proof(
                            vuln["uuid"], proof_obj.plugin.name,
                            proof_obj.text_proof,
                            description=proof_obj.description
                        )
