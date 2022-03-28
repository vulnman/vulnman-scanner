from autorecon.core.plugins import report
from autorecon.config import config
from autorecon.core.vulnman.api.client import VulnmanClient
import os, glob


class Vulnman(report.ReportPlugin):
	_alias_ = "vulnman"
	_version_ = "0.0.1"

	def configure(self):
		self.add_option("vulnman_host", default="http://localhost:8000", help="The vulnman host. Default: %(default)s")
		self.add_option("vulnman_project", help="The vulnman project id.")
		self.add_option("vulnman_token", help="The vulnman api token.")

	async def run(self, targets):
		client = VulnmanClient(self.get_option("vulnman_host"), self.get_option("vulnman_token"))
		client.activate_project(self.get_option("vulnman_project"))

		for target in targets:
			host = client.add_or_get_host(target.ip)

			for service_obj in target.scans.get("services", {}).keys():
				service = client.add_service(host["uuid"], service_obj.name, 
					service_obj.port, service_obj.protocol)
				for vuln_obj in service_obj.vulnerabilities:
					asset_display = "%s/%s %s (%s)" % (service_obj.protocol, service_obj.port, service_obj.name, target.ip) 
					vuln = client.check_and_get_vulnerability(
						vuln_obj.name, asset_display, "service", vuln_obj.vuln_id)
					if not vuln:
						vuln = client.add_vulnerability(
							vuln_obj.name, service["uuid"], "service", vuln_obj.vuln_id
						)
						for proof_obj in vuln_obj.proofs:
							proof = client.add_text_proof(
								vuln["uuid"], proof_obj.plugin.name, proof_obj.text_proof,
								description=proof_obj.description
							)
