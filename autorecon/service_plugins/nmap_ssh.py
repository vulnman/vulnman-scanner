import re
from autorecon.core.plugins import servicescan


class NmapSSH(servicescan.ServiceScan):
	_alias_ = 'nmap-ssh'
	_tags = ["ssh", "safe", "default"]
	_version_ = '0.0.1'
	toolname = "nmap"

	def configure(self):
		self.match_service_name('^ssh')

	async def run(self, service):
		await service.execute(self, 'nmap -sV -p {port} --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -oN "{scandir}/{protocol}_{port}_ssh_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ssh_nmap.xml" {address}')

	async def on_plugin_end(self, output, cmd, target=None, service=None):
		self.check_banner(output, cmd, service)
		self.check_ciphers(output, cmd, service)

	def check_banner(self, output, cmd, service):
		pattern = re.compile(r"(_banner:)(.*\d+.*)")
		proofs = self.proof_from_regex_oneline(cmd, pattern, output)
		if proofs:
			service.add_vulnerability("version_info", proofs, self, name="SSH")

	def check_ciphers(self, output, cmd, service):
		self.logger.info("Not yet implemented")
