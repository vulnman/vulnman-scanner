import re
from vulnman.scanner.plugins import core as plugins


class SSHAudit(plugins.ServiceScanPlugin):
    _alias_ = 'ssh-audit'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "ssh"]

    def configure(self):
        self.match_service_name('^ssh')

    async def run(self, service):
        if service.protocol == 'tcp':
            cmd = "ssh-audit -n -p {port} {address}"
            await service.execute(self, cmd, outfile='{scandir}/{protocol}{port}/{protocol}_{port}_sshaudit.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        self.check_weak_kex_algo(output, cmd, service)
        self.check_weak_host_key(output, cmd, service)
        self.check_weak_ciphers(output, cmd, service)
        self.check_weak_mac_algo(output, cmd, service)

    def check_weak_kex_algo(self, output, cmd, service):
        pattern = re.compile(r"(\(kex\)\s+)(.*)(--\s+\[fail\]|\[warn\]\s+)(.*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        dheater_cipher_found = False
        for match in pattern.finditer(output):
            dheater_cipher_found = True
            text_proof += "§§%s§§\n[...]\n" % match.group()
        if dheater_cipher_found:
            text_proof += "```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("ssh-weak-kex-algo", proofs, self)

    def check_weak_host_key(self, output, cmd, service):
        pattern = re.compile(r"(\(key\)\s+)(.*)(--\s+\[fail\]|\[warn\]\s+)(.*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        dheater_cipher_found = False
        for match in pattern.finditer(output):
            dheater_cipher_found = True
            text_proof += "§§%s§§\n[...]\n" % match.group()
        if dheater_cipher_found:
            text_proof += "```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("ssh-weak-host-key", proofs, self)

    def check_weak_ciphers(self, output, cmd, service):
        pattern = re.compile(r"(\(enc\)\s+)(.*)(--\s+\[fail\]|\[warn\]\s+.*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        dheater_cipher_found = False
        for match in pattern.finditer(output):
            dheater_cipher_found = True
            text_proof += "§§%s§§\n[...]\n" % match.group()
        if dheater_cipher_found:
            text_proof += "```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("ssh-weak-ciphers", proofs, self)

    def check_weak_mac_algo(self, output, cmd, service):
        pattern = re.compile(r"(\(mac\)\s+)(.*)(--\s+\[fail\]|\[warn\]\s+.*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        dheater_cipher_found = False
        for match in pattern.finditer(output):
            dheater_cipher_found = True
            text_proof += "§§%s§§\n[...]\n" % match.group()
        if dheater_cipher_found:
            text_proof += "```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("ssh-weak-mac-algo", proofs, self)
