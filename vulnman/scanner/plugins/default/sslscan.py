import re
import datetime
from vulnman.scanner.plugins import core as plugins


class SSLScan(plugins.ServiceScanPlugin):
    _alias_ = 'sslscan'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "tls", "ssl"]

    def configure(self):
        self.match_all_service_names(True)
        self.require_ssl(True)

    async def run(self, service):
        if service.protocol == 'tcp' and service.secure:
            await service.execute(self, 'sslscan --show-certificate --no-colour {addressv6}:{port} 2>&1',
                                  outfile='{scandir}/{protocol}{port}/{protocol}_{port}_sslscan.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        self.check_tls10(output, cmd, service)
        self.check_tls11(output, cmd, service)
        self.check_ca_true(output, cmd, service)
        self.check_cert_expired(output, cmd, service)
        self.check_cipher_suites(output, cmd, service)
        self.check_dheater(output, cmd, service)

    def check_tls10(self, output, cmd, service):
        pattern = re.compile(r"(TLSv1.0\W+enabled)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output)
        if proofs:
            service.add_vulnerability("tls-1.0-enabled", proofs, self)

    def check_tls11(self, output, cmd, service):
        pattern = re.compile(r"(TLSv1.1\W+enabled)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output)
        if proofs:
            service.add_vulnerability("tls-1.1-enabled", proofs, self)

    def check_ca_true(self, output, cmd, service):
        pattern = re.compile(r"(X509v3\sBasic\sConstraints:\scritical)(\s*)(CA:TRUE)(.*)")
        proofs = self.proof_from_regex_oneline(cmd, pattern, output, highlight_group=3)
        if proofs:
            service.add_vulnerability("cert-ca-true", proofs, self)

    def check_cert_expired(self, output, cmd, service):
        date_format = r"%b %d %H:%M:%S %Y %Z"
        # group 2 is the date
        # pattern_date_start = re.compile(r"(Not valid before:\s)([\w \d:]*\d{4})")
        pattern_date_end = re.compile(r"(Not valid after:\s)([\w \d:]*\d{4} GMT)")
        match = pattern_date_end.search(output)
        if not match:
            return
        if datetime.datetime.now() > datetime.datetime.strptime(match.group(2), date_format):
            proofs = self.proof_from_regex_oneline(cmd, pattern_date_end, output)
            service.add_vulnerability("cert-expired", proofs, self)

    def check_cipher_suites(self, output, cmd, service):
        required_key_size = 128
        # group 5: key length
        pattern = re.compile(r"(Accepted|Preferred)(\s+)(TLSv\d.\d)(\s+)(\d{1,4})(\sbits)(\s+)(\S+)(.*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        weak_ciphers_found = False
        for match in pattern.finditer(output):
            if int(match.group(5)) < required_key_size:
                weak_ciphers_found = True
                text_proof += "§§%s§§\n" % match.group()
            else:
                text_proof += match.group() + "\n"
        if weak_ciphers_found:
            text_proof += "\n[...]\n```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("weak-key-length", proofs, self)

    def check_dheater(self, output, cmd, service):
        pattern = re.compile(r"([Prefered|Accepted]*\s+TLSv\d.\d)(\s+)(\d+)(\s+bits)(\s+)(DHE-[\w-]*)")
        proofs = []
        text_proof = "```\n$ %s\n[...]\n" % cmd
        dheater_cipher_found = False
        for match in pattern.finditer(output):
            dheater_cipher_found = True
            text_proof += "§§%s§§\n[...]\n" % match.group()
        if dheater_cipher_found:
            text_proof += "```"
            proofs.append(self.get_proof_from_data(cmd, text_proof))
            service.add_vulnerability("dheater", proofs, self)
