import re
import datetime
from vulnman.scanner.plugins import core as plugins


class SSLScan(plugins.ServiceScanPlugin):
    _alias_ = 'sslscan'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "tls", "ssl"]
    toolname = "sslscan"
    command = "sslscan --show-certificate --no-colour {address}:{port}"

    def configure(self):
        self.match_all_service_names(True)
        self.require_ssl(True)

    async def run(self, service):
        if service.protocol == 'tcp' and service.secure:
            cmd = self.command + " 2>&1"
            await service.execute(self, cmd, outfile='{scandir}/{protocol}{port}/{protocol}_{port}_sslscan.txt')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        cmd = service.parse_string_vals(self.command)
        self.check_tls10(output, cmd, service)
        self.check_tls11(output, cmd, service)
        self.check_ca_true(output, cmd, service)
        self.check_cert_expired(output, cmd, service)
        self.check_cipher_suites(output, cmd, service)
        self.check_dheater(output, cmd, service)
        self.check_cert_long_lifespan(output, cmd, service)
        self.check_wildcard_cert(output, cmd, service)

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
        pattern_date_end = re.compile(r"(Not valid after:\s)([\w \d:]*\d{4} GMT)")
        match = pattern_date_end.search(output)
        if not match:
            return
        if datetime.datetime.now() > datetime.datetime.strptime(match.group(2), date_format):
            proofs = self.proof_from_regex_oneline(cmd, pattern_date_end, output)
            service.add_vulnerability("cert-expired", proofs, self)

    def check_cert_long_lifespan(self, output, cmd, service):
        date_format = r"%b %d %H:%M:%S %Y %Z"
        max_lifespan_days = 200
        # group 2 is the date
        pattern_date_start = re.compile(r"(Not valid before:\s)([\w \d:]*\d{4} GMT)")
        pattern_date_end = re.compile(r"(Not valid after:\s)([\w \d:]*\d{4} GMT)")
        match_date_end = pattern_date_end.search(output)
        match_date_start = pattern_date_start.search(output)
        if not match_date_start and not match_date_end:
            return
        date_start = datetime.datetime.strptime(match_date_start.group(2), date_format)
        date_end = datetime.datetime.strptime(match_date_end.group(2), date_format)
        days_diff = (date_end - date_start).days
        if days_diff > max_lifespan_days:
            patterns = [pattern_date_start, pattern_date_end]
            proofs = self.proof_from_regex_multiline(cmd, patterns, output)
            service.add_vulnerability("cert-long-lifespan", proofs, self)

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

    def check_wildcard_cert(self, output, cmd, service):
        pattern = re.compile(r"(Altnames:|Subject:)(.*)([DNS:]?)(\*[\w\-.]+)")
        matched = pattern.search(output)
        if not matched:
            return
        if not matched.group(4):
            return
        text_proof = "```\n$ %s\n[...]\n" % cmd
        for match in pattern.finditer(output):
            text_proof += "§§%s§§\n[...]\n" % match.group()
        text_proof += "```"
        proofs = [self.get_proof_from_data(cmd, text_proof)]
        for proof in proofs:
            proof.set_description("The service uses a wildcard certificate for `%s`" % matched.group(4))
        service.add_vulnerability("wildcard-cert", proofs, self)
