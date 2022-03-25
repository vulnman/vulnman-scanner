

class Proof(object):
    def __init__(self, plugin, cmd, text_proof):
        self.plugin = plugin
        self.cmd = cmd
        self.text_proof = text_proof


class VulnerabilityTemplate(object):
    def __init__(self, vuln_id, name, severity):
        self.vuln_id = vuln_id
        self.name = name
        self.severity = severity


class Vulnerability(object):
    def __init__(self, vuln_id, autorecon):
        self.proofs = []
        self.autorecon = autorecon
        self.vuln_id = vuln_id

    def add_proof(self, proof):
        self.proofs.append(proof)

    @property
    def name(self):
        for vuln in self.autorecon.vulnerability_templates:
            if vuln.vuln_id == self.vuln_id:
                return vuln.name
        return None
