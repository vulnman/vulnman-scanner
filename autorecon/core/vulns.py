

class Proof(object):
    def __init__(self, plugin, cmd, text_proof, description=None, matched_value=None):
        self.plugin = plugin
        self.cmd = cmd
        self.text_proof = text_proof
        self.description = description
        self.matched_value = matched_value

    def set_description(self, description):
        self.description = description

    def set_matched_value(self, value):
        self.matched_value = value


class VulnerabilityTemplate(object):
    def __init__(self, vuln_id, name, severity):
        self.vuln_id = vuln_id
        self.name = name
        self.severity = severity


class Vulnerability(object):
    def __init__(self, vuln_id, autorecon, name=None):
        self.proofs = []
        self.autorecon = autorecon
        self.vuln_id = vuln_id
        self.name = name
        if not name:
            for vuln in self.autorecon.vulnerability_templates:
                if vuln.vuln_id == self.vuln_id:
                    self.name = vuln.name

    def add_proof(self, proof):
        self.proofs.append(proof)
