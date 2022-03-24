

class Vulnerability(object):
    severity = "informational"
    name = None

    def __init__(self, name, output):
        self.proofs = []
        self.output = output
        self.name = name


class VulnerabilityManager(object):
    def __init__(self):
        self.vulnerabilities = []
        self.available_vulnerabilities = []

    def get_vulnerability_by_name(self, name):
        pass
