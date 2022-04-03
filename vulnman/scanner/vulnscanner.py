import pluginlib


class VulnmanScanner(object):
    pending_targets = []
    vulnerability_templates = []

    def get_pending_targets(self):
        return self.pending_targets.copy()

    def get_vulnerability_templates(self):
        return self.vulnerability_templates.copy()
