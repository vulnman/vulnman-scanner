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
