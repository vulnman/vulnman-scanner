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


class ProofPattern(object):
    def __init__(self, regex, group_to_highlight=None):
        self.regex = regex
        self.group_to_highlight = group_to_highlight


class TextProof(object):
    def __init__(self, plugin, command, output):
        self.command = command
        self.patterns = []

    def add_pattern(self, regex, group_to_highlight=None):
        self.patterns.append(ProofPattern(regex, group_to_highlight=group_to_highlight))

    def to_text_proof(self):
        text = "```\n"
        text += "$ %s\n" % self.command
        text += "```"
        return text
