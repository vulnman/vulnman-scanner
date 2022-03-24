

class Vulnerability(object):
    def __init__(self, name, plugin, output, severity):
        self.name = name
        self.plugin = plugin
        self.output = output
        self.severity = severity
