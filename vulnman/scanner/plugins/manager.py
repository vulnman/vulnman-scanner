import pluginlib


class PluginManager(object):
    def __init__(self):
        self.loader = pluginlib.PluginLoader(modules=["vulnman.scanner.plugins.default"])

    def get_plugins(self, plugin_type=None):
        if plugin_type:
            return self.loader.plugins.get(plugin_type)
        return self.loader.plugins
