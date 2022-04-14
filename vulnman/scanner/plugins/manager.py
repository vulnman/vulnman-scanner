import pluginlib
from autorecon.config import config


class PluginManager(object):
    def __init__(self):
        custom_plugin_paths = config.get("custom_plugins", [])
        print(config)
        self.loader = pluginlib.PluginLoader(
            modules=["vulnman.scanner.plugins.default"],
            paths=custom_plugin_paths)

    def get_plugins(self, plugin_type=None):
        if plugin_type:
            return self.loader.plugins.get(plugin_type)
        return self.loader.plugins

    def get_portscan_plugins(self):
        return self.get_plugins("portscan")

    def get_servicescan_plugins(self):
        return self.get_plugins("servicescan")

    def get_report_plugins(self):
        return self.get_plugins("report")
