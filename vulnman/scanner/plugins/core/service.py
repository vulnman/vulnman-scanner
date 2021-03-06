import pluginlib
import sys
import re
from shutil import which
from vulnman.core.utils.logging import logger
from vulnman.scanner.plugins.core import base as baseplugin


@pluginlib.Parent("servicescan")
class ServiceScanPlugin(baseplugin.Plugin):
    toolname = None
    toolnames = []

    def __init__(self, autorecon):
        super(ServiceScanPlugin, self).__init__(autorecon)
        self.ports = {"tcp": [], "udp": []}
        self.ignore_ports = {"tcp": [], "udp": []}
        self.services = []
        self.service_names = []
        self.ignore_service_names = []
        self.run_once_boolean = False
        self.require_ssl_boolean = False
        self.max_target_instances = 0
        self.max_global_instances = 0

    def get_toolnames(self):
        return self.toolnames.copy()

    def check(self):
        for toolname in self.get_toolnames():
            if which(toolname) is None:
                self.error('The %s program could not be found. Make sure it is installed.' % toolname)
        if self.get_toolnames():
            return
        if not self.toolname:
            toolname = self.name
        else:
            toolname = self.toolname
        if which(toolname) is None:
            self.error('The %s program could not be found. Make sure it is installed.' % toolname)

    def match_service(self, protocol, port, name, negative_match=False):
        protocol = protocol.lower()
        if protocol not in ["tcp", "udp"]:
            self.logger.error("Invalid protocol")
            sys.exit(1)

        if not isinstance(port, list):
            port = [port]
        port = list(map(int, port))

        if not isinstance(name, list):
            name = [name]
        valid_regex = True
        for r in name:
            try:
                re.compile(r)
            except re.error:
                self.logger.error("Invalid regex: %s" % r)
                valid_regex = False
        if not valid_regex:
            sys.exit(1)
        service = {"protocol": protocol, "port": port, "name": name, "negative_match": negative_match}
        self.services.append(service)

    def match_port(self, protocol, port, negative_match=False):
        protocol = protocol.lower()
        if protocol not in ["tcp", "udp"]:
            self.logger.error("Invalid protocol.")
            sys.exit(1)
        else:
            if not isinstance(port, list):
                port = [port]
            port = list(map(int, port))
            if negative_match:
                self.ignore_ports[protocol] = list(set(self.ignore_ports[protocol] + port))
            else:
                self.ports[protocol] = list(set(self.ports[protocol] + port))

    def match_service_name(self, name, negative_match=False):
        if not isinstance(name, list):
            name = [name]
        valid_regex = True
        for r in name:
            try:
                re.compile(r)
            except re.error:
                self.logger.error("invalid regex: %s" % r)
                valid_regex = False
        if valid_regex:
            if negative_match:
                self.ignore_service_names = list(set(self.ignore_service_names + name))
            else:
                self.service_names = list(set(self.service_names + name))
        else:
            sys.exit(1)

    def require_ssl(self, boolean):
        self.require_ssl_boolean = boolean

    def run_once(self, boolean):
        self.run_once_boolean = boolean

    def match_all_service_names(self, boolean):
        if boolean:
            self.match_service_name('.*')

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        logger.warn(
            "[{byellow}%s{rst}] No 'on_plugin_end()' method implemented!" % self.name)

    @pluginlib.abstractmethod
    async def run(self, service):
        pass

    async def on_new_output_line(self, output, cmd, target=None, service=None):
        """
        run on a new line received from command using CommandStreamReader

        :param output:
        :param cmd:
        :param target:
        :param service:
        :return:
        """
        pass
