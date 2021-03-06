import asyncio
import inspect
import os
import re
import sys
import pluginlib
import yaml
from pathlib import Path
from git import Repo
from vulnman.config import config
from vulnman.core.utils.io import CommandStreamReader
from vulnman.core.utils.logging import logger
from vulnman.core.utils.slugify import slugify
from vulnman.scanner.plugins.core import ServiceScanPlugin, PortScanPlugin, ReportPlugin
from vulnman.core.assets import VulnerabilityTemplate


class VulnmanScanner(object):

    def __init__(self):
        self.pending_targets = []
        self.scanning_targets = []
        self.completed_targets = []
        self.plugins = {}
        self.__slug_regex = re.compile(r'^[a-z0-9\-]+$')
        self.plugin_types = {'port': [], 'service': [], 'report': []}
        self.port_scan_semaphore = None
        self.service_scan_semaphore = None
        self.argparse = None
        self.argparse_group = None
        self.args = None
        self.missing_services = []
        self.taglist = []
        self.tags = []
        self.excluded_tags = []
        self.patterns = []
        self.errors = False
        self.lock = asyncio.Lock()
        self.load_slug = None
        self.load_module = None
        self.vulnerability_templates = []

    def add_argument(self, plugin, name, **kwargs):
        # TODO: make sure name is simple.
        name = '--' + plugin.slug + '.' + slugify(name)

        if self.argparse_group is None:
            self.argparse_group = self.argparse.add_argument_group(
                'plugin arguments', description='These are optional arguments for certain plugins.')
        self.argparse_group.add_argument(name, **kwargs)

    def load_plugins(self):
        custom_plugin_path = config.get("custom_plugins", [])
        loader = pluginlib.PluginLoader(
            modules=['vulnman.scanner.plugins.default'], paths=custom_plugin_path)
        for plugin_type in ["servicescan", "portscan", "reportplugin"]:
            for plugin_name in loader.plugins.get(plugin_type).items():
                plugin = loader.get_plugin(plugin_type, plugin_name[0])(self)
                self.register(plugin, "")

    def register(self, plugin, filename):
        if plugin.disabled:
            return

        if plugin.name is None:
            logger.fail('Error: Plugin with class name "' + plugin.__class__.__name__ + '" in ' + filename +
                        'does not have a name.')

        for _, loaded_plugin in self.plugins.items():
            if plugin.name == loaded_plugin.name:
                logger.fail('Error: Duplicate plugin name "' + plugin.name + '" detected in ' + filename + '.',
                            file=sys.stderr)

        if plugin.slug is None:
            plugin.slug = slugify(plugin.name)
        elif not self.__slug_regex.match(plugin.slug):
            logger.fail(
                'Error: provided slug "' + plugin.slug + '" in ' + filename +
                'is not valid (must only contain lowercase letters, numbers, and hyphens).',
                file=sys.stderr)

        if plugin.slug in config['protected_classes']:
            logger.fail(
                'Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is a protected string. Please change.')

        if plugin.slug not in self.plugins:

            for _, loaded_plugin in self.plugins.items():
                if plugin is loaded_plugin:
                    logger.fail(
                        'Error: plugin "' + plugin.name + '" in ' + filename + ' already loaded as "' +
                        loaded_plugin.name + '" (' + str(loaded_plugin) + ')', file=sys.stderr)

            configure_function_found = False
            run_coroutine_found = False
            manual_function_found = False

            for member_name, member_value in inspect.getmembers(plugin, predicate=inspect.ismethod):
                if member_name == 'configure':
                    configure_function_found = True
                elif member_name == 'run' and inspect.iscoroutinefunction(member_value):
                    if len(inspect.getfullargspec(member_value).args) != 2:
                        logger.fail(
                            'Error: the "run" coroutine in the plugin "' + plugin.name + '" in ' + filename +
                            ' should have two arguments.', file=sys.stderr)
                    run_coroutine_found = True
                elif member_name == 'manual':
                    if len(inspect.getfullargspec(member_value).args) != 3:
                        logger.fail(
                            'Error: the "manual" function in the plugin "' + plugin.name + '" in ' + filename +
                            ' should have three arguments.', file=sys.stderr)
                    manual_function_found = True

            if not run_coroutine_found and not manual_function_found:
                logger.fail(
                    'Error: the plugin "' + plugin.name + '" in ' + filename +
                    ' needs either a "manual" function, a "run" coroutine, or both.', file=sys.stderr)

            if issubclass(plugin.__class__, PortScanPlugin):
                if plugin.type is None:
                    logger.fail(
                        'Error: the PortScan plugin "' + plugin.name + '" in ' + filename +
                        ' requires a type (either tcp or udp).')
                else:
                    plugin.type = plugin.type.lower()
                    if plugin.type not in ['tcp', 'udp']:
                        logger.fail(
                            'Error: the PortScan plugin "' + plugin.name + '" in ' + filename +
                            ' has an invalid type (should be tcp or udp).')
                self.plugin_types["port"].append(plugin)

            elif issubclass(plugin.__class__, ServiceScanPlugin):
                self.plugin_types["service"].append(plugin)
            elif issubclass(plugin.__class__, ReportPlugin):
                self.plugin_types["report"].append(plugin)
            else:
                logger.fail(
                    'Plugin "' + plugin.name + '" in ' + filename +
                    ' is neither a PortScan, ServiceScan, nor a Report.', file=sys.stderr)

            # plugin.tags = [tag.lower() for tag in plugin.tags]

            # Add plugin tags to tag list.
            [self.taglist.append(t) for t in plugin.tags if t not in self.tags]

            plugin.autorecon = self
            if configure_function_found:
                plugin.configure()
            self.plugins[plugin.slug] = plugin
        else:
            logger.fail('Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is already assigned.',
                        file=sys.stderr)

    async def execute(self, cmd, target, tag, plugin, service=None, outfile=None, errfile=None):

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdin=open('/dev/null'),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        cout = CommandStreamReader(process.stdout, target, tag, plugin, cmd, service=service, outfile=outfile)
        cerr = CommandStreamReader(process.stderr, target, tag, plugin, cmd, service=service, outfile=errfile)

        asyncio.create_task(cout.read())
        asyncio.create_task(cerr.read())

        return process, cout, cerr

    def import_vulnerability_templates(self):
        """
        import vulnerability templates from separate repository. vulnerability ids are required
        to upload and match findings in plugins.
        :return:
        """
        template_dir = os.path.join(
            config["base_dir"], "../resources/vulnerability_templates")
        if os.path.isdir(template_dir):
            repo = Repo(template_dir)
            origin = repo.remotes.origin
            origin.pull()
        else:
            Repo.clone_from(config["vuln_template_repo"], template_dir)
        for path in Path(template_dir).rglob('info.yaml'):
            with open(path, "r") as f:
                for item in yaml.safe_load(f):
                    self.vulnerability_templates.append(
                        VulnerabilityTemplate(item["id"], item["name"], item["severity"])
                    )
