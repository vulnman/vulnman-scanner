import re
from autorecon.utils.logger import Logger
from autorecon.utils.slugify import slugify
from autorecon.core.vulns import Proof


class Plugin(object):
    _tags = []

    def __init__(self, autorecon):
        self.autorecon = autorecon
        self.logger = Logger()
        self.description = None
        self.slug = None
        self.priority = 1
        self.disabled = False

    @property
    def tags(self):
        return self._tags.copy()

    def get_description(self):
        return self.description

    def get_priority(self):
        return self.priority

    def add_option(self, name, default=None, help=None):
        self.autorecon.add_argument(self, name, metavar='VALUE', default=default, help=help)

    def add_constant_option(self, name, const, default=None, help=None):
        self.autorecon.add_argument(self, name, action='store_const', const=const, default=default, help=help)

    def add_true_option(self, name, help=None):
        self.autorecon.add_argument(self, name, action='store_true', help=help)

    def add_false_option(self, name, help=None):
        self.autorecon.add_argument(self, name, action='store_false', help=help)

    def add_list_option(self, name, default=None, help=None):
        self.autorecon.add_argument(self, name, nargs='+', metavar='VALUE', default=default, help=help)

    def add_choice_option(self, name, choices, default=None, help=None):
        if not isinstance(choices, list):
            fail('The choices argument for ' + self.name + '\'s ' + name + ' choice option should be a list.')
        self.autorecon.add_argument(self, name, choices=choices, default=default, help=help)

    def get_option(self, name):
        # TODO: make sure name is simple.
        name = self.slug.replace('-', '_') + '.' + slugify(name).replace('-', '_')

        if name in vars(self.autorecon.args):
            return vars(self.autorecon.args)[name]
        else:
            return None

    def get_global_option(self, name, default=None):
        name = 'global.' + slugify(name).replace('-', '_')

        if name in vars(self.autorecon.args):
            if vars(self.autorecon.args)[name] is None:
                if default:
                    return default
                else:
                    return None
            else:
                return vars(self.autorecon.args)[name]
        else:
            if default:
                return default
            return None

    def get_global(self, name, default=None):
        return self.get_global_option(name, default)

    def error(self, msg, verbosity=0):
        self.logger.error('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def warn(self, msg, verbosity=0):
        self.logger.warn('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def info(self, msg, verbosity=0):
        self.logger.info('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def proof_from_regex_oneline(self, cmd, pattern, output, highlight_group=None):
        matched = re.search(pattern, output)
        proofs = None
        if matched:
            if highlight_group:
                text_proof = "```\n$ %s\n[...]\n" % (cmd)
                for index in range(1, len(matched.groups())+1):
                    if highlight_group == index:
                        text_proof += "§§%s§§" % matched.group(index)
                    else:
                        text_proof += matched.group(index)
                text_proof += "\n[...]\n```"
            else:
                text_proof = "```\n$ %s\n[...]\n§§%s§§\n[...]\n```" % (cmd, matched.group())
            proofs = [
                Proof(self, cmd, text_proof)
            ]
        return proofs

    def get_proof_from_data(self, cmd, text_proof):
        return Proof(self, cmd, text_proof)