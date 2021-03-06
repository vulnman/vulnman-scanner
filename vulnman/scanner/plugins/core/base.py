import re
from vulnman.core.assets import Proof
from vulnman.core.utils import logger
from vulnman.core.utils.slugify import slugify


class Plugin(object):
    _tags = []

    def __init__(self, autorecon):
        self.autorecon = autorecon
        self.description = None
        self.slug = None
        self.priority = 1
        self.disabled = False

    @property
    def tags(self):
        tags = self._tags.copy()
        if self.name not in tags:
            tags.append(self.name)
        return tags

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
            logger.fail('The choices argument for ' + self.name + '\'s ' + name + ' choice option should be a list.')
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
        logger.error('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def warn(self, msg, verbosity=0):
        logger.warn('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def info(self, msg, verbosity=0):
        logger.info('{bright}[{bgreen}' + self.name + '{crst}]{rst} ' + msg)

    def proof_from_regex_oneline(self, cmd, pattern, output, highlight_group=None):
        matched = re.search(pattern, output)
        proofs = None
        if matched:
            if highlight_group:
                matched_value = None
                text_proof = "```\n$ %s\n[...]\n" % cmd
                for index in range(1, len(matched.groups())+1):
                    if highlight_group == index:
                        text_proof += "????%s????" % matched.group(index)
                        matched_value = matched.group(index)
                    else:
                        text_proof += matched.group(index)
                text_proof += "\n[...]\n```"
            else:
                text_proof = "```\n$ %s\n[...]\n????%s????\n[...]\n```" % (cmd, matched.group())
                matched_value = matched.group()
            proofs = [
                Proof(self, cmd, text_proof, matched_value=matched_value)
            ]
        return proofs

    def get_proof_from_data(self, cmd, text_proof):
        return Proof(self, cmd, text_proof)

    def proof_from_regex_multiline(self, cmd, patterns, output, highlight_groups=None):
        text_proof = "```\n$ %s\n[...]\n" % cmd
        one_match_found = False
        for pattern in patterns:
            matched = re.search(pattern, output)
            if matched:
                text_proof += "????%s????\n" % matched.group()
                if not one_match_found:
                    one_match_found = True
        if not one_match_found:
            return None
        text_proof += "```"
        proofs = [
            Proof(self, cmd, text_proof)
        ]
        return proofs

    def proof_from_patterns(self, cmd, patterns, output, highlighting_groups=None):
        text_proof = "```\n$ %s\n" % cmd
        for line in output:
            match_found = False
            for pattern in patterns:
                matched = re.search(pattern, line)
                if matched:
                    text_proof += "????%s????\n" % matched.group()
                    match_found = True
                    break
            if not match_found:
                text_proof += line + "\n"
        text_proof += "```"
        proofs = [
            Proof(self, cmd, text_proof)
        ]
        return proofs
