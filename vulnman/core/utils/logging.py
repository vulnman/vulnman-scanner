import sys
import string
from autorecon.config import config
from colorama import Fore, Style


class PrintLogger(object):
    COLORS = {
        "yellow": Fore.YELLOW,
        "red": Fore.RED,
        "green": Fore.GREEN,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
        # bright colors
        "byellow": Fore.YELLOW + Style.BRIGHT,
        "bblue": Fore.BLUE + Style.BRIGHT,
        "bred": Fore.RED + Style.BRIGHT,
        "bgreen": Fore.GREEN + Style.BRIGHT,
        "bmagenta": Fore.MAGENTA + Style.BRIGHT,
        # reset
        "crst": Fore.RESET,
        "bright": Style.BRIGHT,
        "rst": Style.NORMAL + Fore.RESET
    }

    def debug(self, *args, color=Fore.GREEN, sep=' ', end='\n', file=sys.stdout, **kwargs):
        if config["verbose"] >= 2:
            self.cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kwargs)

    def info(self, *args, sep=' ', end='\n', file=sys.stdout, **kwargs):
        self.cprint(*args, color=Fore.BLUE, char='*', sep=sep, end=end, file=file, frame_index=2, **kwargs)

    def warn(self, *args, sep=' ', end='\n', file=sys.stderr, **kwargs):
        self.cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kwargs)

    def error(self, *args, sep=' ', end='\n', file=sys.stderr, **kwargs):
        self.cprint(*args, color=Fore.RED, char="!", sep=sep, end=end, file=file, frame_index=2, **kwargs)

    def fail(self, *args, sep=' ', end='\n', file=sys.stderr, **kwargs):
        self.cprint(*args, color=Fore.RED, char="!", sep=sep, end=end, file=file, frame_index=2, **kwargs)
        exit(-1)

    def cprint(self, *args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, printmsg=True,
           verbosity=0, **kvargs):
        if printmsg and verbosity > config['verbose']:
            return ''
        frame = sys._getframe(frame_index)

        vals = self.COLORS
        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)

        unfmt = ''
        if char is not None:
            unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
        unfmt += sep.join(args)

        fmted = unfmt

        for attempt in range(10):
            try:
                fmted = string.Formatter().vformat(unfmt, args, vals)
                break
            except KeyError as err:
                key = err.args[0]
                unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

        if printmsg:
            print(fmted, sep=sep, end=end, file=file)
        else:
            return fmted


logger = PrintLogger()
