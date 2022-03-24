import sys
import string
import colorama, os, re, unidecode
from colorama import Fore, Style
from autorecon.config import config


class Logger(object):
    def e(self, *args, frame_index=1, **kvargs):
        frame = sys._getframe(frame_index)

        vals = {}

        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)

        return string.Formatter().vformat(' '.join(args), args, vals)

    def fformat(self, s):
        return self.e(s, frame_index=3)

    def cprint(self, *args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, printmsg=True, verbosity=0, **kvargs):
        if printmsg and verbosity > config['verbose']:
            return ''
        frame = sys._getframe(frame_index)

        vals = {
            'bgreen':  Fore.GREEN  + Style.BRIGHT,
            'bred':	Fore.RED	+ Style.BRIGHT,
            'bblue':   Fore.BLUE   + Style.BRIGHT,
            'byellow': Fore.YELLOW + Style.BRIGHT,
            'bmagenta': Fore.MAGENTA + Style.BRIGHT,

            'green':  Fore.GREEN,
            'red':	Fore.RED,
            'blue':   Fore.BLUE,
            'yellow': Fore.YELLOW,
            'magenta': Fore.MAGENTA,

            'bright': Style.BRIGHT,
            'srst':   Style.NORMAL,
            'crst':   Fore.RESET,
            'rst':	Style.NORMAL + Fore.RESET
        }

        if config['accessible']:
            vals = {'bgreen':'', 'bred':'', 'bblue':'', 'byellow':'', 'bmagenta':'', 'green':'', 'red':'', 'blue':'', 'yellow':'', 'magenta':'', 'bright':'', 'srst':'', 'crst':'', 'rst':''}

        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)

        unfmt = ''
        if char is not None and not config['accessible']:
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


    def debug(self, *args, color=Fore.GREEN, sep=' ', end='\n', file=sys.stdout, **kvargs):
        if config['verbose'] >= 2:
            if config['accessible']:
                args = ('Debug:',) + args
            self.cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def info(self, *args, sep=' ', end='\n', file=sys.stdout, **kvargs):
        self.cprint(*args, color=Fore.BLUE, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def warn(self, *args, sep=' ', end='\n', file=sys.stderr,**kvargs):
        if config['accessible']:
            args = ('Warning:',) + args
        self.cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def error(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        if config['accessible']:
            args = ('Error:',) + args
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def fail(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        if config['accessible']:
            args = ('Failure:',) + args
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
        exit(-1)