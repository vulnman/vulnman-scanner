import asyncio
import sys
import termios
import time
from vulnman.config import config


def cancel_all_tasks(_signal, _frame, autorecon, terminal_settings):
    for task in asyncio.all_tasks():
        task.cancel()

    for target in autorecon.scanning_targets:
        for process_list in target.running_tasks.values():
            for process_dict in process_list['processes']:
                try:
                    process_dict['process'].kill()
                # Will get raised if the process finishes before we get to killing it.
                except ProcessLookupError:
                    pass

    if not config['disable_keyboard_control']:
        # Restore original terminal settings.
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, terminal_settings)


def calculate_elapsed_time(start_time, short=False):
    elapsed_seconds = round(time.time() - start_time)

    m, s = divmod(elapsed_seconds, 60)
    h, m = divmod(m, 60)

    elapsed_time = []
    if short:
        elapsed_time.append(str(h).zfill(2))
    else:
        if h == 1:
            elapsed_time.append(str(h) + ' hour')
        elif h > 1:
            elapsed_time.append(str(h) + ' hours')

    if short:
        elapsed_time.append(str(m).zfill(2))
    else:
        if m == 1:
            elapsed_time.append(str(m) + ' minute')
        elif m > 1:
            elapsed_time.append(str(m) + ' minutes')

    if short:
        elapsed_time.append(str(s).zfill(2))
    else:
        if s == 1:
            elapsed_time.append(str(s) + ' second')
        elif s > 1:
            elapsed_time.append(str(s) + ' seconds')
        else:
            elapsed_time.append('less than a second')

    if short:
        return ':'.join(elapsed_time)
    else:
        return ', '.join(elapsed_time)
