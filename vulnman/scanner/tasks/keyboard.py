import sys
import asyncio
import select
from datetime import datetime
from vulnman.config import config
from vulnman.core.utils.logging import logger
from vulnman.scanner.utils.tasks import calculate_elapsed_time


async def keyboard(autorecon):
    keyboard_input = ''
    while True:
        if select.select([sys.stdin], [], [], 0.1)[0]:
            keyboard_input += sys.stdin.buffer.read1(-1).decode('utf8')
            while keyboard_input != '':
                if len(keyboard_input) >= 3:
                    if keyboard_input[:3] == '\x1b[A':
                        keyboard_input = ''
                        if config['verbose'] == 3:
                            logger.info('Verbosity is already at the highest level.')
                        else:
                            config['verbose'] += 1
                            logger.info('Verbosity increased to ' + str(config['verbose']))
                    elif keyboard_input[:3] == '\x1b[B':
                        keyboard_input = ''
                        if config['verbose'] == 0:
                            logger.info('Verbosity is already at the lowest level.')
                        else:
                            config['verbose'] -= 1
                            logger.info('Verbosity decreased to ' + str(config['verbose']))
                    else:
                        if keyboard_input[0] != 's':
                            keyboard_input = keyboard_input[1:]

                if len(keyboard_input) > 0 and keyboard_input[0] == 's':
                    keyboard_input = keyboard_input[1:]
                    for target in autorecon.scanning_targets:
                        count = len(target.running_tasks)

                        tasks_list = []
                        if config['verbose'] >= 1:
                            for key, value in target.running_tasks.items():
                                elapsed_time = calculate_elapsed_time(value['start'], short=True)
                                tasks_list.append('{bblue}' + key + '{rst}' + ' (elapsed: ' + elapsed_time + ')')

                            tasks_list = ':\n    ' + '\n    '.join(tasks_list)
                        else:
                            tasks_list = ''

                        current_time = datetime.now().strftime('%H:%M:%S')

                        if count > 1:
                            logger.info('{bgreen}' + current_time + '{rst} - There are {byellow}' + str(
                                count) + '{rst} scans still running against {byellow}' + target.address + '{rst}' +
                                        tasks_list)
                        elif count == 1:
                            logger.info(
                                '{bgreen}' + current_time +
                                '{rst} - There is {byellow}1{rst} scan still running against {byellow}' +
                                target.address + '{rst}' + tasks_list)
                else:
                    keyboard_input = keyboard_input[1:]
        await asyncio.sleep(0.1)
