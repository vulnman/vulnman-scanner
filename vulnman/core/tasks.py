import asyncio
import time
from datetime import datetime
from vulnman.core.utils import logger


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


async def start_heartbeat(target, period=60):
    while True:
        await asyncio.sleep(period)
        async with target.lock:
            count = len(target.running_tasks)

            tasks_list = ': {BBLUE}' + ', '.join(target.running_tasks.keys()) + '{RST}'

            current_time = datetime.now().strftime('%H:%M:%S')

            if count > 1:
                log_msg = "{BGREEN}" + current_time + "{RST} - There are {BYELLOW}" + str(
                    count) + "{RST} scans still running against {BYELLOW}" + target.address + "{RST}"
                logger.info(log_msg)
                logger.debug(log_msg + tasks_list)
            elif count == 1:
                log_msg = '{BGREEN}' + current_time + '{RST} - There is {BYELLOW}1{RST} scan still running ' \
                                                      'against {BYELLOW}' + target.address + '{RST}'
                logger.info(log_msg)
                logger.debug(log_msg + tasks_list)
